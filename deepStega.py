import torch
import warnings
from deepStegaModel import Hide, Reveal
from deepStegaUtils import DatasetFromFolder
import torch.nn.init as init
import torch.nn as nn
from torch.autograd import Variable
from torch.utils.data import DataLoader
from torchvision.utils import save_image
import torch.optim as optim
from torch.optim.lr_scheduler import MultiStepLR

import numpy as np
import os
from PIL import Image
from torchvision import transforms


def init_weights(m):
    warnings.filterwarnings('ignore')
    classname = m.__class__.__name__
    if classname.find('Conv') != -1:
        init.kaiming_normal(m.weight.data, a=0, mode='fan_in')
    elif classname.find('BatchNorm') != -1:
        m.weight.data.normal_(1.0, 0.02)
        m.bias.data.fill_(0)


# Function to save the model
def saveModel(model, save_path):
    path = save_path
    torch.save(model.state_dict(), path)


def train_model():
    result_dir = 'result'
    ckpt_dir = 'ckpt'
    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(ckpt_dir, exist_ok=True)

    dataset = DatasetFromFolder(r'C:/Users/User/Documents/FYP_Program/trainedData')
    dataloader = DataLoader(dataset, 8, shuffle=True, num_workers=2)

    hide_net = Hide()
    hide_net.apply(init_weights)
    reveal_net = Reveal()
    reveal_net.apply(init_weights)

    criterion = nn.MSELoss()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    hide_net.to(device)
    reveal_net.to(device)
    criterion.to(device)

    optim_h = optim.Adam(hide_net.parameters(), lr=1e-3)
    optim_r = optim.Adam(reveal_net.parameters(), lr=1e-3)

    schedulee_h = MultiStepLR(optim_h, milestones=[100, 1000])
    schedulee_r = MultiStepLR(optim_r, milestones=[100, 1000])

    for epoch in range(2000):
        schedulee_h.step()
        schedulee_r.step()

        epoch_loss_h = 0
        epoch_loss_r = 0
        for i, (secret, cover) in enumerate(dataloader):
            secret = Variable(secret).to(device)
            cover = Variable(cover).to(device)

            optim_h.zero_grad()
            optim_r.zero_grad()

            output = hide_net(secret, cover)
            loss_h = criterion(output, cover)
            reveal_secret = reveal_net(output)
            loss_r = criterion(reveal_secret, secret)

            epoch_loss_h += loss_h.item()
            epoch_loss_r += loss_r.item()

            loss = loss_h + 0.75 * loss_r
            loss.backward()
            optim_h.step()
            optim_r.step()

        print('epoch', epoch)
        print('hide loss: %.3f' % epoch_loss_h)
        print('reveal loss: %.3f' % epoch_loss_r)
        print('=======' * 5 + '>>>')

        if epoch % 50 == 0 or epoch == 2000:
            save_image(torch.cat(
                [secret.cpu().data[:4], reveal_secret.cpu().data[:4], cover.cpu().data[:4], output.cpu().data[:4]],
                dim=0), fp='./{}/res_epoch_{}.png'.format(result_dir, epoch), nrow=4)
            torch.jit.save(torch.jit.script(hide_net), './{}/epoch_{}_hide.pkl'.format(ckpt_dir, epoch))
            torch.jit.save(torch.jit.script(reveal_net), './{}/epoch_{}_reveal.pkl'.format(ckpt_dir, epoch))

        if epoch == 2000:
            torch.save(hide_net.state_dict(), r'C:/Users/User/Documents/FYP_Program/trainedModel/HideNet.pth')
            torch.save(reveal_net.state_dict(), r'C:/Users/User/Documents/FYP_Program/trainedModel/RevealNet.pth')

        else:
            torch.save(hide_net.state_dict(), r'C:/Users/User/Documents/FYP_Program/trainedModel/HideNet/HideNet.pth')
            torch.save(reveal_net.state_dict(), r'C:/Users/User/Documents/FYP_Program/trainedModel/RevealNet/RevealNet.pth')


if __name__ == '__main__':
    train_model()

# # Function to test the model
# def hideImageFunc(secret, cover):
#     result_dir = 'output'
#     output_dir = 'sendImage'
#     os.makedirs(result_dir, exist_ok=True)
#     os.makedirs(output_dir, exist_ok=True)
#
#     # Load the model that we saved at the end of the training loop
#     hide_model = Hide()
#     hide_model.apply(init_weights)
#     hide_path = r'C:/Users/User/Documents/FYP_Program/trainedModel/HideNet/HideNet.pth'
#     hide_model.load_state_dict(torch.load(hide_path))
#
#     reveal_model = Reveal()
#     reveal_model.apply(init_weights)
#     reveal_path = r'C:/Users/User/Documents/FYP_Program/trainedModel/RevealNet/RevealNet.pth'
#     reveal_model.load_state_dict(torch.load(reveal_path))
#
#     hide_model.eval()
#     reveal_model.eval()
#
#     criterion = nn.MSELoss()
#     device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
#
#     hide_model.to(device)
#     reveal_model.to(device)
#     criterion.to(device)
#
#     convert_tensor = transforms.ToTensor()
#
#     secret_convert = np.flip(secret, axis=-1)
#     PIL_secret_image = Image.fromarray(secret_convert)
#     PIL_secret_image = PIL_secret_image.resize((256, 256))
#     secretImage = convert_tensor(PIL_secret_image)
#
#     cover_convert = np.flip(cover, axis=-1)
#     PIL_cover_image = Image.fromarray(cover_convert)
#     coverImage = convert_tensor(PIL_cover_image)
#
#     with torch.no_grad():
#         epoch_loss_h = 0
#         epoch_loss_r = 0
#
#         secretImage = Variable(secretImage).to(device)
#         coverImage = Variable(coverImage).to(device)
#
#         hide_model.zero_grad()
#         reveal_model.zero_grad()
#
#         output = hide_model(secretImage[None, ...], coverImage[None, ...])
#         loss_h = criterion(output, coverImage)
#         reveal_secret = reveal_model(output)
#         loss_r = criterion(reveal_secret, secretImage)
#
#         epoch_loss_h += loss_h.item()
#         epoch_loss_r += loss_r.item()
#
#         print('hide loss: %.3f' % epoch_loss_h)
#         print('reveal loss: %.3f' % epoch_loss_r)
#         print('=======' * 5 + '>>>')
#
#         home = os.path.expanduser("~")
#         save_path = os.path.join(home, "Downloads")
#         save_image(torch.cat([output.cpu().data[:4]], dim=0), fp=save_path+"/embedImage.png")
#
#         # save_image(torch.cat(
#         #         [secretImage.cpu().data[:4], reveal_secret.cpu().data[:4], coverImage.cpu().data[:4], output.cpu().data[:4]],
#         #         dim=0), fp='./{}/result_pic.png'.format(result_dir), nrow=4)


# def revealImageFunc(image):
#     reveal_dir = 'reveal'
#     os.makedirs(reveal_dir, exist_ok=True)
#
#     reveal_model = Reveal()
#     reveal_model.apply(init_weights)
#     reveal_path = r'C:/Users/User/Documents/FYP_Program/trainedModel/RevealNet/RevealNet.pth'
#     reveal_model.load_state_dict(torch.load(reveal_path))
#
#     reveal_model.eval()
#
#     criterion = nn.MSELoss()
#     device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
#     reveal_model.to(device)
#     criterion.to(device)
#
#     # img = cv2.imread(image)
#     img_convert = np.flip(image, axis=-1)
#     PIL_image = Image.fromarray(img_convert)
#
#     convert_tensor = transforms.ToTensor()
#     testImage = convert_tensor(PIL_image)
#     print(testImage)
#
#     with torch.no_grad():
#         reveal_model.zero_grad()
#         testImage = Variable(testImage).to(device)
#         reveal_secret = reveal_model(testImage[None, ...])
#
#         #         save_path = asksaveasfilename()
#         # t = threading.Thread(target=save_path)
#         # t.setDaemon(True)
#         # t.start()
#         # save_image(torch.cat([reveal_secret.cpu().data[:4]], dim=0), fp=save_path + ".png")
#
#         home = os.path.expanduser("~")
#         save_path = os.path.join(home, "Downloads")
#         save_image(torch.cat([reveal_secret.cpu().data[:4]], dim=0), fp=save_path + "/revealedImage.png")
#
#         # save_path = asksaveasfilename()
#         # save_image(torch.cat([reveal_secret.cpu().data[:4]], dim=0), fp=save_path+".png")