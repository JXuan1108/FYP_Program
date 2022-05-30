import cv2
import numpy as np
import torch.utils.data as data
import os
from PIL import Image
from torchvision import transforms

IMG_EXTENSIONS = [
    '.jpg', '.JPG', '.jpeg', '.JPEG',
    '.png', '.PNG', '.ppm', '.PPM', '.bmp', '.BMP',
]


def is_image_file(filename):
    return any(filename.endswith(extension) for extension in IMG_EXTENSIONS)


def load_img(filepath):
    # img = Image.open(filepath)
    img = cv2.imread(filepath)
    img_convert = np.flip(img, axis=-1)
    PIL_image = Image.fromarray(img_convert)
    PIL_image = PIL_image.resize((256, 256))
    return PIL_image


def input_transform(crop_size):
    return transforms.Compose([
        transforms.ToTensor(),
    ])


class DatasetFromFolder(data.Dataset):
    def __init__(self, image_dir, crop_size):
        super(DatasetFromFolder, self).__init__()
        self.input_transform = input_transform(crop_size)
        self.image_filenames = [os.path.join(image_dir, x) for x in os.listdir(image_dir) if is_image_file(x)]     # 这种只适合一个文件夹内全是图片的，子文件夹内图片不会读取
        self.secret_filenames = self.image_filenames[:len(self.image_filenames)//2]
        self.cover_filenames = self.image_filenames[len(self.image_filenames)//2:]
        # print(self.image_filenames)
        # secret_folder = os.path.join(image_dir, 'secretImage')
        # self.secret_image_filenames = [os.path.join(secret_folder, x) for x in os.listdir(secret_folder) if is_image_file(x)]
        # self.secret_filenames = self.secret_image_filenames[:len(self.secret_image_filenames)//2]
        # # print(self.secret_filenames)
        # # self.cover_filenames = self.image_filenames[len(self.image_filenames)//2:]
        # cover_folder = os.path.join(image_dir, 'coverImage')
        # self.cover_image_filenames = [os.path.join(cover_folder, x) for x in os.listdir(cover_folder) if is_image_file(x)]
        # self.cover_filenames = self.cover_image_filenames[len(self.cover_image_filenames)//2:]
        # # print(self.cover_filenames)

    def __getitem__(self, index):
        secret = load_img(self.secret_filenames[index])
        cover = load_img(self.cover_filenames[index])
        if self.input_transform:
            secret = self.input_transform(secret)
            cover = self.input_transform(cover)

        return secret, cover

    def __len__(self):
        return len(self.secret_filenames)
