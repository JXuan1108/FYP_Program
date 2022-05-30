import base64
import glob
import io

import cv2
from PIL import Image
from tkinter.filedialog import *


# def image_compressor(image):
#     img = [cv2.imread(file) for file in glob.glob('C:/Users/User/Documents/FYP/deepStega/data/secretImage/*.tiff')]
#
#     img.save(buf, quality=100, optimize=True, subsampling=0, format='png')
#
#     img_bytes = buf.getvalue()
#
#     return img_bytes

# import cv2
# import os
# base_path = "C:/Users/User/Documents/FYP/deepStega/data/secretImage"
# new_path = "C:/Users/User/Documents/FYP/deepStega/data/convertedImage"
# from PIL import Image
# import os
# directory = r'C:\Users\User\Documents\FYP\deepStega\data\secretImage'
# c=1
# for filename in os.listdir(directory):
#     if filename.endswith(".jpg"):
#         im = Image.open(filename)
#         name='img'+str(c)+'.png'
#         rgb_im = im.convert('RGB')
#         rgb_im.save(name)
#         c+=1
#         print(os.path.join(directory, filename))
#         continue
#     else:
#         continue

import cv2, os


def tif_to_png_converter(filePath):
    base_path = filePath
    new_path = filePath
    for infile in os.listdir(base_path):
        # print("file : " + infile)
        read = Image.open(base_path + infile)
        outfile = infile.split('.')[0] + '.png'
        cv2.imwrite(new_path + outfile, read)
        # Deleting the .tiff file after converting
        if infile[-3:] == "tif":
            print(infile)
            os.remove(filePath + '/' + infile)
            # check if file exists or not


if __name__ == "__main__":
    print("cleaning the files")
    tif_to_png_converter("C:/Users/User/Documents/FYP/deepStega/data/secretImage/")