import base64
import io
from PIL import Image
from tkinter.filedialog import *


def image_compressor(image):
    img = Image.open(image)

    buf = io.BytesIO()
    img.save(buf, quality=75, optimize=True, subsampling=0, format=img.format)

    img_bytes = buf.getvalue()

    return img_bytes


# filepath = askopenfilename()
# img = Image.open(filepath)
# # Height, Width = img.size
# #
# # image = img.resize((Height, Width), Image.ANTIALIAS)
# rgb_im = img.convert('RGB')
# savepath = asksaveasfilename()
#
# rgb_im.save(savepath+"_COMPRESSED.png", format=img.format, quality=75, optimize=True, subsampling=0)
