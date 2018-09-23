
import os
import errno
from PIL import Image
from array import *
from random import shuffle

def png2idx(input_dir='../2_flows_data', output_dir='../2_flows_train/train'):

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    name = [input_dir,output_dir]
    labels_dict={}
    FileList = os.listdir(input_dir)
    data_image = array('B')
    data_label = array('B')
    lb_int=0
    for filename in FileList:
        filename = os.path.join(input_dir,filename)
        # print(filename)
        lb_key=os.path.split(filename)[-1].split('|')[0]
        if lb_key not in labels_dict.keys():
            labels_dict[lb_key]=lb_int
            lb_int +=0
        # label = int(filename.split('/')[2])
        label=labels_dict[lb_key]
        Im = Image.open(filename)
        pixel = Im.load()
        width, height = Im.size
        for x in range(0, width):
            for y in range(0, height):
                data_image.append(pixel[x, y])
        data_label.append(label)  # labels start (one unsigned byte each)
    hexval = "{0:#0{1}x}".format(len(FileList), 6)  # number of files in HEX
    hexval = '0x' + hexval[2:].zfill(8)

    # header for label array
    header = array('B')
    header.extend([0, 0, 8, 1])
    header.append(int('0x' + hexval[2:][0:2], 16))
    header.append(int('0x' + hexval[2:][2:4], 16))
    header.append(int('0x' + hexval[2:][4:6], 16))
    header.append(int('0x' + hexval[2:][6:8], 16))
    data_label = header + data_label

    # additional header for images array
    if max([width, height]) <= 256:
        header.extend([0, 0, 0, width, 0, 0, 0, height])
    else:
        raise ValueError('Image exceeds maximum size: 256x256 pixels');

    header[3] = 3  # Changing MSB for image data (0x00000803)
    data_image = header + data_image
    output_file = open(name[1] + '-images-idx3-ubyte', 'wb')
    data_image.tofile(output_file)
    output_file.close()
    output_file = open(name[1] + '-labels-idx1-ubyte', 'wb')
    data_label.tofile(output_file)
    output_file.close()

    # gzip resulting files
    os.system('gzip ' + name[1] + '-images-idx3-ubyte')
    os.system('gzip ' + name[1] + '-labels-idx1-ubyte')

if __name__ == '__main__':
    png2idx()