# -*- coding:utf-8 -*-
r"""
    cnn by pytorch
"""
import os
import shutil
import time
from divide_categories import divide_categories

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from sklearn.metrics import confusion_matrix
from torch.utils.data import Dataset, DataLoader


random_seed = 42
np.random.seed(random_seed)
torch.manual_seed(random_seed)

class TrafficDataset(Dataset):
    """ traffic dataset."""

    def __init__(self, input_dir, transform=None):
        """
        Args:
            csv_file (string): Path to the csv file with annotations.
            root_dir (string): Directory with all the images.
            transform (callable, optional): Optional transform to be applied
                on a sample.
        """

        def load_data(input_dir=''):
            data_dict = {'images': [], 'labels': []}
            for sub_folder in sorted(os.listdir(input_dir), key=lambda x: x.lower()):
                label = [int(sub_folder.split(':')[0])-1]  # label from 0, 1, 2,
                for file in os.listdir(os.path.join(input_dir, sub_folder)):
                    file_tmp = os.path.join(input_dir, sub_folder)
                    file_tmp = os.path.join(file_tmp, file)
                    data_dict['images'].append(np.array(Image.open(file_tmp)))
                    data_dict['labels'].append(label)

            return data_dict

        self.data = load_data(input_dir)
        self.transform = transform

    def __len__(self):
        return len(self.data['labels'])

    def __getitem__(self, idx):
        # img_name = os.path.join(self.root_dir,
        #                         self.landmarks_frame.iloc[idx, 0])
        # image = io.imread(img_name)
        # landmarks = self.landmarks_frame.iloc[idx, 1:].as_matrix()
        # landmarks = landmarks.astype('float').reshape(-1, 2)
        # sample = {'images': image, 'landmarks': landmarks}
        image = torch.Tensor(self.data['images'][idx])
        label = torch.Tensor(self.data['labels'][idx])
        sample = {'images': image, 'labels': label}
        if self.transform:
            sample = self.transform(sample)

        return sample

#
# def split_train_val_test(dataset, train_val_test_size=[0.6, 0.2, 0.2], shuffle_flg=True):
#     from torch.utils.data.sampler import SubsetRandomSampler
#     # Creating data indices for training and validation splits:
#     dataset_size = len(dataset['labels'])
#     indices = list(range(dataset_size))
#     split = int(np.floor(train_val_test_size[0] * dataset_size))
#     if shuffle_flg:
#         np.random.seed(random_seed)
#         np.random.shuffle(indices)
#     train_indices, val_indices = indices[:split], indices[split:]
#
#     # Creating PT data samplers and loaders:
#     train_sampler = SubsetRandomSampler(train_indices)
#     val_sampler = SubsetRandomSampler(val_indices)
#
#     #
#     # # Training
#     # n_training_samples = int(len(dataset['labels']) * train_val_test_size[0])
#     # train_sampler = SubsetRandomSampler(np.arange(n_training_samples, dtype=np.int64))
#     # # Validation
#     # n_val_samples = int(len(dataset['labels']) * train_val_test_size[1])
#     # val_sampler = SubsetRandomSampler(np.arange(n_training_samples, n_training_samples + n_val_samples, dtype=np.int64))
#     # Test
#     n_test_samples = int(len(dataset['labels']) * train_val_test_size[-1])
#     test_sampler = SubsetRandomSampler(np.arange(n_test_samples, dtype=np.int64))
#
#     # train_size = int(0.8 * len(dataset))
#     # test_size = len(dataset) - train_size
#     # train_dataset, test_dataset = torch.utils.data.random_split(dataset, [train_size, test_size])
#
#     return train_sampler, val_sampler, test_sampler


def split_train_test(dataset, test_size=0.2, shuffle_flg=True):
    from torch.utils.data.sampler import SubsetRandomSampler
    # Creating data indices for training and validation splits:
    dataset_size = len(dataset)
    indices = list(range(dataset_size))
    split = int(np.floor(test_size * dataset_size))
    if shuffle_flg:
        np.random.seed(random_seed)
        np.random.shuffle(indices)
    train_indices, test_indices = indices[split:],indices[:split]

    # Creating PT data samplers and loaders:
    train_sampler = SubsetRandomSampler(train_indices)
    test_sampler = SubsetRandomSampler(test_indices)

    return train_sampler,test_sampler


class Shape(nn.Module):
    def __init__(self,  batch_size=10, output=10, idx_layer='',):
        super(Shape, self).__init__()
        self.idx_layer = idx_layer
        self.batch_size = batch_size
        self.output=output

    def forward(self, x):
        # Do your print / debug stuff here
        # print('print_%sth_layer (batch_size x out_dim)=%s' % (self.idx_layer, x.shape))
        x=x.view(-1, 1, self.output)
        return x

class SimpleCNN(torch.nn.Module):
    # Our batch shape for input x is (3, 32, 32)

    def __init__(self, dataset):
        super(SimpleCNN, self).__init__()

        # self.train_sampler, self.val_sampler, self.test_sampler = split_train_val_test(dataset.data,
        #                                                                                train_val_test_size=[0.6, 0.2,
        #                                                                                                     0.2])
        self.train_sampler, self.test_sampler = split_train_test(dataset,test_size=0.2, shuffle_flg=True)
        self.batch_size = 64
        self.n_epochs = 200

        self.net = nn.Sequential(nn.Conv2d(1, 6, kernel_size=(5, 5), stride=(1, 1)),
                                 nn.MaxPool2d(2, 2),
                                 nn.LeakyReLU(True),
                                 nn.Conv2d(6, 3, kernel_size=(5, 5)),
                                 nn.MaxPool2d(2, 2),
                                 nn.LeakyReLU(True),
                                 Shape(self.batch_size,3*4*4),  # custom shape.
                                 nn.Linear(3 * 4*4, 100),
                                 nn.LeakyReLU(True),
                                 nn.Linear(100, 12),
                                 nn.Softmax()
                                 )

        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = torch.optim.SGD(self.net.parameters(), lr=0.0001, momentum=0.9)

    def forward(self, x):
        x = self.net(x)

        return x

    def train(self, dataset):

        # train_size = int(0.8 * len(dataset))
        # test_size = len(dataset) - train_size
        # train_dataset, test_dataset = torch.utils.data.random_split(dataset, [train_size, test_size])
        #
        # train_loader = DataLoader(train_dataset, batch_size=self.batch_size,
        #                           shuffle=True, num_workers=4, drop_last=True)
        self.dataset = dataset
        train_loader = DataLoader(dataset, batch_size=self.batch_size, sampler=self.train_sampler,
                                  shuffle=False, num_workers=4, drop_last=True)
        # val_loader = DataLoader(dataset, batch_size=1000, sampler=self.val_sampler,
        #                         shuffle=False, num_workers=4, drop_last=True)
        # val_loader = DataLoader(dataset, batch_size=1000, sampler=self.train_sampler,
        #                         shuffle=False, num_workers=4, drop_last=True)
        # val_loader = train_loader

        self.loss_dict={'train_loss':[],'train_acc':[],'test_loss':[],'test_acc':[]}
        # Time for printing
        training_start_time = time.time()
        # Loop for n_epochs
        for epoch in range(self.n_epochs):
            running_loss = 0.0
            print_every = self.batch_size
            start_time = time.time()
            train_loss_tmp = 0
            for i, data in enumerate(train_loader):
                # Get inputs
                inputs, labels = data['images'], data['labels']
                batch_len = labels.size()[0]
                inputs = inputs.view(batch_len,1, inputs.size()[1],inputs.size()[2])
                # labels = torch.zeros(labels.size()[0], 12).scatter_(1, labels.long(),1)
                                                                            # int to one-hot, (dim, index, value=1)
                # print(f"{inputs.size()}")
                # Set the parameter gradients to zero
                self.optimizer.zero_grad()
                # Forward pass, backward pass, optimize
                outputs = self.forward(inputs)
                loss_size = self.criterion(outputs.view(batch_len,12), labels.long().view(batch_len,))
                loss_size.backward()
                self.optimizer.step()
                # Print statistics
                # running_loss += loss_size.data[0]
                train_loss_tmp += loss_size.data.item()
                print(f"i={i}, loss_size:{loss_size}")
                # # Print every 10th batch of an epoch
                # if (i + 1) % (print_every + 1) == 0:
                #     print("Epoch {}, {:d}% \t train_loss: {:.2f} took: {:.2f}s".format(
                #         epoch + 1, int(100 * (i + 1) / self.batch_size), running_loss / print_every,
                #         time.time() - start_time))
                #     # Reset running loss and time
                #     running_loss = 0.0
                #     start_time = time.time()

            # # At the end of the epoch, do a pass on the validation set
            train_loss_tmp, train_acc_tmp = self.evaluate(self.train_sampler)
            self.loss_dict['train_loss'].append(train_loss_tmp)
            self.loss_dict['train_acc'].append(train_acc_tmp)

            test_loss_tmp, test_acc_tmp=self.evaluate(self.test_sampler)
            self.loss_dict['test_loss'].append(test_loss_tmp)
            self.loss_dict['test_acc'].append(test_acc_tmp)

        print("Training finished, took {:.2f}s".format(time.time() - training_start_time))

    def evaluate(self,test_sampler):
        # self.net(test_data)
        test_loader = DataLoader(self.dataset, batch_size=self.batch_size, sampler=test_sampler,
                                shuffle=False, num_workers=4, drop_last=True)
        test_loss_tmp = 0
        for idx, data in enumerate(test_loader):
            # Forward pass
            inputs, labels = data['images'], data['labels']
            inputs = inputs.view(labels.size()[0], 1, inputs.size()[1], inputs.size()[2])
            test_outputs = self.forward(inputs)
            val_loss_size = self.criterion(test_outputs.view(labels.size()[0],12), labels.long().view(labels.size()[0],))
            test_loss_tmp += val_loss_size.data[0]

            test_preds = np.argmax(test_outputs.view(labels.size()[0],12).detach().numpy(),axis=1)
            print(f"real_labels:{list(labels.view(labels.size()[0],).numpy())}")
            print(f"val_preds:{test_preds}")
            if len(test_preds) != len(list(labels.view(labels.size()[0],).numpy())):
                print(len(test_preds), len(list(labels.view(labels.size()[0],).numpy())))
                continue
            if idx == 0:
                cm= confusion_matrix(test_preds,labels)
            else:
                try:
                    cm_pre = cm
                    cm = cm_pre+ confusion_matrix(test_preds,labels)
                    # cm +=confusion_matrix(test_preds,labels)
                except:
                    cm = cm_pre

        print("test loss = {:.2f}".format(test_loss_tmp / len(test_loader)))
        print(f"cm:{cm}")

        acc=sum([cm[i,i] for i in range(cm.shape[0])]) / cm.sum()
        print(f"acc:{acc}")

        return test_loss_tmp, acc

def plot_data(loss_dict):

    import matplotlib.pyplot as plt
    # plt.plot(loss_dict['train_acc'],'-g')
    # plt.plot(loss_dict['test_acc'],'*r')

    plt.plot(loss_dict['train_loss'],'-b')
    plt.plot(loss_dict['test_loss'],'*m')

    plt.show()


if __name__ == '__main__':
    output_dir = '../categories'
    if not os.path.exists(output_dir):
        output_dir = divide_categories(input_dir='../images-full_sessions', output_dir=output_dir)

    dataset = TrafficDataset(output_dir)
    cnn_m = SimpleCNN(dataset)
    cnn_m.train(dataset)

    plot_data(cnn_m.loss_dict)