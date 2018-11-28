# -*- coding:utf-8 -*-
r"""
    Implement CNN by pytorch 0.41
"""
import os
import time

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader

from _5_plot.divide_categories import divide_categories

random_seed = 42
np.random.seed(random_seed)
torch.manual_seed(random_seed)


def load_data(input_dir=''):
    data_dict = {'images': [], 'labels': []}
    for sub_folder in sorted(os.listdir(input_dir), key=lambda x: x.lower()):
        label = int(sub_folder.split(':')[0]) - 1  # label from 0, 1, 2,
        for file in os.listdir(os.path.join(input_dir, sub_folder)):
            file_tmp = os.path.join(input_dir, sub_folder)
            file_tmp = os.path.join(file_tmp, file)
            data_dict['images'].append(np.array(Image.open(file_tmp)))
            data_dict['labels'].append(label)

    return data_dict


class TrafficDataset(Dataset):
    """ traffic dataset."""

    def __init__(self, dataset_tuple=(), transform=None):
        """
        Args:
            csv_file (string): Path to the csv file with annotations.
            root_dir (string): Directory with all the images.
            transform (callable, optional): Optional transform to be applied
                on a sample.
        """

        self.X, self.y = dataset_tuple
        self.transform = transform

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        # image = torch.Tensor(self.data['images'][idx])
        # label = torch.Tensor(self.data['labels'][idx])
        image = torch.Tensor(self.X[idx])
        # label = torch.Tensor(self.y[idx])
        label = torch.Tensor([self.y[idx]])
        # sample = {'images': image, 'labels': label}
        sample = (image, label)
        if self.transform:
            sample = self.transform(sample)

        return sample


def split_train_test_pytorch(dataset, test_size=0.2, shuffle_flg=True):
    """

    :param dataset:
    :param test_size:
    :param shuffle_flg:
    :return:
    """
    from torch.utils.data.sampler import SubsetRandomSampler
    # Creating data indices for training and testing splits:
    dataset_size = len(dataset)
    indices = list(range(dataset_size))  # [0,1,2,..]
    split = int(np.floor(test_size * dataset_size))  # return the floor value
    if shuffle_flg:
        np.random.seed(random_seed)
        np.random.shuffle(indices)
    train_indices, test_indices = indices[split:], indices[:split]

    # Creating PT data samplers and loaders:
    train_sampler = SubsetRandomSampler(train_indices)
    test_sampler = SubsetRandomSampler(test_indices)

    train_set = DataLoader(dataset, batch_size=len(train_indices), sampler=train_sampler,
                           shuffle=False, num_workers=4, drop_last=False)

    test_set = DataLoader(dataset, batch_size=len(test_indices), sampler=test_sampler,
                          shuffle=False, num_workers=4, drop_last=False)

    return iter(train_set).next(), iter(test_set).next()


def split_train_test(X, y, test_size=0.2, shuffle_flg=True):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, shuffle=shuffle_flg)

    return (X_train, y_train), (X_test, y_test)


class Shape(nn.Module):
    def __init__(self, in_dim, out_dim=10, idx_layer='', ):
        super(Shape, self).__init__()
        self.idx_layer = idx_layer
        self.out_dim = out_dim

    def forward(self, x):
        # Do your print / debug stuff here
        # print('print_%sth_layer (batch_size x out_dim)=%s' % (self.idx_layer, x.shape))
        x = x.view(-1, 1, self.out_dim)
        return x


class SimpleCNN(torch.nn.Module):

    def __init__(self, n_epochs=10, n_classes=10):
        super(SimpleCNN, self).__init__()

        self.batch_size = 64
        self.n_epochs = n_epochs
        self.n_classes = n_classes

        self.net = nn.Sequential(nn.Conv2d(1, 6, kernel_size=(5, 5), stride=(1, 1)),
                                 nn.MaxPool2d(2, 2),
                                 nn.LeakyReLU(True),
                                 nn.Conv2d(6, 3, kernel_size=(5, 5)),
                                 nn.MaxPool2d(2, 2),
                                 nn.LeakyReLU(True),
                                 Shape(-1, out_dim=3 * 4 * 4),  # custom shape.
                                 nn.Linear(3 * 4 * 4, 100),
                                 nn.LeakyReLU(True),
                                 nn.Linear(100, self.n_classes),
                                 nn.Softmax()
                                 )

        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = torch.optim.SGD(self.net.parameters(), lr=0.0001, momentum=0.9)

    def forward(self, x):
        x = self.net(x)

        return x

    def train(self, train_set=(), val_set=()):
        r"""

        :param train_set:
        :param val_set:
        :return:
        """

        dataset = TrafficDataset(train_set)
        train_loader = DataLoader(dataset, batch_size=self.batch_size,
                                  shuffle=False, num_workers=4, drop_last=True)
        self.stats_dict = {'train_loss': [], 'train_acc': [], 'test_loss': [], 'test_acc': []}
        training_start_time = time.time()

        for epoch in range(self.n_epochs):
            train_loss_tmp = 0
            for idx, (b_X, b_y) in enumerate(train_loader):
                bth_len = b_y.size()[0]
                height = b_X.size()[1]
                width = b_X.size()[2]
                inputs = b_X.view(bth_len, 1, height, width)
                # labels = torch.zeros(labels.size()[0], self.n_classes).scatter_(1, labels.long(),1)
                # int to one-hot, (dim, index, value=1)
                # Set the parameter gradients to zero
                self.optimizer.zero_grad()
                # Forward pass, backward pass, optimize
                train_out_vals = self.forward(inputs)
                train_loss = self.criterion(train_out_vals.view(bth_len, self.n_classes), b_y.long().view(bth_len, ))
                train_loss.backward()
                self.optimizer.step()

                train_loss_tmp += train_loss.data.item()
                print(f"i={idx}, loss_size:{train_loss}")

            # # evalute on the validation set after each epoch.
            train_loss_tmp, train_acc_tmp = self.evaluate(train_set, name='train_set')
            self.stats_dict['train_loss'].append(train_loss_tmp)
            self.stats_dict['train_acc'].append(train_acc_tmp)

            test_loss_tmp, test_acc_tmp = self.evaluate(val_set, name='val_set')
            self.stats_dict['test_loss'].append(test_loss_tmp)
            self.stats_dict['test_acc'].append(test_acc_tmp)

        print(f"Training finished, took {time.time()-training_start_time}s")

    def evaluate(self, test_set=(), name='test_set'):
        r"""

        :param test_set:
        :return:
        """

        dataset = TrafficDataset(test_set)
        test_loader = DataLoader(dataset, batch_size=self.batch_size,
                                 shuffle=False, num_workers=4, drop_last=False)
        test_loss_tmp = 0
        for idx, (b_X, b_y) in enumerate(test_loader):
            bth_len = b_y.size()[0]
            height = b_X.size()[1]
            width = b_X.size()[2]
            inputs = b_X.view(bth_len, 1, height, width)
            test_out_vals = self.forward(inputs)
            test_loss = self.criterion(test_out_vals.view(bth_len, self.n_classes), b_y.long().view(bth_len, ))
            test_loss_tmp += test_loss.data.item()

            test_preds = np.argmax(test_out_vals.view(bth_len, self.n_classes).detach().numpy(), axis=1)
            # print(f"real_labels:{list(labels.view(labels.size()[0],).numpy())}")
            print(f"{name}: preds:{test_preds}")
            # if len(test_preds) != len(list(b_y.view(bth_len, ).numpy())):
            #     print(len(test_preds), len(list(b_y.view(bth_len, ).numpy())))
            #     continue
            if idx == 0:
                cm = confusion_matrix(test_preds, b_y)
            else:
                try:
                    cm_pre = cm
                    cm = cm_pre + confusion_matrix(test_preds, b_y)
                    # cm +=confusion_matrix(test_preds,labels)
                except:
                    print('cm_pre')
                    cm = cm_pre

        print(name + " loss = {:.2f}".format(test_loss_tmp / len(test_loader)))
        print(f"cm:{cm}")

        acc = sum([cm[i, i] for i in range(cm.shape[0])]) / cm.sum()
        print(f"acc:{acc}")

        return test_loss_tmp, acc


def plot_data(stats_dict):
    import matplotlib.pyplot as plt
    # plt.plot(stats_dict['train_acc'],'-g')
    # plt.plot(stats_dict['test_acc'],'*r')

    plt.plot(stats_dict['train_loss'], '-b')
    plt.plot(stats_dict['test_loss'], '*m')

    plt.show()


def main():
    output_dir = '../categories'
    if not os.path.exists(output_dir):
        output_dir = divide_categories(input_dir='../images-full_sessions', output_dir=output_dir)

    dataset_dict = load_data(output_dir)
    train_set, test_set = split_train_test(dataset_dict['images'], dataset_dict['labels'], test_size=0.3,
                                           shuffle_flg=True)
    train_set, val_set = split_train_test(train_set[0], train_set[1], test_size=0.2, shuffle_flg=True)

    cnn_mdl = SimpleCNN(n_classes=len(set(dataset_dict['labels'])))
    cnn_mdl.train(train_set=train_set, val_set=val_set)
    cnn_mdl.evaluate(test_set=test_set)

    plot_data(cnn_mdl.stats_dict)


if __name__ == '__main__':
    main()
