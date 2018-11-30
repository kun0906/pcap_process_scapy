import os
import random
import shutil


def split_train_test(input_dir, output_dir='./2_split_train_test', train_percent=0.7):
    train_dir = os.path.join(output_dir, 'Train')
    test_dir = os.path.join(output_dir, 'Test')
    # if not os.path.exists(train_dir):
    #     os.makedirs(train_dir)
    # if not os.path.exists(test_dir):
    #     os.makedirs(test_dir)
    lb = 0
    if os.path.isdir(input_dir):
        for sub_apps_dir in os.listdir(input_dir):
            sub_apps_dir_path = os.path.join(input_dir, sub_apps_dir)
            if os.path.isdir(sub_apps_dir_path):
                lst = os.listdir(sub_apps_dir_path)
                if lst != []:
                    train_num = int(train_percent * len(lst))
                    random.shuffle(lst)
                    train_lst = lst[0:train_num]
                    # train_list = list(map(lambda(x:x train_lst)))
                    train_dir_tmp = os.path.join(train_dir, str(lb))
                    test_dir_tmp = os.path.join(test_dir, str(lb))
                    # train_dir_tmp = os.path.join(train_dir_tmp,sub_apps_dir)
                    # test_dir_tmp = os.path.join(test_dir_tmp, sub_apps_dir)
                    if not os.path.exists(train_dir_tmp):
                        os.makedirs(train_dir_tmp)
                    if not os.path.exists(test_dir_tmp):
                        os.makedirs(test_dir_tmp)
                    for file_tmp in train_lst:
                        shutil.copy2(os.path.join(sub_apps_dir_path, file_tmp), train_dir_tmp)
                    for file_tmp in lst[train_num:]:
                        shutil.copy2(os.path.join(sub_apps_dir_path, file_tmp), test_dir_tmp)
                    lb += 1
    else:
        print('%s is not a dir.' % input_dir)

    return 0


if __name__ == '__main__':
    input_dir = '../sessions_data'
    split_train_test(input_dir, output_dir='../2_split_train_test', train_percent=0.7)
