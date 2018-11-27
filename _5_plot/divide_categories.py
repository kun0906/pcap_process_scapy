# -*- coding:utf-8 -*-
r"""
    divide categories
"""

import os
import shutil

def divide_categories(input_dir="", output_dir=''):
    """
    UNB 2017 VPN and Non-VPN Dataset   150files <=Pcap files (141) + Tor(9 files)
        1) "Non-VPN(110)"
        2) "VPN (31)"

        note: Tor(9 files): ['torFacebook','torGoogle','torTwitter','torVimeo1' ,'torVimeo2' ,'torVimeo3' ,'torYoutube1','torYoutube2' ,'torYoutube3']

    :param input_dir:
    :param output_dir:
    :return:
    """
    categories_dict = {
        "1:chat": ['AIMchat1', 'AIMchat2', 'aim_chat_3a', 'aim_chat_3b', 'facebookchat1', 'facebookchat2',
                   'facebookchat3', 'facebook_chat_4a', 'facebook_chat_4b',
                   'hangouts_chat_4a', 'hangout_chat_4b', 'ICQchat1', 'ICQchat2', 'icq_chat_3a', 'icq_chat_3b',
                   'skype_chat1a', 'skype_chat1b'],
        "2:email": ['gmailchat1', 'gmailchat2', 'gmailchat3', 'email1a', 'email1b', 'email2a', 'email2b'],
        "3:file_transfer": ['skype_file1', 'skype_file2', 'skype_file3', 'skype_file4', 'skype_file5', 'skype_file6',
                            'skype_file7', 'skype_file8', 'ftps_down_1a', 'ftps_down_1b', 'ftps_up_2a', 'ftps_up_2b',
                            'scp1', 'scpDown1', 'scpDown2', 'scpDown3', 'scpDown4', 'scpDown5', 'scpDown6',
                            'scpUp1', 'scpUp2', 'scpUp3', 'scpUp4', 'scpUp5', 'scpUp6', 'sftp1', 'sftpDown1',
                            'sftpDown2', 'sftp_down_3a', 'sftp_down_3b', 'sftpUp1', 'sftp_up_2a', 'sftp_up_2b'],
        "4:p2p": ['Torrent01'],
        "5:video": ['facebook_video1a', 'facebook_video1b', 'facebook_video2a', 'hangouts_video1b',
                    'hangouts_video2a', 'hangouts_video2b',
                    'netflix1', 'netflix2', 'netflix3', 'netflix4', 'skype_video1a', 'skype_video1b', 'skype_video2a',
                    'skype_video2b', 'spotify1', 'spotify2', 'spotify3', 'spotify4', 'vimeo1', 'vimeo2', 'vimeo3',
                    'vimeo4', 'youtube1', 'youtube2', 'youtube3', 'youtube4', 'youtube5', 'youtube6', 'youtubeHTML5_1'],
        "6:audio": ['facebook_audio1a', 'facebook_audio1b', 'facebook_audio2a', 'facebook_audio2b',
                    'facebook_audio3', 'facebook_audio4',
                    'hangouts_audio1a', 'hangouts_audio1b', 'hangouts_audio2a', 'hangouts_audio2b', 'hangouts_audio3',
                    'hangouts_audio4', 'skype_audio1a', 'skype_audio1b', 'skype_audio2a', 'skype_audio2b',
                    'skype_audio3', 'skype_audio4',
                    'voipbuster1b', 'voipbuster2b', 'voipbuster3b', 'voipbuster_4a', 'voipbuster_4b'],
        "7:chat": ['vpn_aim_chat1a', 'vpn_aim_chat1b', 'vpn_facebook_chat1a', 'vpn_facebook_chat1b',
                   'vpn_hangouts_chat1a', 'vpn_hangouts_chat1b', 'vpn_icq_chat1a', 'vpn_icq_chat1b', 'vpn_skype_chat1a',
                   'vpn_skype_chat1b'],
        "8:email": ['vpn_email2a', 'vpn_email2b'],
        "9:file_transfer": ['vpn_ftps_A', 'vpn_ftps_B', 'vpn_sftp_A', 'vpn_sftp_B', 'vpn_skype_files1a',
                            'vpn_skype_files1b'],
        "10:p2p": ['vpn_bittorrent'],
        "11:video": ['vpn_netflix_A', 'vpn_spotify_A', 'vpn_vimeo_A', 'vpn_vimeo_B', 'vpn_youtube_A'],
        "12:audio": ['vpn_facebook_audio2', 'vpn_hangouts_audio1', 'vpn_hangouts_audio2', 'vpn_skype_audio1',
                     'vpn_skype_audio2',
                     'vpn_voipbuster1a', 'vpn_voipbuster1b']

    }
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    pre_total_files = 0
    overcopy_cnt = 0
    total_tor_files = 0
    i = 0
    for idx, sub_folder in enumerate(sorted(os.listdir(input_dir), key=lambda x: x.lower())):
        files_lst_len = len(os.listdir(os.path.join(input_dir, sub_folder)))
        print(f"idx:{idx}, {sub_folder}:{files_lst_len}")
        pre_total_files += files_lst_len
        # sum_dict ={"non-vpn":0,"vpn":0}
        # for idx, (key, value) in enumerate(categories_dict.items()):
        #
        #     print(f"key:\'{key}\', {len(value)}")
        #     if idx < 6:
        #         sum_dict['non-vpn'] +=len(value)
        #     else:
        #         sum_dict['vpn'] +=len(value)
        # print(f"total:{sum_dict}")
        # break
        categories_flg = False
        for idx_tmp, (key, value) in enumerate(categories_dict.items()):
            if sub_folder in value:
                categories_flg = True
                output_dir_tmp = os.path.join(output_dir, key)
                if not os.path.exists(output_dir_tmp):
                    os.makedirs(output_dir_tmp)
                # shutil.copytree(os.path.join(input_dir,sub_folder), output_dir_tmp,)
                pre_copy_len = len(os.listdir(output_dir_tmp))
                input_dir_tmp = os.path.join(input_dir, sub_folder)
                for file in os.listdir(input_dir_tmp):
                    if os.path.exists(os.path.join(output_dir_tmp, file)):
                        # raise Exception("Destination file exists!")
                        print(f'{file} already exists')
                        i += 1
                        shutil.copy2(os.path.join(input_dir_tmp, file),
                                     os.path.join(output_dir_tmp, file + '_copy_' + str(i)))  # shutil.copy2(src, dst)
                    else:
                        shutil.copy2(os.path.join(input_dir_tmp, file), output_dir_tmp)  # shutil.copy2(src, dst)
                if files_lst_len != 0 and pre_copy_len != 0 and len(
                        os.listdir(output_dir_tmp)) < pre_copy_len + files_lst_len:
                    print(
                        f'overcopy happened. before copy:{pre_copy_len}, after copy:{len(os.listdir(output_dir_tmp))}, copy files:{files_lst_len}')
                    overcopy_cnt += ((pre_copy_len + files_lst_len) - len(os.listdir(output_dir_tmp)))
        if not categories_flg:
            total_tor_files += files_lst_len

    total_files = 0
    for idx, sub_folder in enumerate(sorted(os.listdir(output_dir), key=lambda x: x.lower())):
        files_lst_len = len(os.listdir(os.path.join(output_dir, sub_folder)))
        print(f"idx:{idx}, {sub_folder}:{files_lst_len}")
        total_files += files_lst_len

    assert pre_total_files == total_files + overcopy_cnt + total_tor_files

    print(
        f"total_files:{total_files}, pre_total_files:{pre_total_files}, overcopy_cnt:{overcopy_cnt},{i}, tor_files:{total_tor_files}")

    return output_dir

