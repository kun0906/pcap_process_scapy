# -*- coding:utf-8 -*-
"""
    Purpose:
        pcaps process
"""


import os

import pyshark


def pcap2sessions(pcap_file, output_dir='.\\out'):
    """

    :param pcap_file:
    :param output_dir:
    :return:
    """
    cap = pyshark.FileCapture(pcap_file)
    sess_dict = {}
    for pkt in cap:
        data = ''
        if 'tcp' in pkt:
            key = "tcp_stream_index_" + pkt.tcp.stream
            # print(key)
            if int(pkt.tcp.len) != 0:
                data = str(pkt.tcp.payload)
        elif 'udp' in pkt:
            print(pkt)
            key = "udp.stream_index_" + pkt.udp.stream
            if int(pkt.udp.length) != 0:
                # input_data = str(pkt.udp.payload)
                data = ''
        else:
            key = 'others'
        if key not in sess_dict.keys():
            sess_dict[key] = data
        else:
            sess_dict[key] += ':' + data

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for k, v in sess_dict.items():
        output_file = os.path.join(output_dir, k + '.bin')
        with open(output_file, 'w') as out:
            out.write(v)
            out.flush()

    return 1


if __name__ == '__main__':
    pcap_file = '../pcaps_data/aim_chat_3a.pcap'
    pcap2sessions(pcap_file, output_dir='testbins')
    print('finished')
