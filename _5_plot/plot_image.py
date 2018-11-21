# -*- coding:utf-8 -*-
r"""
    plot the packet's payload to image

"""

import errno
import os
import time
from array import *
from random import shuffle
from _3_pcap_parser import *
from _3_pcap_parser.pcap2sessions_scapy import *
from PIL import Image
from scapy.layers.inet import IP
from scapy.utils import PcapReader


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def save_payload_to_image(payload_1d,image_width=28, output_name='demo.png'):

    if len(payload_1d) < image_width*image_width:
        print(payload_1d)
        payload_1d += b'\x00'*(image_width*image_width-len(payload_1d))
    if len(payload_1d) > image_width*image_width:
        payload_1d = payload_1d[:image_width*image_width]
    hexst = binascii.hexlify(payload_1d)
    payload_1d = numpy.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])

    rn = len(payload_1d) // image_width
    fh = numpy.reshape(payload_1d[:rn * image_width], (-1, image_width))
    fh = numpy.uint8(fh)

    im = Image.fromarray(fh)
    im.save(output_name)

    return output_name


def getMatrixfrom_pcap(filename,width):
    with open(filename, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    rn = len(fh)//width
    fh = numpy.reshape(fh[:rn*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh


def process_pcap(input_file='.pcap',image_width=28, output_dir='./data'):
    all_stats_dict, sess_dict =pcap2sessions_statistic_with_pcapreader_scapy_improved(input_file)
    print(f"all_stats_dict:{all_stats_dict}")
    # print(f"sess_dict:{sess_dict}")   # there will be huge information, please do print it out.

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for idx, (k,v) in enumerate(sess_dict.items()):
        line_bytes = b''
        for pkt in v:  #pkt is IP pakcet, no ethernet header
            line_bytes += pkt.payload.payload.original
        # payload_1d = list(map(lambda x:int(x,16), line_str.split('\\x')))  # change hex to decimal
        output_name = os.path.join(output_dir, k + f'-({len(line_bytes)//image_width}x{image_width}).png')
        print(f"idx={idx}, output_name:{output_name}")
        # print(f"len(line_bytes)={len(line_bytes)}, ((height,width)={len(line_bytes)//image_width}x{image_width}), {line_bytes}")
        save_payload_to_image(line_bytes, image_width=image_width, output_name=output_name)


def pcap2sessions_statistic_with_pcapreader_scapy_improved(input_f):
    """
        achieve the statistic of full sessions in pcap after removing uncompleted TCP sessions
        There is no process on UDP sessions

        Improved version : just use one for loop

        Note:
            pkts_lst = rdpcap(input_f)  # this will read all packets in memory at once.
            changed  to :
            There are 2 classes:
                PcapReader - decodes all packets immediately
                RawPcapReader - does not decode packets

                Both of them have iterator interface (which I fixed in latest commit). So you can write in your case:

                with PcapReader('file.pcap') as pr:
                  for p in pr:
                    ...do something with a packet p...

            reference:
                https://github.com/phaethon/kamene/issues/7

        flags in scapy
         flags = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }
    :param input_f:
    :return:
    """
    st = time.time()
    print('process ... \'%s\'' % input_f, flush=True)
    # Step 1. read from pcap and do not return a list of packets
    try:
        # pkts_lst = rdpcap(input_f)  # this will read all packets in memory at once, please don't use it directly.
        # input_f  = '../1_pcaps_data/vpn_hangouts_audio2.pcap'  #
        # input_f = '/home/kun/PycharmProjects/Pcap2Sessions_Scapy/1_pcaps_data/aim_chat_3a.pcap'  #
        myreader = PcapReader(input_f)  # iterator, please use it to process large file, such as more than 4 GB
    except MemoryError as me:
        print('memory error ', me)
        return -1
    except FileNotFoundError as fnfe:
        print('file not found ', fnfe)
        return -2
    except:
        print('other exceptions')
        return -10

    # Step 2. achieve all the session in pcap.
    # data.stats
    pkts_stats = {'non_Ether_IPv4_pkts': 0, 'non_IPv4_pkts': 0, 'non_TCP_UDP_pkts': 0, 'TCP_pkts': 0,
                  'UDP_pkts': 0}
    cnt = 0
    sess_dict = {}
    first_print_flg = True
    max_pkts_cnt = 1
    while True:
        pkt = myreader.read_packet()
        if pkt is None:
            break
        if max_pkts_cnt >= 100000:
            print(
                '\'%s\' includes more than %d packets and in this time just process the first %d packets. Please split it firstly and do again.' % (
                input_f, max_pkts_cnt, max_pkts_cnt))
            break
        max_pkts_cnt += 1
        # step 1. parse "Ethernet" firstly
        if pkt.name == "Ethernet":
            if first_print_flg:
                first_print_flg = False
                print('\'%s\' encapsulated by "Ethernet Header" directly' % input_f)
            if pkt.payload.name.upper() in ['IP', 'IPV4']:
                if pkt.payload.payload.name.upper() in ["TCP", "UDP"]:
                    if cnt == 0:
                        print('packet[0] info: "%s:%d-%s:%d-%s"+%s' % (
                            pkt.payload.src, pkt.payload.payload.sport, pkt.payload.dst, pkt.payload.payload.dport,
                            pkt.payload.payload.name, pkt.payload.payload.payload))
                    five_tuple = pkt.payload.src + ':' + str(
                        pkt.payload.payload.sport) + '-' + pkt.payload.dst + ':' + str(
                        pkt.payload.payload.dport) + '-' + pkt.payload.payload.name.upper()
                    # save_session_to_dict(k=five_tuple, v=pkt,sess_dict=sess_dict)
                    save_session_to_dict(k=five_tuple, v=pkt.payload,
                                         sess_dict=sess_dict)  # only save Ethernet payload to sess_dict
                    cnt += 1
                    # pkts_lst.append(pkt.payload)  # only include "IPv4+IPv4_payload"
                    if pkt.payload.payload.name.upper() == "TCP":
                        pkts_stats['TCP_pkts'] += 1
                    else:
                        pkts_stats['UDP_pkts'] += 1
                else:
                    pkts_stats['non_TCP_UDP_pkts'] += 1
                    # pkts_stats['IPv4_pkts'] += 1
            else:
                pkts_stats['non_IPv4_pkts'] += 1
        else:  # step 2. if this pkt can not be recognized as "Ethernet", then try to parse it as (IP,IPv4)
            pkt = IP(pkt)  # without ethernet header,  then try to parse it as (IP,IPv4)
            if first_print_flg:
                first_print_flg = False
                print('\'%s\' encapsulated by "IP Header" directly, without "Ethernet Header"' % input_f)
            if pkt.name.upper() in ['IP', 'IPV4']:
                if pkt.payload.name.upper() in ["TCP", "UDP"]:
                    if cnt == 0:
                        print('packet[0] info: "%s:%d-%s:%d-%s"+%s' % (
                            pkt.src, pkt.payload.sport, pkt.dst, pkt.payload.dport,
                            pkt.payload.name, pkt.payload.payload))
                    five_tuple = pkt.src + ':' + str(
                        pkt.payload.sport) + '-' + pkt.dst + ':' + str(
                        pkt.payload.dport) + '-' + pkt.payload.name.upper()
                    save_session_to_dict(k=five_tuple, v=pkt, sess_dict=sess_dict)
                    cnt += 1
                    # pkts_lst.append(pkt.payload)  # only include "IPv4+IPv4_payload"
                    if pkt.payload.name.upper() == "TCP":
                        pkts_stats['TCP_pkts'] += 1
                    else:
                        pkts_stats['UDP_pkts'] += 1
                else:
                    pkts_stats['non_TCP_UDP_pkts'] += 1
                    # pkts_stats['IPv4_pkts'] += 1
            else:
                pkts_stats['non_IPv4_pkts'] += 1
                # print('unknown packets type!',pkt.name)
                pkts_stats['non_Ether_IPv4_pkts'] += 1

    # data.stats
    # print('%s info is %s' % (input_f, pkts_lst))
    print('packet info:"srcIP:srcPort-dstIP:dstPort-prtcl" + IP_payload')

    # Step 3. achieve all full session in sess_dict.
    full_sess_dict = {}
    for k, v in sess_dict.items():  # all pkts in sess_dict without Ethernet headers and tails
        prtl = k.split('-')[-1]
        if prtl == "TCP":
            """
                only save the first full session in v (maybe there are more than one full session in v)
            """
            tcp_sess_list = []
            full_session_flg = False
            i = -1
            TCP_start_flg = False
            for pkt in v:
                i += 1
                if len(v) < 5:  # tcp start (3 packets) + tcp finish (at least 2 packets)
                    print('%s not full session, it only has %d packets' % (k, len(v)))
                    break
                S = str(pkt.payload.fields['flags'])
                # step 1. discern the begin of TCP session.
                if 'S' in S:
                    if 'A' not in S:  # the first SYN packet in TCP session.
                        # if flags[S] == "SYN":
                        TCP_start_flg = True
                        tcp_sess_list.append(pkt)
                        continue  # cannot ignore
                    else:  # the second SYN + ACK
                        tcp_sess_list.append(pkt)
                    continue
                # step 2. discern the transmitted data of TCP session
                if TCP_start_flg:  # TCP data transform.
                    for pkt_t in v[i:]:
                        tcp_sess_list.append(pkt_t)
                        F = str(pkt_t.payload.fields['flags'])
                        if 'F' in F:  # if  flags[F]== "FIN":
                            full_session_flg = True
                        # step 3. discern the finish of TCP session.
                        if 'S' in str(pkt_t.payload.fields['flags']) and len(
                                tcp_sess_list) >= 5:  # the second session
                            print('the second session begins.')
                            break
                else:  # TCP_start_flg = False
                    # print('TCP still does not begin...')
                    pass
                if full_session_flg:
                    full_sess_dict[k] = tcp_sess_list
                    # print('tcp_sess_list:', k, len(tcp_sess_list))
                    break
        elif prtl == "UDP":
            # if len(v) < 2:
            #     print('%s is not a UDP session.'%k)
            # else:
            #     full_sess_dict[k] = v
            full_sess_dict[k] = v  # do not do any process for UDP session.
        else:
            pass
    print('pkts_stats is ', pkts_stats)
    print('Number of sessions(TCP/UDP) in %s is %d, number of full session(TCP/UDP) is %d' % (
        input_f, len(sess_dict.keys()), len(full_sess_dict.keys())))
    print('all_sess_dict:', count_protocls(sess_dict), '\nfull_sess_dict:', count_protocls(full_sess_dict))

    all_stats_dict = {}
    all_stats_dict['pkts_stats'] = pkts_stats
    all_stats_dict['all_sess'] = count_protocls(sess_dict)
    all_stats_dict['full_sess'] = count_protocls(full_sess_dict)
    all_stats_dict['full_sess_size_distribution'] = count_sess_size(full_sess_dict)

    print(all_stats_dict)

    return all_stats_dict, sess_dict

if __name__ == '__main__':
    input_file = '../1_pcaps_data/aim_chat_3a.pcap'
    # pcap2sessions_statistic_with_pcapreader_scapy_improved(input_file)
    process_pcap(input_file,output_dir='../data/aim_chat_3a')