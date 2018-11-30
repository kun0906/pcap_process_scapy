# -*- coding:utf-8 -*-
"""
    Purpose:
        pcaps process
"""

from scapy.layers.inet import IP
from scapy.utils import PcapReader


def pcap2_parser(input_f):
    """

    :param input_f:
    :return:
    """
    try:
        # pkts_lst = rdpcap(input_f)  # this will read all packets in memory at once, please don't use it directly.
        #  input_f  = '/home/kun/PycharmProjects/pcap_process_scapy/pcaps_data/vpn_hangouts_audio2.pcap'  #
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
        # input_data.stats
    pkts_stats = {'non_Ether_IPv4_pkts': 0, 'non_IPv4_pkts': 0, 'non_TCP_UDP_pkts': 0, 'TCP_pkts': 0,
                  'UDP_pkts': 0}
    cnt = 0
    sess_dict = {}
    first_print_flg = True
    while True:
        pkt = myreader.read_packet()
        if pkt is None:
            break

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

                        ### ...

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
                print('\'%s\' encapsulated by "IP Header" directly, without "Ethernet Header" ' % input_f)
            if pkt.name.upper() in ['IP', 'IPV4']:
                if pkt.payload.name.upper() in ["TCP", "UDP"]:
                    if cnt == 0:
                        print('packet[0] info: "%s:%d-%s:%d-%s"+%s' % (
                            pkt.src, pkt.payload.sport, pkt.dst, pkt.payload.dport,
                            pkt.payload.name, pkt.payload.payload))

                        ### ...

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

    print('packet info:"srcIP:srcPort-dstIP:dstPort-prtcl" + IP_payload')


if __name__ == '__main__':
    input_f = ''
    pcap2_parser()
