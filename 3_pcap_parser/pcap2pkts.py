# -*- coding:utf-8 -*-
"""
    Purpose:
        transform 'pcap or pcapng' to 'packets' (pkts) with scapy.

    Requirements:
        scapy
        python 3.x

    Created time:
        2018.10.10
    Version:
        0.0.1
    Author:

"""
from scapy.all import rdpcap


def pcap2packets(input_file='.pcap or pcapng'):
    """
        "transform pcap to packets"
    :param input_file: pcap or pcapng
    :return: a list of packets.
    """
    pkts_lst = []
    data = rdpcap(input_file)
    print('%s info is ', data)
    ab_pkts = {'non_Ether_pkts': 0, 'non_IPv4_pkts': 0, 'non_TCP_UDP_pkts': 0}
    print('packet info:"srcIP:srcPort-dstIP:dstPort-prtcl" + IP_payload')
    cnt = 0
    for pkt in data:
        if pkt.name == "Ethernet":
            if pkt.payload.name.upper() in ['IP', 'IPV4']:
                if pkt.payload.payload.name.upper() in ["TCP", "UDP"]:
                    if cnt == 0:
                        print('packet info: "%s:%d-%s:%d-%s"+%s' % (
                        pkt.payload.src, pkt.payload.payload.sport, pkt.payload.dst, pkt.payload.payload.dport,
                        pkt.payload.payload.name, pkt.payload.payload))
                    pkts_lst.append(pkt.payload)  # only include "IPv4+IPv4_payload"
                else:
                    ab_pkts['non_TCP_UDP_pkts'] += 1
            else:
                ab_pkts['non_IPv4_pkts'] += 1
        else:
            ab_pkts['non_Ether_pkts'] += 1
    print('Number of packets in %s is %d.' % (input_file, len(pkts_lst)))
    print('Abnormal packets in %s is %s' % (input_file, ab_pkts))

    return pkts_lst


if __name__ == '__main__':
    input_file = 'aim_chat_3a.pcap'
    pcap2packets(input_file)
