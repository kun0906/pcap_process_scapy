# -*- coding:utf-8 -*-

"""
   Purpose:
        Achieve Streams information by scapy.

        TCP and UDP streams in this source are based on five tuple <srcIP:srcPort<->dstIP:dstPort-protocol>, ignore the direction.
        srcIP->dstIP and dstIP->srcIP are different flow, but they belongs to the same stream (bi-directional flows).

        all packets with the same 5-touple (source host, destination host, source port, destination port, transport protocol)
        regardless of packet direction are considered part of the same session.

   Note:
        1) the stream's calculation is not based on TCP 3 handshake, only on five tuple, so there will be problems if multiple TCP streams have the same tuple.
           (If there will exist multiple TCP streams have the same five tuple? )
           In new wireshark version, there will be more complicated to calculate stream.
        2) it does not perform any proper TCP session reassembly. and out-of-order TCP packets will also cause the data to be store in an out of sequence.
        3) ICMP do not have port, so it can not be recognized as stream.

    References:
        1. https://stackoverflow.com/questions/6076897/follow-tcp-stream-where-does-field-stream-index-come-from
        2. https://osqa-ask.wireshark.org/questions/59467/tcp-stream-index-question
        3. https://blog.packet-foo.com/2015/03/tcp-analysis-and-the-five-tuple/
        4. https://www.netresec.com/?page=SplitCap
        5. https://stackoverflow.com/questions/32317848/multiple-tcp-connection-on-same-ip-and-port/32318220

"""

import binascii
import os

import numpy
from PIL import Image
from scapy.all import rdpcap


def save_png(output_name='five_tuple.png', data=b'', width=28):
    hexst = binascii.hexlify(data)
    im_size = width * width  # generated square image
    if im_size > ((len(hexst) // 2) // width) * width:
        hexst = hexst + b'00' * (im_size - len(hexst) // 2)
    else:
        hexst = hexst[:width * 2 * width * 2]
    # print(len(hexst))
    decimal_data = numpy.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])  # 16(hex) ->10(decimal)
    decimal_data = numpy.reshape(decimal_data[:width * width], (-1, width))
    image_data = numpy.uint8(decimal_data)

    im = Image.fromarray(image_data)
    im.save(output_name)

    return output_name


def pcap2flows(input_file, output_dir='../2_flows_data'):
    """
        flow is based on five tuple, howerver, there is direction between srcIP and dstIP.
            srcIP->dstIP and dstIP->srcIP are recognized as different flow.

    :param input_file:
    :param output_dir:
    :return:
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    file_prefix = os.path.split(input_file)[-1].split('.')[0]
    data = rdpcap(input_file)
    data.stats
    sess = data.sessions()  # can achieve flows in default, not sessions
    others_pkts = 0
    for k, v in sess.items():
        # print(k,v)
        sess_tmp = b''
        for vv in v:
            payload = vv.payload.payload.payload.original
            sess_tmp += payload
        if sess_tmp == b'':
            print('\'%s\' is not a flow.' % k)
            others_pkts += 1
            continue
        k = os.path.join(output_dir, file_prefix + '|' + k.replace(' ', '_') + '.png')
        print(k, sess_tmp)
        output_file = save_png(k, sess_tmp)
    print('others_pkts = %d' % others_pkts)

    return output_dir


def get_protocol(pkt):
    prtl = []
    cnt = 0
    while pkt.name != 'Raw' and pkt.name != 'NoPayload':
        if cnt > 10:
            print('protocol parser error.!')
            return prtl
        prtl.append(pkt.name)
        pkt = pkt.payload
        cnt += 1

    return prtl


def pcap2sessions(input_file, output_dir='../2_sessions_data', layer='L7'):
    """

    :param input_file:
    :param output_dir:
    :param layer: achieve 'L3-L7' or only 'L7' or 'AllLyers' data
            'L3-L7': IP+payload
            'L7': only TCP/UDP's payload
            'AllLyers' includes Ethernet
    :return:
    """

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    file_prefix = os.path.split(input_file)[-1].split('.')[0]
    pkts = rdpcap(input_file)

    others_pkts = 0
    streams_dict = {}
    for pkt in pkts:
        prtl_lst = get_protocol(pkt)
        # print(prtl_lst)
        if "TCP" in prtl_lst:
            prtl = 'TCP'
        elif "UDP" in prtl_lst:
            prtl = 'UDP'
        else:
            prtl = 'others'

            others_pkts += 1
            key = prtl_lst
            if 'IP' in prtl_lst:
                print(others_pkts, key, pkt['IP'].src + '->' + pkt['IP'].dst)
            else:
                print(others_pkts, key, pkt[prtl_lst[0]].src + '->' + pkt[prtl_lst[0]].dst)
        if prtl in ['TCP', 'UDP']:
            key_src2dst = prtl + "-" + pkt['IP'].src + ':' + str(pkt[prtl].sport) + '<->' + pkt['IP'].dst + ':' + str(
                pkt[prtl].dport)
            key_dst2src = prtl + '-' + pkt['IP'].dst + ':' + str(pkt[prtl].dport) + '<->' + pkt['IP'].src + ':' + str(
                pkt[prtl].sport)
            if key_src2dst not in streams_dict.keys() and key_dst2src not in streams_dict.keys():
                streams_dict[key_src2dst] = b''
            else:
                if key_src2dst not in streams_dict.keys():
                    key_src2dst = key_dst2src
                if layer == 'L3-L7':
                    streams_dict[key_src2dst] += pkt['IP'].original  # IP Header + IP Payload data
                elif layer == 'L7':
                    streams_dict[key_src2dst] += pkt[prtl].payload.original  # only TCP/UDP Payload data
                else:  # AllLayers : include Ethernet
                    streams_dict[key_src2dst] += pkt.original  # Ethernet Header + Ethernet Payload data

    print('others_pkts = %d' % others_pkts)
    streams_stats_info = {'TCP_streams': 0, 'UDP_streams': 0, 'Others': 0}
    nodata_streams = 0
    for k, v in streams_dict.items():
        if 'TCP' in k:
            prtl = 'TCP_streams'
        elif 'UDP' in k:
            prtl = 'UDP_streams'
        else:
            prtl = 'Others'
        streams_stats_info[prtl] += 1
        output_file = os.path.join(output_dir, file_prefix + '_' + k + '.png')
        if v != b'':
            # print(k, src_dst_flow)
            output_file = save_png(output_file, v)
        else:
            print('\'%s\' is not a stream.' % k)
            nodata_streams += 1
            # continue
    print(streams_stats_info, 'nodata_streams:', nodata_streams)

    return output_dir


def pcap2sessions_forward_backward(input_file, output_dir=''):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    file_prefix = os.path.split(input_file)[-1].split('.')[0]
    pkts = rdpcap(input_file)

    # data.stats
    sess = pkts.sessions()  # session based on direction, that is flow
    others_pkts = 0
    for k, v in sess.items():
        # print(k,v)
        src_dst_flow = b''
        dst_src_flow = b''
        for vv in v:
            payload = vv.payload.payload.payload.original
            src = k.split(' ')[1].split(':')[0]
            dst = k.split(' ')[-1].split(':')[0]
            if vv.payload.name == 'IP':
                if vv.payload.src == src and vv.payload.dst == dst:
                    # src-> dst flow
                    src_dst_flow += payload
                else:  # dst->src flow
                    print('---', src, dst)
                    k = k[0:len(k) // 2].replace(src, dst)
                    k = k[len(k) // 2:].replace(dst, src)
                    dst_src_flow += payload
            else:
                pass

    return output_dir


if __name__ == '__main__':
    input_file = '../1_pcaps_data/aim_chat_3a.pcap'
    pcap2sessions(input_file)
    # pcap2flows(input_file)
