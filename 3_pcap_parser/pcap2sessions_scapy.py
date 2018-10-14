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
import time
from collections import Counter

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


def pcap2sessions_dir(input_dir, output_dir, layer='L7'):
    for file in os.listdir(input_dir):
        output_file_dir = os.path.join(output_dir, os.path.split(file)[-1].split('.')[0])
        # if not os.path.exists(output_file_dir):
        #     os.makedirs(output_file_dir)
        file = os.path.join(input_dir, file)
        print('processing ', file, ' -> output_dir:', output_file_dir)
        pcap2sessions(file, output_file_dir, layer=layer)


def save_session_to_dict(k='five_tuple', v='pkt', sess_dict={}):
    k_src2dst = k
    # swap src and dst
    tmp_lst = k.split('-')
    k_dst2src = tmp_lst[1] + '-' + tmp_lst[0] + '-' + tmp_lst[-1]
    if k_src2dst not in sess_dict.keys() and k_dst2src not in sess_dict.keys():
        sess_dict[k] = []
    if k_src2dst in sess_dict.keys():
        sess_dict[k].append(v)
    else:
        sess_dict[k_dst2src].append(v)


def count_protocls(sess_dict):
    """
        get TCP and UDP distribution
    :param sess_dict:
    :return:
    """
    res_dict = {'TCP': 0, 'UDP': 0}
    prtls_lst = []
    for key in sess_dict.keys():
        prtl = key.split('-')[-1]
        if prtl not in res_dict.keys():
            res_dict[prtl] = 1
        else:
            res_dict[prtl] += 1
        prtls_lst.append(prtl)

    # if 'TCP' not in prtls_lst:
    #     res_dict['TCP'] =0
    # if 'UDP' not in prtls_lst:
    #     res_dict['UDP']=0

    return res_dict


def count_sess_size(sess_dict):
    """
        get each sess size (sum of pkts_len in this sess), not flow.
    :param sess_dict:
    :return:
    """
    res_dict = {'TCP': [], 'UDP': []}
    for key in sess_dict.keys():
        prtl = key.split('-')[-1]
        if prtl not in res_dict.keys():
            res_dict[prtl] = [sum([len(p) for p in sess_dict[key]])]
        else:
            res_dict[prtl].append(sum([len(p) for p in sess_dict[key]]))

    return res_dict


def pcap2sessions_statistic(input_file):
    """
        achieve the statistic of full sessions in pcap after removing uncompleted TCP sessions
        There is no process on UDP sessions

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
    :param input_file:
    :return:
    """
    st = time.time()
    print('process ... \'%s\'' % input_file)
    # Step 1. read from pcap and return a list of packets
    try:
        pkts_lst = rdpcap(input_file)
    except MemoryError as me:
        print('memory error ', me)
        return -1
    except FileNotFoundError as fnfe:
        print('file not found ', fnfe)
        return -2
    except:
        print('other exceptions')
        return -10

    # data.stats
    print('%s info is %s' % (input_file, pkts_lst))
    pkts_stats = {'non_Ether_pkts': 0, 'non_IPv4_pkts': 0, 'non_TCP_UDP_pkts': 0, 'TCP_pkts': 0,
                  'UDP_pkts': 0}
    print('packet info:"srcIP:srcPort-dstIP:dstPort-prtcl" + IP_payload')

    # Step 2. achieve all the session in pcap.
    cnt = 0
    sess_dict = {}
    for pkt in pkts_lst:
        if pkt.name == "Ethernet":
            if pkt.payload.name.upper() in ['IP', 'IPV4']:
                if pkt.payload.payload.name.upper() in ["TCP", "UDP"]:
                    if cnt == 0:
                        print('packet[0] info: "%s:%d-%s:%d-%s"+%s' % (
                            pkt.payload.src, pkt.payload.payload.sport, pkt.payload.dst, pkt.payload.payload.dport,
                            pkt.payload.payload.name, pkt.payload.payload.payload))
                    five_tuple = pkt.payload.src + ':' + str(
                        pkt.payload.payload.sport) + '-' + pkt.payload.dst + ':' + str(
                        pkt.payload.payload.dport) + '-' + pkt.payload.payload.name.upper()
                    save_session_to_dict(k=five_tuple, v=pkt, sess_dict=sess_dict)
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
        else:
            pkts_stats['non_Ether_pkts'] += 1

    # Step 3. achieve all full session in sess_dict.
    full_sess_dict = {}
    for k, v in sess_dict.items():
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
                S = str(pkt.payload.payload.fields['flags'])
                # step 1. discern the begin of TCP session.
                if 'S' in S:
                    TCP_start_flg = True
                    if 'A' not in S:  # the first SYN packet in TCP session.
                        # if flags[S] == "SYN":
                        tcp_sess_list.append(pkt)
                    else:  # the second SYN + ACK
                        tcp_sess_list.append(pkt)
                    continue
                # step 2. discern the transmitted data of TCP session
                if TCP_start_flg:  # TCP data transform.
                    for pkt_t in v[i:]:
                        tcp_sess_list.append(pkt_t)
                        F = str(pkt_t.payload.payload.fields['flags'])
                        if 'F' in F:  # if  flags[F]== "FIN":
                            full_session_flg = True
                        # step 3. discern the finish of TCP session.
                        if 'S' in str(pkt_t.payload.payload.fields['flags']) and len(
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
        input_file, len(sess_dict.keys()), len(full_sess_dict.keys())))
    print('all_sess_dict:', count_protocls(sess_dict), '\nfull_sess_dict:', count_protocls(full_sess_dict))

    all_stats_dict = {}
    all_stats_dict['pkts_stats'] = pkts_stats
    all_stats_dict['all_sess'] = count_protocls(sess_dict)
    all_stats_dict['full_sess'] = count_protocls(full_sess_dict)
    all_stats_dict['full_sess_size_distribution'] = count_sess_size(full_sess_dict)

    print(all_stats_dict)

    return all_stats_dict


def achieve_stats_info_for_dir(input_dir, out_file='./log.txt'):
    """

    :param input_dir:
    :param out_file:
    :return:
    """
    st = time.time()
    all_stats_dict = {'full_sess': {'TCP': 0, 'UDP': 0}, 'all_sess': {'TCP': 0, 'UDP': 0},
                      'pkts_stats': {'TCP_pkts': 0, 'UDP_pkts': 0, 'non_TCP_UDP_pkts': 0, 'non_IPv4_pkts': 0,
                                     'non_Ether_pkts': 0}, 'full_sess_size_distribution': {'TCP': [], 'UDP': []}}
    # all_stats_dict['full_sess']['TCP'] =0
    # all_stats_dict['full_sess']['UDP'] =0
    # all_stats_dict['all_sess']['TCP'] =0
    # all_stats_dict['all_sess']['UDP'] =0
    # all_stats_dict['pkts_stats']['TCP_pkts'] =0
    # all_stats_dict['pkts_stats']['UDP_pkts']=0
    # all_stats_dict['pkts_stats']['non_TCP_UDP_pkts'] =0
    # all_stats_dict['pkts_stats']['non_IPv4_pkts'] =0
    # all_stats_dict['pkts_stats']['non_Ether_pkts'] =0
    file_lst = os.listdir(input_dir)
    i = 1
    with open(out_file, 'w') as out:
        for file in file_lst:
            st_tmp = time.time()
            stats_info = pcap2sessions_statistic(os.path.join(input_dir, file))
            print('%d/%d => %s takes %.2f(s)\n' % (i, len(file_lst), file, time.time() - st_tmp))
            line_str = '%d/%d => %s takes %.2f(s) => ' % (
            i, len(file_lst), file, time.time() - st_tmp) + '%s\n' % stats_info
            out.write(line_str)
            out.flush()
            i += 1
            all_stats_dict['full_sess']['TCP'] += stats_info['full_sess']['TCP']
            all_stats_dict['full_sess']['UDP'] += stats_info['full_sess']['UDP']
            all_stats_dict['all_sess']['TCP'] += stats_info['all_sess']['TCP']
            all_stats_dict['all_sess']['UDP'] += stats_info['all_sess']['UDP']
            all_stats_dict['pkts_stats']['TCP_pkts'] += stats_info['pkts_stats']['TCP_pkts']
            all_stats_dict['pkts_stats']['UDP_pkts'] += stats_info['pkts_stats']['UDP_pkts']
            all_stats_dict['pkts_stats']['non_TCP_UDP_pkts'] += stats_info['pkts_stats']['non_TCP_UDP_pkts']
            all_stats_dict['pkts_stats']['non_IPv4_pkts'] += stats_info['pkts_stats']['non_IPv4_pkts']
            all_stats_dict['pkts_stats']['non_Ether_pkts'] += stats_info['pkts_stats']['non_Ether_pkts']
            all_stats_dict['full_sess_size_distribution']['TCP'].append(
                [file, len(stats_info['full_sess_size_distribution']['TCP']),
                 stats_info['full_sess_size_distribution']['TCP']])
            all_stats_dict['full_sess_size_distribution']['UDP'].append(
                [file, len(stats_info['full_sess_size_distribution']['UDP']),
                 stats_info['full_sess_size_distribution']['UDP']])

        line_str = '\nall _stats_dict => %s\n' % all_stats_dict
        out.write(line_str)

    print('all_stats_dict:', all_stats_dict)
    print('It takes %.2f(s)' % (time.time() - st))

    return all_stats_dict


if __name__ == '__main__':
    # input_file = '../1_pcaps_data/UDP.pcap'
    # input_file = '../1_pcaps_data/aim_chat_3a.pcap'
    # pcap2sessions_statistic(input_file)

    input_dir = '../1_pcaps_data'
    achieve_stats_info_for_dir(input_dir)

    # pcap2sessions(input_file)
    # pcap2flows(input_file)

    # input_dir = '../1_pcaps_data/VPN-Hangout'
    # output_dir= '../2_sessions_data'
    # pcap2sessions_dir(input_dir,output_dir,layer='L7')
