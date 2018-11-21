# -*- coding: utf-8 -*-
r"""
    Using 'tshark' to achieve  pcap statistic information.

    usage:
        python3 pcap.statistic_tshark.py

    created at:
        2018/11/14

    tshark -z
        tshark -r ../1_pcaps_data/aim_chat_3a.pcap  -z io
        tshark: Invalid -z argument "io"; it must be one of:
     afp,srt
     ancp,tree
     ansi_a,bsmap
     ansi_a,dtap
     ansi_map
     bacapp_instanceid,tree
     bacapp_ip,tree
     bacapp_objectid,tree
     bacapp_service,tree
     bootp,stat
     camel,counter
     camel,srt
     collectd,tree
     compare
     conv,bluetooth
     conv,eth
     conv,fc
     conv,fddi
     conv,ip
     conv,ipv6
     conv,ipx
     conv,jxta
     conv,mptcp
     conv,ncp
     conv,rsvp
     conv,sctp
     conv,sll
     conv,tcp
     conv,tr
     conv,udp
     conv,usb
     conv,wlan
     dcerpc,srt
     dests,tree
     diameter,avp
     diameter,srt
     dns,tree
     endpoints,bluetooth
     endpoints,eth
     endpoints,fc
     endpoints,fddi
     endpoints,ip
     endpoints,ipv6
     endpoints,ipx
     endpoints,jxta
     endpoints,mptcp
     endpoints,ncp
     endpoints,rsvp
     endpoints,sctp
     endpoints,sll
     endpoints,tcp
     endpoints,tr
     endpoints,udp
     endpoints,usb
     endpoints,wlan
     expert
     f5_tmm_dist,tree
     f5_virt_dist,tree
     fc,srt
     flow,any
     flow,icmp
     flow,icmpv6
     flow,lbm_uim
     flow,tcp
     follow,http
     follow,ssl
     follow,tcp
     follow,udp
     gsm_a
     gsm_a,bssmap
     gsm_a,dtap_cc
     gsm_a,dtap_gmm
     gsm_a,dtap_mm
     gsm_a,dtap_rr
     gsm_a,dtap_sacch
     gsm_a,dtap_sm
     gsm_a,dtap_sms
     gsm_a,dtap_ss
     gsm_a,dtap_tp
     gsm_map,operation
     gtp,srt
     h225,counter
     h225_ras,rtd
     hart_ip,tree
     hosts
     hpfeeds,tree
     http,stat
     http,tree
     http2,tree
     http_req,tree
     http_seq,tree
     http_srv,tree
     icmp,srt
     icmpv6,srt
     io,phs
     io,stat
     ip_hosts,tree
     ip_srcdst,tree
     ipv6_dests,tree
     ipv6_hosts,tree
     ipv6_ptype,tree
     ipv6_srcdst,tree
     isup_msg,tree
     lbmr_queue_ads_queue,tree
     lbmr_queue_ads_source,tree
     lbmr_queue_queries_queue,tree
     lbmr_queue_queries_receiver,tree
     lbmr_topic_ads_source,tree
     lbmr_topic_ads_topic,tree
     lbmr_topic_ads_transport,tree
     lbmr_topic_queries_pattern,tree
     lbmr_topic_queries_pattern_receiver,tree
     lbmr_topic_queries_receiver,tree
     lbmr_topic_queries_topic,tree
     ldap,srt
     mac-lte,stat
     megaco,rtd
     mgcp,rtd
     mtp3,msus
     ncp,srt
     osmux,tree
     plen,tree
     proto,colinfo
     ptype,tree
     radius,rtd
     rlc-lte,stat
     rpc,programs
     rpc,srt
     rtp,streams
     rtsp,stat
     rtsp,tree
     sametime,tree
     scsi,srt
     sctp,stat
     sip,stat
     smb,sids
     smb,srt
     smb2,srt
     smpp_commands,tree
     sv
     ucp_messages,tree
     wsp,stat

"""
import os
import subprocess


def ip_statistic(in_dir):
    results = []
    if os.path.isdir(in_dir):
        files_lst = sorted(os.listdir(in_dir))
        for idx, file in enumerate(files_lst):
            in_file = os.path.join(os.path.abspath(in_dir), file)
            # cmd =['/usr/bin/tshark', f' -nr \'{in_file}\' -z io,phs']
            # cmd = f'/usr/bin/tshark -nr {in_file} -T fields -e ip.src -e ip.dst -z endpoints,ip| sort -u'
            cmd = f'tshark -nr "{in_file}" -qz ip_hosts,tree| sort -u'
            # cmd = f'/usr/bin/tshark -nr {in_file} -qz io,stat,0'
            print(f'{idx}/{len(files_lst)}, {cmd}')
            if ('.pcap' in file) or ('.pcapng' in file):
                result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
            else:
                result = ''
            results.append([idx, in_file, result])
            print(result)
    else:
        in_file = in_dir
        cmd = f'/usr/bin/tshark -nr "{in_file}" -T fields -e ip.src | sort -u'
        print(cmd)
        results.append(subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode('utf-8'))

    return results

    return result


def protocol_statistic(in_dir):
    results = []
    if os.path.isdir(in_dir):
        files_lst = sorted(os.listdir(in_dir))
        for idx, file in enumerate(files_lst):
            in_file = os.path.join(os.path.abspath(in_dir), file)
            # cmd =['/usr/bin/tshark', f' -nr \'{in_file}\' -z io,phs']
            cmd = f'tshark -nr "{in_file}" -q -z io,phs'
            # cmd = f'/usr/bin/tshark -nr \'{in_file}\' -q -z io,stat,1'
            print(f'{idx}/{len(files_lst)}, {cmd}')
            if ('.pcap' in file) or ('.pcapng' in file):
                result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True).stdout.decode('utf-8')
            else:
                result = ''
            results.append([idx, in_file, result])
            print(result)
    else:
        in_file = in_dir
        cmd = f'/usr/bin/tshark -nr "{in_file}" -q -z io,phs'
        print(cmd)
        results.append(subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode('utf-8'))

    return results


def save_data(data_lst, out_file='./out.txt'):
    with open(out_file, 'w')as out_hdl:
        for idx, file_name, data in data_lst:
            line = f'{idx}/{len(data_lst)} {file_name}\n{data}\n'
            out_hdl.write(line)


def get_first_col(data):
    res_lst = []
    data_lst = data.split('\n')
    for line in data_lst:
        val = line.lstrip().split()
        print(val)
        if len(val) > 1:
            if val[0] not in res_lst:
                res_lst.append(val[0])

    return res_lst


def all_stat(data_lst, out_file='./out.txt', ptype='ip_stat'):
    res_lst = []
    with open(out_file, 'w')as out_hdl:
        for idx, file_name, data in data_lst:
            line = f'{idx}/{len(data_lst)} {file_name}\n'
            print(line)
            if ptype == 'ip_stat':
                line_lst = get_first_col(data)
            elif ptype == 'prtl_stat':
                line_lst = get_first_col(data)
            else:
                pass
            res_lst.extend(line_lst)
            line = ','.join(line_lst)
            out_hdl.write(line)
    res_lst = sorted(set(res_lst))

    return res_lst


if __name__ == '__main__':
    in_dir = '../1_pcaps_data/'
    results = protocol_statistic(in_dir)
    # save_data(results,out_file='protocol_stat.txt')
    prtl_stat = all_stat(results, out_file='protocol_stat_summary.txt', ptype='prtl_stat')
    print(f'prtl_stat:{prtl_stat}')
    results = ip_statistic(in_dir)
    save_data(results, out_file='ip_stat.txt')
    ip_stat = all_stat(results, out_file='protocol_stat_summary.txt', ptype='ip_stat')
    print(f'ip_stat:{ip_stat}')
