

from ast import literal_eval

python_dict = literal_eval("{'a': 1}")

def parse_result_log(input_f='.txt'):

    all_sess_dict={'TCP':0, 'UDP':0}
    full_sess_dict={'TCP':0, 'UDP':0}

    out_s = ''
    with open(input_f,'r') as in_f:
        line = in_f.readline()
        while line:
            if line.startswith('process'):
                out_s = line
            elif "just process the first 50001 packets" in line:
                out_s += line
            elif "Number of sessions(TCP/UDP)" in line:
                out_s += line
            elif '(s)' in line:
                out_s += line
                print(out_s)
                out_s = ''
            else:
                pass
            if "all_sess_dict" in line:
                all_dict_tmp = literal_eval('{'+line.split('{')[1])
                all_sess_dict['TCP'] += all_dict_tmp['TCP']
                all_sess_dict['UDP'] += all_dict_tmp['UDP']
            elif "full_sess_dict" in line:
                full_dict_tmp = literal_eval('{' + line.split('{')[1])
                full_sess_dict['TCP'] += full_dict_tmp['TCP']
                full_sess_dict['UDP'] += full_dict_tmp['UDP']
            else:
                pass

            line = in_f.readline()

    print('all_sess_dict', all_sess_dict)
    print('full_sess_dict', full_sess_dict)

def calculate_sessions_size(input_f):

    with open(input_f,'r') as in_f:
        line = in_f.readline()
        while line:
            if line.startswith('{'):
                all_sess_dict=literal_eval(line)
                full_sess_size_distribution= all_sess_dict['full_sess_size_distribution']
                elephant_sessions= 0
                mice_sessions=0
                normal_sessions_size =0
                for lst in full_sess_size_distribution['TCP']:
                    for sess_size_tmp in lst[-1]:
                        if sess_size_tmp < 100*1024:
                            mice_sessions += 1
                        elif sess_size_tmp > 1*1024*1024:
                            elephant_sessions += 1
                        else:
                            normal_sessions_size +=1

                for lst in full_sess_size_distribution['UDP']:
                    for sess_size_tmp in lst[-1]:
                        if sess_size_tmp < 100 * 1024:
                            mice_sessions += 1
                        elif sess_size_tmp > 1 * 1024 * 1024:
                            elephant_sessions += 1
                        else:
                            normal_sessions_size += 1

            line = in_f.readline()

        print('elephant_sessions:',elephant_sessions)
        print('mice_sessions:',mice_sessions)
        print('normal_sessions:',normal_sessions_size)

if __name__ == '__main__':
    # input_f = '/home/kun/PycharmProjects/Pcap2Sessions_Scapy/1_pcaps_data/outlog_9508115_4294967294_20181023.out'
    # parse_result_log(input_f)

    input_f = '/home/kun/PycharmProjects/Pcap2Sessions_Scapy/1_pcaps_data/all_session_dict'
    calculate_sessions_size(input_f)