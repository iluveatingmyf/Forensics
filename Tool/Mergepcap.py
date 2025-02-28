from scapy.all import PcapReader, wrpcap

#删除UDP/TCP/HTTP 之外的包都不处理

#合并/删除 homeassistant中 频率超过5的包

# 处理 HomeAssistant 数据包，删除频率超过 5 的包
def processHA(HAfile_path, HAfile_path_new):
    packets = []
    
    # 读取 pcap 文件
    with PcapReader(HAfile_path) as pcap_reader:
        for packet in pcap_reader:
            if packet.haslayer(IP):  # 确保数据包有 IP 层
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                pkt_len = len(packet)  # 获取数据包长度

                # 将关心的字段作为标识符
                packet_key = (src_ip, dst_ip, pkt_len)

                # 存储包及其标识符
                packets.append((packet, packet_key))

    # 统计每个包标识符的频率
    packet_counter = Counter([pkt_key for _, pkt_key in packets])
    
    # 过滤掉频率超过 5 的包
    filtered_packets = [pkt for pkt, pkt_key in packets if packet_counter[pkt_key] <= 5]
    
    # 写入新 PCAP 文件
    wrpcap(HAfile_path_new, filtered_packets)
    
    return HAfile_path_new  # 返回处理后的新文件路径

#def FilterProtocol():

def merge_pcap_files(output_file, input_files):
    merged_packets = []
    
    # 逐个读取输入文件并提取数据包
    for file in input_files:
        try:
            with PcapReader(file) as pcap_reader:
                for packet in pcap_reader:
                    try:
                        merged_packets.append(packet)
                    except Exception as e:
                        print(f"Error reading a packet from {file}: {e}")
                        continue  # 跳过有问题的数据包，继续读取下一个数据包
        except Exception as e:
            print(f"Error opening {file}: {e}")
            continue  # 如果文件无法打开，跳过整个文件
    
    # 按照数据包的时间戳排序
    merged_packets.sort(key=lambda pkt: pkt.time)
    
    # 重新分配数据包索引
    for i, pkt in enumerate(merged_packets):
        pkt.id = i + 1
    
    # 将排序后的数据包写入输出文件
    wrpcap(output_file, merged_packets)


HAfile_path= "../TrafficDataset/Dos/dos.pcap"
Rfile_path = "../TrafficDataset/Dos/dosHA.pcap"
"""
HAfile_path_new= "./mimicHA_bak.pcap"
Rfile_path_new = "./mimic_bak.pcap"


HAfile = processHA(HAfile_path,HAfile_path_new)
HAfile = FilterProtocol(HAfile)

Rfile = FilterProtocol(Rfile_path)"""


output_file = "../TrafficDataset/Dos/merged.pcap"


input_files=[HAfile_path, Rfile_path]

merge_pcap_files(output_file, input_files)
#output_file = "/Users/myf/Provenance_project/NetworkProvenanceGraph/explicit/half/both.pcap"
#input_files = ["/Users/myf/Provenance_project/NetworkProvenanceGraph/explicit/half/H.pcap", "/Users/myf/Provenance_project/NetworkProvenanceGraph/explicit/half/R.pcap"]
#merge_pcap_files(output_file, input_files)
