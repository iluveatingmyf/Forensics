import pyshark
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import TCP, UDP
from flow_generator import FlowGenerator
import numpy as np
from collections import Counter
from datetime import datetime

def frequent(flows, frequency_threshold=5):
    """
    统计高频次且时间呈现周期性的流，并打印出来。

    :param flows: 流的列表，每个流包含时间戳和数据包信息
    :param frequency_threshold: 频率阈值，表示流必须达到的最小包数
    """
    flow_counter = Counter()  # 用于统计流的频次
    packet_length_counter = Counter()  # 用于统计包长度序列

    # 遍历每个流，统计每个流的包的数量和长度序列
    for flow in flows:
        # 提取包长度序列
        packet_lengths = [segment['length'] for segment in flow['segments']]
        packet_length_set = frozenset(packet_lengths)  # 转换为集合以便计数
        packet_length_counter[packet_length_set] += 1  # 统计长度序列出现次数

        flow_key = flow['flow_key']
        packet_count = len(flow['segments'])
        flow_counter[flow_key] += packet_count

    # 打印包长度序列的频次
    print("Packet Length Frequencies:")
    for lengths, count in packet_length_counter.items():
        print(f"Length Sequence: {lengths} | Count: {count}")

    # 找到频率高于阈值的流
    high_frequency_flows = {k: v for k, v in flow_counter.items() if v >= frequency_threshold}
    
    # 检查这些流是否周期性
    periodic_flows = []

    for flow_key in high_frequency_flows.keys():
        # 找到对应的流
        flow = next(f for f in flows if f['flow_key'] == flow_key)
        timestamps = [segment['timestamp'] for segment in flow['segments']]
        
        # 计算时间间隔
        time_diffs = np.diff(timestamps)
        
        # 检查时间间隔是否一致（周期性）
        if len(time_diffs) > 0:
            avg_diff = np.mean(time_diffs)
            # 检查时间差是否在平均值的10%内
            if all(abs(diff - avg_diff) <= 0.1 * avg_diff for diff in time_diffs):
                periodic_flows.append(flow)

    # 打印高频次且周期性的流
    print("High Frequency Periodic Flows:")
    for flow in periodic_flows:
        print(f"Flow Key: {flow['flow_key']} | Packet Count: {len(flow['segments'])} | Start Time: {datetime.fromtimestamp(flow['start_time'])} | End Time: {datetime.fromtimestamp(flow['end_time'])}")


def filter_protocol(pcap_path, output_path):
    # 读取pcap文件并过滤非TCP/UDP的包
    packets = rdpcap(pcap_path)
    print(f"Total packets: {len(packets)}")
    
    filtered = [pkt for pkt in packets if pkt.haslayer(TCP) or pkt.haslayer(UDP)]

    filtered = [pkt for pkt in filtered if not (pkt.haslayer('IP') and (pkt['IP'].dst in ['224.0.0.251', '224.0.0.50']))]

    print(f"Filtered packets: {len(filtered)}")

    # 保存过滤后的数据包到新的PCAP文件
    wrpcap(output_path, filtered)
    print(f"Filtered packets saved to {output_path}")


def filter_specific_ips(pcap_path, output_path, specific_ips):
    """
    过滤出源IP和目标IP在特定列表中的所有数据包，并保存到新的PCAP文件。

    :param pcap_path: 输入的PCAP文件路径
    :param output_path: 输出的PCAP文件路径
    :param specific_ips: 包含特定IP的列表
    """
    # 读取PCAP文件
    packets = rdpcap(pcap_path)
    print(f"Total packets: {len(packets)}")

    # 过滤源IP和目标IP在特定列表中的数据包
    filtered_packets = [
        pkt for pkt in packets 
        if (pkt.haslayer('IP') and (pkt['IP'].src in specific_ips or pkt['IP'].dst in specific_ips))
    ]
    
    print(f"Filtered packets: {len(filtered_packets)}")

    # 保存过滤后的数据包到新的PCAP文件
    wrpcap(output_path, filtered_packets)
    print(f"Filtered packets saved to {output_path}")

# 输入和输出PCAP路径
pcap_path = "../TrafficDataset/Dos/dosHA.pcap"
output_path = "../TrafficDataset/test/dosHA.pcap"
filter_protocol(pcap_path, output_path)
specific_ips = ["192.168.0.192", "192.168.0.176"]  # 需要过滤的IP列表
filter_specific_ips(output_path, output_path, specific_ips)

cap = pyshark.FileCapture(output_path)
flow_gen = FlowGenerator(cap)
flow_gen.generate_flows()
flows = flow_gen.get_flows()

#frequent(flows)