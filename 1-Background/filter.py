import json
from flow_generator import FlowGenerator
import pyshark
import numpy as np

class TrafficFilter:   
    def __init__(self):
        # 加载背景流量模式指纹
        return

    # 主函数：处理流量过滤
    def filter_traffic(self, pcap_file, background_patterns):
        cap = pyshark.FileCapture(pcap_file)
        flow_gen = FlowGenerator(cap)
        flow_gen.generate_flows()
        flows = flow_gen.get_flows()

        filtered_flows = []
        total_flows = len(flows)  # 总的流量数量
        filtered_count = 0  # 过滤掉的流量计数

        # 用于记录第一个匹配到的背景流量的时间戳和时间间隔
        first_flow_timestamp = None
        first_flow_interval = None


        # 遍历每个流进行过滤
        for flow in flows:
            is_background_flow = False  # 标志当前流是否为背景流量

            flow_length_set = set()
            # 提取流的包长度序列
            for segment in flow['segments']:
                if segment['direction'] == 1:
                    flow_length_set.add(segment['length'])
                else:
                    flow_length_set.add(-segment['length'])

            # 获取流的源IP
            flow_ip = flow['initiator']

            # 检查该流是否匹配背景流量模式
            if flow_ip in background_patterns:
                for cluster_id, cluster_data in background_patterns[flow_ip].items():
                    # 比较包长度集合与所有可能性
                    for pattern in cluster_data['unique_packet_patterns']:
                        pattern_set = set(pattern)
                        
                        # 匹配流量长度集和模式中的可能性
                        if flow_length_set == pattern_set:
                            # 如果匹配上，标记为背景流量
                            is_background_flow = True

                            """# 获取当前流的时间戳
                            current_flow_timestamp = sorted([segment['timestamp'] for segment in flow['segments']])[0]

                            # 如果是第一次匹配到背景流量
                            if first_flow_timestamp is None:
                                # 记录第一个流的时间戳，用于后续流量的比较
                                first_flow_timestamp = current_flow_timestamp
                                break
                            
                            # 如果不是第一次流量，计算与第一个流的时间间隔
                            time_interval = current_flow_timestamp - first_flow_timestamp

                            # 获取背景流量的平均周期和弹性时间窗口
                            avg_interval = cluster_data['average_period_time']
                            std_interval = cluster_data['std_period_time']
                            elastic_time_window = cluster_data['elastic_time_window']

                            # 判断当前时间间隔是否在背景流量的周期性范围内
                            if (avg_interval - std_interval <= time_interval <= avg_interval + std_interval):
                                is_background_flow = True
                            else:
                                is_background_flow = False
                            
                            break"""
                    if is_background_flow:
                        break

            # 如果当前流不是背景流量，保留该流；否则，增加过滤计数
            if not is_background_flow:
                filtered_flows.append(flow)
            else:
                filtered_count += 1

        # 输出过滤结果
        print(f"Total flows processed: {total_flows}")
        print(f"Total flows filtered (background traffic): {filtered_count}")

        return filtered_flows



# 打印保留下来的流量数量
with open('background_traffic_patterns.json', 'r') as f:
    background_patterns = json.load(f)
Filter = TrafficFilter()
pcap_input = "../TrafficDataset/c_inner_yeelight.pcap"
filtered_flows = Filter.filter_traffic(pcap_input, background_patterns)
print(f"Total remaining flows: {len(filtered_flows)}")
