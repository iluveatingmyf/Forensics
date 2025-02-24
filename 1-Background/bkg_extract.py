# bkg_extract.py
import json
import numpy as np
from sklearn.cluster import DBSCAN
import os
from flow_generator import FlowGenerator
import pyshark

# 检查文件是否存在
if os.path.exists('background_traffic_patterns.json'):
    # 加载背景流量模式指纹
    with open('background_traffic_patterns.json', 'r') as f:
        background_patterns = json.load(f)
else:
    print("No existing background traffic patterns found. Proceeding with new extraction.")
    background_patterns = {}  # 如果文件不存在，初始化为空字典



def filter_outliers(intervals):
    # 计算时间间隔的均值和标准差
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    
    # 设置阈值，去除大于 (mean + 3 * std) 和小于 (mean - 3 * std) 的异常值
    filtered_intervals = [interval for interval in intervals if (mean_interval - 3 * std_interval) <= interval <= (mean_interval + 3 * std_interval)]
    
    return np.array(filtered_intervals)

# 手动计算Jaccard相似度
def jaccard_similarity(set1, set2):
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    if union == 0:
        return 0
    return intersection / union

# 主代码
def process_traffic(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    flow_gen = FlowGenerator(cap)
    flow_gen.generate_flows()
    flows = flow_gen.get_flows()

    traffic_by_device = {}
    for flow in flows:
        for ip in [flow['initiator'], flow['responder']]:
            if ip not in traffic_by_device:
                traffic_by_device[ip] = []
            traffic_by_device[ip].append(flow)
    return traffic_by_device

# 调用处理函数
pcap_input = "../TrafficDataset/Gateway/gate_bkg.pcap"
traffic_by_device = process_traffic(pcap_input)

# 处理设备流量
output_data = {}
for device_ip, flows in traffic_by_device.items():
    # 初始化变量
    length_sets = []
    length_set_timestamps = []
    
    for flow in flows:
        length_set = set()
        for segment in flow['segments']:
            if segment['direction'] == 1:
                length_set.add(segment['length'])
            else:
                length_set.add(-segment['length'])

        length_sets.append(length_set)
        length_set_timestamps.append(flow['start_time'])
    # 相似性聚类
    similarity_matrix = np.zeros((len(length_sets), len(length_sets)))
    for i in range(len(length_sets)):
        for j in range(i + 1, len(length_sets)):
            similarity_matrix[i, j] = jaccard_similarity(length_sets[i], length_sets[j])
            similarity_matrix[j, i] = similarity_matrix[i, j]
    
    # 使用DBSCAN进行聚类
    dbscan = DBSCAN(metric='precomputed', eps=0.2, min_samples=2)
    labels = dbscan.fit_predict(1 - similarity_matrix)

    # 聚类结果处理
    clusters = {}
    for idx, label in enumerate(labels):
        if label == -1:
            continue
        if label not in clusters:
            clusters[label] = {'length_sets': set(), 'timestamps': []}
        clusters[label]['length_sets'].add(tuple(sorted(length_sets[idx])))
        clusters[label]['timestamps'].append(length_set_timestamps[idx])

    device_data = {}
    for cluster_id, cluster_data in clusters.items():
        unique_patterns = sorted(list(cluster_data['length_sets']))
        timestamps = sorted(cluster_data['timestamps'])
        if len(timestamps) > 1:
            intervals = np.diff(timestamps)
            filtered_intervals = filter_outliers(intervals)

            avg_interval = np.mean(filtered_intervals )
            std_interval = np.std(filtered_intervals )
            time_window = (avg_interval - std_interval, avg_interval + std_interval)
        else:
            avg_interval, std_interval, time_window = "N/A", "N/A", "N/A"

        device_data[f'Cluster_{cluster_id}'] = {
            "unique_packet_patterns": unique_patterns,
            "average_period_time": avg_interval,
            "std_period_time": std_interval,
            "elastic_time_window": time_window
        }
    
    output_data[device_ip] = device_data

# 保存输出为JSON文件
with open('background_traffic_patterns.json', 'w') as f:
    json.dump(output_data, f, indent=4)

print(json.dumps(output_data, indent=4))