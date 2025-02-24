from 1



# 挖掘频繁模式

#切分

# 频繁模式画图

# 指纹



# 打印保留下来的流量数量
with open('background_traffic_patterns.json', 'r') as f:
    background_patterns = json.load(f)
Filter = TrafficFilter()
pcap_input = "../TrafficDataset/c_inner_yeelight.pcap"
filtered_flows = Filter.filter_traffic(pcap_input, background_patterns)
print(f"Total remaining flows: {len(filtered_flows)}")


