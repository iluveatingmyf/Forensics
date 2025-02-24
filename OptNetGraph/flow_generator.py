import pyshark

SILENCE_THRESHOLD = 2.0

class FlowGenerator:
    def __init__(self, packets, silence_threshold=SILENCE_THRESHOLD):
        self.packets = packets
        self.silence_threshold = silence_threshold
        self.active_flows = {}  # Active flows being tracked
        self.completed_flows = []  # Completed flows

    def create_flow_key(self, packet):
        if not hasattr(packet, 'ip') or not hasattr(packet, 'transport_layer') or not packet.transport_layer:
            return None
        ips = sorted([packet.ip.src, packet.ip.dst])
        src_ip, dst_ip = ips[0], ips[1]
        protocol = packet.transport_layer
        ports = sorted([packet[protocol].srcport, packet[protocol].dstport])
        src_port, dst_port = ports[0], ports[1]
        
        if 'HTTP' in packet:
            protocol = "HTTP"
            src_port, dst_port = sorted([packet[packet.transport_layer].srcport, packet[packet.transport_layer].dstport])
        
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def generate_flows(self):      
        for packet in self.packets:
            if not hasattr(packet, 'ip'):
                continue  # 跳过没有IP层或传输层的数据包
            flow_key = self.create_flow_key(packet)
            if flow_key is None:
                continue  # 如果flow_key为None，则跳过这个包
            timestamp = float(packet.sniff_timestamp)

            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                if timestamp - flow['end_time'] > self.silence_threshold:
                    # If current packet is outside the silence threshold, finalize current flow and start a new one
                    self.completed_flows.append(flow)
                    self.active_flows[flow_key] = self.new_flow(flow_key, packet, timestamp)
                else:
                    # Update existing flow
                    self.update_flow(flow, packet, timestamp)
            else:
                # Start new flow
                self.active_flows[flow_key] = self.new_flow(flow_key, packet, timestamp)
        
        for flow in self.active_flows.values():
            self.completed_flows.append(flow)
            
    def new_flow(self, flow_key, packet, timestamp):
        return {
            'flow_key': flow_key,
            'segments': [self.create_segment(packet, timestamp)],
            'start_time': timestamp,
            'end_time': timestamp,
            'initiator': packet.ip.src,
            'responder': packet.ip.dst,
            'length': {int(packet.length)},  # 初始化为一个set，存储包长度，类型为数字
        }

    def update_flow(self, flow, packet, timestamp):
        flow['segments'].append(self.create_segment(packet, timestamp))
        flow['end_time'] = timestamp  # Update end time to last packet time
        flow['length'].add(int(packet.length))  # 将新的长度添加到set中，不会重复

    def create_segment(self, packet, timestamp):
        return {
            'timestamp': timestamp,
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'src_port': packet[packet.transport_layer].srcport,
            'dst_port': packet[packet.transport_layer].dstport,
            'protocol': packet.transport_layer,
            'length': int(packet.length),
            'direction': self.get_direction(packet)  # 表示方向，1 或 0
        }

    def get_direction(self, packet):
        def is_local_ip(ip):
            local_ip_ranges = ["192.168.", "10.", "172.16."]
            return any(ip.startswith(prefix) for prefix in local_ip_ranges)
        
        src_is_local = is_local_ip(packet.ip.src)
        dst_is_local = is_local_ip(packet.ip.dst)

        # 方向，1表示本地 -> 外部，0表示外部 -> 本地
        if src_is_local and not dst_is_local:
            return 1  # 本地 -> 外部
        elif dst_is_local and not src_is_local:
            return 0  # 外部 -> 本地
        else:
            return 1  # 默认：本地 -> 外部

    # 获取并且排序flows
    def get_flows(self):
        return sorted(self.completed_flows, key=lambda x: x['start_time'])


cap = pyshark.FileCapture("./attack.pcap")
flow_gen = FlowGenerator(cap)
flow_gen.generate_flows()
flows = flow_gen.get_flows()
print(flows[0]["length"])