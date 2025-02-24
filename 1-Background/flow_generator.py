# flow_generator.py
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
            'responder': packet.ip.dst
        }

    def update_flow(self, flow, packet, timestamp):
        flow['segments'].append(self.create_segment(packet, timestamp))
        flow['end_time'] = timestamp  # Update end time to last packet time

    def create_segment(self, packet, timestamp):
        return {
            'timestamp': timestamp,
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'src_port': packet[packet.transport_layer].srcport,
            'dst_port': packet[packet.transport_layer].dstport,
            'protocol': packet.transport_layer,
            'length': int(packet.length),
            'direction': self.get_direction(packet)
        }

    def get_direction(self, packet):
        def is_local_ip(ip):
            local_ip_ranges = ["192.168.", "10.", "172.16."]
            return any(ip.startswith(prefix) for prefix in local_ip_ranges)
        src = is_local_ip(packet.ip.src)
        dst = is_local_ip(packet.ip.dst)

        if src and (not dst):
            return 1
        elif dst and (not src):
            return 0

    # 获取并且排序flows
    def get_flows(self):
        return sorted(self.completed_flows, key=lambda x: x['start_time'])
