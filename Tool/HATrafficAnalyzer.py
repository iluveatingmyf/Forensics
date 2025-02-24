import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
import pyshark
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import TCP, UDP
from flow_generator import FlowGenerator
from typing import List, Dict, Any, Tuple, Optional
from PatternMatcher import PatternMatcher

class HATrafficAnalyzer:
    def __init__(self, fingerprint_path: str, noise_path: str):
        """
        Initialize the analyzer with device fingerprints and noise patterns
        
        Args:
            fingerprint_path: Path to the HAFingerprint.json file
            noise_path: Path to the HAnoise.json file
        """
        self.fingerprints = self._load_json(fingerprint_path)
        self.noise_patterns = self._load_json(noise_path)
        self.MAX_TIME_DIFF = 0.03 # Maximum time difference between consecutive packets in a pattern (seconds)
        
    def _load_json(self, path: str) -> Dict:
        """Load and parse JSON file"""
        with open(path, 'r') as f:
            return json.load(f)
    
    def _get_flow_pattern(self, flow: Dict) -> List[int]:
        """提取flow中的packet长度序列"""
        return [segment['length'] for segment in flow['segments']]



    def _get_consecutive_flows(self, flows: List[Dict]) -> List[List[Dict]]:
        """
        将flows分组为连续的序列（基于时间和设备）
        返回连续flow序列的列表
        """
        if not flows:
            return []
        
        consecutive_groups = []
        current_group = [flows[0]]
        
        for i in range(1, len(flows)):
            current_flow = flows[i]['segments'][0]
            prev_flow = flows[i-1]['segments'][0]
            
            # 检查是否连续
            same_devices = (
                (current_flow['src_ip'] == prev_flow['src_ip'] and 
                 current_flow['dst_ip'] == prev_flow['dst_ip']) or
                (current_flow['src_ip'] == prev_flow['dst_ip'] and 
                 current_flow['dst_ip'] == prev_flow['src_ip'])
            )

            time_consecutive = (current_flow['timestamp'] - prev_flow['timestamp'] 
                              <= self.MAX_TIME_DIFF)
            
            if same_devices and time_consecutive:
                current_group.append(current_flow)
            else:
                if len(current_group) >= 2:  # 只保存长度大于1的组
                    consecutive_groups.append(current_group)
                current_group = [current_flow]
        
        if len(current_group) >= 2:
            consecutive_groups.append(current_group)
            
        return consecutive_groups





    def analyze_flows(self, flows: List[Dict]) -> List[Dict]:
        """
        分析一系列flows，识别出命令和过滤噪声
        
        Args:
            flows: flow列表，每个flow包含segments等信息
            
        Returns:
            识别出的命令列表
        """
        identified_commands = []
        flows = sorted(flows, key=lambda x: x['start_time'])  # 按时间排序

        # 获取所有连续的flow组
        consecutive_groups = self._get_consecutive_flows(flows)
        print(consecutive_groups[0])

        i = 0
        while i < len(flows):
            current_flow = flows[i]
            # 获取设备IP
            device_ip = None
            if current_flow['src_ip'] in self.fingerprints:
                device_ip = current_flow['src_ip']
            elif current_flow['dst_ip'] in self.fingerprints:
                device_ip = current_flow['dst_ip']
                
            if not device_ip:
                i += 1
                continue
                
            # 尝试匹配命令模式
            command_match = self._match_command_flows(device_ip, flows[i:])
            if command_match:
                command_name, flow_count = command_match
                identified_commands.append({
                    'device_ip': device_ip,
                    'command': command_name,
                    'timestamp': flows[i]['start_time'],
                    'flows': flows[i:i+flow_count]
                })
                i += flow_count
                continue
                
            # 检查是否是噪声模式
            noise_count = self._match_noise_flows(device_ip, flows[i:])
            if noise_count:
                i += noise_count
                continue
                
            i += 1
            
        return identified_commands


    def _match_command_flows(self, device_ip: str, flows: List[Dict]) -> Optional[Tuple[str, int]]:
        """
        匹配命令模式
        
        Returns:
            如果匹配成功，返回(命令名, 需要的flow数量)，否则返回None
        """
        device_patterns = self.fingerprints[device_ip]
        
        for command_name, command_patterns in device_patterns.items():
            # 统一处理嵌套和非嵌套模式
            if not isinstance(command_patterns[0], list):
                command_patterns = [command_patterns]
                
            for pattern in command_patterns:
                # 检查我们是否有足够的flows来匹配这个模式
                if len(flows) < len(pattern):
                    continue
                    
                # 检查每个flow的packet长度是否匹配模式
                pattern_matches = True
                for j in range(len(pattern)):
                    if j > 0 and not self._flows_are_consecutive(flows[j-1], flows[j]):
                        pattern_matches = False
                        break
                        
                    flow_pattern = self._get_flow_pattern(flows[j])
                    if flow_pattern != pattern[j]:
                        pattern_matches = False
                        break
                        
                if pattern_matches:
                    return command_name, len(pattern)
                    
        return None


    def _match_noise_flows(self, device_ip: str, flows: List[Dict]) -> int:
        """
        匹配噪声模式
        
        Returns:
            如果匹配成功，返回匹配的flow数量，否则返回0
        """
        if device_ip not in self.noise_patterns:
            return 0
            
        noise_patterns = self.noise_patterns[device_ip]
        
        for pattern in noise_patterns:
            if len(flows) < len(pattern):
                continue
                
            # 检查每个flow的packet长度是否匹配噪声模式
            pattern_matches = True
            for j in range(len(pattern)):
                if j > 0 and not self._flows_are_consecutive(flows[j-1], flows[j]):
                    pattern_matches = False
                    break
                    
                flow_pattern = self._get_flow_pattern(flows[j])
                if flow_pattern != pattern[j]:
                    pattern_matches = False
                    break
                    
            if pattern_matches:
                return len(pattern)
                
        return 0

 
def filter_protocol(pcap_path: str, output_path: str) -> None:
    """Filter out non-TCP/UDP packets and multicast traffic"""
    packets = rdpcap(pcap_path)
    print(f"Total packets: {len(packets)}")
    
    filtered = [
        pkt for pkt in packets 
        if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and
        not (pkt.haslayer('IP') and pkt['IP'].dst in ['224.0.0.251', '224.0.0.50'])
    ]
    
    print(f"Filtered packets: {len(filtered)}")
    wrpcap(output_path, filtered)

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



def analyze_pcap_flows(flows: List[Dict], fingerprint_path: str, noise_path: str) -> None:
    """主函数：分析PCAP文件中的flows"""
    analyzer = HATrafficAnalyzer(fingerprint_path, noise_path)
    
    commands = analyzer.analyze_flows(flows)
    
    # 打印识别出的命令
    for cmd in commands:
        print(f"设备 {cmd['device_ip']} 在 "
              f"{datetime.fromtimestamp(cmd['timestamp'])} "
              f"执行了命令 {cmd['command']}")
        print("Flow模式:")
        for flow in cmd['flows']:
            print(f"  {self._get_flow_pattern(flow)}")
        print()


if __name__ == "__main__":
    # Example usage
    pcap_path = "../TrafficDataset/test/ha_test.pcap"
    filtered_path = "../TrafficDataset/test/ha_test_filtered.pcap"
    
    flow_gen = FlowGenerator(pcap_path)
    flow_gen.generate_flows()
    flows = flow_gen.get_flows()


    fingerprint_path = "../TrafficDataset/HAFingerprint.json"
    noise_path = "../TrafficDataset/HAnoise.json"
    specific_ips = ["192.168.0.192", "192.168.0.176"]  # 需要过滤的IP列表
    
    # Filter protocols first
    filter_protocol(pcap_path, filtered_path)
    filter_specific_ips(filtered_path, filtered_path, specific_ips)

    cap = pyshark.FileCapture(filtered_path)
    flow_gen = FlowGenerator(cap)
    flow_gen.generate_flows()
    flows = flow_gen.get_flows()
    
    analyze_pcap_flows(flows, fingerprint_path, noise_path)

    # Analyze the filtered PCAP"""