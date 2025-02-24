from scapy.all import rdpcap, sendp

class ReplayPacket:
    def __init__(self, pcap_file):
        self.packets = rdpcap(pcap_file)[1]  # 读取所有数据包

    def replay(self):
        for i, pkt in enumerate(self.packets):
            print(f"Packet {i}: {pkt.summary()} - Layers: {pkt.layers()}")
            if pkt.haslayer('IP'):
                # 打印关键信息
                src_ip = pkt['IP'].src
                dst_ip = pkt['IP'].dst
                print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

                if pkt.haslayer('UDP'):
                    # 打印源和目标端口
                    src_port = pkt['UDP'].sport
                    dst_port = pkt['UDP'].dport
                    print(f"Source Port: {src_port}, Destination Port: {dst_port}")

                    # 发送原始数据包
                    sendp(pkt, verbose=0)
                    print("Packet sent!")
                else:
                    print("No UDP layer found in this packet.")
            else:
                print("No IP layer found in this packet.")

# 示例用法
replay_instance = ReplayPacket('./c_inner_open.pcap')
replay_instance.replay()