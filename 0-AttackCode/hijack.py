import socket
import struct
import time
from typing import Tuple
from scapy.layers.inet import UDP
from scapy.all import sendp, Ether, IP, UDP
from scapy.utils import rdpcap
from scapy.packet import Raw


class replay_packet:
    def __init__(self, pcap_file, port):
        self.packet =rdpcap(pcap_file)[1]
        self.port = port

    def replay(self):
        pkt = self.packet
        pkt.dport = self.port
        sendp(pkt, verbose=0)
        print(f"Replaying to IP: {pkt.dst}")
        print(f"Replaying to port: {self.port}")
        print(f"Replaying from IP: {pkt.src}")
        print(f"Replaying from port: {pkt.sport}")

# 本机IP地址
local_ip = '192.168.0.146'

# 目标修改IP
new_ip_1 = '192.168.0.176'
new_ip_2 = '192.168.0.159'
# 定义常量
PORT_CONSTANT = 42708

LISTEN_PORT = 10000  # 监听端口



# 判断是否是本机IP地址
def is_local_ip(ip: str) -> bool:
    return ip == local_ip


# 修改源IP和目标IP


def modify_ips(src_ip: str, dst_ip: str) -> Tuple[str, str]:
    #根据源IP和目标IP是否为本机IP来决定是否修改它们
    if is_local_ip(src_ip):
        # 如果源IP是本机IP，修改源IP
        src_ip = new_ip_1 if src_ip != new_ip_1 else new_ip_2
    if is_local_ip(dst_ip):
        # 如果目标IP不是本机IP，修改目标IP
        dst_ip = new_ip_1 if dst_ip != new_ip_1 else new_ip_2
    return src_ip, dst_ip

# 修改数据包的源IP和源端口
def modify_packet(pkt, src, dst):
    def add_udp_layer(pkt, new_src_port, new_dst_port):
        # 构造UDP层
        udp_layer = UDP(sport=new_src_port, dport=new_dst_port)    
        # 用原始数据填充
        udp_layer.payload = pkt[Raw] if Raw in pkt else b""   
        # 在IP层上加上UDP层
        ip_layer = IP(src=pkt[IP].src, dst=pkt[IP].dst) / udp_layer      
        return ip_layer
    print(f"Packet: {pkt.summary()} - Layers: {pkt.layers()}")
    pkt[IP].src = src[0]      # 修改源IP
    pkt[IP].dst = dst[0]     # 修改目标IP
    modified_pkt = add_udp_layer(pkt, src[1], src[1])

    return modified_pkt

# 定义关键数据包的结构
class KeyPacket:
    def __init__(self, client_ip, destination_ip, client_port, destination_port, data, timestamp):
        self.client_ip = client_ip  # 源IP
        self.destination_ip = destination_ip  # 目标IP
        self.client_port = client_port  # 源端口
        self.destination_port = destination_port  # 目标端口
        self.data = data  # 数据包内容
        self.timestamp = timestamp  # 捕获时间
        self.length = len(data)  # 数据包长度

    def __repr__(self):
        return f"KeyPacket(client_ip={self.client_ip}, destination_ip={self.destination_ip}, " \
               f"client_port={self.client_port}, destination_port={self.destination_port}, " \
               f"length={self.length}, timestamp={self.timestamp})"


# 记录捕获的关键数据包列表
captured_key_packets = []
last_replay_time = None  # 上次重放时间，用于定时重放

Host = Tuple[str, int]  # 定义Host类型，包含IP地址和端口

# Constants for handling ancillary data (附加数据处理常量)
IP_RECVORIGDSTADDR = 20  # 用于接收原始目标地址的常量
SOL_IPV6 = 41  # IPv6 相关常量
IPV6_RECVORIGDSTADDR = 74  # 用于接收IPv6目标地址的常量

# 接收并解析数据包
def recv_tproxy_udp(bind_sock, bufsize) -> Tuple[Host, Host, bytes]:
    max_ancillary_size = 28  # sizeof(struct sockaddr_in6)，IPv6的最大附加数据大小
    data, ancdata, flags, client = bind_sock.recvmsg(bufsize, socket.CMSG_SPACE(max_ancillary_size))

    #
    # 打印接收到的数据包和附加数据，方便调试
    print(f"Client: {client}")
    print(f"Received data: {data}")
    print(f"Ancillary data: {ancdata}")
    # 如果没有附加数据，打印并返回
    if not ancdata:
        print("No ancillary data received.")
        return client, None, data  # 直接返回客户端信息、目标地址为None、数据包内容

    # 解析附加数据
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        # 处理IPv4数据包
        if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
            family, port = struct.unpack('=HH', cmsg_data[0:4])
            port = socket.htons(port)

            if family != socket.AF_INET:
                raise TypeError(f"Unsupported socket type '{family}'")

            ip = socket.inet_ntop(family, cmsg_data[4:8])  # 转换IP地址
            destination = (ip, port)  # 目标地址
            return client, destination, data  # 返回客户端地址、目标地址和数据包内容

        # 处理IPv6数据包
        elif cmsg_level == SOL_IPV6 and cmsg_type == IPV6_RECVORIGDSTADDR:
            family, port = struct.unpack('=HH', cmsg_data[0:4])
            port = socket.htons(port)

            if family != socket.AF_INET6:
                raise TypeError(f"Unsupported socket type '{family}'")

            ip = socket.inet_ntop(family, cmsg_data[8:24])  # 转换IPv6地址
            destination = (ip, port)  # 目标地址
            return client, destination, data  # 返回客户端地址、目标地址和数据包内容

    raise ValueError("Unable to parse datagram")  # 如果解析失败，抛出异常

# 判断数据包是否为控制命令
def is_key_packet(data: bytes, client_ip: str, destination_ip: str, client_port: int, destination_port: int) -> bool:
    """
    判断数据包是否为控制命令。通过检查数据包长度来判断是否为关键数据包。
    关键数据包会保存其内容，并附带时间戳和标志信息，方便后期重放时进行修改。
    """
    # 假设关键数据包的长度范围（例如96字节或64字节），你可以根据实际情况调整这个值
    if len(data) == 96:
        print(f"[+] Captured key packet: {client_ip}:{client_port} -> {destination_ip}:{destination_port}")
        
        # 创建KeyPacket对象保存详细的字段信息
        key_packet = KeyPacket(client_ip, destination_ip, client_port, destination_port, data, time.time())
        
        # 保存关键数据包
        captured_key_packets.append(key_packet)
        return True  # 返回True表示这是关键数据包
    return False  # 否则返回False

# 处理并转发数据包
def forward_packet(source: tuple, destination: tuple, data: bytes, delay: bool):
    """
    转发数据包到指定的目标地址
    如果delay为True，进行延时处理
    """
    pkt = IP(data)
    pkt = modify_packet(pkt, source, destination)
    sendp(pkt, verbose=0)
    print(f"Forwarded packet with source {source} to {destination}")



    """if delay:
        for i in range(4, 0, -1):
            print(f"Forwarding in {i} seconds...")
            time.sleep(1)
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_sock:
        forward_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            forward_sock.sendto(data, destination)
            print(f"Forwarding to {destination_ip}:{destination_port} with data length: {len(data)}")
        except Exception as e:
            print(f"Error sending packet: {e}")"""


# 定时重放捕获的关键包
def replay_key_packets():
    """
    重放所有捕获的关键数据包
    """
    for packet in captured_key_packets:
        print(f"Replaying: {packet}")
        forward_packet((packet.destination_ip, packet.destination_port), packet.data, delay=False)


# 主程序，负责接收、转发数据包并定时重放关键数据包
server_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
server_sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)  # 设置透明代理选项
server_sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)  # 设置接收目标地址的选项
server_sock.bind(('0.0.0.0', 10000))  # 绑定到端口10000，监听所有的UDP流量


# 主循环
while True:
    try:
        print('Waiting for message...')  # 等待接收数据包
        data, ancdata, flags, client = server_sock.recvmsg(8192, socket.CMSG_SPACE(24))
        
        # 打印接收到的数据包
        print(f"Received data from {client}")
        print(f"Ancillary data: {ancdata}")


        #client, destination, data = recv_tproxy_udp(server_sock, 8192)  # 接收数据包
        #print(f"Received data from {client} intended for {destination}")

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == 20:
                family, port = struct.unpack('=HH', cmsg_data[0:4])
                port = socket.htons(port)
                if family == socket.AF_INET:
                    start = 4
                    length = 4
                else:
                    raise
                ip = socket.inet_ntop(family, cmsg_data[start:start + length])
                destination = (ip, port)

        # 获取客户端IP和目标IP
        client_ip, client_port = client
        # 判断端口号是否为替代端口
        if PORT_CONSTANT!=client_port:
            PORT_CONSTANT = client_port
        destination_ip, destination_port = destination

        # 修改源IP和目标IP
        client_ip, destination_ip = modify_ips(client_ip, destination_ip)


        # 打印修改后的IP信息
        print(f"Modified client IP: {client_ip}, destination IP: {destination_ip}")

        if destination_ip == "192.168.0.176":
            destination_port = 54321
        
        if destination_ip == "192.168.0.159":
            destination_port = PORT_CONSTANT

        print("src")
        print((client_ip, client_port))
        print("dst")
        print((destination_ip, destination_port))
        
        forward_packet((client_ip, client_port),(destination_ip, destination_port), data, delay=False)
        #pcap_file = "./target.pcap"
        #Replay = replay_packet(pcap_file, PORT_CONSTANT)
        #Replay.replay()

        #forward_packet((client_ip, client_port), data, delay=False)

        """

        # 持续转发所有数据包
        forward_packet(destination, data, delay=False)

        # 如果数据包是关键数据包，则保存
        if is_key_packet(data, client[0], destination[0], client[1], destination[1]):
            print("[+] Captured key packet!")

        # 定时重放关键数据包（例如每10秒重放一次）
        if last_replay_time is None or time.time() - last_replay_time >= 10:
            print("[+] Replaying captured key packets...")
            replay_key_packets()  # 重放关键数据包
            last_replay_time = time.time()  # 更新重放时间"""

    except Exception as e:
        print(e)  # 捕获并输出异常
