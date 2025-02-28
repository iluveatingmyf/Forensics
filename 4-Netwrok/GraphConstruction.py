# provenance_graph.py
from flow_generator import FlowGenerator
from NodeVersioning import NodeVersioning, epoch_to_datetime_string
import json
from datetime import datetime, timezone
from py2neo import Graph, Node, Relationship
import pyshark


def epoch_to_datetime_string(epoch_timestamp):
    dt_object = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc)
    return dt_object.isoformat()

def get_packet_lengths_with_direction(flow):
    length_set = set()  # 使用 set 存储无序无重复的长度
    initiator = flow['initiator']
    responder = flow['responder']
    
    for segment in flow['segments']:
        length = segment['length']
        
        # 判断方向，initiator 发送的数据用正数表示，responder 发送的数据用负数表示
        if segment['src_ip'] == initiator:
            length_set.add(length)  # 发起者发送，正数
        else:
            length_set.add(-length)  # 响应者发送，负数

    return length_set

def generate_provenance_graph(flows):
    node_versioner = NodeVersioning() 
    flow_index = 0  # 网络事件编号

    for flow in flows:
        flow_index += 1
        initiator_ip = flow['initiator']
        responder_ip = flow['responder']

        # 获取或创建发起者节点（有版本管理），并返回是否为新创建的节点
        initiator_node, initiator_version, initiator_is_new = node_versioner.get_or_create_node(initiator_ip, is_initiator=True)

        # 获取或创建响应者节点（有版本管理），并返回是否为新创建的节点
        responder_node, responder_version, responder_is_new = node_versioner.get_or_create_node(responder_ip, is_initiator=False)

        flow_properties = {
            'start_time': epoch_to_datetime_string(flow['start_time']),
            'end_time': epoch_to_datetime_string(flow['end_time']),
            'length': list(get_packet_lengths_with_direction(flow)),
            'protocol': flow['segments'][0]['protocol']
        }

        if responder_is_new:
            # 1. 如果响应者是新的节点，则直接创建边
            flow_rel = Relationship(initiator_node, flow['segments'][0]['protocol'], responder_node, **flow_properties)
            node_versioner.graph.create(flow_rel)
            node_versioner.total_created_edges += 1  # 记录创建的边
        # 2. 如果发起者是新创建的，但响应者不是，更新响应者版本并创建边（不需要冗余检测）
        elif initiator_is_new and not responder_is_new:
            new_responder_node = node_versioner.update_version(responder_node, responder_ip)
            flow_rel = Relationship(initiator_node, flow['segments'][0]['protocol'], new_responder_node, **flow_properties)
            node_versioner.graph.create(flow_rel)
            node_versioner.total_created_edges += 1  # 记录创建的边
        else:
            # 如果没有冗余边，更新响应者版本并创建新边
            if not node_versioner.has_redundant_edge(initiator_node, responder_node, flow_properties):
                new_responder_node = node_versioner.update_version(responder_node, responder_ip)
                flow_rel = Relationship(initiator_node, flow['segments'][0]['protocol'], new_responder_node, **flow_properties)
                node_versioner.graph.create(flow_rel)
                node_versioner.total_created_edges += 1  # 记录创建的边
    # 输出统计结果
    print(f"Total nodes created: {node_versioner.total_created_nodes}")
    print(f"Total edges created: {node_versioner.total_created_edges}")
    print(f"Edges skipped due to redundancy: {node_versioner.skipped_edges}")

cap = pyshark.FileCapture("../TrafficDataset/Dos/merged.pcap")
flow_gen = FlowGenerator(cap)
flow_gen.generate_flows()
flows = flow_gen.get_flows()

generate_provenance_graph(flows)