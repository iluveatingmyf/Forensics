from py2neo import Graph, Node, Relationship
from datetime import datetime, timezone
from flow_generator import FlowGenerator
import pyshark
import uuid

# 将epoch时间戳转换为ISO时间格式
def epoch_to_datetime_string(epoch_timestamp):
    dt_object = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc)
    return dt_object.isoformat()

def jaccard_similarity(set1, set2):
    """
    计算两个集合的Jaccard相似度。
    """
    if not isinstance(set1, set) or not isinstance(set2, set):
        raise ValueError("Both arguments must be sets.")
        
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    return len(intersection) / len(union) if union else 0

class OptimizedNodeVersioning:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="neo4j"):
        self.graph = Graph(uri, auth=(user, password))
        self.nodes = {}  # 用于存储设备的最新版本 {(IP): (version_number, Node)}
        self.created_edges_count = 0
        self.skipped_edges_count = 0

    def update_or_create_node(self, ip, is_initiator, check_relationship_func):
        latest_version, latest_node = self.nodes.get(ip, (0, None))

        # 如果是initiator并且已经有版本存在，直接返回最新的节点
        if is_initiator and latest_node:
            return latest_node

        # 在创建新的节点之前，先检查冗余边
        if latest_node and check_relationship_func(latest_node):
            # 如果发现冗余边，不创建新版本节点，直接返回当前节点
            return latest_node

        # 否则创建新的节点版本
        new_version_number = latest_version + 1
        new_node = Node("Device", name=f"Device_{ip}_v{new_version_number}", IP=str(ip), version=new_version_number, uuid=str(uuid.uuid4()))
        self.graph.create(new_node)

        # 记录最新版本
        self.nodes[ip] = (new_version_number, new_node)

        # 如果有上一个版本，创建HAS_NEXT_VERSION的关系
        if latest_node:
            version_rel = Relationship(latest_node, "HAS_NEXT_VERSION", new_node)
            self.graph.create(version_rel)

        return new_node

    def create_relationship_with_reo(self, initiator_node, responder_node, protocol, properties, length_threshold=5):
        """
        实现冗余边优化（REO）。在添加一条边之前，检查该边是否已经存在。
        如果已经存在，则跳过创建新边。length_threshold 用于比较流的长度集合之间的Jaccard相似度。
        """
        existing_relationships = self.graph.match((initiator_node, responder_node), r_type=protocol)
        
        # 获取当前流的长度集合
        current_length_set = set(properties["length"])
        
        for rel in existing_relationships:
            # 确保 "length" 属性存在
            if "length" in rel:
                existing_length_set = set(rel["length"])

                # 计算Jaccard相似度
                similarity = jaccard_similarity(current_length_set, existing_length_set)

                # 如果相似度大于等于阈值，跳过创建新边
                if similarity >= length_threshold / len(current_length_set.union(existing_length_set)):
                    self.skipped_edges_count += 1
                    return True
            else:
                print(f"Warning: Relationship {rel} does not have 'length' attribute")
        
        return False

    def create_relationship_with_reo_star(self, initiator_node, responder_node, protocol, properties, length_threshold=5):
        """
        实现全局冗余边优化（REO*）。在添加一条边之前，检查是否有祖先节点已经具有相同的边。
        length_threshold 用于比较流的长度集合之间的Jaccard相似度。
        """
        current_node = initiator_node
        current_length_set = set(properties["length"])
        
        # 递归检查 initiator_node 的祖先节点是否有相同的边
        while current_node:
            # 查询所有前序版本的节点
            query = """
            MATCH (prev:Device)-[r:HAS_NEXT_VERSION]->(current:Device {uuid: $current_uuid})
            RETURN prev
            """
            previous_version_result = self.graph.run(query, current_uuid=current_node["uuid"]).data()

            previous_versions = [result['prev'] for result in previous_version_result]

            for prev_version in previous_versions:
                # 查询所有 responder_node 版本
                query = """
                MATCH (responder:Device {uuid: $responder_uuid})<-[:HAS_NEXT_VERSION*]-(versions:Device)
                RETURN versions
                """
                responder_versions = self.graph.run(query, responder_uuid=responder_node["uuid"]).data()

                for version in responder_versions:
                    # 对于每个版本，查询是否已经存在冗余边
                    query = """
                    MATCH (a:Device)-[r:{}]->(b:Device)
                    WHERE a.uuid = $start_uuid AND b.uuid = $end_uuid
                    RETURN r
                    """.format(protocol)
                    existing_relationships = self.graph.run(query, start_uuid=prev_version["uuid"], end_uuid=version["versions"]["uuid"]).data()

                    for rel in existing_relationships:
                        # 确保 "length" 属性存在
                        if "length" in rel:
                            existing_length_set = set(rel["length"])

                            # 计算Jaccard相似度
                            similarity = jaccard_similarity(current_length_set, existing_length_set)

                            # 如果相似度大于等于阈值，跳过创建新边
                            if similarity >= length_threshold / len(current_length_set.union(existing_length_set)):
                                self.skipped_edges_count += 1
                                return True
                        else:
                            print(f"Warning: Relationship {rel} does not have 'length' attribute")

            # 继续检查下一个前序版本
            current_node = previous_versions[0] if previous_versions else None

        return False

    def report(self):
        print(f"Created edges: {self.created_edges_count}")
        print(f"Skipped edges: {self.skipped_edges_count}")

# 生成网络活动的依赖图
def generate_provenance_graph(flows, use_reo_star=True, length_threshold=5):
    """
    生成网络活动的依赖图，支持REO或REO*优化策略。
    
    :param flows: 网络流的列表
    :param use_reo_star: 如果为True，使用REO*全局冗余边优化；否则使用REO冗余边优化
    :param length_threshold: 用于决定是否创建新边的长度集合的阈值，表示两个流的对称差异元素个数。
    """
    node_versioner = OptimizedNodeVersioning() 
    flow_index = 0
    for flow in flows:
        flow_index += 1
        initiator_ip = flow['initiator']
        responder_ip = flow['responder']

        lengths = set()
        for segment in flow['segments']:
            if 'length' in segment:
                lengths.add(segment['length'])
            else:
                print(f"Warning: Segment {segment} does not have 'length' attribute")

        properties = {
            'index': str(flow_index),
            'start_time': epoch_to_datetime_string(flow['start_time']),
            'end_time': epoch_to_datetime_string(flow['end_time']),
            'length': list(lengths),
            'protocol': flow['segments'][0]['protocol']
        }

        # 更新或创建发起者和响应者节点
        initiator_node = node_versioner.update_or_create_node(initiator_ip, True, lambda node: node_versioner.create_relationship_with_reo_star(node, responder_node, properties['protocol'], properties, length_threshold) if use_reo_star else lambda node: node_versioner.create_relationship_with_reo(node, responder_node, properties['protocol'], properties, length_threshold))
        responder_node = node_versioner.update_or_create_node(responder_ip, False, lambda node: node_versioner.create_relationship_with_reo_star(node, responder_node, properties['protocol'], properties, length_threshold) if use_reo_star else lambda node: node_versioner.create_relationship_with_reo(node, responder_node, properties['protocol'], properties, length_threshold))

        # 如果未跳过边，则创建边
        if not node_versioner.create_relationship_with_reo_star(initiator_node, responder_node, properties['protocol'], properties, length_threshold) if use_reo_star else not node_versioner.create_relationship_with_reo(initiator_node, responder_node, properties['protocol'], properties, length_threshold):
            flow_rel = Relationship(initiator_node, properties['protocol'], responder_node, **properties)
            node_versioner.graph.create(flow_rel)
            node_versioner.created_edges_count += 1

    node_versioner.report()

# Example usage:
cap = pyshark.FileCapture("./attack.pcap")
flow_gen = FlowGenerator(cap)
flow_gen.generate_flows()
flows = flow_gen.get_flows()

# 生成依赖图时，指定是否使用REO* (默认True)，并设置 length_threshold 用于长度集合的比较
generate_provenance_graph(flows, use_reo_star=True, length_threshold=3)
