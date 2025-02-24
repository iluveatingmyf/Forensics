from py2neo import Graph, Node, Relationship
from datetime import datetime, timezone

# 将epoch时间戳转换为ISO时间格式
def epoch_to_datetime_string(epoch_timestamp):
    dt_object = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc)
    return dt_object.isoformat()

def jaccard_similarity(set1, set2):
    """
    计算两个集合的Jaccard相似度。
    """
    # 确保输入是集合类型
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

    def update_or_create_node(self, ip, is_initiator):
        latest_version, latest_node = self.nodes.get(ip, (0, None))

        # 如果是initiator并且已经有版本存在，直接返回最新的节点
        if is_initiator and latest_node:
            return latest_node

        # 否则创建新的节点版本
        new_version_number = latest_version + 1
        new_node = Node("Device", name=f"Device_{ip}_v{new_version_number}", IP=str(ip), version=new_version_number)
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
            existing_length_set = set(rel["length"])

            # 计算Jaccard相似度
            similarity = jaccard_similarity(current_length_set, existing_length_set)

            print(similarity)
            print(1 - length_threshold / len(current_length_set.union(existing_length_set)))

            # 如果相似度大于等于阈值（1 - length_threshold / (总长度集合大小)），认为流相似，跳过创建新边
            if similarity >= (1 - length_threshold / len(current_length_set.union(existing_length_set))):
                self.skipped_edges_count += 1
                return
        
        # 否则创建新边
        flow_rel = Relationship(initiator_node, protocol, responder_node, **properties)
        self.graph.create(flow_rel)
        self.created_edges_count += 1

    def create_relationship_with_reo_star(self, initiator_node, responder_node, protocol, properties, length_threshold=5):
        """
        实现全局冗余边优化（REO*）。在添加一条边之前，检查是否有祖先节点已经具有相同的边。
        length_threshold 用于比较流的长度集合之间的Jaccard相似度。
        """
        current_node = initiator_node
        current_length_set = set(properties["length"])

        print("dfadfasdfadsf")
        print(current_length_set)
        # 递归检查 initiator_node 的祖先节点是否有相同的边
        while current_node:
            existing_relationships = self.graph.match((current_node, responder_node), r_type=protocol)

            for rel in existing_relationships:
                existing_length_set = set(rel["length"])

                # 计算Jaccard相似度
                similarity = jaccard_similarity(current_length_set, existing_length_set)
                print(similarity)
                print(1 - length_threshold / len(current_length_set.union(existing_length_set)))

                # 如果相似度大于等于阈值（1 - length_threshold / (总长度集合大小)），认为流相似，跳过创建新边
                if similarity >= (1 - length_threshold / len(current_length_set.union(existing_length_set))):
                    self.skipped_edges_count += 1
                    return

            # 查找当前节点的前一个版本
            previous_version = self.graph.match((None, current_node), r_type="HAS_NEXT_VERSION").first()
            current_node = previous_version.start_node if previous_version else None

        # 如果没有发现冗余边，则创建新边
        flow_rel = Relationship(initiator_node, protocol, responder_node, **properties)
        self.graph.create(flow_rel)
        self.created_edges_count += 1

    def report(self):
        print(f"Created edges: {self.created_edges_count}")
        print(f"Skipped edges: {self.skipped_edges_count}")

# 使用REO和REO*示例
if __name__ == "__main__":
    node_versioner = OptimizedNodeVersioning()

    # Example of how to create relationships using REO
    initiator_node = node_versioner.update_or_create_node("192.168.1.1", True)
    responder_node = node_versioner.update_or_create_node("192.168.1.2", False)
    
    properties = {
        "start_time": "2023-09-13T12:00:00Z",
        "end_time": "2023-09-13T12:05:00Z",
        "protocol": "TCP",
        "length": {1000, 500, 200}  # 示例流的长度集合
    }

    # 设置阈值为 3，允许长度集合之间的最大差异为3个元素
    node_versioner.create_relationship_with_reo(initiator_node, responder_node, "TCP", properties, length_threshold=3)
    node_versioner.create_relationship_with_reo_star(initiator_node, responder_node, "TCP", properties, length_threshold=3)
    
    # 打印创建和跳过的边数
    node_versioner.report()