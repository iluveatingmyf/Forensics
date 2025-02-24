from py2neo import Graph, Node, Relationship
from datetime import datetime, timezone

# 将epoch时间戳转换为ISO时间格式
def epoch_to_datetime_string(epoch_timestamp):
    dt_object = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc)
    return dt_object.isoformat()

class NodeVersioning:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="neo4j"):
        self.graph = Graph(uri, auth=(user, password))
        self.nodes = {}  # 用于存储设备的最新版本 {(IP): (version_number, Node)}
        self.total_created_nodes = 0  # 记录创建的总点数量
        self.total_created_edges = 0  # 记录创建的总边数量
        self.skipped_edges = 0  # 记录由于冗余检测跳过的边
        
    
    def get_or_create_node(self, ip, is_initiator):
        """
        获取或创建设备节点，返回最新版本节点、版本号以及是否为新创建的标识符。
        如果节点不存在，创建版本为1的新节点；如果节点存在，查询数据库获取最新版本。
        """
        # 从数据库中查询该IP的设备节点，按版本号降序排列，获取最新版本
        query = f"MATCH (n:Device {{IP: '{ip}'}}) RETURN n ORDER BY n.version DESC LIMIT 1"
        result = self.graph.run(query).data()

        if not result:
            # 如果设备节点不存在，创建新版本1节点
            new_node = Node("Device", name=f"Device_{ip}_v1", IP=str(ip), version=1)
            self.graph.create(new_node)
            self.total_created_nodes += 1  # 记录创建的点
            self.nodes[ip] = (1, new_node)
            return new_node, 1, True  # True 表示新创建的节点
        else:
            # 如果设备节点存在，返回最新版本的节点和版本号
            latest_node = result[0]['n']
            latest_version = latest_node['version']
            self.nodes[ip] = (latest_version, latest_node)
            return latest_node, latest_version, False  # False 表示已有节点




    def has_redundant_edge(self, initiator_node, responder_node, flow_properties):
        """
        检查 initiator 节点和 responder 的历史版本（只考虑 10 秒内创建的版本）之间是否存在冗余边。
        冗余边判定条件：在时间窗口内（如 10 秒）相同设备之间的数据包长度集合完全一致。
        """
        time_window = 10.0  # 设定时间窗口，单位为秒
        current_flow_start_time = datetime.fromisoformat(flow_properties['start_time']).timestamp()

        # 初始化空列表来收集符合条件的历史边
        candidate_edges = []

        def collect_edges_for_initiator_responder(current_initiator_ip, current_responder_ip, current_flow_start_time, time_window):
            # 通过 IP 获取 initiator 的所有历史版本节点，按版本降序排列
            initiator_versions = self.graph.run(
                f"MATCH (n:Device {{IP: '{current_initiator_ip}'}}) RETURN n ORDER BY n.version DESC"
            ).data()
            #print(initiator_versions)

            # 通过 IP 获取 responder 的所有历史版本节点，按版本降序排列
            responder_versions = self.graph.run(
                f"MATCH (n:Device {{IP: '{current_responder_ip}'}}) RETURN n ORDER BY n.version DESC"
            ).data()
            #print(responder_versions)


            # 遍历 initiator 和 responder 的所有版本
            for initiator in initiator_versions:
                for responder in responder_versions:
                    # 查找 initiator_node 和当前版本的 responder_node 之间的所有边，忽略方向
                    query = f"""
                        MATCH (i:Device {{IP: '{initiator['n']['IP']}'}})-[r]-(r_node:Device {{IP: '{responder['n']['IP']}'}})
                        RETURN r
                    """
                    result = self.graph.run(query).data()

                    for rel in result:
                        relationship = rel['r']  # 关系对象
                        print(f"Found relationship: {relationship}")
                        rel_start_time = datetime.fromisoformat(relationship['start_time']).timestamp()
                        rel_lengths = set(relationship['length'])  # 获取边的长度集合

                        # 计算时间差并检查时间窗口
                        time_diff = float(current_flow_start_time) - rel_start_time
                        if 0 <= time_diff <= time_window and set(flow_properties['length']) == rel_lengths:
                            # 将符合条件的边添加到候选列表中
                            candidate_edges.append({
                                'initiator': initiator['n'],
                                'responder': responder['n'],
                                'start_time': rel_start_time,
                                'lengths': rel_lengths
                            })
                            print(f"Collected edge between {initiator['n']} and {responder['n']} with lengths {rel_lengths} and time_diff {time_diff}")

            return candidate_edges

        # 收集 10 秒内 initiator 和 responder 之间的所有历史版本的交互边
        candidate_edges = collect_edges_for_initiator_responder(initiator_node['IP'], responder_node['IP'], current_flow_start_time, time_window)
        print(candidate_edges)
        # 检查收集到的候选边是否存在冗余
        for edge in candidate_edges:
            if set(flow_properties['length']) == edge['lengths']:
                print(f"Redundant edge found between {edge['initiator']} and {edge['responder']} with lengths {edge['lengths']}")
                self.skipped_edges += 1  # 记录跳过的边
                return True  # 在时间窗口内且数据包长度集合一致，判定为冗余边

        print("No redundant edge found. Proceeding to create a new edge.")
        return False

    def update_version(self, node, ip):
        """
        将节点的版本加1，创建新版本节点，并创建 HAS_NEXT_VERSION 关系
        """
        latest_version = node['version']
        new_version = latest_version + 1
        new_node = Node("Device", name=f"Device_{ip}_v{new_version}", IP=str(ip), version=new_version)
        self.graph.create(new_node)
        self.total_created_nodes += 1  # 记录创建的点

        # 创建 HAS_NEXT_VERSION 边连接旧版本和新版本
        version_rel = Relationship(node, "HAS_NEXT_VERSION", new_node)
        self.graph.create(version_rel)
        self.total_created_edges += 1  # 记录创建的边


        # 更新最新版本
        self.nodes[ip] = (new_version, new_node)
        return new_node
