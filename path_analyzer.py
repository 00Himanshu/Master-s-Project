import networkx as nx
from typing import List
from logger import Logger

class PathAnalyzer:
    def __init__(self):
        self.logger = Logger().get_logger()

    def analyze_attack_paths(self, graph: nx.Graph, start_node: str, start_access: str, target_node: str, target_access: str) -> List[List[str]]:
            start_node = f"{start_node}_{start_access}"
            target_node = f"{target_node}_{target_access}"
            """Find all possible attack paths between two nodes."""
            try:
                if start_node not in graph or target_node not in graph:
                    self.logger.warning("Node is not present in graph")
                    return []
                    
                return list(nx.shortest_path(graph, start_node, target_node))       
            except nx.NetworkXNoPath:
                self.logger.info("No paths exist between specified nodes")
                return []
            except Exception as e:
                self.logger.error(f"Path analysis failed: {e}")
                return []