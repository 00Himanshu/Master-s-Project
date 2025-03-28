import networkx as nx
from logger import Logger  # Assuming this is a custom module
import json
from typing import Optional, Tuple, List, Set, Dict
from collections import deque

class GraphBuilder:
    def __init__(self, json_data: str):
        self.logger = Logger().get_logger()
        self.logger.info('GraphBuilder initialized')
        self.G = nx.DiGraph()
        self._data = json_data  # Parse JSON data
        self._escalated_assets = set()  # Track assets escalated to HIGH

    def initial_conditions(self, asset_id: str, access_level: str) -> nx.DiGraph:
        """Initialize the graph with starting asset and access level from JSON."""
        try:
            self.logger.info(f'Initializing conditions for asset: {asset_id}, access_level: {access_level}')

            asset = next((a for a in self._data['assets'] if a['asset_id'] == asset_id), None)
            if not asset:
                self.logger.error(f"Asset {asset_id} not found in JSON data")
                return None
            
            # Add the initial OS-level node
            node_id = f"{asset_id}_{access_level}"
            self.G.add_node(node_id,
                            asset=asset['asset'],
                            version=asset['asset_version'],
                            ip=asset['host_ip'],
                            mac=asset['host_mac'],
                            cpe=asset['asset_cpe'])
            
            self.logger.debug(f'Added initial node: {node_id}')
            return self.exploit_neighbours(asset_id, access_level)
        
        except Exception as e:
            self.logger.error(f"Error in initial_conditions: {e}")
            raise

    def escalate_privileges(self, asset_id: str, access_level: str) -> Tuple[str, str]:
        """Attempt privilege escalation on a target asset using JSON vulnerabilities."""
        if asset_id in self._escalated_assets:
            self.logger.debug(f"Skipping escalation for {asset_id}: already escalated to HIGH")
            return asset_id, "HIGH"

        try:
            self.logger.info(f'Attempting privilege escalation on {asset_id} ({access_level})')
            asset = next((a for a in self._data['assets'] if a['asset_id'] == asset_id), None)
            if not asset:
                return asset_id, access_level

            # Check OS and service vulnerabilities for escalation to HIGH
            vulns = [
                    {**v, "asset": asset["asset"], "source": "OS"} for v in asset.get("vulnerabilities", [])
                ] + [
                    {**v, "asset": s["service"], "source": "SERVICE"} for s in asset.get("services", []) for v in s.get("vulnerabilities", [])
                ]
            
            escalations = [
                vuln for vuln in vulns
                if vuln['postconditions']['gained_access'] == 'HIGH'
                and (vuln['preconditions']['required_access'] in [access_level, 'NONE'])]

            if not escalations:
                self.logger.debug(f'No escalation paths found for {asset_id}')
                return asset_id, access_level

            # Add CVE nodes and escalated node
            new_access = "HIGH"
            target_node = f"{asset_id}_{new_access}"
            self.G.add_node(target_node,
                            asset=asset['asset'],
                            version=asset['asset_version'],
                            ip=asset['host_ip'],
                            mac=asset['host_mac'],
                            cpe=asset['asset_cpe'],
                            is_service=False)

            for vuln in escalations:
                cve_node = f"{vuln['cve_id']}_{asset_id}"
                self.G.add_node(cve_node,
                                cve_score=vuln['cve_score'],
                                asset=asset['asset'])
                
                self.G.add_edge(f"{asset_id}_{access_level}", cve_node, connection="LOCAL")
                self.G.add_edge(cve_node, target_node, connection="LOCAL")
                self.logger.info(f"Escalated via {cve_node} to {new_access}")

            self._escalated_assets.add(asset_id)
            return asset_id, new_access

        except Exception as e:
            self.logger.error(f"Escalation failed for {asset_id}: {e}")
            return asset_id, access_level

    def find_neighbours(self, asset_id: str) -> List[Dict]:
        """Find directly connected assets from JSON connections."""
        try:
            return [
                conn for conn in self._data.get('connections', [])
                if conn['source_asset'] == asset_id
            ]
        except Exception as e:
            self.logger.error(f"Neighbor lookup failed for {asset_id}: {e}")
            return []

    def exploit_neighbours(self, asset_id: str, access_level: str) -> nx.DiGraph:
        """Iteratively explore attack paths through network neighbors using DFS."""
        visited: Set[Tuple[str, str]] = set()
        stack = [(asset_id, access_level)]

        while stack:
            current_asset, current_access = stack.pop()
            node_key = (current_asset, current_access)

            if node_key in visited:
                self.logger.debug(f"Skipping visited node: {node_key}")
                continue
            visited.add(node_key)

            # Attempt privilege escalation
            if current_access != 'HIGH':
             esc_asset, esc_access = self.escalate_privileges(current_asset, current_access)

            if esc_access != current_access:
                stack.append((esc_asset, esc_access))

            # Explore neighbors
            neighbors = self.find_neighbours(current_asset)
            for neighbor in neighbors:
                target_id = neighbor['destination_asset']
                conn_type = neighbor['connection_type']
                target_asset = next((a for a in self._data['assets'] if a['asset_id'] == target_id), None)
                if not target_asset:
                    continue

                # Combine OS and service vulnerabilities
                vulns = [
                    {**v, "asset": target_asset["asset"], "source": "OS"} for v in target_asset.get("vulnerabilities", [])
                ] + [
                    {**v, "asset": s["service"], "source": "SERVICE"} for s in target_asset.get("services", []) for v in s.get("vulnerabilities", [])
                ]

                for vuln in vulns:
                    if conn_type == "NETWORK" and vuln['preconditions']['connection_type'] not in ['NETWORK'] and vuln['preconditions']['required_access'] != 'None':
                        continue

                    if conn_type == "ADJACENT_NETWORK" and vuln['preconditions']['connection_type'] not in ['NETWORK', 'ADJACENT_NETWORK'] and vuln['preconditions']['required_access'] != 'None':
                        continue

                    target_node = f"{target_id}_{vuln['postconditions']['gained_access']}"

                    self.G.add_node(target_node,
                                    asset=target_asset['asset'],
                                    version=target_asset['asset_version'],
                                    ip=target_asset['host_ip'],
                                    mac=target_asset['host_mac'],
                                    cpe=target_asset['asset_cpe'])
                    
                    self._add_exploit_path(current_asset, current_access, target_id, vuln, target_node, conn_type)
                    stack.append((target_id, vuln['postconditions']['gained_access']))
        return self.G

    def _add_exploit_path(self, source_id: str, source_access: str, target_id: str, vuln: Dict, target_node: str, conn_type: str):
        """Add vulnerability path to the graph."""
        cve_node = f"{vuln['cve_id']}_{target_id}"
        self.G.add_node(cve_node,
                        cve_score=vuln['cve_score'],
                        asset=vuln.get('asset', 'unknown'))
        self.G.add_edge(f"{source_id}_{source_access}", cve_node, connection=conn_type)
        self.G.add_edge(cve_node, target_node, connection=conn_type)
        self.logger.debug(f"Added path: {source_id}_{source_access} -> {cve_node} -> {target_node}")

    def analyze_attack_paths(self, start_node: str, target_node: str) -> List[List[str]]:
        """Find all possible attack paths between two nodes."""
        try:
            if start_node not in self.G or target_node not in self.G:
                self.logger.warning("Missing nodes in graph")
                return []
            return list(nx.all_simple_paths(self.G, start_node, target_node))
        except nx.NetworkXNoPath:
            self.logger.info("No paths exist between specified nodes")
            return []
        except Exception as e:
            self.logger.error(f"Path analysis failed: {e}")
            return []

if __name__ == "__main__":
    # Example JSON data
    json_data = '''
    {
      "assets": [
        {
          "asset_id": "1",
          "asset": "Microsoft Windows 10 1607 - 11 23H2",
          "asset_version": "10",
          "host_ip": "172.16.16.17",
          "host_mac": "",
          "asset_cpe": "cpe:2.3:o:microsoft:windows_10",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2020-12345",
              "cve_score": 7.8,
              "attack_complexity": "LOW",
              "preconditions": {
                "required_access": "LOW",
                "connection_type": "LOCAL"
              },
              "postconditions": {
                "gained_access": "LOW"
              }
            },
            {
              "cve_id": "CVE-2020-54321",
              "cve_score": 9.8,
              "preconditions": {
                "required_access": "HIGH",
                "connection_type": "NETWORK"
              },
              "postconditions": {
                "gained_access": "LOW"
              }
            }
          ],
          "services": [
            {
              "service": "RDP",
              "port": 3389,
              "version": "3.1.1",
              "cpe": "cpe:2.3:a:microsoft:rdp:3.1.1",
              "vulnerabilities": [
                {
                  "cve_id": "CVE-2020-12345",
                  "cve_score": 7.8,
                  "attack_complexity": "LOW",
                  "preconditions": {
                    "required_access": "LOW",
                    "connection_type": "LOCAL"
                  },
                  "postconditions": {
                    "gained_access": "LOW"
                  }
                }
              ]
            },
            {
              "service": "SMB",
              "port": 445,
              "version": "3.1.1",
              "cpe": "cpe:2.3:a:microsoft:smb:3.1.1",
              "vulnerabilities": [
                {
                  "cve_id": "CVE-2020-54321",
                  "cve_score": 9.8,
                  "preconditions": {
                    "required_access": "HIGH",
                    "connection_type": "NETWORK"
                  },
                  "postconditions": {
                    "gained_access": "LOW"
                  }
                }
              ]
            }
          ]
        },
        {
          "asset_id": "27",
          "asset": "Linux 4.15 - 5.19",
          "asset_version": "4.X",
          "host_ip": "192.168.30.2",
          "host_mac": "00:0C:29:1C:40:ED",
          "asset_cpe": "cpe:2.3:o:linux:linux_kernel:4",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2020-5426",
              "cve_score": 9.8,
              "preconditions": {
                "required_access": "HIGH",
                "connection_type": "NETWORK"
              },
              "postconditions": {
                "gained_access": "LOW"
              }
            }
          ],
          "services": [
            {
              "service": "SSH",
              "port": 22,
              "version": "3.1.1",
              "cpe": "cpe:2.3:a:linux:ssh:3.1.1",
              "vulnerabilities": [
                {
                  "cve_id": "CVE-2020-5426",
                  "cve_score": 9.8,
                  "preconditions": {
                    "required_access": "HIGH",
                    "connection_type": "NETWORK"
                  },
                  "postconditions": {
                    "gained_access": "LOW"
                  }
                }
              ]
            }
          ]
        }
      ],
      "connections": [
        {
          "source_asset": "1",
          "destination_asset": "27",
          "connection_type": "NETWORK"
        }
      ]
    }
    '''

    analyzer = GraphBuilder(json_data)
    asset_id = '1'
    access_level = "LOW"
    graph = analyzer.initial_conditions(asset_id, access_level)
    for node in graph.nodes(data=True):
        print(json.dumps(node, indent=4))