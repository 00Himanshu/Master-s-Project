from pyvis.network import Network
import networkx as nx
import json
from Graph_builder import GraphBuilder
from path_analyzer import PathAnalyzer
from logger import Logger
from netscan import NetworkScanner
from firewall_connection import SophosFirewallManager
from fetch_cve import CVESearcher
from cve2mitre import CVE2Mitre
from db import Database

def visualize_graph(graph, filename):
    """Visualize network graph with PyVis"""
    net = Network(
        height="940px", width="100%",
        bgcolor="#1a1a1a", font_color="white",
        directed=True, notebook=False
    )
    
    # Add nodes with styling
    for node in graph.nodes(data=True):
        new_node = node[0]
        props = {
            "title": str(node[1]),
            "color": "#32CD32" if new_node.startswith("CVE") else "#FF4500",
            "shape": "box" if new_node.startswith("CVE") else "dot",
            "size": 20 if new_node.startswith("CVE") else 25
        }
        net.add_node(new_node, **props)
    
    # Add edges with styling
    for edge in graph.edges(data=True):
        net.add_edge(edge[0], edge[1], title=str(edge[2]), color="#888888", width=1)
    
    # Configure physics for better layout
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "springLength": 100,
          "springConstant": 0.02
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      },
      "interaction": {
        "navigationButtons": true
      }
    }
    """)
    
    net.show(filename, notebook=False)
    #webbrowser.open(filename)

def visualize_attack_path(graph, path, filename):
    """Highlight specific path in network visualization"""
    net = Network(
        height="940px", width="100%",
        bgcolor="#1a1a1a", font_color="white",
        directed=True, notebook=False
    )
    
    path_edges = list(zip(path[:-1], path[1:]))

    
    # Add all nodes
    for node in graph.nodes(data=True):
        new_node = node[0]
        props = {
            "title": str(node[1]),
            "color": "#32CD32" if new_node.startswith("CVE") else "#FF4500",
            "size": 30 if new_node.startswith("CVE") else 20,
            "shape": "box" if new_node.startswith("CVE") else "dot"
        }
        net.add_node(new_node, **props)

    # Add edges with highlighting
    for edge in graph.edges(data=True):
        edge_props = {
            "color": "#FF0000" if (edge[0], edge[1]) in path_edges else "#888888",
            "width": 3 if (edge[0], edge[1]) in path_edges else 1
        }
        net.add_edge(edge[0], edge[1], title=str(edge[2]), **edge_props)
    
    # Configure physics for better layout
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "springLength": 100,
          "springConstant": 0.02
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      },
      "interaction": {
        "navigationButtons": true
      }
    }
    """)

    net.show(filename, notebook=False)
    #webbrowser.open(filename)

def main():
    logger = Logger().get_logger()
    logger.info('Starting main function')
    
    # Initialize components
    db = Database()
    G = nx.DiGraph()

    while True:
        print("\nXploitMap v1.0")
        print("1. Perform a network scan")
        print("2. Fetch firewall rules")
        print("3. Fetch CVE DATA")
        print("4. Build Attack Graph")
        print("5. Find Shortest path to target asset")
        print("6. Exit")

        option = input("Enter an option (1-6): ").strip()
#-------------------------------------------------------------------------------------------------------------------------------------------
        if option == "1":
            netscan = NetworkScanner()
            assets=[]
            target = input("Enter the target IP address or hostname: ").strip()
            asset_info=netscan.run(target)
            # with open("Data/scan_data.json", "r") as f:
            #     asset_info = json.load(f)

            for scan_data in asset_info:
                host_ip = scan_data['ip']
                host_mac = scan_data['mac']
                os=scan_data['os']["name"]
                os_version=scan_data['os']["version"]
                os_cpe=scan_data['os']["cpe"]

                asset_id=db.create_asset(asset_type=os, asset_version=os_version, host_ip=host_ip, asset_port= None, host_mac=host_mac, asset_cpe=os_cpe)
                if asset_id:
                    assets.append(asset_id)

                for port in scan_data['ports']:
                    port_num = port['port']
                    port_service = port['service']
                    port_version = port['version']
                    port_cpe = port['cpe']
                    asset_id = db.create_asset(asset_type=port_service, asset_version=port_version, host_ip=host_ip, asset_port= port_num, host_mac=host_mac, asset_cpe=port_cpe)
                    if asset_id:
                        assets.append(asset_id)

                print("assest id:", assets)
                dst_assets = assets
                for src_asset in assets:
                    for dst_asset in dst_assets:
                        if src_asset != dst_asset:
                            db.create_connection(src_asset, dst_asset, "ADJACENT_NETWORK")
#-------------------------------------------------------------------------------------------------------------------------------------------
        elif option == "2":
            FIREWALL_IP = "172.16.16.16"
            USERNAME = "apiadmin"
            PASSWORD = "API@admin1"
            PORT = 4444
            VERIFY_SSL = False  # Set to True if using valid SSL certificate
            firewall_manager = SophosFirewallManager(
                firewall_ip=FIREWALL_IP,
                username=USERNAME,
                password=PASSWORD,
                port=PORT,
                verify_ssl=VERIFY_SSL
            )

            rules = firewall_manager.run()
            logger.info(f'Firewall rules fetched')
            # with open("firewall_rules.json", "r") as f:
            #     rules = json.load(f)
            
            try:
                database= db.db_connect()
                cursor = database.cursor(dictionary=True)

                for rule in rules:
                    source_ip = rule["source_ip"]
                    destination_ip = rule["destination_ip"]
                    source_ips = tuple(source_ip)  # ('172.16.16.17',)
                    destination_ips = tuple(destination_ip)  # ('192.168.40.2', '192.168.30.2')
                    connection_type = "NETWORK"

                    source_placeholders = ','.join(['%s'] * len(source_ips))  
                    source_query = f"SELECT asset_id FROM assets WHERE host_ip IN ({source_placeholders}) AND asset_port IS NULL"
                    cursor.execute(source_query, source_ips)
                    source_results = cursor.fetchall()

                    # Query for destination IPs
                    dest_placeholders = ','.join(['%s'] * len(destination_ips))
                    dest_query = f"SELECT asset_id FROM assets WHERE host_ip IN ({dest_placeholders}) AND asset_port IS NULL"
                    cursor.execute(dest_query, destination_ips)                    
                    destination_results = cursor.fetchall()

                    for source in source_results:
                        for destination in destination_results:
                            db.create_connection(source["asset_id"], destination["asset_id"], connection_type)
                            logger.info(f'Firewall rule inserted: {source} -> {destination}')
            except Exception as e:
                database.rollback()
                logger.error(f"Error inserting firewall rules: {e}")
            finally:
                cursor.close()


        elif option == "3":
            cve_searcher = CVESearcher()
            # cve2mitre = CVE2Mitre()
            cve_searcher.process_assets()
            # cve2mitre.fetch_mapping()
            logger.info(f'Fetched CVE DATA')
#-------------------------------------------------------------------------------------------------------------------------------------------
        elif option == "4":
            database = db.db_connect()
            cursor = database.cursor(dictionary=True)

            cursor.execute("""
                        SELECT asset_id, asset_type, asset_version, host_ip, host_mac, asset_cpe, asset_port
                        FROM assets
                    """)
            assets_raw = cursor.fetchall()

            # Fetch connections
            cursor.execute("""
                SELECT source_asset, destination_asset, connection_type
                FROM connections
            """)
            connections = cursor.fetchall()

            # Fetch vulnerabilities with preconditions and postconditions
            cursor.execute("""
                SELECT v.asset_type, v.cve_id, v.cve_score,
                    p.required_access, p.connection_type,
                    pc.gained_access
                FROM vulnerability v
                LEFT JOIN precondition p ON v.cve_id = p.cve_id
                LEFT JOIN postcondition pc ON v.cve_id = pc.cve_id
            """)
            vulnerabilities_raw = cursor.fetchall()

            # Organize assets into OS and services
            assets_dict = {}
            for asset in assets_raw:
                asset_id = asset['asset_id']
                if asset['asset_port'] is None:  # OS-level asset
                    assets_dict[asset_id] = {
                        'asset_id': str(asset_id),
                        'asset': asset['asset_type'],
                        'asset_version': asset['asset_version'] or '',
                        'host_ip': asset['host_ip'],
                        'host_mac': asset['host_mac'] or '',
                        'asset_cpe': asset['asset_cpe'] or '',
                        'vulnerabilities': [],
                        'services': []
                    }
                else:  # Service-level asset
                    # Find the parent OS asset by host_ip
                    parent_asset = next((a for a in assets_dict.values() if a['host_ip'] == asset['host_ip']), None)
                    if parent_asset:
                        parent_asset['services'].append({
                            'service': asset['asset_type'],
                            'port': asset['asset_port'],
                            'version': asset['asset_version'] or '',
                            'cpe': asset['asset_cpe'] or '',
                            'vulnerabilities': []
                        })

            # Map vulnerabilities to assets and services
            for vuln in vulnerabilities_raw:
                # Find matching OS assets
                for asset in assets_dict.values():
                    if asset['asset'] == vuln['asset_type']:
                        asset['vulnerabilities'].append({
                            'cve_id': vuln['cve_id'],
                            'cve_score': float(vuln['cve_score']),
                            'attack_complexity': 'LOW',  # Placeholder, as not in DB
                            'preconditions': {
                                'required_access': vuln['required_access'] or 'NONE',
                                'connection_type': vuln['connection_type'] or 'NETWORK'
                            },
                            'postconditions': {
                                'gained_access': vuln['gained_access'] or 'LOW'
                            }
                        })
                    # Find matching services
                    for service in asset['services']:
                        if service['service'] == vuln['asset_type']:
                            service['vulnerabilities'].append({
                                'cve_id': vuln['cve_id'],
                                'cve_score': float(vuln['cve_score']),
                                'attack_complexity': 'LOW',  # Placeholder
                                'preconditions': {
                                    'required_access': vuln['required_access'] or 'NONE',
                                    'connection_type': vuln['connection_type'] or 'NETWORK'
                                },
                                'postconditions': {
                                    'gained_access': vuln['gained_access'] or 'LOW'
                                }
                            })

            # Structure the final JSON
            result = {
                'assets': list(assets_dict.values()),
                'connections': [
                    {
                        'source_asset': str(conn['source_asset']),
                        'destination_asset': str(conn['destination_asset']),
                        'connection_type': conn['connection_type']
                    } for conn in connections
                ]
            }
            # with open("Data/attack_graph.json", "w") as f:
            #     json.dump(result, f, indent=4)

            graph_builder = GraphBuilder(result)
            asset = input("Enter the asset identifier: ").strip()
            access_level = input("Enter access level (LOW/HIGH): ").strip().upper()
            
            if access_level not in ["LOW", "HIGH"]:
                print("Invalid access level. Please enter LOW or HIGH.")
                logger.error(f'Invalid access level: {access_level}')
                continue
            logger.info(f'Setting initial conditions - Asset: {asset}, Access: {access_level}')
            graph = graph_builder.initial_conditions(asset, access_level)

            G.update(graph)
            logger.info('Graph updated with initial conditions')

            with open("Data/nodes.json", "w") as f:
                json.dump(list(G.nodes(data=True)), f)

            with open("Data/edges.json", "w") as f:
                json.dump(list(G.edges(data=True)), f)

            visualize_graph(G, "Network_graph.html")
#-------------------------------------------------------------------------------------------------------------------------------------------
        elif option == "5":
            path_analyzer = PathAnalyzer()
            if not G.nodes():
                print("Graph not initialized! Use option 5 first.")
                logger.error('Shortest path requested on empty graph')
                continue
                
            src_asset = input("Enter source asset identifier: ").strip()
            src_access = input(f"Enter {src_asset} access level (LOW/HIGH): ").strip().upper()
            target_asset = input("Enter target asset identifier: ").strip()
            target_access = input(f"Enter {target_asset} access level (LOW/HIGH): ").strip().upper()

            logger.info(f'Finding path: {src_asset}({src_access}) -> {target_asset}({target_access})')
            
            try:
                path = path_analyzer.analyze_attack_paths(
                    G, src_asset, src_access, 
                    target_asset, target_access
                )
                
                if not path:
                    print("No viable attack path exists!")
                    logger.info('No attack path found')
                    continue

                #print(f"Optimal attack path: {' -> '.join(path)}")
                visualize_attack_path(G, path, "attack_path.html")

            except KeyError as e:
                print(f"Invalid asset in path: {e}")
                logger.error(f'Invalid asset in path calculation: {e}')

        elif option == "6":
            print("Exiting XploitMap...")
            logger.info('User initiated program exit')
            break

        else:
            print("Invalid option. Please enter 1-7.")
            logger.warning(f'Invalid menu option selected: {option}')

if __name__ == "__main__":
    main()