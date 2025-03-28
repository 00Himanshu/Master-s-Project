from sophosfirewall_python.firewallapi import SophosFirewall
from typing import Dict, List, Optional, Tuple
import json
from logger import Logger

class SophosFirewallManager:
    """
    Sophos Firewall Management Class
    
    This class provides methods to manage and configure Sophos Firewalls programmatically.

    Model and Firmware: XGS107 (SFOS 21.0.0 GA-Build169)
    """
    
    def __init__(self, firewall_ip: str = "172.16.16.16", username: str = "apiadmin", 
                 password: str = "API@admin1", port: int = 4444, verify_ssl: bool = False):

        self.logger = Logger().get_logger()
        self.firewall_ip = firewall_ip
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.firewall = None

    def connect(self) -> bool:
        """Establish connection to the firewall"""
        try:
            self.firewall = SophosFirewall(
                hostname=self.firewall_ip,
                username=self.username,
                password=self.password,
                port=self.port,
                verify=self.verify_ssl
            )
            login_response = self.firewall.login()
            self.logger.info("Successfully logged in: %s", login_response)
            return True
        except Exception as e:
            self.logger.error("Error connecting to firewall: %s", str(e))
            return False

    def disconnect(self) -> None:
        """Disconnect from the firewall"""
        if self.firewall:
            try:
                self.firewall.logout()
                self.logger.info("Logged out successfully")
            except Exception as e:
                self.logger.error("Error logging out: %s", str(e))
            finally:
                self.firewall = None

    def fetch_firewall_rules(self) -> Tuple[Optional[List], Optional[List], Optional[List], Optional[List]]:
        """
        Fetch firewall rules from Sophos Firewall
        
        Returns:
            tuple: (interfaces, ip_hosts, firewall_rules, ip_hostgroup) or (None, None, None, None) if failed
        """
        if not self.connect():
            return None, None, None, None

        try:
            # Fetch Network Configuration
            network_response = self.firewall.get_interface()
            rules_response = self.firewall.get_fw_rule()
            ip_host_response = self.firewall.get_ip_host()
            ip_hostgroup_response = self.firewall.get_ip_hostgroup()

            # Extract data from responses
            if ("IPHost" in ip_host_response["Response"] and 
                "Interface" in network_response["Response"] and 
                "FirewallRule" in rules_response["Response"] and 
                "IPHostGroup" in ip_hostgroup_response["Response"]):
                
                interfaces = network_response["Response"]["Interface"]
                ip_hosts = ip_host_response["Response"]["IPHost"]
                firewall_rules = rules_response["Response"]["FirewallRule"]
                ip_hostgroup = ip_hostgroup_response["Response"]["IPHostGroup"]
                with open("Data/interfaces.json", "w") as f:
                    json.dump(interfaces, f, indent=4)
                with open("Data/ip_hosts.json", "w") as f:
                    json.dump(ip_hosts, f, indent=4)
                with open("Data/firewall_rules.json", "w") as f:
                    json.dump(firewall_rules, f, indent=4)

                return interfaces, ip_hosts, firewall_rules, ip_hostgroup
            else:
                self.logger.warning("No firewall rules found in response")
                return None, None, None, None

        except Exception as e:
            self.logger.error("Error fetching firewall rules: %s", str(e))
            return None, None, None, None

        # finally:
        #     self.disconnect()

    def process_host(self, host: Dict) -> List[str]:
        """Process different host types and return list of IPs"""
        ips = []
        host_type = host["HostType"]
        
        if host_type == "IP":
            ip = host.get("IPAddress")
            if ip:
                ips.append(ip)
                
        elif host_type == "IPRange":
            start_ip = host.get("StartIPAddress")
            end_ip = host.get("EndIPAddress")
            if start_ip and end_ip:
                start_octets = start_ip.split(".")
                end_octets = end_ip.split(".")
                if start_octets[:-1] == end_octets[:-1]:  # Same subnet
                    start = int(start_octets[-1])
                    end = int(end_octets[-1]) + 1
                    ips.extend(
                        [".".join(start_octets[:-1] + [str(i)]) for i in range(start, end)]
                    )
                    
        elif host_type == "Network":
            ip = host.get("IPAddress")
            subnet = host.get("Subnet")
            if ip and subnet:
                ips.extend(self.get_zone_ip(ip, subnet))
                    
        elif host_type == "IPList":
            ip_list = host.get("ListOfIPAddresses")
            if ip_list:
                ips.extend(ip_list.split(","))

        return ips

    def get_zone_ip(self, ip: str, subnet: str) -> List[str]:
        """Get IP addresses for a given zone"""
        ips = []
        # Convert IP and subnet to lists of integers
        ip_octets = [int(octet) for octet in ip.split(".")]
        subnet_octets = [int(octet) for octet in subnet.split(".")]

        # Calculate network address using bitwise AND
        network = [ip_octets[i] & subnet_octets[i] for i in range(4)]

        # Calculate number of hosts by counting 0 bits in subnet mask
        host_bits = sum(bin(octet).count('0') for octet in subnet_octets)
        total_addresses = 2 ** host_bits

        current_ip = network.copy()
        for increment in range(1, total_addresses - 1):  # Exclude network and broadcast
            for pos in range(3, -1, -1):
                if subnet_octets[pos] != 255:
                    current_ip[pos] = network[pos] + (increment % 256)
                    increment //= 256
            ips.append(".".join(str(octet) for octet in current_ip))
        
        return ips

    def process_firewall_config(self, interfaces: List, hosts: List, hostgroup: List, rules: List) -> None:
        """Process firewall configuration"""
        data = []
        # Create mappings for easier lookup
        interface_map = {i["Name"]: i for i in interfaces}
        host_map = {h["Name"]: h for h in hosts}
        hostgroup_map = {hg["Name"]: hg for hg in hostgroup}
        
        # Process each firewall rule
        for rule in rules:
            if rule["Status"] != "Enable" or rule["PolicyType"] != "Network" or rule["NetworkPolicy"]["Action"] != "Accept":
                continue

            network_policy = rule["NetworkPolicy"]
            action = network_policy["Action"]
            rule_name = rule["Name"]

            # Get source zones
            source_zones = network_policy.get("SourceZones", {}).get("Zone", "Any")
            if isinstance(source_zones, str):
                source_zones = [source_zones]

            # Get destination zones
            dest_zones = network_policy["DestinationZones"].get("Zone", "Any")
            if isinstance(dest_zones, str):
                dest_zones = [dest_zones]

            if ("WAN" in source_zones and len(source_zones) == 1) or ("WAN" in dest_zones and len(dest_zones) == 1):
                    continue
            elif "WAN" in source_zones:
                source_zones.remove("WAN")

            elif "WAN" in dest_zones:
                dest_zones.remove("WAN")
                
            # Handle source networks
            source_networks = []
            source_ips = []
            if "SourceNetworks" in network_policy and "Network" in network_policy["SourceNetworks"]:
                networks = network_policy["SourceNetworks"]["Network"]
                network_list = networks if isinstance(networks, list) else [networks]
                for net in network_list:
                    source_networks.append(net)
                    if net in hostgroup_map:
                        hg_hosts = hostgroup_map[net]["HostList"]["Host"]
                        hg_host_list = hg_hosts if isinstance(hg_hosts, list) else [hg_hosts]
                        for host in hg_host_list:
                            if host in host_map:
                                source_ips.extend(self.process_host(host_map[host]))
                    elif net in host_map:
                        source_ips.extend(self.process_host(host_map[net]))
            else:
                for zone in source_zones:
                    if zone in interface_map:
                        zone_ip = interface_map[zone].get("IPAddress")
                        zone_subnet = interface_map[zone].get("Netmask")
                        if zone_ip and zone_subnet and zone_ip != "null":
                            zone_ips = self.get_zone_ip(zone_ip, zone_subnet)
                            source_ips.extend(zone_ips)
                            
            # Handle destination networks
            destination_networks = []
            destination_ips = []
            if "DestinationNetworks" in network_policy and "Network" in network_policy["DestinationNetworks"]:
                networks = network_policy["DestinationNetworks"]["Network"]
                network_list = networks if isinstance(networks, list) else [networks]
                for net in network_list:
                    destination_networks.append(net)
                    if net in hostgroup_map:
                        hg_hosts = hostgroup_map[net]["HostList"]["Host"]
                        hg_host_list = hg_hosts if isinstance(hg_hosts, list) else [hg_hosts]
                        for host in hg_host_list:
                            if host in host_map:
                                destination_ips.extend(self.process_host(host_map[host]))
                    elif net in host_map:
                        destination_ips.extend(self.process_host(host_map[net]))
            else:
                for zone in dest_zones:
                    if zone in interface_map:
                        zone_ip = interface_map[zone].get("IPAddress")
                        zone_subnet = interface_map[zone].get("Netmask")
                        if zone_ip and zone_subnet and zone_ip != "null":
                            zone_ips = self.get_zone_ip(zone_ip, zone_subnet)
                            destination_ips.extend(zone_ips)

            data.append({
                "source_zone": source_zones,
                "source_ip": source_ips,
                "source_network": source_networks,
                "destination_zone": dest_zones,
                "destination_networks": destination_networks,
                "destination_ip": destination_ips,
                "action": action,
                "rule_name": rule_name,
                "status": rule["Status"]
            })

        return data

    def run(self) -> None:
        """Fetch and process firewall rules in one operation"""
        interfaces, hosts, rules, hostgroup = self.fetch_firewall_rules()
        if all([interfaces, hosts, rules, hostgroup]):
            rules = self.process_firewall_config(interfaces, hosts, hostgroup, rules)
            return rules
        else:
            self.logger.error("Failed to fetch firewall rules")

if __name__ == "__main__":
    # Configuration
    FIREWALL_IP = "172.16.16.16"
    USERNAME = "apiadmin"
    PASSWORD = "API@admin1"
    PORT = 4444
    VERIFY_SSL = False

    # Create firewall manager instance with custom configuration
    firewall_mgr = SophosFirewallManager(
        firewall_ip=FIREWALL_IP,
        username=USERNAME,
        password=PASSWORD,
        port=PORT,
        verify_ssl=VERIFY_SSL
    )
    # Fetch and process rules
    rule = firewall_mgr.run()