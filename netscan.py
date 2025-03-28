import nmap
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from logger import Logger

class NetworkScanner:
    def __init__(self):
        """Initialize the NetworkScanner with Nmap PortScanner."""
        self.nm = nmap.PortScanner()
        self.logger = Logger().get_logger()

    def scan(self, network_range):
        """Perform an Nmap scan on the specified network range."""
        self.logger.info(f"Starting network scan on {network_range}...")
        try:
            self.nm.scan(hosts=network_range, arguments='-T4 -A -sS --script=vulners.nse')
            self.logger.info("Scan completed.")
        except nmap.PortScannerError as e:
            self.logger.error(f"Scan failed: {e}. Try running with sudo.")
            sys.exit(1)

    def scan_network(self, network, max_workers=10):
        """Discover active hosts and scan them in parallel using ThreadPoolExecutor."""
        self.nm.scan(hosts=network, arguments='-sn')  # Ping scan to find active hosts
        active_hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
        self.logger.info(f"Found {len(active_hosts)} active hosts.")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan, host): host
                for host in active_hosts
            }
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    future.result()  # Wait for scan to complete
                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")

    def compile_results(self):
        """Compile scan results and perform vulnerability assessment."""
        results = []

        for host in self.nm.all_hosts():
            with open("Data/scan_result.json", "w") as f:
                f.write(str(self.nm[host]))

            if self.nm[host].state() != 'up':
                continue
            
            host_info = {
                'hostname': self.nm[host].hostname() or '',
                'ip': host,
                'mac': self.nm[host]['addresses'].get('mac', ''),
                'os': {
                    'family': '',
                    'name': '',
                    'version': '',
                    'accuracy': '',
                    'cpe': ''
                },
                'ports': []
            }

            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                os_match = self.nm[host]['osmatch'][0]
                host_info['os'] = {
                    'family': os_match.get('osclass', [{}])[0].get('osfamily', ''),
                    'name': os_match['name'],
                    'version': os_match.get('osclass', [{}])[0].get('osgen', ''),
                    'accuracy': os_match.get('accuracy', ''),
                    'cpe': os_match.get('osclass', [{}])[0].get('cpe', '')[0].replace('/', '2.3:')
                }

            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': service['state'],
                        'service': service['name'] or '',
                        'version': service['version'] or '',
                        'cpe': service.get('cpe', '').replace('/', '2.3:')
                    }
                    host_info['ports'].append(port_info)

            results.append(host_info)

        return results

    def run(self, network_range):
        """Run the network scan and compile results, then display them."""
        self.scan_network(network_range)
        results = self.compile_results()
        self.logger.info("Scan completed")
        return results

if __name__ == "__main__":
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    scanner = NetworkScanner()

    with open("Data/result.json", "w") as f:
        f.write(scanner.run(network_range))