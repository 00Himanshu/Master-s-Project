# XploitMap

**XploitMap** is a cybersecurity tool developed as a master's project to model and visualize attack graphs using the **Common Vulnerability Scoring System (CVSS)** framework. It integrates network scanning, vulnerability assessment, firewall rule analysis, and graph-based attack path modeling to help security professionals understand and mitigate potential attack vectors in a network.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [How It Works](#how-it-works)
- [CVSS Integration](#cvss-integration)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Project Overview
XploitMap aims to bridge the gap between raw network data and actionable security insights by generating attack graphs that model how vulnerabilities (CVEs) can be exploited across a network. Leveraging CVSS metrics, it simulates privilege escalation and lateral movement, providing a visual representation of attack paths using `networkx` and `pyvis`. The tool is designed for security analysts, penetration testers, and network administrators.

## Features
- **Network Scanning**: Uses `nmap` to discover hosts, operating systems, and services.
- **Firewall Rule Analysis**: Integrates with Sophos Firewall (XGS107, SFOS 21.0.0) to fetch and process rules.
- **CVE Data Retrieval**: Queries the NVD API to fetch vulnerability data based on asset CPEs or keywords.
- **Attack Graph Generation**: Builds directed graphs modeling attack paths using CVSS preconditions and postconditions.
- **Visualization**: Renders interactive graphs with `pyvis`, highlighting assets, CVEs, and attack paths.
- **Database Storage**: Stores assets, connections, and vulnerabilities in a MySQL database.
- **Command-Line Interface**: Offers a menu-driven interface for ease of use.
- **Web Interface (In Progress)**: A Flask-based frontend for browser-based interaction.

## Architecture
XploitMap is modular, with components interacting via a central database and graph-building logic:
- **Network Scanner (`netscan.py`)**: Discovers assets and feeds them into the database.
- **Firewall Manager (`firewall_connection.py`)**: Extracts network topology from Sophos Firewall rules.
- **CVE Searcher (`fetch_cve.py`)**: Fetches and processes CVSS data from NVD.
- **Database (`db.py`)**: Stores assets, connections, vulnerabilities, and CVSS metrics.
- **Graph Builder (`Graph_builder.py`)**: Constructs attack graphs using CVSS-driven logic.
- **Main Script (`main.py`)**: Orchestrates the workflow and visualizes results.
- **Web App (`app.py`)**: Provides a web-based interface (under development).
- **Logger (`logger.py`)**: Logs events to console and file for debugging.

## Prerequisites
- **Operating System**: Linux (recommended) or Windows with sudo/admin privileges for `nmap`.
- **Python**: 3.8+
- **Dependencies**:
  - `nmap` (install via `sudo apt install nmap` or equivalent)
  - Python libraries (see `requirements.txt` below)
- **MySQL**: A running MySQL server with a database configured.
- **Sophos Firewall**: Access to a Sophos Firewall (XGS107, SFOS 21.0.0) for rule fetching (optional).
- **Internet**: For NVD API access.

### `requirements.txt`
```
networkx
pyvis
mysql-connector-python
python-dotenv
requests
sophosfirewall-python
flask
python-nmap
```

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/00Himanshu/Master-s-Project.git
   cd Master-s-Project
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   sudo apt install nmap  # On Linux
   ```

3. **Set Up MySQL**:
   - Create a database (e.g., `xploitmap_db`).
   - Configure environment variables in a `.env` file:
     ```
     MYSQL_HOST=localhost
     MYSQL_USER=your_username
     MYSQL_PASSWORD=your_password
     MYSQL_DATABASE=xploitmap_db
     ```

4. **Sophos Firewall Configuration** (Optional):
   - Update `FIREWALL_IP`, `USERNAME`, `PASSWORD`, and `PORT` in `main.py` or `firewall_connection.py` if using a different firewall.

5. **Create Data Directory**:
   ```bash
   mkdir Data
   ```

## Usage
Run the command-line interface:
```bash
python main.py
```

### Menu Options
1. **Perform a Network Scan**: Scans a target IP range (e.g., `192.168.1.0/24`) and stores assets.
2. **Fetch Firewall Rules**: Connects to a Sophos Firewall to retrieve and process rules.
3. **Fetch CVE Data**: Queries NVD for vulnerabilities based on scanned assets.
4. **Build Attack Graph**: Constructs and visualizes an attack graph from a starting asset and access level.
5. **Find Shortest Path**: Analyzes and visualizes attack paths between two assets.
6. **Exit**: Closes the program.

### Example
```bash
# Start the tool
python main.py

# Choose option 1
Enter the target IP address or hostname: 192.168.1.0/24

# Choose option 3 to fetch CVEs
# Choose option 4
Enter the asset identifier: 1
Enter access level (LOW/HIGH): LOW
# Opens Network_graph.html in browser

# Choose option 5
Enter source asset identifier: 1
Enter 1 access level (LOW/HIGH): LOW
Enter target asset identifier: 27
Enter 27 access level (LOW/HIGH): HIGH
# Opens attack_path.html in browser
```

For the web interface (incomplete):
```bash
python app.py
# Visit http://localhost:5000 in your browser
```

## File Structure
```
Master-s-Project/
├── Data/                # Stores JSON outputs (e.g., scan_data.json, firewall_rules.json)
├── templates/           # HTML templates for Flask (e.g., graph.html)
├── firewall_connection.py  # Sophos Firewall integration
├── logger.py            # Logging utility
├── Graph_builder.py     # Attack graph construction
├── main.py              # Main CLI script
├── netscan.py           # Network scanning with nmap
├── app.py               # Flask web app (in progress)
├── db.py                # MySQL database management
├── fetch_cve.py         # CVE data retrieval from NVD
├── path_analyzer.py     # Path analysis utility
├── .env                 # Environment variables (not tracked)
└── README.md            # This file
```

## How It Works
1. **Asset Discovery**: `netscan.py` scans the network, identifying hosts, OSes, and services.
2. **Firewall Analysis**: `firewall_connection.py` fetches rules, mapping source/destination IPs and zones.
3. **Vulnerability Fetching**: `fetch_cve.py` queries NVD, extracting CVSS metrics for assets.
4. **Data Storage**: `db.py` stores assets, connections, and vulnerabilities in MySQL.
5. **Graph Building**: `Graph_builder.py` constructs a directed graph using CVSS preconditions (e.g., required access) and postconditions (e.g., gained access).
6. **Visualization**: `main.py` renders the graph and attack paths using `pyvis`.

## CVSS Integration
XploitMap leverages CVSS to enhance attack graph modeling:
- **Preconditions**: Attack Vector (connection type) and Privileges Required (access level) determine exploit feasibility.
- **Postconditions**: Impact metrics (Confidentiality, Integrity, Availability) infer gained access (HIGH/LOW).
- **Scoring**: CVSS base scores are stored but not yet used for path prioritization.
- **Example**: A CVE requiring LOW access over a NETWORK connection can escalate to HIGH if impacts are severe.

## Limitations
- **Incomplete Web Interface**: `app.py` is under development and lacks full functionality.
- **CVSS Utilization**: Scores aren’t used for path ranking; complexity is hardcoded as "LOW".
- **Sophos Dependency**: Firewall integration is specific to Sophos XGS107.
- **Error Handling**: Some components lack robust recovery from failures (e.g., NVD API timeouts).
- **Scalability**: Large networks may slow down graph generation and visualization.

## Future Enhancements
- **Full Web Interface**: Complete `app.py` with interactive graph controls.
- **CVSS Path Ranking**: Prioritize attack paths by cumulative CVSS score or complexity.
- **Broader Firewall Support**: Extend `firewall_connection.py` to other vendors (e.g., Cisco, Palo Alto).
- **Temporal Metrics**: Incorporate CVSS temporal scores for dynamic risk assessment.
- **Performance Optimization**: Parallelize graph building for large networks.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments
- **xAI**: For providing Grok, which assisted in code review and documentation.
- **NVD**: For the CVE database and API.
- **Sophos**: For firewall API documentation.
- **NetworkX & PyVis**: For graph modeling and visualization libraries.

---

This README provides a detailed overview of your project, its technical underpinnings, and instructions for use. It’s structured to be both user-friendly and academically rigorous. Let me know if you’d like to tweak any section—perhaps add more technical details, adjust the tone, or include specific academic references! What’s your next question or task related to the project?
