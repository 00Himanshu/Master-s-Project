import os
import mysql.connector as sql
from dotenv import load_dotenv
from db import Database
import requests
from typing import Dict, Optional, List
from logger import Logger
from contextlib import contextmanager

load_dotenv()

class CVESearcher:
    """
    Handles CVE searches using asset data and stores results in the database.
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    def __init__(self):
        """Initialize logger and database connection."""
        self.logger = Logger().get_logger()
        self.database = Database()
        self._db_conn= self.database.db_connect()
        self._cursor = self._db_conn.cursor(dictionary=True) 
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def _make_request(self, url: str) -> Optional[Dict]:
        """Make HTTP request with error handling."""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"HTTP request failed: {e}")
            return None

    def search_cve_keyword(self, asset: str, exact_match: bool = True) -> Optional[Dict]:
        """Search CVEs by keyword with optional exact match."""
        param = f"keywordSearch={asset}"
        if exact_match:
            param += "&keywordExactMatch"
        
        url = f"{self.BASE_URL}?{param}"
        data = self._make_request(url)
        
        if not data and exact_match:
            self.logger.info("No exact match found. Falling back to general search.")
            return self.search_cve_keyword(asset, exact_match=False)
        
        return data

    def search_cve_cpe(self, cpe: str) -> Optional[Dict]:
        """Search CVEs by CPE name."""
        url = f"{self.BASE_URL}?cpeName={cpe}"
        return self._make_request(url)

    def process_assets(self) -> None:
        """Process assets from database and search for CVEs."""
        try:
            
                self._cursor.execute("SELECT * FROM assets")
                assets = self._cursor.fetchall()
                for asset in assets:
                    self.logger.info(f"Processing asset: {asset}")
                    data = self._search_asset_cve(asset)
                    if data:
                        self.transform_cve_data(data, asset['asset_type'])
        except Exception as e:
            self.logger.error(f"Error processing assets: {e}")
            raise

    def _search_asset_cve(self, asset: Dict) -> Optional[Dict]:
        """Determine and execute appropriate CVE search method."""
        asset_type = asset['asset_type']
        asset_cpe = asset['asset_cpe']
        
        if asset_cpe:
            self.logger.info("Using CPE search")
            data = self.search_cve_cpe(asset_cpe)
            if not data:
                self.logger.info("CPE search failed, falling back to keyword search")
                data = self.search_cve_keyword(asset_type)
            return data
        elif asset_type:
            data = self.search_cve_keyword(asset_type)
            return data
        else:
            self.logger.info("Using keyword search")
            return self.search_cve_keyword(asset_type)

    def _extract_cvss_metrics(self, metrics: Dict) -> Dict:
        """Extract CVSS metrics from different versions."""
        cvss_data = {}
        
        # CVSS v3.1
        if metrics.get("cvssMetricV31"):
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_data = {
                "version": "3.1",
                "attack_vector": data.get("attackVector", ""),
                "attack_complexity": data.get("attackComplexity", ""),
                "privileges_required": data.get("privilegesRequired", ""),
                "confidentiality": data.get("confidentialityImpact", ""),
                "integrity": data.get("integrityImpact", ""),
                "availability": data.get("availabilityImpact", ""),
                "score": str(data.get("baseScore", ""))
            }
        
        # CVSS v3.0
        elif metrics.get("cvssMetricV3"):
            data = metrics["cvssMetricV3"]
            cvss_data = {
                "version": "3.0",
                "attack_vector": data.get("attackVector", ""),
                "attack_complexity": data.get("attackComplexity", ""),
                "privileges_required": data.get("privilegesRequired", ""),
                "confidentiality": data.get("confidentialityImpact", ""),
                "integrity": data.get("integrityImpact", ""),
                "availability": data.get("availabilityImpact", ""),
                "score": str(data.get("baseScore", ""))
            }
        
        # CVSS v2.0
        elif metrics.get("cvssMetricV2"):
            data = metrics["cvssMetricV2"][0]["cvssData"]
            privileges_map = {"MULTIPLE": "HIGH", "SINGLE": "LOW"}
            cvss_data = {
                "version": "2.0",
                "attack_vector": data.get("accessVector", ""),
                "attack_complexity": data.get("accessComplexity", ""),
                "privileges_required": privileges_map.get(data.get("authentication", ""), ""),
                "confidentiality": data.get("confidentialityImpact", ""),
                "integrity": data.get("integrityImpact", ""),
                "availability": data.get("availabilityImpact", ""),
                "score": str(data.get("baseScore", ""))
            }
        
        # Determine gained access level
        if cvss_data:
            impacts = [cvss_data["confidentiality"], cvss_data["integrity"], cvss_data["availability"]]
            cvss_data["gained_access"] = "HIGH" if all(i in ("HIGH", "COMPLETE") for i in impacts) else "LOW"
        
        return cvss_data

    def transform_cve_data(self, data: Dict, asset_type: str) -> None:
        """Transform and store CVE data in the database."""
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            
            cvss = self._extract_cvss_metrics(metrics)
            if not cvss:
                self.logger.warning(f"No CVSS metrics found for CVE: {cve_id}")
                continue

            try:
                required_access=cvss["privileges_required"]
                connection_type=cvss["attack_vector"]
                cve_id=cve_id
                self._cursor.execute("INSERT INTO precondition (required_access, connection_type, cve_id) VALUES (%s, %s, %s)", (required_access, connection_type, cve_id))
                self._db_conn.commit()
                gained_access=cvss["gained_access"]
                self._cursor.execute("INSERT INTO postcondition (cve_id, gained_access) VALUES (%s, %s)", (cve_id, gained_access))
                self._db_conn.commit()
                asset_type=asset_type
                cve_score=cvss["score"]
                self._cursor.execute("INSERT INTO vulnerability (asset_type, cve_id, cve_score) VALUES (%s, %s, %s)", (asset_type, cve_id, cve_score))
                self._db_conn.commit()
            except Exception as e:
                self.logger.error(f"Error storing CVE {cve_id} data: {e}")

    def __del__(self):
        """Clean up resources."""
        self.session.close()


if __name__ == "__main__":
    try:
        searcher = CVESearcher()
        searcher.process_assets()
    except Exception as e:
        logger = Logger().get_logger()
        logger.error(f"Application error: {e}")