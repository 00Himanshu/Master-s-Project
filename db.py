from logger import Logger
import re
import mysql.connector as sql
from dotenv import load_dotenv
import os

load_dotenv()

class Database:
    def __init__(self):
        self.logger = Logger().get_logger()

    @staticmethod
    def is_valid_ip(ip):
        """Validates an IP address format."""
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return bool(pattern.match(ip)) and all(0 <= int(num) < 256 for num in ip.split('.'))

    def db_connect(self):
        """Establishes a connection to the database using environment variables."""
        try:
            db = sql.connect(
                host=os.getenv("MYSQL_HOST"),
                user=os.getenv("MYSQL_USER"),
                password=os.getenv("MYSQL_PASSWORD"),
                database=os.getenv("MYSQL_DATABASE")
            )
            self.logger.info("Connected to database")
            return db
        except sql.Error as e:
            self.logger.error(f"Database connection error: {e}")
            return None

    def create_table_if_not_exists(self, connection):
        """Creates necessary tables in the database if they do not already exist."""
        queries = [
            """
            CREATE TABLE IF NOT EXISTS assets (
                asset_id INT AUTO_INCREMENT PRIMARY KEY,
                asset_type VARCHAR(255) NOT NULL,
                asset_version VARCHAR(255),
                host_ip VARCHAR(45),
                asset_port INT,
                host_mac VARCHAR(255),
                asset_cpe VARCHAR(255)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS connections (
                source_asset VARCHAR(255) NOT NULL,
                destination_asset VARCHAR(255) NOT NULL,
                connection_type VARCHAR(255) NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS precondition (
                required_access VARCHAR(255) DEFAULT NULL,
                connection_type VARCHAR(255) DEFAULT NULL,
                cve_id VARCHAR(255) NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS postcondition (
                cve_id VARCHAR(255) NOT NULL,
                gained_access VARCHAR(255) NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS vulnerability (
                asset_type VARCHAR(255) NOT NULL,
                cve_id VARCHAR(255) NOT NULL,
                cve_score VARCHAR(255) DEFAULT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS cve2mitre (
                cve_id VARCHAR(255) NOT NULL,
                capability_description VARCHAR(255) NOT NULL,
                mapping_type VARCHAR(255) NOT NULL,
                mitre_id VARCHAR(255) NOT NULL,
                attack_name VARCHAR(255) NOT NULL
            );
            """
        ]
        
        cursor = connection.cursor()
        try:
            for query in queries:
                cursor.execute(query)
            connection.commit()
            self.logger.info("Tables checked/created successfully.")
        except sql.Error as e:
            connection.rollback()
            self.logger.error(f"Error creating tables: {e}")
        finally:
            cursor.close()

    def create_asset(self, asset_type, asset_version, host_ip, asset_port, host_mac, asset_cpe):
        """Inserts or retrieves an asset record from the database."""
        database = self.db_connect()
        if not database:
            return

        try:
            self.create_table_if_not_exists(database)
            cursor = database.cursor()
            cursor.execute("""
                INSERT INTO assets (asset_type, asset_version, host_ip, asset_port, host_mac, asset_cpe)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE asset_id=LAST_INSERT_ID(asset_id)
            """, (asset_type, asset_version, host_ip, asset_port, host_mac, asset_cpe))
            asset_id = cursor.lastrowid
            database.commit()
            self.logger.info(f"Inserted/Retrieved asset ID: {asset_id}")
            return asset_id
        except sql.Error as e:
            database.rollback()
            self.logger.error(f"Error inserting asset: {e}")
        finally:
            cursor.close()
            database.close()

    def create_connection(self, source, destination, connection_type):
        """Inserts a connection record into the database."""

        database = self.db_connect()

        if not database:
            return

        try:
            cursor = database.cursor()
            cursor.execute("""
                INSERT INTO connections (source_asset, destination_asset, connection_type)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE source_asset=source_asset
            """, (source, destination, connection_type))
            database.commit()
            self.logger.info(f"Inserted/Retrieved connection: {source} -> {destination} ({connection_type})")
        except sql.Error as e:
            database.rollback()
            self.logger.error(f"Error inserting connection: {e}")
        finally:
            cursor.close()
            database.close()

    def create_vulnerability(self, asset_type, cve_id, cve_score):
        """Inserts a vulnerability record into the database."""
        database = self.db_connect()
        if not database:
            return

        try:
            cursor = database.cursor()
            cursor.execute("""
                INSERT INTO vulnerability (asset_type, cve_id, cve_score)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE cve_score=VALUES(cve_score)
            """, (asset_type, cve_id, cve_score))
            database.commit()
            self.logger.info(f"Inserted/Retrieved vulnerability: {asset_type} -> {cve_id} ({cve_score})")
        except sql.Error as e:
            database.rollback()
            self.logger.error(f"Error inserting vulnerability: {e}")
        finally:
            cursor.close()
            database.close()

    def create_cve2mitre(self, cve_id, capability_description, mapping_type, mitre_id, attack_name):
        """Inserts a CVE-to-MITRE mapping into the database."""
        database = self.db_connect()
        if not database:
            return

        try:
            cursor = database.cursor()
            cursor.execute("""
                INSERT INTO cve2mitre (cve_id, capability_description, mapping_type, mitre_id, attack_name)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE capability_description=VALUES(capability_description)
            """, (cve_id, capability_description, mapping_type, mitre_id, attack_name))
            database.commit()
            self.logger.info(f"Inserted/Retrieved CVE to MITRE mapping: {cve_id} -> {mitre_id} ({attack_name})")
        except sql.Error as e:
            database.rollback()
            self.logger.error(f"Error inserting CVE to MITRE mapping: {e}")
        finally:
            cursor.close()
            database.close()
    
    def get_asset(self):
        "Get assets details from the Database"
        database = self.db_connect()
        if not database:
            return

        try:
            cursor = database.cursor(dictionary=True)
            cursor.execute("SELECT * FROM assets")
            assets = cursor.fetchall()
            return assets
        except sql.Error as e:
            self.logger.error(f"Error fetching assets: {e}")
    
    def get_connections(self):
        "Get connections details from the Database"
        database = self.db_connect()
        if not database:
            return

        try:
            cursor = database.cursor(dictionary=True)
            cursor.execute("SELECT * FROM connections")
            connections = cursor.fetchall()
            return connections
        except sql.Error as e:
            self.logger.error(f"Error fetching connections: {e}")