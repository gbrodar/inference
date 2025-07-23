import os
import json
from neo4j import GraphDatabase
from tqdm import tqdm
from dotenv import load_dotenv

# Load environment variables for Neo4j credentials
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)


def mark_all_cves(tx):
    """Set the kev_exploited property to 'false' on all CVE nodes."""
    tx.run("MATCH (c:CVE) SET c.kev_exploited = 'false'")


def mark_exploited(tx, cve_id):
    """Set kev_exploited to 'true' for a specific CVE."""
    tx.run(
        "MATCH (c:CVE {cveId: $cve_id}) SET c.kev_exploited = 'true'",
        cve_id=cve_id,
    )


def update_kev_flags(file_path: str):
    """Update CVE nodes with KEV exploitation information."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    kev_cves = [
        entry.get("cveID")
        for entry in data.get("vulnerabilities", [])
        if entry.get("cveID")
    ]

    with driver.session() as session:
        session.write_transaction(mark_all_cves)
        for cve_id in tqdm(kev_cves, desc="\U0001F504 Updating CVEs", unit="cve"):
            session.write_transaction(mark_exploited, cve_id)


if __name__ == "__main__":
    update_kev_flags("../data/kev/known_exploited_vulnerabilities.json")
    print("\u2705 KEV exploited flags updated.")
