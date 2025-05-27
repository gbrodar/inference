import json
from neo4j import GraphDatabase
from tqdm import tqdm

from dotenv import load_dotenv

# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
# Neo4j connection
driver = GraphDatabase.driver("bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD))


def import_kev_entry(tx, kev):
    try:
        tx.run("""
            MERGE (k:KEV {cveId: $cveId})
            SET k.vendor = $vendor,
                k.product = $product,
                k.name = $name,
                k.description = $description,
                k.dateAdded = date($dateAdded),
                k.dueDate = date($dueDate),
                k.requiredAction = $requiredAction,
                k.notes = $notes,
                k.knownRansomwareCampaignUse = $ransomwareUse
        """,
        cveId=kev.get("cveID"),
        vendor=kev.get("vendorProject"),
        product=kev.get("product"),
        name=kev.get("vulnerabilityName"),
        description=kev.get("shortDescription"),
        dateAdded=kev.get("dateAdded"),
        dueDate=kev.get("dueDate"),
        requiredAction=kev.get("requiredAction"),
        notes=kev.get("notes"),
        ransomwareUse=kev.get("knownRansomwareCampaignUse"))

        # Link to CVE
        result = tx.run("MATCH (c:CVE {id: $cveId}) RETURN c", cveId=kev.get("cveID"))
        if result.single():
            tx.run("""
                MATCH (c:CVE {id: $cveId})
                MATCH (k:KEV {cveId: $cveId})
                MERGE (c)-[:IS_EXPLOITED_IN]->(k)
            """, cveId=kev.get("cveID"))
        else:
            print(f"[⚠️] CVE not found in graph: {kev.get('cveID')}")

        # Link to CWE nodes if they exist
        for cwe_id in kev.get("cwes", []):
            if cwe_id:
                result = tx.run("MATCH (w:CWE {id: $cweId}) RETURN w", cweId=cwe_id)
                if result.single():
                    tx.run("""
                        MATCH (k:KEV {cveId: $cveId})
                        MATCH (w:CWE {id: $cweId})
                        MERGE (k)-[:RELATED_TO]->(w)
                    """, cveId=kev.get("cveID"), cweId=cwe_id)
                else:
                    print(f"[⚠️] CWE not found: {cwe_id}")

    except Exception as e:
        print(f"[❌] Error processing {kev.get('cveID')}: {e}")

def load_kev_data(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    kev_entries = data.get("vulnerabilities", [])
    print(f"📦 Total KEV entries to import: {len(kev_entries)}")
    with driver.session() as session:
        for kev in tqdm(kev_entries, desc="🚀 Importing KEV entries", unit="entry"):
            session.write_transaction(import_kev_entry, kev)

if __name__ == "__main__":
    load_kev_data("../data/kev/known_exploited_vulnerabilities.json")
    print("✅ KEV import complete.")
