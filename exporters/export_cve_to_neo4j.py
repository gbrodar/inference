import os
import json
import logging
from tqdm import tqdm
from neo4j import GraphDatabase
import argparse

from dotenv import load_dotenv
# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


# --- Configure logging ---
log_dir = '../.log'
log_file = 'cve_import_errors.log'
log_path = os.path.join(log_dir, log_file)

os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=log_path,
    filemode='a',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Neo4j functions ---

def create_constraint(driver):
    with driver.session() as session:
        session.run("""
        CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
        FOR (c:CVE) REQUIRE c.cveId IS UNIQUE
        """)

def import_cve_file(file_path, driver):
    try:
        #print(f"Reading file: {file_path}")
        with open(file_path, 'r') as file:
            cve_json = json.load(file)

        #print(f"Top-level JSON type: {type(cve_json).__name__}")

        if isinstance(cve_json, list):
            for idx, item in enumerate(cve_json):
                #print(f"Processing item {idx} in list")
                if isinstance(item, dict):
                    process_cve(item, driver)
                else:
                    print(f"⚠️ Skipped non-dict item in list: {item}")
        elif isinstance(cve_json, dict):
            process_cve(cve_json, driver)
        else:
            print(f"⚠️ Unsupported JSON structure: {type(cve_json).__name__}")

    except Exception as e:
        error_message = f"❌ Error processing file {file_path}: {e}"
        print(error_message)
        logging.error(error_message)

def process_cve(cve_json, driver):
    """Extract relevant information from a CVE JSON blob and create the node."""
    try:
        meta = cve_json.get("cveMetadata", {})
        cve_id = meta.get("cveId")
        if not cve_id:
            raise ValueError("Missing cveMetadata.cveId")

        data = {
            "cveId": cve_id,
            "dateReserved": meta.get("dateReserved"),
            "datePublished": meta.get("datePublished"),
            # 'dateUpdated' or 'dateModified' may exist depending on the source
            "dateModified": meta.get("dateUpdated") or meta.get("dateModified"),
            "description": None,
            "vectorString": None,
            "baseScore": None,
            "baseSeverity": None,
        }

        containers = cve_json.get("containers", {})
        for container in containers.values():
            if isinstance(container, dict):
                container_list = [container]
            elif isinstance(container, list):
                container_list = container
            else:
                continue
            for item in container_list:
                if not isinstance(item, dict):
                    continue
                if data["description"] is None:
                    descs = item.get("descriptions")
                    if isinstance(descs, list) and descs:
                        data["description"] = descs[0].get("value")
                if data["vectorString"] is None:
                    metrics = item.get("metrics")
                    if isinstance(metrics, list) and metrics:
                        first_metric = metrics[0]
                        cvss = (
                            first_metric.get("cvssV3_1")
                            or first_metric.get("cvssV3_0")
                            or first_metric
                        )
                        if isinstance(cvss, dict):
                            data["vectorString"] = cvss.get("vectorString")
                            data["baseScore"] = cvss.get("baseScore")
                            data["baseSeverity"] = cvss.get("baseSeverity")
                if data["description"] and data["vectorString"]:
                    break
            if data["description"] and data["vectorString"]:
                break

        with driver.session() as session:
            session.execute_write(create_cve_node, data)

    except Exception as e:
        error_message = f"❌ Error inside process_cve: {e}"
        print(error_message)
        logging.error(error_message)



def create_cve_node(tx, data):
    query = """
    MERGE (c:CVE {cveId: $cveId})
    SET c.dateReserved = $dateReserved,
        c.datePublished = $datePublished,
        c.dateModified = $dateModified,
        c.description = $description,
        c.vectorString = $vectorString,
        c.baseScore = $baseScore,
        c.baseSeverity = $baseSeverity
    """
    tx.run(
        query,
        cveId=data.get("cveId"),
        dateReserved=data.get("dateReserved"),
        datePublished=data.get("datePublished"),
        dateModified=data.get("dateModified"),
        description=data.get("description"),
        vectorString=data.get("vectorString"),
        baseScore=data.get("baseScore"),
        baseSeverity=data.get("baseSeverity"),
    )

# --- Import multiple files ---
def import_cve_data(directory, driver, years=None):
    """Import CVE files from *directory* filtered by *years*.

    If years is None or contains "all" then all subdirectories are scanned.
    """
    cve_files = []

    if not years or "all" in years:
        search_dirs = [directory]
    else:
        search_dirs = [os.path.join(directory, y) for y in years]

    for search in search_dirs:
        print(f"🔍 Scanning directory: {search}")
        if not os.path.isdir(search):
            print(f"⚠️ Directory does not exist: {search}")
            continue
        for root, _, files in os.walk(search):
            for file in files:
                if file.startswith("CVE-") and file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    cve_files.append(full_path)

    if not cve_files:
        print("⚠️ No CVE files found. Check directory structure or path.")
        return

    print(f"✅ Found {len(cve_files)} CVE JSON files")

    # Now import each file
    for cve_file in tqdm(cve_files, desc="📦 Importing CVE files", unit="file"):
        try:
            import_cve_file(cve_file, driver)
        except Exception as e:
            print(f"[❌] Error importing {cve_file}: {e}")

# --- Main ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import CVE JSON files into Neo4j")
    parser.add_argument(
        "years",
        nargs="*",
        help="Years of CVEs to import (e.g. 2020 2021). Use 'all' or no argument to import everything.",
    )
    args = parser.parse_args()

    cve_directory = "../data/cve/cvelistV5-main/cves"
    uri = "bolt://localhost:7687"

    driver = GraphDatabase.driver(uri, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

    create_constraint(driver)
    import_cve_data(cve_directory, driver, years=args.years)

    driver.close()

    print("✅ CVE import completed successfully.")
