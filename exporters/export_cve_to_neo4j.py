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


def safe_iterate(session, cve_id, container_type, data, function_to_call):
    if isinstance(data, dict):
        function_to_call(session, cve_id, container_type, data)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                function_to_call(session, cve_id, container_type, item)

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

def create_container_node(tx, cve_id, container_type):
    if not cve_id or not container_type:
        return
    query = """
    MERGE (ct:Container {cveId: $cveId, type: $type})
    MERGE (c:CVE {cveId: $cveId})
    MERGE (c)-[:HAS_CONTAINER]->(ct)
    """
    tx.run(query, cveId=cve_id, type=container_type)

def create_metric_node(tx, cve_id, container_type, metric):
    if not isinstance(metric, dict):
        return
    cvss = metric.get('cvssV3_1') or metric.get('cvssV3_0')
    if not isinstance(cvss, dict):
        return
    vector_string = cvss.get('vectorString')
    if not vector_string:
        return  # We must have a vectorString to uniquely identify Metric

    query = """
    MERGE (m:Metric {vectorString: $vectorString})
    ON CREATE SET
        m.baseScore = $baseScore,
        m.baseSeverity = $baseSeverity,
        m.attackVector = $attackVector,
        m.attackComplexity = $attackComplexity,
        m.privilegesRequired = $privilegesRequired,
        m.userInteraction = $userInteraction,
        m.scope = $scope,
        m.confidentialityImpact = $confidentialityImpact,
        m.integrityImpact = $integrityImpact,
        m.availabilityImpact = $availabilityImpact,
        m.version = $version
    WITH m
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_METRIC]->(m)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           vectorString=vector_string,
           baseScore=cvss.get('baseScore'),
           baseSeverity=cvss.get('baseSeverity'),
           attackVector=cvss.get('attackVector'),
           attackComplexity=cvss.get('attackComplexity'),
           privilegesRequired=cvss.get('privilegesRequired'),
           userInteraction=cvss.get('userInteraction'),
           scope=cvss.get('scope'),
           confidentialityImpact=cvss.get('confidentialityImpact'),
           integrityImpact=cvss.get('integrityImpact'),
           availabilityImpact=cvss.get('availabilityImpact'),
           version=cvss.get('version')
    )

def create_reference_node(tx, cve_id, container_type, ref):
    if not isinstance(ref, dict):
        return
    url = ref.get('url')
    if not url:
        return

    query = """
    MERGE (r:Reference {url: $url})
    ON CREATE SET r.tags = $tags
    WITH r
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_REFERENCE]->(r)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           url=url,
           tags=ref.get('tags')
    )

def create_product_node(tx, cve_id, container_type, product):
    if not isinstance(product, dict):
        return
    vendor = product.get('vendor')
    product_name = product.get('product')
    if not vendor or not product_name:
        return

    query = """
    MERGE (p:Product {vendor: $vendor, product: $product})
    WITH p
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:AFFECTS_PRODUCT]->(p)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           vendor=vendor,
           product=product_name
    )

def create_description_node(tx, cve_id, container_type, desc):
    if not isinstance(desc, dict):
        return
    lang = desc.get('lang')
    value = desc.get('value')
    if not lang or not value:
        return

    query = """
    MERGE (d:Description {lang: $lang, value: $value})
    WITH d
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_DESCRIPTION]->(d)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           lang=lang,
           value=value
    )

def create_problem_type_node(tx, cve_id, container_type, problem):
    if not isinstance(problem, dict):
        return

    descriptions = problem.get('descriptions', [])
    for desc in descriptions:
        if not isinstance(desc, dict):
            continue
        cwe_id = desc.get('cweId')
        description = desc.get('description')

        # FIX: skip if no cweId
        if not cwe_id:
            continue

        query = """
        MERGE (p:ProblemType {cweId: $cweId, description: $description})
        WITH p
        MATCH (ct:Container {cveId: $cveId, type: $type})
        MERGE (ct)-[:HAS_PROBLEM_TYPE]->(p)
        """
        tx.run(query,
               cveId=cve_id,
               type=container_type,
               cweId=cwe_id,
               description=description
        )

def create_configuration_node(tx, cve_id, container_type, config):
    if not isinstance(config, dict):
        return

    description = config.get('description')

    # FIX: skip if no description
    if not description:
        return

    query = """
    MERGE (cfg:Configuration {description: $description})
    WITH cfg
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_CONFIGURATION]->(cfg)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           description=description
    )

def create_impact_node(tx, cve_id, container_type, impact):
    if not isinstance(impact, dict):
        return

    description = impact.get('description')

    # FIX: skip if no description
    if not description:
        return

    query = """
    MERGE (i:Impact {description: $description})
    WITH i
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_IMPACT]->(i)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           description=description
    )

def create_solution_node(tx, cve_id, container_type, solution):
    if not isinstance(solution, dict):
        return

    description = solution.get('description')

    # FIX: skip if no description
    if not description:
        return

    query = """
    MERGE (s:Solution {description: $description})
    WITH s
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_SOLUTION]->(s)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           description=description
    )


def create_exploit_node(tx, cve_id, container_type, exploit):
    if not isinstance(exploit, dict):
        return

    description = exploit.get('description')

    # FIX: skip if no description
    if not description:
        return

    query = """
    MERGE (e:Exploit {description: $description})
    WITH e
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_EXPLOIT]->(e)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           description=description
    )


def create_workaround_node(tx, cve_id, container_type, workaround):
    if not isinstance(workaround, dict):
        return

    description = workaround.get('description')

    # FIX: skip if no description
    if not description:
        return

    query = """
    MERGE (w:Workaround {description: $description})
    WITH w
    MATCH (ct:Container {cveId: $cveId, type: $type})
    MERGE (ct)-[:HAS_WORKAROUND]->(w)
    """
    tx.run(query,
           cveId=cve_id,
           type=container_type,
           description=description
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
