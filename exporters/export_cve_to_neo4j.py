import os
import json
import logging
from tqdm import tqdm
from neo4j import GraphDatabase

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
    try:
        #print(f"Processing CVE JSON: keys={list(cve_json.keys())}")
        cve_id = cve_json.get('cveMetadata', {}).get('cveId')
        if not cve_id:
            raise ValueError(f"Missing cveMetadata.cveId. Content was: {cve_json}")

        with driver.session() as session:
            #print(f"Creating CVE node for {cve_id}")
            session.execute_write(create_cve_node, cve_json.get('cveMetadata', {}))

            containers = cve_json.get('containers', {})
            #print(f"Containers found: {list(containers.keys())}")
            for container_type, container_content in containers.items():
                #print(f"Processing container: {container_type}")

                if isinstance(container_content, dict):
                    container_list = [container_content]
                elif isinstance(container_content, list):
                    container_list = container_content
                else:
                    print(f"⚠️ Unexpected container content type: {type(container_content).__name__}")
                    continue

                for container_data in container_list:
                    if not isinstance(container_data, dict):
                        print(f"⚠️ Skipping non-dict item inside container {container_type}: {container_data}")
                        continue

                    session.execute_write(create_container_node, cve_id, container_type)

                    safe_iterate(session, cve_id, container_type, container_data.get('metrics', []), create_metric_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('references', []),
                                 create_reference_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('affected', []),
                                 create_product_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('descriptions', []),
                                 create_description_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('problemTypes', []),
                                 create_problem_type_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('configurations', []),
                                 create_configuration_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('impacts', []), create_impact_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('solutions', []),
                                 create_solution_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('exploits', []),
                                 create_exploit_node)
                    safe_iterate(session, cve_id, container_type, container_data.get('workarounds', []),
                                 create_workaround_node)



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

def create_cve_node(tx, cve_metadata):
    if not isinstance(cve_metadata, dict):
        return
    query = """
    MERGE (c:CVE {cveId: $cveId})
    ON CREATE SET
        c.state = $state,
        c.assignerOrgId = $assignerOrgId,
        c.assignerShortName = $assignerShortName,
        c.dateReserved = $dateReserved,
        c.datePublished = $datePublished,
        c.dateUpdated = $dateUpdated
    """
    tx.run(query,
           cveId=cve_metadata.get('cveId'),
           state=cve_metadata.get('state'),
           assignerOrgId=cve_metadata.get('assignerOrgId'),
           assignerShortName=cve_metadata.get('assignerShortName'),
           dateReserved=cve_metadata.get('dateReserved'),
           datePublished=cve_metadata.get('datePublished'),
           dateUpdated=cve_metadata.get('dateUpdated')
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

def import_cve_data(directory, driver):

    cve_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('CVE') and file.endswith('.json'):
                cve_files.append(os.path.join(root, file))

    for cve_file in tqdm(cve_files, desc="Importing CVE files", unit="file"):
        import_cve_file(cve_file, driver)

# --- Main ---

if __name__ == "__main__":
    #cve_directory = './data/cve/2024'  # Directory containing CVE JSON files
    cve_directory = './data/cve/cvelistV5-main/cves/2024'  # Directory containing CVE JSON files
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Neo4j678!@"

    driver = GraphDatabase.driver(uri, auth=(user, password))

    create_constraint(driver)
    import_cve_data(cve_directory, driver)

    driver.close()

    print("✅ CVE import completed successfully.")
