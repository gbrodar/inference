import os
import json
import logging
from tqdm import tqdm
from neo4j import GraphDatabase

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

from dotenv import load_dotenv
# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
# Neo4j connection
driver = GraphDatabase.driver("bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD))


def import_cwe_data(cwe_json_path: str):
    logging.info(f"Loading CWE data from: {cwe_json_path}")

    with open(cwe_json_path, "r", encoding="utf-8") as f:
        cwe_list = json.load(f)

    with driver.session() as session:
        for cwe in tqdm(cwe_list, desc="Importing CWEs"):
            cwe_id = f"CWE-{cwe.get('CWE-ID')}"
            props = {
                "id": cwe_id,
                "name": cwe.get("Name"),
                "abstraction": cwe.get("Weakness Abstraction"),
                "status": cwe.get("Status"),
                "description": cwe.get("Description"),
                "extended_description": cwe.get("Extended Description"),
                "related_weaknesses": cwe.get("Related Weaknesses"),
                "alternate_terms": cwe.get("Alternate Terms"),
                "modes_of_introduction": cwe.get("Modes Of Introduction"),
                "consequences": cwe.get("Common Consequences"),
                "potential_mitigations": cwe.get("Potential Mitigations"),
                "observed_examples": cwe.get("Observed Examples"),
                "taxonomy_mappings": cwe.get("Taxonomy Mappings"),
                "related_attack_patterns": cwe.get("Related Attack Patterns"),
            }

            # Create CWE node
            session.run("""
                MERGE (cwe:CWE {id: $id})
                SET cwe += $props
            """, id=cwe_id, props=props)

            # Link to CVE if problemType matches
            session.run("""
                MATCH (cwe:CWE {id: $cwe_id})
                MATCH (problem:ProblemType {cweId: $cwe_id})
                MERGE (problem)-[:HAS_CWE]->(cwe)
            """, cwe_id=cwe_id)

    logging.info("✅ CWE import completed.")

def create_cwe_relationships(cwe_json_path: str):
    logging.info(f"Creating CWE relationships from: {cwe_json_path}")

    with open(cwe_json_path, "r", encoding="utf-8") as f:
        cwe_list = json.load(f)

    with driver.session() as session:
        for cwe in tqdm(cwe_list, desc="Linking Related CWEs"):
            source_id = f"CWE-{cwe.get('CWE-ID')}"
            related_raw = cwe.get("Related Weaknesses", "")
            if not related_raw:
                continue

            related_parts = related_raw.split("::")

            for part in related_parts:
                tokens = part.strip().split(":")
                for i, token in enumerate(tokens):
                    if token == "CWE ID" and i + 1 < len(tokens):
                        related_cwe_id = f"CWE-{tokens[i + 1].strip()}"

                        session.run("""
                            MERGE (target:CWE {id: $target_id})
                            WITH target
                            MATCH (source:CWE {id: $source_id})
                            MERGE (source)-[:RELATED_TO]->(target)
                        """, {"source_id": source_id, "target_id": related_cwe_id})

    logging.info("✅ Related CWE relationships created.")

def main():
    cwe_json_path = os.path.join("..", "data", "cwe", "cwe_data.json")

    if not os.path.exists(cwe_json_path):
        logging.error(f"File not found: {cwe_json_path}")
        return

    import_cwe_data(cwe_json_path)
    create_cwe_relationships(cwe_json_path)


if __name__ == "__main__":
    main()
