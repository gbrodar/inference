import json
import re
import os
from tqdm import tqdm
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)

# Ensure CAPEC node uniqueness
def create_constraint():
    with driver.session() as session:
        session.run(
            """
            CREATE CONSTRAINT capec_id_unique IF NOT EXISTS
            FOR (c:CAPEC) REQUIRE c.id IS UNIQUE
            """
        )

# --- Utilities ---

def parse_list(value: str):
    """Return a list from a '::'-delimited string."""
    if not value:
        return []
    return [v.strip() for v in str(value).split("::") if v.strip()]


def parse_consequences(value: str):
    """Parse the consequences field into a list."""
    if not value:
        return []
    return [v.strip() for v in str(value).split("::") if v.strip()]


def clean_related_weaknesses(rw_string: str):
    """Extract CWE IDs from the related weaknesses field."""
    if not rw_string:
        return []
    ids = []
    for part in rw_string.split("::"):
        match = re.search(r"(\d+)", part)
        if match:
            ids.append(f"CWE-{match.group(1)}")
    return ids

def extract_capec_relationships(rap_string):
    if not rap_string:
        return []
    pattern = r"NATURE:(\w+):CAPEC ID:(\d+)"
    return [(f"CAPEC-{capec_id}", rel_type) for rel_type, capec_id in re.findall(pattern, rap_string)]

# --- Phase 1: Create CAPEC nodes ---

def create_capec_node(tx, entry):
    capec_raw_id = entry.get("ID") or entry.get("'ID")
    capec_id = f"CAPEC-{capec_raw_id}"

    props = {
        "id": capec_id,
        "name": entry.get("Name"),
        "abstraction": entry.get("Abstraction"),
        "description": entry.get("Description"),
        "likelihood": entry.get("Likelihood Of Attack"),
        "severity": entry.get("Typical Severity"),
        "execution_flow": parse_list(entry.get("Execution Flow")),
        "prerequisites": parse_list(entry.get("Prerequisites")),
        "resources_required": parse_list(entry.get("Resources Required")),
        "consequences": parse_consequences(entry.get("Consequences")),
    }

    tx.run(
        """
        MERGE (c:CAPEC {id: $id})
        SET c += $props
        """,
        id=capec_id,
        props=props,
    )

# --- Phase 2: Link relationships ---

def create_capec_relationships(tx, entry):
    capec_raw_id = entry.get("ID") or entry.get("'ID")
    capec_id = f"CAPEC-{capec_raw_id}"

    # Link to CWE nodes
    for cwe_id in clean_related_weaknesses(entry.get("Related Weaknesses", "")):
        result = tx.run("MATCH (w:CWE {id: $cwe_id}) RETURN w", cwe_id=cwe_id)
        if result.single():
            tx.run("""
                MATCH (c:CAPEC {id: $capec_id})
                MATCH (w:CWE {id: $cwe_id})
                MERGE (c)-[:RELATED_TO]->(w)
            """, capec_id=capec_id, cwe_id=cwe_id)
        else:
            print(f"[⚠️] Missing CWE {cwe_id} for {capec_id}")

    # Link to other CAPECs
    for related_id, rel_type in extract_capec_relationships(entry.get("Related Attack Patterns", "")):
        result = tx.run("MATCH (r:CAPEC {id: $related_id}) RETURN r", related_id=related_id)
        if result.single():
            rel = re.sub(r"[^A-Za-z0-9_]", "_", rel_type).upper()
            tx.run(
                f"""
                MATCH (c:CAPEC {{id: $capec_id}})
                MATCH (r:CAPEC {{id: $related_id}})
                MERGE (c)-[:{rel}]->(r)
                """,
                capec_id=capec_id,
                related_id=related_id,
            )
        else:
            print(f"[⚠️] Missing CAPEC {related_id} ({rel_type}) for {capec_id}")

# --- Combined Loader ---

def load_capec_data(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        capec_entries = json.load(f)

    print(f"📦 Total CAPEC entries: {len(capec_entries)}")

    # Phase 1: create nodes
    with driver.session() as session:
        for entry in tqdm(capec_entries, desc="🧱 Creating CAPEC nodes", unit="entry"):
            try:
                session.execute_write(create_capec_node, entry)
            except Exception as e:
                capec_id = entry.get("ID") or entry.get("'ID")
                print(f"[❌] Error creating CAPEC-{capec_id}: {e}")

    # Phase 2: create relationships
    with driver.session() as session:
        for entry in tqdm(capec_entries, desc="🔗 Creating CAPEC relationships", unit="entry"):
            try:
                session.execute_write(create_capec_relationships, entry)
            except Exception as e:
                capec_id = entry.get("ID") or entry.get("'ID")
                print(f"[❌] Error linking CAPEC-{capec_id}: {e}")

# Extract TTPs from taxonomy mappings
def extract_attack_taxonomy_ttps(taxonomy_string):
    if not taxonomy_string:
        return []
    mappings = []
    chunks = taxonomy_string.split("TAXONOMY NAME:")
    for chunk in chunks:
        if chunk.startswith("ATTACK"):
            match = re.search(r"ENTRY ID:(\d+)", chunk)
            if match:
                mappings.append(f"T{match.group(1)}")
    return mappings

# Create the link
def create_capec_ttp_link(tx, capec_id, external_id):
    tx.run("""
        MATCH (c:CAPEC {id: $capec_id})
        MATCH (t:TTP {external_id: $external_id})
        MERGE (c)-[:USES_TTP]->(t)
    """, capec_id=capec_id, external_id=external_id)

# Link pass
def link_capecs_to_ttps_via_taxonomy(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        capec_entries = json.load(f)

    with driver.session() as session:
        for entry in tqdm(capec_entries, desc="📎 Linking CAPECs via Taxonomy", unit="capec"):
            capec_raw_id = entry.get("ID") or entry.get("'ID")
            capec_id = f"CAPEC-{capec_raw_id}"
            taxonomy_string = entry.get("Taxonomy Mappings", "")

            for ttp_id in extract_attack_taxonomy_ttps(taxonomy_string):
                try:
                    session.execute_write(create_capec_ttp_link, capec_id, ttp_id)
                except Exception as e:
                    print(f"[❌] Failed to link {capec_id} to {ttp_id}: {e}")

if __name__ == "__main__":
    path_to_capec = "../data/capec/capec_data.json"
    create_constraint()
    load_capec_data(path_to_capec)
    link_capecs_to_ttps_via_taxonomy(path_to_capec)
    print("✅ CAPEC → TTP linking via Taxonomy complete.")
    print("✅ CAPEC import and relationship linking completed.")
