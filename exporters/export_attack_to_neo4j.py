import json
import os
from stix2 import parse
from tqdm import tqdm
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# ✅ Correct Neo4j connection using basic_auth
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=basic_auth(NEO4J_USERNAME, NEO4J_PASSWORD)
)

# Load STIX data
def load_attack_bundle(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return [parse(obj, allow_custom=True) for obj in data['objects']]

# Create STIX node in Neo4j
def create_attack_object(tx, obj):
    stix_id = obj.get('id')
    name = obj.get('name', '')
    description = obj.get('description', '')
    created = str(obj.get('created', ''))  # 🔧 Convert to str
    modified = str(obj.get('modified', ''))  # 🔧 Convert to str
    labels = obj.get('labels', [])
    type_ = obj.get('type', 'unknown').replace('-', '_').upper()

    tx.run(f"""
        MERGE (n:{type_} {{id: $stix_id}})
        SET n.name = $name,
            n.description = $description,
            n.created = $created,
            n.modified = $modified,
            n.labels = $labels
    """, stix_id=stix_id, name=name, description=description,
         created=created, modified=modified, labels=labels)

# Create relationships between STIX nodes
def create_attack_relationship(tx, rel):
    source_id = rel.source_ref
    target_id = rel.target_ref
    rel_type = rel.relationship_type.upper()

    tx.run("""
        MATCH (a {id: $source_id})
        MATCH (b {id: $target_id})
        MERGE (a)-[r:ATTACK_REL {type: $rel_type}]->(b)
    """, source_id=source_id, target_id=target_id, rel_type=rel_type)

# Run full import
def import_attack_bundle(stix_objects):
    with driver.session() as session:
        for obj in tqdm(stix_objects, desc="🧱 Creating STIX nodes"):
            if obj['type'] != 'relationship':
                session.execute_write(create_attack_object, obj)

        for obj in tqdm(stix_objects, desc="🔗 Creating STIX relationships"):
            if obj['type'] == 'relationship':
                session.execute_write(create_attack_relationship, obj)

# Entry point
if __name__ == "__main__":
    path = "../data/enterprise-attack/enterprise-attack.json"  # adjust path as needed
    print(f"📦 Loading ATT&CK STIX bundle from {path}")
    stix_objects = load_attack_bundle(path)
    import_attack_bundle(stix_objects)
    print("✅ ATT&CK STIX import complete.")
