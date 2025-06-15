import os
import json
from collections import defaultdict
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
from dotenv import load_dotenv

# === Load environment variables ===
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# === Neo4j connection ===
driver = GraphDatabase.driver(
    "bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)

# === Load local embedding model (GPU) ===
model = SentenceTransformer("BAAI/bge-base-en-v1.5", device="cuda")

# === Load database schema ===
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "database_schema.json")

def load_schema(path=SCHEMA_PATH):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    fields = defaultdict(set)
    for entry in data:
        label = entry["nodeType"].strip(":`")
        prop = entry["propertyName"]
        if prop != "embedding":
            fields[label].add(prop)
    return {label: sorted(props) for label, props in fields.items()}

# Manual overrides for identifier fields per label
ID_FIELD_OVERRIDES = {
    "CVE": "cveId",
    "KEV": "cveId",
    "Container": "cveId",
    "Metric": "vectorString",
    "TTP": "external_id",
    "ProblemType": "cweId",
    "Reference": "url",
    "Product": "product",
    "Description": "value",
}

def guess_id_field(label, props):
    if label in ID_FIELD_OVERRIDES:
        return ID_FIELD_OVERRIDES[label]
    return "id" if "id" in props else props[0]

# === Query node data ===
def fetch_nodes(label, fields, id_field="id"):
    with driver.session() as session:
        if label == "CVE":
            result = session.run(
                f"""
                MATCH (n:CVE)-[:HAS_CONTAINER]->(:Container)-[:HAS_DESCRIPTION]->(d:Description)
                WITH n.{id_field} AS id, collect(d.value) AS descriptions
                RETURN id, descriptions
                """
            )
            return [record.data() for record in result]

        field_clause = ", ".join([f"n.{f} AS {f}" for f in fields])
        query = f"MATCH (n:{label}) RETURN n.{id_field} AS id"
        if field_clause:
            query += ", " + field_clause
        result = session.run(query)
        return [record.data() for record in result]

# === Store embedding ===
def store_embedding(label, node_id, embedding, id_field="id"):
    with driver.session() as session:
        session.run(
            f"""
            MATCH (n:{label} {{{id_field}: $node_id}})
            SET n.embedding = $embedding
            """,
            node_id=node_id,
            embedding=embedding
        )

# === Generate vector for node content ===
def embed_text(text):
    return model.encode(text, convert_to_numpy=True).tolist()

# === Run vectorization for a label ===
def vectorize_label(label, fields, id_field="id"):
    print(f"🚀 Vectorizing {label} nodes...")
    nodes = fetch_nodes(label, fields, id_field=id_field)
    for node in tqdm(nodes, desc=f"🔢 Embedding {label}", unit="node"):
        parts = []
        for f in fields:
            value = node.get(f)
            if not value:
                continue
            if isinstance(value, (list, tuple, set)):
                parts.extend(str(v) for v in value if v)
            elif isinstance(value, dict):
                parts.extend(str(v) for v in value.values() if v)
            else:
                parts.append(str(value))
        text = " ".join(parts)
        if text.strip():
            try:
                embedding = embed_text(text)
                store_embedding(label, node["id"], embedding, id_field=id_field)
            except Exception as e:
                print(f"[❌] Failed to embed {label} {node['id']}: {e}")

# === Entry Point ===
if __name__ == "__main__":
    schema = load_schema()

    # CVE descriptions are stored on related Description nodes
    if "CVE" in schema:
        schema["CVE"] = ["descriptions"]

    for label, props in schema.items():
        id_field = guess_id_field(label, props)
        fields = [p for p in props if p != "embedding"]
        if label != "CVE":
            fields = [f for f in fields if f != id_field] or [id_field]
        try:
            vectorize_label(label, fields, id_field=id_field)
        except Exception as e:
            print(f"[❌] Error processing {label}: {e}")

    print("✅ Embedding complete for all node types defined in schema.")
