import os
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

# === Query node data ===
def fetch_nodes(label, fields):
    with driver.session() as session:
        result = session.run(
            f"""
            MATCH (n:{label})
            RETURN n.id AS id, {", ".join([f"n.{f} AS {f}" for f in fields])}
            """
        )
        return [record.data() for record in result]

# === Store embedding ===
def store_embedding(label, node_id, embedding):
    with driver.session() as session:
        session.run(
            f"""
            MATCH (n:{label} {{id: $node_id}})
            SET n.embedding = $embedding
            """,
            node_id=node_id,
            embedding=embedding
        )

# === Generate vector for node content ===
def embed_text(text):
    return model.encode(text, convert_to_numpy=True).tolist()

# === Run vectorization for a label ===
def vectorize_label(label, fields):
    print(f"🚀 Vectorizing {label} nodes...")
    nodes = fetch_nodes(label, fields)
    for node in tqdm(nodes, desc=f"🔢 Embedding {label}", unit="node"):
        text = " ".join(str(node.get(f, "") or "") for f in fields)
        if text.strip():
            try:
                embedding = embed_text(text)
                store_embedding(label, node["id"], embedding)
            except Exception as e:
                print(f"[❌] Failed to embed {label} {node['id']}: {e}")

# === Entry Point ===
if __name__ == "__main__":
    vectorize_label("CAPEC", ["name", "description", "prerequisites", "consequences", "executionFlow",
                              "mitigations"])
    vectorize_label("ATTACK_PATTERN", ["name", "description"])
    print("✅ Embedding complete for CAPEC and ATTACK_PATTERN nodes.")
