from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
import numpy as np
from dotenv import load_dotenv
import os

# Setup
load_dotenv()
driver = GraphDatabase.driver("bolt://localhost:7687", auth=(
    os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD")
))
model = SentenceTransformer("BAAI/bge-base-en-v1.5", device="cuda")

def embed_query(query):
    return model.encode(query, convert_to_numpy=True)

def find_closest_nodes(label, query_embedding, top_k=5):
    with driver.session() as session:
        result = session.run(
            f"""
            MATCH (n:{label})
            WHERE n.embedding IS NOT NULL
            RETURN n.id AS id, n.name AS name, n.description AS description, n.embedding AS embedding
            """
        )

        matches = []
        for record in result:
            node_embedding = np.array(record["embedding"])
            score = np.dot(query_embedding, node_embedding) / (
                np.linalg.norm(query_embedding) * np.linalg.norm(node_embedding)
            )
            matches.append({
                "id": record["id"],
                "name": record["name"],
                "description": record["description"],
                "score": float(score)
            })

        top_results = sorted(matches, key=lambda x: x["score"], reverse=True)[:top_k]

        # === Expand results with related nodes ===
        for node in top_results:
            expansion = session.run(
                """
                MATCH (n {id: $node_id})-[:USES_TTP]->(t:TTP)<-[:USES_TTP]-(related)
                RETURN t.external_id AS ttp_id, t.url AS ttp_url, 
                       labels(related)[0] AS related_label,
                       related.id AS related_id, related.name AS related_name
                """,
                node_id=node["id"]
            )
            node["related"] = [r.data() for r in expansion]

        return top_results


if __name__ == "__main__":
    query = "attacks involving remote desktop exploitation"
    q_vec = embed_query(query)

    results = find_closest_nodes("CAPEC", q_vec, top_k=5)
    for r in results:
        print(f"\n🔍 {r['score']:.3f} | {r['id']} | {r['name']}")
        for rel in r["related"]:
            print(f"    ↳ TTP: {rel['ttp_id']} | {rel['related_label']}: {rel['related_name']} ({rel['related_id']})")
