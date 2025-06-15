import os
from dotenv import load_dotenv
import numpy as np
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

# Load environment variables
load_dotenv()

# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=(os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))
)

# Embedding model - same as used during vectorization
model = SentenceTransformer("BAAI/bge-base-en-v1.5", device="cuda")

def _embed(text: str) -> np.ndarray:
    """Create an embedding for the given text."""
    return model.encode(text, convert_to_numpy=True)

def semantic_search(label: str, query: str, top_k: int = 5):
    """Perform semantic search over nodes of the provided label.

    Args:
        label: The Neo4j node label to search.
        query: Natural language query string.
        top_k: Number of results to return.

    Returns:
        List of dictionaries containing node id, name, description and similarity score.
    """
    query_vec = _embed(query)
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
            node_vec = np.array(record["embedding"])
            score = float(np.dot(query_vec, node_vec) / (np.linalg.norm(query_vec) * np.linalg.norm(node_vec)))
            matches.append({
                "id": record["id"],
                "name": record.get("name"),
                "description": record.get("description"),
                "score": score,
            })
    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches[:top_k]

if __name__ == "__main__":
    for result in semantic_search("CAPEC", "remote desktop exploitation", top_k=3):
        print(f"{result['score']:.3f} | {result['id']} | {result['name']}")
