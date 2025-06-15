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

def semantic_search(label: str | None = None, query: str = "", top_k: int = 5):
    """Perform semantic search over nodes.

    Args:
        label: Optional Neo4j node label to search. If ``None`` all labels are searched.
        query: Natural language query string.
        top_k: Number of results to return.

    Returns:
        List of dictionaries containing the node label, all node properties and
        the similarity score.
    """
    query_vec = _embed(query)
    with driver.session() as session:
        match_clause = f"MATCH (n:{label})" if label else "MATCH (n)"
        result = session.run(
            f"""
            {match_clause}
            WHERE n.embedding IS NOT NULL
            RETURN labels(n)[0] AS label, n AS node
            """
        )
        matches = []
        for record in result:
            node = record["node"]
            node_vec = np.array(node["embedding"])
            score = float(
                np.dot(query_vec, node_vec)
                / (np.linalg.norm(query_vec) * np.linalg.norm(node_vec))
            )
            node_dict = dict(node)
            matches.append({"label": record.get("label"), **node_dict, "score": score})
    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches[:top_k]

if __name__ == "__main__":
    print("Label-specific search (CAPEC):")
    for result in semantic_search("CAPEC", "remote desktop exploitation", top_k=3):
        print(f"{result['score']:.3f} | {result['id']} | {result['name']}")

    print("\nLabel-agnostic search:")
    for result in semantic_search(query="remote desktop exploitation", top_k=3):
        print(
            f"{result['label']} | {result['score']:.3f} | {result['id']} | {result['name']}"
        )
