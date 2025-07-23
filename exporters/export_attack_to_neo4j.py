import json
import os
import re
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)


def create_constraint():
    """Ensure uniqueness of TTP nodes by ttp_id."""
    with driver.session() as session:
        session.run(
            """
            CREATE CONSTRAINT ttp_id_unique IF NOT EXISTS
            FOR (t:TTP) REQUIRE t.ttp_id IS UNIQUE
            """
        )


def create_ttp(tx, ttp_id, name, description, phases):
    tx.run(
        """
        MERGE (t:TTP {ttp_id: $ttp_id})
        SET t.name = $name,
            t.description = $description,
            t.phases = $phases
        """,
        ttp_id=ttp_id,
        name=name,
        description=description,
        phases=phases,
    )


def create_ttp_capec_link(tx, ttp_id, search):
    tx.run(
        """
        MATCH (t:TTP {ttp_id: $ttp_id})
        MATCH (c:CAPEC)
        WHERE any(m IN c.taxonomy_mappings WHERE m CONTAINS $search)
        MERGE (t)-[:RELATED_TO]->(c)
        """,
        ttp_id=ttp_id,
        search=search,
    )


def import_attack_ttps(json_path: str):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    with driver.session() as session:
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            name = obj.get("name", "")
            description = obj.get("description", "")

            # Extract phases from kill_chain_phases
            phases = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name")
                    if phase_name:
                        phases.append(phase_name)

            # Find the mitre-attack external_id
            ttp_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ttp_id = ref.get("external_id")
                    break

            if ttp_id:
                session.execute_write(
                    create_ttp,
                    ttp_id,
                    name,
                    description,
                    phases,
                )


def link_ttps_to_capecs():
    """Create relationships between TTP and CAPEC nodes using taxonomy mappings."""
    with driver.session() as session:
        result = session.run("MATCH (t:TTP) RETURN t.ttp_id AS id")
        for record in result:
            ttp_id = record["id"]
            base_match = re.match(r"T(\d{4})", ttp_id)
            if not base_match:
                continue
            search = f"ATTACK:ENTRY ID:{base_match.group(1)}"
            session.execute_write(create_ttp_capec_link, ttp_id, search)


def main():
    json_path = os.path.join("..", "data", "enterprise-attack", "enterprise-attack.json")
    print(f"Loading ATT&CK data from {json_path}")

    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)

    create_constraint()
    import_attack_ttps(json_path)
    link_ttps_to_capecs()
    print("TTP import complete.")


if __name__ == "__main__":
    main()
