import os
import json
import logging
from tqdm import tqdm
from neo4j import GraphDatabase, exceptions

# Configure logging
log_dir = '../.log'
log_file = 'import_errors.log'
log_path = os.path.join(log_dir, log_file)

# Create the log directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)

# Set up logging to file
logging.basicConfig(
    filename=log_path,
    filemode='a',  # Append mode
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def create_cpe_node(tx, cpe_item):
    query = """
    CREATE (c:CPE {
        cpe_item: $cpe_item,
        title: $title,
        vendor: $vendor,
        product: $product,
        version: $version
    });
    """
    tx.run(query, **cpe_item)

def import_cpe_data(file_path, uri, user, password):
    # Load JSON data from the file
    try:
        with open(file_path, 'r') as file:
            cpe_data = json.load(file)
    except Exception as e:
        logging.error(f"Failed to load JSON data from {file_path}: {e}")
        return

    # Connect to the Neo4j database
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
    except exceptions.Neo4jError as e:
        logging.error(f"Failed to connect to Neo4j: {e}")
        return

    # Iterate over each CPE entry using tqdm for a progress bar
    with driver.session() as session:
        for item in tqdm(cpe_data, desc="Importing CPE entries", unit="entry"):
            # Map JSON keys to the parameters expected by the Cypher query
            mapped_item = {
                "cpe_item": item.get("cpe-item", ""),
                "title": item.get("title", ""),
                "vendor": item.get("vendor", ""),
                "product": item.get("product", ""),
                "version": item.get("version", "")
            }
            try:
                session.write_transaction(create_cpe_node, mapped_item)
            except exceptions.Neo4jError as e:
                error_message = f"Failed to import entry {mapped_item.get('cpe_item', 'Unknown')}: {e}"
                print(error_message)
                logging.error(error_message)
            except Exception as e:
                error_message = f"An unexpected error occurred with entry {mapped_item.get('cpe_item', 'Unknown')}: {e}"
                print(error_message)
                logging.error(error_message)

    driver.close()

if __name__ == "__main__":
    file_path = '../data/cpe/cpe_dictionary.json'
    uri = "bolt://localhost:7687"  # Update if your Neo4j instance is hosted elsewhere
    user = "neo4j"                 # Your Neo4j username
    password = "Neo4j678!@"          # Your Neo4j password

    import_cpe_data(file_path, uri, user, password)
