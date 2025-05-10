import csv
import json
import os
from tqdm import tqdm

# Define input directory and output JSON file
input_dir = "../data/cwe"
output_json = "data/cwe/cwe_data.json"

# Ensure the directory exists
os.makedirs(input_dir, exist_ok=True)

# List all CSV files in the directory
csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]

capec_data = []

# Process each CSV file
for csv_file in tqdm(csv_files, desc="Processing CSV files"):
    file_path = os.path.join(input_dir, csv_file)
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            capec_data.append(row)

# Save JSON output
with open(output_json, mode='w', encoding='utf-8') as file:
    json.dump(capec_data, file, indent=4)

print(f"CSV data from {len(csv_files)} files converted and saved to {output_json}")
