import csv
import json
import os
from tqdm import tqdm

# Define input directory and output JSON file
input_dir = "../data/capec"
output_json = "../data/capec/capec_data.json"  # moved up a level to avoid confusion

# Ensure the directory exists
os.makedirs(input_dir, exist_ok=True)

# Collect all CSV files in the directory
csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]

capec_data = []

# Process each CSV file
for csv_file in tqdm(csv_files, desc="📄 Reading CAPEC CSVs"):
    file_path = os.path.join(input_dir, csv_file)
    with open(file_path, mode='r', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        for row in reader:
            capec_data.append(row)

# Write a proper JSON array to output file
with open(output_json, mode='w', encoding='utf-8') as file:
    json.dump(capec_data, file, indent=4, ensure_ascii=False)

print(f"✅ Converted {len(csv_files)} CSV files into {len(capec_data)} CAPEC entries at {output_json}")
