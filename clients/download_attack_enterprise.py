import os
import requests
from tqdm import tqdm

# URL of the latest MITRE ATT&CK Enterprise STIX 2.1 JSON file
json_url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

# Directory where the JSON file will be saved
save_dir = '../data/enterprise-attack'
os.makedirs(save_dir, exist_ok=True)

# Path to save the JSON file
save_path = os.path.join(save_dir, 'enterprise-attack.json')

# Function to download the JSON file with a progress bar
def download_json(url, path):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 Kilobyte
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Downloading JSON')
    with open(path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)
    progress_bar.close()

# Download the JSON file
download_json(json_url, save_path)

print(f'Download complete. JSON saved to {save_path}')
