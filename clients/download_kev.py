import os
import requests
from tqdm import tqdm

# URL of the JSON file
json_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Directory where the JSON file will be saved
save_dir = "../data/kev"
json_filename = "known_exploited_vulnerabilities.json"
save_path = os.path.join(save_dir, json_filename)

# Ensure the directory exists
os.makedirs(save_dir, exist_ok=True)


# Function to download the JSON file with a progress bar
def download_json(url, save_path):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get("content-length", 0))
    block_size = 1024  # 1 Kilobyte
    progress_bar = tqdm(total=total_size, unit="B", unit_scale=True, desc="Downloading JSON")

    with open(save_path, "wb") as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)

    progress_bar.close()


# Download the JSON file
download_json(json_url, save_path)

print(f"Download complete. JSON saved to {save_path}")
