import os
import requests
import zipfile
from tqdm import tqdm
from io import BytesIO


# URL of the main branch ZIP file
zip_url = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip'

# Directory where the ZIP file will be extracted
extract_dir = '../data/cve'

# Create the directory if it doesn't exist
os.makedirs(extract_dir, exist_ok=True)

# Function to download the ZIP file with a progress bar
def download_zip(url):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 Kilobyte
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Downloading ZIP')
    buffer = BytesIO()
    for data in response.iter_content(block_size):
        progress_bar.update(len(data))
        buffer.write(data)
    progress_bar.close()
    buffer.seek(0)
    return buffer

# Function to extract the ZIP file with a progress bar
def extract_zip(buffer, extract_to):
    with zipfile.ZipFile(buffer) as zip_ref:
        members = zip_ref.infolist()
        progress_bar = tqdm(total=len(members), unit='file', desc='Extracting ZIP')
        for member in members:
            zip_ref.extract(member, extract_to)
            progress_bar.update(1)
        progress_bar.close()

# Download and extract the ZIP file
zip_buffer = download_zip(zip_url)
extract_zip(zip_buffer, extract_dir)

print('Download and extraction complete.')
