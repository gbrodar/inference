import os
import requests
import zipfile
from tqdm import tqdm
from io import BytesIO


# List of URLs to download
zip_urls = [
    'https://capec.mitre.org/data/csv/1000.csv.zip',
    'https://capec.mitre.org/data/csv/3000.csv.zip'
]

# Directory where the ZIP files will be extracted
extract_dir = '../data/capec'

# Create the directory if it doesn't exist
os.makedirs(extract_dir, exist_ok=True)

# Function to download a ZIP file with a progress bar
def download_zip(url):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 Kilobyte
    filename = url.split('/')[-1]
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc=f'Downloading {filename}')
    buffer = BytesIO()
    for data in response.iter_content(block_size):
        progress_bar.update(len(data))
        buffer.write(data)
    progress_bar.close()
    buffer.seek(0)
    return buffer, filename

# Function to extract a ZIP file with a progress bar
def extract_zip(buffer, extract_to):
    with zipfile.ZipFile(buffer) as zip_ref:
        members = zip_ref.infolist()
        progress_bar = tqdm(total=len(members), unit='file', desc=f'Extracting {zip_ref.filename}')
        for member in members:
            zip_ref.extract(member, extract_to)
            progress_bar.update(1)
        progress_bar.close()

# Download and extract each ZIP file
for url in zip_urls:
    zip_buffer, zip_filename = download_zip(url)
    extract_zip(zip_buffer, extract_dir)

print('All downloads and extractions are complete.')
