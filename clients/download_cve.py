import requests
import json
import os
import zipfile
from datetime import datetime
from tqdm import tqdm

NVD_API_KEY = "d9e7b673-c4cd-47e1-892d-f70f02c0f0d"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def download_cve_feed(start_year=2015, output_dir="../data"):
    """
    Download and extract CVE data from NVD feeds for years from start_year to the current year.

    Args:
        start_year (int): The starting year for fetching CVE data.
        output_dir (str): Directory to save and extract the CVE JSON files.
    """
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    current_year = datetime.now().year
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"

    for year in tqdm(range(start_year, current_year + 1), desc="Processing CVE Feeds"):
        # URL for the year's feed
        feed_url = f"{base_url}/nvdcve-1.1-{year}.json.zip"
        zip_file_path = os.path.join(output_dir, f"nvdcve-1.1-{year}.json.zip")
        json_file_path = os.path.join(output_dir, f"nvdcve-1.1-{year}.json")

        try:
            # Download the zip file
            print(f"Downloading {feed_url}...")
            response = requests.get(feed_url, stream=True)
            response.raise_for_status()

            # Save the zip file
            with open(zip_file_path, "wb") as zip_file:
                for chunk in response.iter_content(chunk_size=8192):
                    zip_file.write(chunk)

            print(f"Downloaded {zip_file_path}")

            # Extract the JSON file from the zip archive
            with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
                zip_ref.extractall(output_dir)
                print(f"Extracted {json_file_path}")

        except requests.RequestException as e:
            print(f"Error downloading {feed_url}: {e}")
        except zipfile.BadZipFile as e:
            print(f"Error extracting {zip_file_path}: {e}")


# Function to fetch CVE data with error handling
def fetch_cve_api_data(start_date, end_date, results_per_page=2000):
    cve_list = []
    start_index = 0

    try:
        while True:
            params = {
                "pubStartDate": f"{start_date}T00:00:00.000",
                "pubEndDate": f"{end_date}T00:00:00.000",
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }

            try:
                response = requests.get(NVD_API_URL, params=params, timeout=(10, 30))
                response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                break  # Stop execution on request failure

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                break  # Stop execution if response is not valid JSON

            if "vulnerabilities" in data:
                cve_list.extend(data["vulnerabilities"])

            total_results = data.get("totalResults", 0)

            start_index += results_per_page
            if start_index >= total_results:
                break

    except Exception as e:
        print(f"Unexpected error: {e}")

    try:
        # Ensure the 'data' folder exists
        os.makedirs("../data", exist_ok=True)

        # Extract year from start_date
        year = start_date.split("-")[0]
        filename = f"data/cve/cve_data_{year}.json"

        # Save data to the file
        with open(filename, "w") as f:
            json.dump(cve_list, f, indent=4)

        print(f"Saved {len(cve_list)} CVEs to '{filename}'")

    except IOError as e:
        print(f"File write error: {e}")



def cleanup_zip_files(directory="./data"):
    """
    Remove residual .zip files from the specified directory.

    Args:
        directory (str): Path to the directory where .zip files should be removed.
    """
    if not os.path.exists(directory):
        print(f"Directory '{directory}' does not exist.")
        return

    # List all .zip files in the directory
    zip_files = [f for f in os.listdir(directory) if f.endswith(".zip")]

    if not zip_files:
        print("No .zip files found to clean up.")
        return

    # Use tqdm to show progress
    for zip_file in tqdm(zip_files, desc="Cleaning up .zip files"):
        try:
            zip_file_path = os.path.join(directory, zip_file)
            os.remove(zip_file_path)
        except Exception as e:
            print(f"Error removing {zip_file}: {e}")

    print("Cleanup complete.")

if __name__ == "__main__":
    fetch_cve_api_data('2024-01-01', '2024-01-31', 2000)