import os
import json
import requests
import logging
from datetime import datetime
import time

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define the custom User-Agent header.
# custom_user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"
custom_user_agent = "Wget/1.21.1 (linux-gnu)"


# Function to download and save a file with retries
def download_file_with_retry(url, save_path, max_retries=3, retry_delay=5):
    retries = 0
    while retries < max_retries:
        try:
            headers = {"User-Agent": custom_user_agent}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            if response.status_code == 200:
                with open(save_path, 'wb') as file:
                    file.write(response.content)
                return  # Successfully downloaded, exit the loop
        except requests.exceptions.RequestException as e:
            logging.error(e)
            logging.error(f"Failed to download file from {url}. Retrying...")
            retries += 1
            time.sleep(retry_delay)
    logging.error(f"Failed to download file from {url} after {max_retries} retries.")

# Function to fetch and store blacklist data
def fetch_blacklist_sources(config_path):
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(config_path, 'r') as config_file:
        config = json.load(config_file)

    ip_blacklist_sources_path = dir_path + "/" + config['ipBlacklistSourcesPath']
    if not os.path.exists(ip_blacklist_sources_path):
        os.makedirs(ip_blacklist_sources_path)

    for source in config['blackListSources']:
        source_name = source['name']
        source_path = os.path.join(ip_blacklist_sources_path, source_name)
        if not os.path.exists(source_path):
            os.makedirs(source_path)

        meta_data = {
            'name': source_name,
            'source': source['source'],
            'description': source['description'],
            'modified': datetime.now().isoformat(),
        }

        fetch_urls = source['fetchUrls']
        for url in fetch_urls:
            file_name = os.path.basename(url)
            save_path = os.path.join(source_path, file_name)
            download_file_with_retry(url, save_path)

        with open(os.path.join(source_path, 'meta.json'), 'w') as meta_file:
            json.dump(meta_data, meta_file, indent=4)
        
        logging.info(f"Downloaded files for {source_name} to {source_path}")

if __name__ == "__main__":
    dir_path = os.path.dirname(os.path.realpath(__file__))
    config_path = dir_path + "/config/config.json"
    
    fetch_blacklist_sources(config_path)
