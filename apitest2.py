#apitest2
import pandas as pd
import requests
import time
import logging
import urllib3

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(filename='nvd_api.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Replace 'YOUR_API_KEY' with your actual API key
api_key = 'd713e685-2dc2-424b-8737-dfc0ad3d990c'

# Define a list of test CVE IDs
test_cve_ids = [
    'CVE-2023-22001',
    'CVE-2023-22002',
    'CVE-2023-22003',
    'CVE-2023-22004',
    'CVE-2018-15133',
    'CVE-2016-20017',
    'CVE-2023-38203',
    'CVE-2020-2551',
    'CVE-2014-8361',
    'CVE-2021-3129'
]

# Base URL for the NVD API
base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


# Function to perform a single CVE lookup with exponential backoff
def lookup_cve(cve_id, retry_count=0):
    url = f'{base_url}?cveId={cve_id}'
    headers = {'apiKey': api_key}

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.info(f"Successful lookup for CVE ID: {cve_id}")

        # Process and log the response data as needed
        data = response.json()
        print(f"Data for {cve_id}: {data}")  # Example of processing the data

    except requests.exceptions.RequestException as e:
        status_code = e.response.status_code if e.response else None

        if status_code:
            logging.error(f"Error retrieving data for CVE ID: {cve_id} - Status Code: {status_code}")
            print(f"Error retrieving data for CVE ID: {cve_id} (Status Code: {status_code})")

            if 'message' in e.response.headers:
                message = e.response.headers['message']
                logging.error(f"Additional information: {message}")
                print(f"Additional information: {message}")

            if status_code == 429:
                if retry_count < 3:
                    delay_secs = 2 ** retry_count
                    logging.info(f"Rate limit reached for CVE ID: {cve_id}. Retrying in {delay_secs} seconds...")
                    print(f"Rate limit reached for CVE ID: {cve_id}. Retrying in {delay_secs} seconds...")
                    time.sleep(delay_secs)
                    return lookup_cve(cve_id, retry_count + 1)
                else:
                    logging.error(f"Exceeded retry limit for CVE ID: {cve_id}.")
                    print(f"Exceeded retry limit for CVE ID: {cve_id}.")

            elif status_code == 403:
                logging.warning(f"Access denied for CVE ID: {cve_id}. Check API key and permissions.")
                print(f"Access denied for CVE ID: {cve_id}. Check API key and permissions.")

        else:
            logging.error(f"Unexpected error retrieving data for CVE ID: {cve_id} - {e}")
            print(f"Unexpected error retrieving data for CVE ID: {cve_id} - {e}")

# Iterate over each CVE ID in the list and perform the lookup
for cve_id in test_cve_ids:
    lookup_cve(cve_id)
