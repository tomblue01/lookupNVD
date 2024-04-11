import json
import pandas as pd
import requests
import time
import logging
import urllib3
import re
import tkinter as tk
from tkinter import filedialog

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(filename='nvd_api.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def fetch_cve_data(cve_id, session, api_key):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    url = f'{base_url}?cveId={cve_id}'
    headers = {'apiKey': api_key}

    try:
        response = session.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()

        logging.debug(f"API response for {cve_id}: {json.dumps(data, indent=4)}")
        print(f"API response for {cve_id}: {json.dumps(data, indent=4)}")

        return data

    except requests.exceptions.RequestException as e:
        logging.error(f"Error retrieving data for CVE ID: {cve_id}: {e}")
        print(f"Error retrieving data for CVE ID: {cve_id}: {e}")
        return None



def process_cve_data(data):
    cvss_score = None
    windows_applicable = 'No'

    vulnerabilities = data.get('vulnerabilities', [])
    if vulnerabilities:
        cve_data = vulnerabilities[0].get('cve', {})
        metrics = cve_data.get('metrics', {})
        cvssMetricV31 = metrics.get('cvssMetricV31', [])
        cvssMetricV2 = metrics.get('cvssMetricV2', [])

        if cvssMetricV31:
            cvssData = cvssMetricV31[0].get('cvssData', {})
            cvss_score = cvssData.get('baseScore')

        # If no CVSS v3.1 score is found, check for CVSS v2.0 score
        elif cvssMetricV2:
            cvssData = cvssMetricV2[0].get('cvssData', {})
            cvss_score = cvssData.get('baseScore')
        else:
            print("cvssMetricV31 and cvssMetricV2 not found")

        configurations = cve_data.get('configurations', [])
        
        for configuration in configurations:
            nodes = configuration.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    criteria = cpe_match.get('criteria', '')
                    if 'microsoft:windows' in criteria.lower():
                        windows_applicable = 'Yes'
                        break  # Break out of the innermost loop once we find a Windows match
                if windows_applicable == 'Yes':
                    break  # Break out of the outer loop once we find a Windows match
        
    return cvss_score, windows_applicable


def main():
    api_key = 'YOUR KEY HERE'
    session = requests.Session()

    root = tk.Tk()
    root.withdraw()

    excel_file = filedialog.askopenfilename(title="Select Excel file", filetypes=[("Excel files", "*.xlsx")])
    if not excel_file:
        print("No file selected, exiting.")
        return

    df = pd.read_excel(excel_file)
    if 'CVE' not in df.columns:
        print("Error: The required 'CVE' column is missing in the Excel file.")
        return

    for index, row in df.iterrows():
        cve_id = row['CVE']
        data = fetch_cve_data(cve_id, session, api_key)
        if data:
            cvss_score, windows_applicable = process_cve_data(data)
            df.at[index, 'CVSS Score'] = cvss_score
            df.at[index, 'Applicable for Windows'] = windows_applicable

        if (index + 1) % 5 == 0:
            time.sleep(5)  # Throttle requests

    updated_file_path = filedialog.asksaveasfilename(title="Save updated Excel file", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
    if updated_file_path:
        df.to_excel(updated_file_path, index=False)
        print(f"Updated Excel file saved at '{updated_file_path}'.")

if __name__ == "__main__":
    main()
