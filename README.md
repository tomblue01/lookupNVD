# lookupNVDv4.py    
#
# lookupNVDv4.py will take CVE input from a spreadsheet with column name 'CVE', and lookup CVSS scores from NVD using API, create new spreadsheet with the merged results. It will also analyze the CPE information and if microsoft:windows is found, will mark the CVE as "Is Windows Applicable" to "Yes" in the output spreadsheet. Note that a rate limit is built into the script due to the NVD API being rate limited.
#
# Steps: 
# 0. Provide API key to nvd (needed to increase rate limit; if no API key, may need to adjust the rate limit timing in the code)
# 1. run python script
# 2. select input spreadsheet with CVEs (must be in column labeled 'CVE'; else change the column name in the script)
# 3. once lookups are complete, you will be prompted to name the output spreadsheet
#
#
# apitest2.py will run a test using manual CVEs specified in the code. This will ensure your API key and API connectivity are working. Verbose logging is turned on to allow for troubleshooting 

