from requests.auth import HTTPBasicAuth
from datetime import datetime
import time
import requests
import json
import os
from os.path import exists
import re

class CVEFetcher():
    def __init__(self, versions):
        self.versions = versions
    
    def GetVulnerabilities(self):
        cached = False
        cached_cves_f = [pos_json for pos_json in os.listdir('.') if pos_json.startswith('CachedCVEs')]
        if cached_cves_f:
            if exists(cached_cves_f):
                if not os.stat(cached_cves_f[0]).st_size == 0:
                    print("Cached file found")
                    cached = True
                    vulnerabilities = self.get_CVEs_Local(cached_cves_f[0])

                    return vulnerabilities, cached
        return self.get_CVEs_NIST(), cached

    def get_CVEs_Local(self, cached_cves_f):
        pattern = r"_(.*?).json"
        match = re.search(pattern, cached_cves_f)
        date_str = match.group(1)
        current_dtime = datetime.today().strftime('%Y_%m_%d')
        file_date = datetime.strptime(date_str, "%Y_%m_%d")
        current_dtime = datetime.strptime(current_dtime, "%Y_%m_%d")
        
        delta = current_dtime - file_date
        print(f"Delta is {delta}")
        if delta.days < 7:
            with open(cached_cves_f, "r") as f:
                loaded_json = json.load(f)    
            return loaded_json

    def get_CVEs_NIST(self):
        vulnerabilities = {}
        auth = HTTPBasicAuth("apiKey", "9a9374cd-04e7-4706-ae4c-fa4855a8f846")
        headers = {"Accept": "application/json"}
        dtime = datetime.today().strftime('%Y_%m_%d')


        with open(f"CachedCVEs{dtime}.json", "w") as f:
            for service in self.versions:
                resultsPerPage = 0
                if not self.versions[service] == "Unknown":
                    print(f"Searching CVEs for service {service}")
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
                    response = requests.get(url, headers=headers, auth=auth)
                    while not response.status_code == 200:
                        time.sleep(6)
                        response = requests.get(url, headers=headers, auth=auth)
                    data = json.loads(response.text)
                    while data["totalResults"] > data["resultsPerPage"]:
                        resultsPerPage += data["resultsPerPage"]
                        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={resultsPerPage}&keywordSearch={service}"
                        response = requests.get(url, headers=headers, auth=auth)
                        data = json.loads(response.text)

                        json.dump(data, f)

                    vulnerabilities[service] = data
                    time.sleep(6)
        return vulnerabilities