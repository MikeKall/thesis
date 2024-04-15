from requests.auth import HTTPBasicAuth
from datetime import datetime
import time
import requests
import json
import os
from os.path import exists


class CVEFetcher():
    def __init__(self, versions):
        self.versions = versions
    
    def GetVulnerabilities(self):
        cached = False
        pattern = r"_(.*?).json"
        if exists("CachedCVEs.json"):
            if not os.stat("CachedCVEs.json").st_size == 0:
                print("Cached file found")
                cached = True
                vulnerabilities = self.get_CVEs_Local()

                return vulnerabilities, cached
        else:
            return self.get_CVEs_NIST(), cached

    def get_CVEs_Local(self, versions):
        json_file = [pos_json for pos_json in os.listdir('.') if pos_json.startswith('CachedCVEs')]
        with open(json_file[0], "r") as f:
            loaded_json = json.load(f)    
        return loaded_json, versions

    def get_CVEs_NIST(self):
        vulnerabilities = {}
        auth = HTTPBasicAuth("apiKey", "9a9374cd-04e7-4706-ae4c-fa4855a8f846")
        headers = {"Accept": "application/json"}
        dtime = datetime.today().strftime('_%Y_%m_%d')


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