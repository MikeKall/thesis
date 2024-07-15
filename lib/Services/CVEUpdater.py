from requests.auth import HTTPBasicAuth
from datetime import datetime
import time
import requests
import json
import os
from os.path import exists
import re
from packaging.version import Version
from pprint import pprint

class CVEUpdater():
    def __init__(self, versions):
        self.versions = versions
    
    def GetVulnerabilities(self):
        cached_cves_f = [pos_json for pos_json in os.listdir('.') if pos_json.startswith('CachedCVEs')]
        if cached_cves_f:
            if exists(cached_cves_f[0]):
                if not os.stat(cached_cves_f[0]).st_size == 0:
                    print("Cached file found")
                    cached_vulnerabilities = self.get_CVEs_Local(cached_cves_f[0])
                    new_vulnerabilities = {}

                    # Check if there is a new service that doesn't exist in the cached file
                    for service, version in self.versions.items():
                        if  not version == "Unknown" and not service in cached_vulnerabilities.keys():
                            new_vulnerabilities = self.get_CVEs_NIST({service:version})

                    all_vulnerabilities =  cached_vulnerabilities | new_vulnerabilities
                    
                    return all_vulnerabilities
        else:
            vulnerabilities = self.get_CVEs_NIST()
            self.writeTofile(vulnerabilities)

        return vulnerabilities

    def get_CVEs_Local(self, cached_cves_f):
        pattern = r"(\d.*?).json"
        match = re.search(pattern, cached_cves_f)
        date_str = match.group(1)
        current_dtime = datetime.today().strftime('%Y_%m_%d')
        current_dtime = datetime.strptime(current_dtime, "%Y_%m_%d")
        file_date = datetime.strptime(date_str, "%Y_%m_%d")
        
        
        delta = current_dtime - file_date
        if delta.days < 7:
            with open(cached_cves_f, "r") as f:
                loaded_json = json.load(f)    
            return loaded_json
        else:
            print("Cache file is outdated.")
            print("Retrieving new data... Please wait ")
            os.remove(cached_cves_f)
            vulnerabilities = self.get_CVEs_NIST()
            self.writeTofile(vulnerabilities)
            return vulnerabilities

    def get_CVEs_NIST(self, versions={}):
        vulnerabilities = {}
        auth = HTTPBasicAuth("apiKey", "9a9374cd-04e7-4706-ae4c-fa4855a8f846")
        headers = {"Accept": "application/json"}
        if not versions:
            versions = self.versions
        
        for service in versions:
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
                vulnerabilities[service] = data
                time.sleep(6)

        return vulnerabilities
        
    
    
    def writeTofile(self, data):
        dtime = datetime.today().strftime('%Y_%m_%d')
        with open(f"CachedCVEs{dtime}.json", "w+") as f:
            json.dump(data, f)

    def CVEfilter(self, vulnerabilities):
        active_vulnerbilities = {}
        possible_vulnerabilities = {}
        
        for service_name, service_version in self.versions.items():
            while True:
                # Check if NIST has returned any vulnerabilities for each services
                try:
                    if not vulnerabilities[service_name]['resultsPerPage'] > 0:
                        break
                except:
                    # if services doesn't exist in the vulnerabilietis dict
                    break

                if                      not service_version == "Unknown":
                    index = 0
                    has_startingVersion = True
                    has_endingVersion = True
                    pattern = r"^([\d.-]+)"
                    try:
                        starting_version = vulnerabilities[service_name]['vulnerabilities'][index]['cve']['configurations'][0]["nodes"][0]["cpeMatch"][0]["versionEndIncluding"]
                        starting_version_match = re.search(pattern, starting_version)
                        if starting_version_match:
                            starting_version = starting_version_match.group(0)
                    except:
                        has_startingVersion = False
                        pass
                    
                    try:
                        ending_version = vulnerabilities[service_name]['vulnerabilities'][index]['cve']['configurations'][0]["nodes"][0]["cpeMatch"][0]["versionEndIncluding"]
                        ending_version_match = re.search(pattern, ending_version)
                        if ending_version_match:
                            ending_version = ending_version_match.group(0)
                    except:
                        has_endingVersion = False
                        pass
                    
                    
                    service_version_match = re.search(pattern, service_version)
                    try:
                        if service_version_match:
                            service_version = service_version_match.group(0)
                            if has_startingVersion and has_endingVersion:
                                if Version(starting_version) <= Version(service_version) <= Version(ending_version):
                                    active_vulnerbilities[service_name] = {"CVE": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['id'],
                                                                            "Severity": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
                                                                            "Exploitability Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'],
                                                                            "Impact Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['impactScore'],
                                                                            "Service Version": service_version,
                                                                            "Starting Version": starting_version,
                                                                            "Ending Version": ending_version}
                                break
                            elif has_endingVersion:
                                if Version(service_version) <= Version(ending_version):
                                    active_vulnerbilities[service_name] = {"CVE": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['id'],
                                                                            "Severity": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
                                                                            "Exploitability Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'],
                                                                            "Impact Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['impactScore'],
                                                                            "Service Version": service_version,
                                                                            "Ending Version": ending_version}
                                    
                                break
                                
                            else:
                                possible_vulnerabilities[service_name] = {"CVE": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['id'],
                                                                            "Severity": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
                                                                            "Exploitability Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'],
                                                                            "Impact Score": vulnerabilities[service_name]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['impactScore'],
                                                                            "Service Version": service_version
                                                                            }
                                break
                    except:
                        pass
                    index += 1
                else:
                    break
        return active_vulnerbilities, possible_vulnerabilities