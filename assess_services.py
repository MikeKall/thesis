import subprocess
import re
import time
import requests
import json
from requests.auth import HTTPBasicAuth
from os.path import exists
import pandas as pd



class assess_services():
    
    def __init__(self, distro):
        super(assess_services, self).__init__()
        self.distro = distro

        
    def HasNumbers(self, inString):
        return any(char.isdigit() for char in inString)

    def create_report(self, data):
        with open('output.txt', 'w+') as f:
            print(f"There are {data['totalResults']} known vulnerabilities for service {service}", file=f)
            # Print the CVEs
            for num in range(data['totalResults']):
                print(data['vulnerabilities'][num]['cve']['id']+" "+data['vulnerabilities'][num]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], file=f )

    
    def GetWinServices(self):
        cmd = ['powershell.exe', '-Command', 'Get-Service | Where-Object {$_.Status -eq "Running"} | select name']

        proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
        services = []
        for line in proc:
            stripped_line = line.rstrip()
            if stripped_line:
                if stripped_line=="Name" or stripped_line=="----":
                    continue
                services.append(stripped_line)
        return services

    def GetWinVersions(self, services):
        service_version = {} # service_name:version
        services_paths = {} # service_name:exe path
        
        # Get the paths of every service exe
        for service in services:
            cmd = ['powershell.exe', '-Command', f'(Get-cimInstance -ClassName win32_service -Filter \'Name like "{service}"\').PathName']
            proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")

            if not "svchost.exe" in proc[0]:
                services_paths[service] = proc[0].rstrip()
            else:
                services_paths[service] = 'Unknown'
                
        # Parse the full path of the exe and get the version
        pattern = "(C:.*?exe)"
        for service in services_paths:
            services_paths[service] = services_paths[service].replace('\\','\\\\')
            match = re.search(pattern, services_paths[service])
            if match:
                filtered_service_path = match.group(1)
            else:
                filtered_service_path = ''
            

            if filtered_service_path:
                cmd = f'wmic datafile where \'name="{filtered_service_path}"\' get version'
                proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
                service_version[service] = proc[1].strip()
            else:
                service_version[service] = "Unknown"

        return service_version

        

    def FindServices(self, distro):
        # Check the services for the running OS
        if distro == 'windows':
            services = self.GetWinServices()
            return services
        elif distro == "rh":
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")
            return services
            
        elif distro == "debian":
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")           
            return services


    def FindVersions(self, distro, services):
        versions = {}
        if distro == 'windows':
            versions = self.GetWinVersions(services)
            return versions
        
        elif distro == "rh":
            for service in services:
                service_name = self.clean_service_name(service)
                if service_name:
                    cmd_out = subprocess.run(["rpm", "-qa", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    cmd_out = cmd_out.stdout.decode()
                else:
                    continue
                if cmd_out:
                    if not(service_name in versions.keys()) and self.HasNumbers(cmd_out.split("-")[1]):
                        versions[service_name] = cmd_out.split("-")[1]   
            return versions
            
        elif distro == "debian":
            for service in services:
                service_name = self.clean_service_name(service)
                if service_name:
                    cmd_out = subprocess.run(["dpkg", "-l", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    cmd_out = cmd_out.stdout
                else:
                    continue
                if cmd_out:
                    filtered_out = cmd_out.rstrip().split("\n")[-1]
                    version = re.sub(' +', ' ', filtered_out).split(" ")

                    if not(service_name in versions.keys()):
                        versions[service_name] = version[2].split("-")[0]
            return versions


    def clean_service_name(self, service):
        pattern = '(\S+)(?=.service)'
        match = re.search(pattern, service)
        if match:
            service_name = match.group(1)
        else:
            service_name = ''
        return service_name

    
    def GetVulnerabilities(self, versions):
        
        if exists("local_cves.csv"):
           vulnerabilities = self.get_cves_from_file(versions)
        
        else:
            vulnerabilities = {}
            auth = HTTPBasicAuth('apiKey', '9a9374cd-04e7-4706-ae4c-fa4855a8f846')
            headers = {'Accept': 'application/json'}

            with open('local_cves.json', 'w') as f:
                for service in versions:
                    resultsPerPage = 0
                    if not versions[service] == "Unknown":
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
                    else:
                        vulnerabilities[service] = "Unknown"
            
            #vulnerabilities[service]['vulnerabilities'][0]['cve']['configurations'][0][]
            return(vulnerabilities)


    def get_cves_from_file(self, versions):
        dumpedDict = json.dumps(versions)
        loaded_json = json.loads(dumpedDict)
        print(loaded_json)
        #df = pd.read_json(versions)
        #cves = ""
        #return cves



'''
print(f"Data: {vulnerabilities}")
with open('output.txt', 'w') as f:
    f.write('')


with open('output.txt', 'a+') as f:
    for service in vulnerabilities:
        cve = vulnerabilities[service]
        print(service, file=f)
        print(cve, file=f)
        print()
        print(f"There are {cve['totalResults']} known vulnerabilities for service {service}", file=f)
        # Print the CVEs
        for num in range(cve['totalResults']):
            print(cve['vulnerabilities'][num]['cve']['id']+" "+cve['vulnerabilities'][num]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], file=f )
'''