import subprocess
import re
import time
import requests
import json
import platform
from requests.auth import HTTPBasicAuth
import csv

class assess_services():
    
    def __init__(self):
        super(assess_services, self).__init__()

    def has_numbers(self, inString):
        return any(char.isdigit() for char in inString)

    def create_report(self, data):
        with open('output.txt', 'w+') as f:
            print(f"There are {data['totalResults']} known vulnerabilities for service {service}", file=f)
            # Print the CVEs
            for num in range(data['totalResults']):
                print(data['vulnerabilities'][num]['cve']['id']+" "+data['vulnerabilities'][num]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], file=f )


    def find_os(self):
        os = platform.system().lower()

        if os == 'linux':
            with open('/etc/os-release') as f:
                data = [line.strip() for line in f if line.startswith(('PRETTY_NAME='))]
                distro_name = [line.split('=')[1].strip('"') for line in data][0].lower()
                if 'fedora' in distro_name or 'centos' in distro_name:
                    print(f'Running on RedHat based')
                    distro = "rh"                
                elif 'debian' in distro_name or 'ubuntu' in distro_name:
                    print(f'Running on Debian based')
                    distro = "debian" 
                return distro
        elif os == 'windows':
            print(f'Running on Windows')
            distro = "windows" 
            return distro
        else:
            print(f'OS {os} is not supported by the tool')
            exit()
    
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

        

    def find_services(self, distro):
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


    def find_versions(self, distro, services):
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
                    if not(service_name in versions.keys()) and self.has_numbers(cmd_out.split("-")[1]):
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

    
    def get_vulnerabilities(self, versions):
        # 9a9374cd-04e7-4706-ae4c-fa4855a8f846
        vulnerabilities = {}
        auth = HTTPBasicAuth('apiKey', '9a9374cd-04e7-4706-ae4c-fa4855a8f846')
        headers = {'Accept': 'application/json'}


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
                print(response.text)
                while data["totalResults"] > data["resultsPerPage"]:
                    resultsPerPage += data["resultsPerPage"]
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={resultsPerPage}&keywordSearch={service}"
                    response = requests.get(url, headers=headers, auth=auth)
                    data = json.loads(response.text)
                vulnerabilities[service] = data
                time.sleep(6)
            else:
                vulnerabilities[service] = "Unknown"
        
        return(vulnerabilities)



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