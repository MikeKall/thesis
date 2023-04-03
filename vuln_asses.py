import subprocess
import re
import time
import requests
import json
import platform
import zipfile
#from reportlab.pdfgen import canvas

class vuln_report():
    
    def __init__(self):
        super(vuln_report, self).__init__()

    def has_numbers(self, inString):
        return any(char.isdigit() for char in inString)

    def create_report(self, data):
        with open('output.txt', 'w+') as f:
            print(f"There are {data['totalResults']} known vulnerabilities for service {service}", file=f)
            # Print the CVEs
            for num in range(data['totalResults']):
                print(data['vulnerabilities'][num]['cve']['id']+" "+data['vulnerabilities'][num]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], file=f )


    def check_cve(self, service, version):
        time.sleep(5)

        url_encoded = service+"%20"+version
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={url_encoded}"
        response = requests.get(url)
        print(response)
        
        data = json.loads(response.text)
        
        return(data)

        #formatted_data = json.dumps(data, indent=2)
        # Get the list of CVEs from the response
        #cves = data['vulnerabilities']['cve']

    
    def ListWinServices():
        cmd = 'powershell "gps | where {$_.MainWindowTitle } | select Description'
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        for line in proc.stdout:
            if line.rstrip():
                # only print lines that are not empty
                # decode() is necessary to get rid of the binary string (b')
                # rstrip() to remove `\r\n`
                print(line.decode().rstrip())


        


    '''
    In this function we are trying to list all the services and their versions. 
    Sometimes in linux when we list the versions for each service we get garbage results, so we are checking
    if in the string that we got there is a number in it. 
    '''
    def find_services(self, os):

        # Check the services for the running OS
        if 'windows' in os:
            print(f'Running on Windows')
            ListWinServices()

        elif 'fedora' in os or 'centos' in os:
            print(f'Running on RedHat based')
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")

            # Get the versions of the services
            service_versions = subprocess.run(["rpm", "-qa"], stdout=subprocess.PIPE).stdout.decode().split("\n")
            
        elif 'debian' in os or 'ubuntu' in os:
            print(f'Running on Debian based')
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")            
        else:
            print(f'OS {os} is not supported by the tool')
            exit()

        services_versions = {} # Dict with services as keys and their versions as values
        service_vulnerabilities = {}
        for version in service_versions:
            # if it's not null
            if version:
                # if the service version isn't already in the list and if the version is indeed a number
                if not(version in services_versions.keys()) and self.has_numbers(version.split("-")[1]):
                    services_versions[version.split("-")[0]] =  version.split("-")[1]

        
        # Iterate through the list of running services
        for i in range(4):
        #for service in services:
            service = services[i]
            if service:
                try:
                    # Trim the service name
                    service_name = service.split()[0]
                    cleaned_service_name = re.findall("\\w+(?=\\.)",service_name)[0]
                    
                    print(cleaned_service_name)
                    # If it's not in the dictionary of discovered services with versions
                    if cleaned_service_name in services_versions.keys():
                        service_cves = self.check_cve(cleaned_service_name, services_versions[cleaned_service_name])
                        service_vulnerabilities[cleaned_service_name] = service_cves
                        break
                except:
                    pass
        
        print(service_vulnerabilities)
        return service_vulnerabilities

    def find_os(self):
        os = platform.system().lower()

        if os == 'linux':
            with open('/etc/os-release') as f:
                data = [line.strip() for line in f if line.startswith(('PRETTY_NAME='))]
                distro_name = [line.split('=')[1].strip('"') for line in data]
                return distro_name[0].lower()
        elif os == 'windows':
            return os
        else:
            return 'not compatible'


#asses = vuln_report()




#vulnerabilities = asses.find_services(asses.find_os())


'''
cves = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip")
open('cves_2023.zip', 'wb').write(cves.content)
with zipfile.ZipFile('cves_2023.zip', 'r') as zip_ref:
    zip_ref.extractall('cves_2023')


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
        break
'''
