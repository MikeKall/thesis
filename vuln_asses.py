import subprocess
import re
import time
import requests
import json
import platform
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
        #print(response)
        data = json.loads(response.text)
        
        return(data)

        #formatted_data = json.dumps(data, indent=2)
        # Get the list of CVEs from the response
        #cves = data['vulnerabilities']['cve']

        
        



    def find_services(self, os):

        if 'windows' in os:
            print(f'Running on Windows')
        elif 'fedora' in os or 'centos' in os:
            print(f'Running on RedHat based')
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")

            service_versions = subprocess.run(["rpm", "-qa"], stdout=subprocess.PIPE).stdout.decode().split("\n")
            #print(service_versions)
        elif 'debian' in os or 'ubuntu' in os:
            print(f'Running on Debian based')
            # Get a list of all running services
            services = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], stdout=subprocess.PIPE).stdout.decode().split("\n")            
        else:
            print(f'OS {os} is not supported by the tool')
            exit()

        versions = {}
        all_data = []
        for version in service_versions:
            if version:
                if not(version in versions.keys()) and self.has_numbers(version.split("-")[1]):
                    versions[version.split("-")[0]] =  version.split("-")[1]

        # Iterate through the list of running services
        for i in range(4):
        #for service in services:
            service = services[i]
            if service:
                try:
                    # Get the service name
                    service_name = service.split()[0]
                    
                    cleaned_service_name = re.findall("\\w+(?=\\.)",service_name)[0]
                    #print(cleaned_service_name)

                    if cleaned_service_name in versions.keys():
                        all_data[0].append(cleaned_service_name)
                        all_data[1].append(self.check_cve(cleaned_service_name, versions[cleaned_service_name]))
                        #break
                except:
                    pass
        return all_data

    def find_os(self):
        os = platform.system().lower()

        if os == 'linux':
            with open('/etc/os-release') as f:
                data = [line.strip() for line in f if line.startswith(('PRETTY_NAME='))]
                distro_name = [line.split('=')[1].strip('"') for line in data]
                return distro_name.lower()
        elif os == 'windows':
            return os
        else:
            return 'not compatible'


asses = vuln_report()


data = asses.find_services(asses.find_os())

print(data)
with open('output.txt', 'w') as f:
    f.write('')

with open('output.txt', 'a+') as f:
    for service in data[0]:
        for cve in data[1]:
            print(service, file=f)
            print(cve, file=f)
            print(f"There are {cve['totalResults']} known vulnerabilities for service {service}", file=f)
            # Print the CVEs
            for num in range(cve['totalResults']):
                print(cve['vulnerabilities'][num]['cve']['id']+" "+cve['vulnerabilities'][num]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], file=f )

