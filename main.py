import assess_services
import assess_users
from pprint import pprint 
import platform
import threading
import json
from os.path import exists

print("\n\n")
def find_os():
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
                return distro, os
        elif os == 'windows':
            print(f'Running on Windows')
            distro = "windows" 
            return distro, os
        else:
            print(f'OS {os} is not supported by the tool')
            exit()


distro, os = find_os()

print("==== Assessment for local services ====")

# Find vulnerable services
test_services = assess_services.assess_services(distro, os)
services = test_services.FindServices()
versions = test_services.FindVersions(services)
vulnerabilities = test_services.GetVulnerabilities(versions)
print(f"\n\n== Services ==\n")
pprint(services)
print(f"\n\n== Versions ==\n")
pprint(versions)

print("\n\n== Vulnerabilities ==\n")
#pprint(vulnerabilities)
with open("local_cves.json", "w+") as f:
     f.write(json.dumps(vulnerabilities))

for service in versions:
    print(f"Service: {service}")
    try:
        index = 0
        while True:
            #print(f"CVE: {vulnerabilities[service]['vulnerabilities'][index]}")
            print(f"CVE: {vulnerabilities[service]['vulnerabilities'][index]['cve']['id']}")
            print(f"Severity: {vulnerabilities[service]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']}")
            print(f"Exploitability Score: {vulnerabilities[service]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore']}")
            print(f"Impact Score: {vulnerabilities[service]['vulnerabilities'][index]['cve']['metrics']['cvssMetricV2'][0]['impactScore']}")
            print("")
            index+=1    
    except Exception as e:
        pass



print("\n\n\n==== Assessment for local Users ====")
# Find vulnerable users
test_users = assess_users.assess_users(distro, os)
local_users = test_users.GetUsers()
wordlist = test_users.ReadWordlist()
vulnerable_users = {}
print("\n== Discovered Users ==")
for user in local_users:
    print(user)

local_users = ["TestUser", "UserTest"] #DEMO
for user in local_users:
    stripped_user = user.strip()
    if stripped_user:
        print(f"Trying passwords for {stripped_user}")
        success, password = test_users.PassCracker(wordlist, stripped_user)
        if success:
            vulnerable_users[stripped_user] = password
            print(f"\n> Found password\n\n")
            #print(f"> {password}\n")
        else:
            print(f"\n> Couldn't find password\n\n")


critical_users = {}

print("\n\n== Vulnerable users Found ==")
for user in vulnerable_users:
    print(user)

for user in vulnerable_users:
   group = test_users.PrivilagedGroupsMember(user)
   if not group == "-":
       critical_users[user] = group

print("\n== High privilaged Users ==")
for user, group in critical_users.items():
    print(f"User {user} is a member of {group}")

print("\n\n\n")




        