import lib.assess_services as assess_services 
import lib.assess_users as assess_users
import lib.assess_configs as assess_configs
from pprint import pprint
import platform
import threading
import json
from os.path import exists
import argparse

# Create script arguments 
parser = argparse.ArgumentParser()
parser.add_argument("-U", "--crack_users", action="store_true", help='Use a wordlist to test user passwords')
parser.add_argument("-w", "--wordlist", help='Provide a wordlist file')
parser.add_argument("-S", "--services",action="store_true", help='Provide a wordlist file' )
parser.add_argument("-C", "--configurations", action="store_true", help='Check for missconfigurations in services')
args = parser.parse_args()

# Check if wordlist is provided
if args.crack_users and not args.wordlist:
    print("Please provide a wordlist")
    exit()

service_trigger = False
user_trigger = False
configs_trigger = False


# Determine in which OS the script is running
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


if args.services:
    service_trigger = True
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



if args.crack_users:
    user_trigger = True
    print("\n\n\n==== Assessment for local Users ====")
    # Find vulnerable users
    test_users = assess_users.assess_users(distro, os)
    local_users = test_users.GetUsers()
    wordlist = test_users.ReadWordlist(args.wordlist)
    vulnerable_users = {}
    print("\n== Discovered Users ==")
    for user in local_users:
        print(user)

    # local_users = ["TestUser", "UserTest"]
    print(f"This operation can take up to {round((len(local_users)*len(wordlist)*2)/120)} hours\nAre you sure you want to continue?(N/y)")
    if input(">") in ["y", "Y"]:

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

if args.configurations:
    test_configurations = assess_configs.assess_configs(distro, os)
    test_configurations.apache_configs()




if not service_trigger and not user_trigger and not configs_trigger:
    print("Exiting... Nothing to do")




        