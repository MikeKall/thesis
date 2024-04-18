import lib.ServiceScanController as ServiceScanController 
import lib.os_prober as os_prober
import lib.assess_users as assess_users
import lib.assess_configs as assess_configs
import lib.CVEFetcher as CVEFetcher
from pprint import pprint
import json
import argparse
from datetime import datetime


# Create script arguments 
parser = argparse.ArgumentParser()
parser.add_argument("-U", "--crack_users", action="store_true", help='Use a wordlist to test user passwords')
parser.add_argument("-w", "--wordlist", help='Provide a wordlist file')
parser.add_argument("-S", "--services",action="store_true", help='Check services for CVEs' )
parser.add_argument("-C", "--configurations", action="store_true", help='Check for missconfigurations in services')
args = parser.parse_args()

# Check if wordlist is provided
if args.crack_users and not args.wordlist:
    print("Please provide a wordlist")
    exit()

service_trigger = False
user_trigger = False
configs_trigger = False
distro, os = os_prober.os_prober.find_os()
serviceController_obj = ServiceScanController.ServiceScanController(distro)

if args.services:
    service_trigger = True
    print("==== Assessment for local services ====")

    # Find vulnerable services
    services = serviceController_obj.FindServices()
    versions = serviceController_obj.FindVersions(services)
    CVESFetcher_obj = CVEFetcher.CVEFetcher(versions)
    vulnerabilities, cache_exists = CVESFetcher_obj.GetVulnerabilities()
    if not cache_exists:
        CVESFetcher_obj.writeTofile(vulnerabilities)
        


    print(f"\n\n== Services ==\n")
    #pprint(services)
    print(f"\n\n== Versions ==\n")
    pprint(versions)
    print("\n\n== Vulnerabilities ==\n")
    #pprint(vulnerabilities)

    active_vulnerabilites, possible_vulnerabilites = CVESFetcher_obj.CVEfilter(vulnerabilities)
    
    print(f"== Active ==\n")
    if active_vulnerabilites == None:
        print("None found")
        print("")
    else:
        pprint(active_vulnerabilites)
    print(f"== Other Possible Matches ==\n")
    pprint(possible_vulnerabilites)
    

    

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




        