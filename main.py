import lib.Services.ServiceScanController as ServiceScanController 
import lib.OSProber as OSProber
import lib.Users.UserAssessmentController as UserAssessController
import lib.Configurations.ConfigController as ConfigController
import lib.Services.CVEUpdater as CVEUpdater
from pprint import pprint
import time
import argparse
from datetime import datetime, timedelta


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

tool_start_time = time.time()

service_trigger = False
user_trigger = False
configs_trigger = False
distro, os = OSProber.os_prober.find_os()
serviceController_obj = ServiceScanController.ServiceScanController(distro)


if args.services:
    sstart_time = time.time()
    service_trigger = True
    print("==== Assessment for local services ====")

    # Find vulnerable services
    services = serviceController_obj.FindServices()
    versions = serviceController_obj.FindVersions(services)
    CVESFetcher_obj = CVEUpdater.CVEUpdater(versions)
    vulnerabilities, cache_exists = CVESFetcher_obj.GetVulnerabilities()
    if not cache_exists:
        CVESFetcher_obj.writeTofile(vulnerabilities)
        
    version_count = 0
    for version in versions.values():
        if not version == "Unknown":
            version_count += 1


    print(f"\n\n== Services ==\n")
    pprint(f"{len(services)} services have been discovered")
    print(f"\n\n== Versions ==\n")
    pprint(f"{version_count} services report their versions")
    print("\n\n=== Vulnerabilities ===\n")
    #pprint(vulnerabilities)

    active_vulnerabilites, possible_vulnerabilites = CVESFetcher_obj.CVEfilter(vulnerabilities)
    
    print(f"== Active ==\n")
    if not active_vulnerabilites: # if dictionary is empty
        print("None found")
        print("")
    else:
        pprint(active_vulnerabilites)
    print(f"== Other Possible Matches ==\n")
    pprint(possible_vulnerabilites)
    
    serviceScan_duration = time.time() - sstart_time

    

if args.crack_users:
    u1start_time = time.time()
    user_trigger = True
    print("\n\n\n==== Assessment for local Users ====")
    # Find vulnerable users
    user_assessment_obj = UserAssessController.UserAssessmentController(distro, os)
    local_users = user_assessment_obj.GetVulnerableUsers() 
    wordlist = user_assessment_obj.ReadWordlist(args.wordlist)
    vulnerable_users = {}
    group = "-"
    print("\n== Discovered Users ==")
    for user in local_users:
        print(user)
    u1total_time = time.time() - u1start_time

    print(f"Do you want to assess all the users? If yes it could take up to {round((len(local_users)*len(wordlist)*2)/120)} hours.(N/y)")
    print(f"Alternatively you can specify specific users. (type S if you want to add custom users)")
    # local_users = ["TestUser", "UserTest"]
    user_input = input(">")
    u2start_time = time.time() # This var will get overidden. It helps only in case the user want provide a possitive input
    if user_input.lower() in ["s", "y"]:
        if user_input.lower() == "s":
            while True:
                local_users = input("Please provide the usernames seperated by comma (,):\n>")
                try:
                    local_users = local_users.split(",")
                    break
                except Exception as e:
                    continue
        
        u2start_time = time.time()
        for user in local_users:
            stripped_user = user.strip()
            if stripped_user:
                print(f"Trying passwords for {stripped_user}")
                success, password = user_assessment_obj.PassCracker(wordlist, stripped_user)
                if success:
                    vulnerable_users[stripped_user] = password
                    print(f"\n> Password Found")
                    print(f"> {password}\n")
                else:
                    print(f"\n> Couldn't find password\n\n")

        critical_users = {}

        print("\n\n== Vulnerable users Found ==")
        for user in vulnerable_users:
            print(user)

        for user in vulnerable_users:
            group = user_assessment_obj.PrivilagedGroupsMember(user)        
            if not group == "-":
                critical_users[user] = group

        print("\n== Vulnerable High privilaged Users ==")
        for user, group in critical_users.items():
            print(f"User {user} is a member of {group}")


    u2total_time = time.time() - u2start_time
    userScan_duration = u1total_time + u2total_time

if args.configurations:
    cstart_time = time.time()
    configs_trigger = True
    test_configurations = ConfigController.ConfigController(distro, os)
    configuration_results = test_configurations.ChooseConfigs()

    if any(configuration_results):
        for item in configuration_results:
            if item:
                pprint(item)
    else:
        print("No hardening tips to recommend")

    configsScan_duration = time.time() - cstart_time

if not service_trigger and not user_trigger and not configs_trigger:
    print("Exiting... Nothing to do")        


tool_duration = time.time() - tool_start_time


print("\n\n===== Execution time =====")
print(f"Tool execution total time: {str(timedelta(seconds=tool_duration))}")
if service_trigger:
    print(f"Service scan duration: {str(timedelta(seconds=serviceScan_duration))}")

if user_trigger:
    print(f"User scan duration: {str(timedelta(seconds=userScan_duration))}")

if configs_trigger:
    print(f"Configurations scan duration: {str(timedelta(seconds=configsScan_duration))}")

print()