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
        


    print(f"\n\n== Services ==\n")
    #pprint(services)
    print(f"\n\n== Versions ==\n")
    pprint(versions)
    print("\n\n== Vulnerabilities ==\n")
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
    ustart_time = time.time()
    user_trigger = True
    print("\n\n\n==== Assessment for local Users ====")
    # Find vulnerable users
    user_assessment_obj = UserAssessController.UserAssessmentController(distro, os)
    local_users = user_assessment_obj.GetVulnerableUsers() 
    wordlist = user_assessment_obj.ReadWordlist(args.wordlist)
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
                success, password = user_assessment_obj.PassCracker(wordlist, stripped_user)
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
            group = user_assessment_obj.PrivilagedGroupsMember(user)
        if not group == "-":
            critical_users[user] = group

        print("\n== High privilaged Users ==")
        for user, group in critical_users.items():
            print(f"User {user} is a member of {group}")


    userScan_duration = time.time() - ustart_time

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

print("===== Execution time =====")
print(f"Tool execution total time: {tool_duration/60}")
print(f"Service scan duration: {serviceScan_duration/60}")
print(f"User scan duration: {userScan_duration/60}")
print(f"Configurations scan duration: {configsScan_duration/60}")
print("=========================================================\n\n")
print("===== Execution time =====")
print(f"Tool execution total time: {str(timedelta(seconds=tool_duration))}")
print(f"Service scan duration: {str(timedelta(seconds=serviceScan_duration))}")
print(f"User scan duration: {str(timedelta(seconds=userScan_duration))}")
print(f"Configurations scan duration: {str(timedelta(seconds=configsScan_duration))}")
print()