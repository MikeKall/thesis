import openpyxl.styles
import lib.Services.ServiceScanController as ServiceScanController 
import lib.OSProber as OSProber
import lib.Users.UserAssessmentController as UserAssessController
import lib.Configurations.ConfigController as ConfigController
import lib.Services.CVEUpdater as CVEUpdater
import lib.Reporter as Reporter
from pprint import pprint
import time
import argparse
from datetime import timedelta
import openpyxl
import shutil

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

active_vulnerabilities = {}
possible_vulnerabilities = {}
local_users = []
critical_users = {}
vulnerable_users = {}
configurations = []

if args.services:
    sstart_time = time.time()
    service_trigger = True
    print("==== Assessment for local services ====")

    # Find vulnerable services
    services = serviceController_obj.FindServices()
    versions = serviceController_obj.FindVersions(services)
    CVESFetcher_obj = CVEUpdater.CVEUpdater(versions)
    vulnerabilities = CVESFetcher_obj.GetVulnerabilities()
        
    version_count = 0
    for version in versions.values():
        if not version == "Unknown":
            version_count += 1


    print(f"\n\n== Services ==\n")
    pprint(f"{len(services)} services have been discovered")
    print(f"\n\n== Versions ==\n")
    pprint(f"{version_count} services report their versions")
    print("\n\n=== Vulnerabilities ===\n")

    active_vulnerabilities, possible_vulnerabilities = CVESFetcher_obj.CVEfilter(vulnerabilities)
    
    print(f"== Active ==\n")
    if not active_vulnerabilities: # if dictionary is empty
        print("None found")
        print("")
    else:
        pprint(active_vulnerabilities)
    print(f"== Other Possible Matches ==\n")
    pprint(possible_vulnerabilities)
    
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

    print(f"Do you want to assess all the users? If yes it could take up to {round((len(local_users)*len(wordlist)*2)/120)} hour(s).(N/y)")
    print(f"Alternatively you can specify specific users. (type S if you want to add custom users)")
    
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
    print("\n\n\n==== Configuration Assessment ====")
    configs_trigger = True
    test_configurations = ConfigController.ConfigController(distro, os)
    apache, postgresql, nftables, registry = test_configurations.ChooseConfigs()
    configurations = {"Registry": registry, "Apache": apache, "Postgresql":postgresql, "Nftables":nftables}
    print()
    if any([registry, apache, postgresql, nftables]):
        
        if registry:
            print("Registry needs review")
            pprint(registry)
        
        if apache:
            print("Apache configurations")
            for config in apache.keys():
                print(f"\nConfiguration: {config}")
                for rule in apache[config]:
                    exists = apache[config][rule]
                    if not exists:
                        print(f"Consider adding \"{rule}\" in the configuration file")
                        apache[config][rule]  = f"Consider adding \"{rule}\" in the configuration file"
        if postgresql:
            print("Postgresqk configurations")
            for config in postgresql.keys():
                points = 0
                print(f"\nConfiguration: {config}")
                for rule in postgresql[config]:
                    exists = postgresql[config][rule]
                    if rule == "noauth_connections" and exists:
                        points += 1
                        print(f"Warning: The configuration file allows connections without authentication")
                        postgresql[config][rule] = "Warning: The configuration file allows connections without authentication"
                    elif rule == "unrestricted_listening" and exists:
                        points += 1
                        print(f"Warning: The configuration file allows connections from anywhere")
                        postgresql[config][rule] = "Warning: The configuration file allows connections from anywhere"
                    elif rule == "ssl" and not exists:
                        points += 1
                        print(f"Consider adding \"{rule}\" in the configuration file")
                        postgresql[config][rule] = f"Consider adding \"{rule}\" in the configuration file"
                    elif rule == "keep_alive" and not exists:
                        points += 1
                        print(f"Consider adding \"{rule}\" in the configuration file")
                        postgresql[config][rule] = f"Consider adding \"{rule}\" in the configuration file"
                if points == 0:
                    print("File is well configured")

        if nftables:
            print("Nftables configurations")
            print(f"Warning: {nftables[0]}")
            print(f"Warning: {nftables[1]}")

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

xlsx_file = "report.xlsx"
pdf_file = "report.pdf"
reporter_obj = Reporter.Reporter(xlsx_file)
reporter_obj.create_services_report(active_vulnerabilities, possible_vulnerabilities)
reporter_obj.create_user_report(vulnerable_users, critical_users)
reporter_obj.create_conf_report(configurations)
reporter_obj.xlsx_to_pdf(pdf_file)
print(f"Report files {xlsx_file} and {pdf_file} have been created")


