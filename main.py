import assess_services
import assess_users
from pprint import pprint 
import platform
import threading

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
                return distro
        elif os == 'windows':
            print(f'Running on Windows')
            distro = "windows" 
            return distro
        else:
            print(f'OS {os} is not supported by the tool')
            exit()





distro = find_os()
#test_services = assess_services.assess_services()
test_users = assess_users.assess_users(distro)
local_users = test_users.GetWinUsers()
wordlist = test_users.ReadWordlist()
vulnerable_users = {}

for user in local_users:
    stripped_user = user.strip()
    stripped_user = "ALGSOC20L\mkalliafas"
    if stripped_user:
        print(f"\nTrying passwords for {stripped_user}")
        success, password = test_users.WinPassCracker(wordlist, stripped_user)
        if success:
            vulnerable_users[stripped_user] = password
            print(f"\nFound password for {stripped_user}")
            print(f"> {password}")
        else:
            print(f"\nCouldn't find password for {stripped_user}")

    break

critical_users = []

for user in vulnerable_users:
   critical_users.append(test_users.PrivilagedGroupsMember(user))




#services = assess.FindServices(distro)
#versions = assess.FindVersions(distro, services)
#vulnerabilities = assess.GetVulnerabilities(versions)
#print(f"\n\n== Services ==\n")
#pprint(services)
#print(f"\n\n== Versions ==\n")
#pprint(versions)
#print("\n\n== Vulnerabilities ==\n")
#pprint(vulnerabilities)

#vulnerabilities = asses.get_vulnerabilities(versions)