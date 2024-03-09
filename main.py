import assess_services
from pprint import pprint 

assess = assess_services.assess_services()

distro = assess.find_os()
services = assess.find_services(distro)
versions = assess.find_versions(distro, services)
vulnerabilities = assess.get_vulnerabilities(versions)
print(f"\n\n== Services ==\n")
pprint(services)
print(f"\n\n== Versions ==\n")
pprint(versions)
print("\n\n== Vulnerabilities ==\n")
pprint(vulnerabilities)

with open('output.txt', 'w+') as f:
    f.write(services)
    f.write(versions)
    f.write(vulnerabilities)
#vulnerabilities = asses.get_vulnerabilities(versions)