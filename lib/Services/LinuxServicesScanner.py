import subprocess
import re

class LinuxServicesScanner:

    def __init__(self, distro):
        self.distro = distro

    def GetServices(self):
        if self.distro == "rh":
            # Get a list of all running services
            services = (
                subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--state=running"],
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .split("\n")
            )
            return services
        elif self.distro == "debian":
            # Get a list of all running services
            services = (
                subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--state=running"],
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .split("\n")
            )
            return services
        
    def GetVersions(self, services):
        versions = {}
        if self.distro == "rh":
            for service in services:
                service_name = self.clean_service_name(service)
                if service_name:
                    cmd_out = subprocess.run(
                        ["rpm", "-qa", service_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    cmd_out = cmd_out.stdout.decode()
                else:
                    continue
                if cmd_out:
                    if not (service_name in versions.keys()) and self.HasNumbers(
                        cmd_out.split("-")[1]
                    ):
                        versions[service_name] = cmd_out.split("-")[1]
            return versions
        elif self.distro == "debian":
            for service in services:
                service_name = self.clean_service_name(service)
                if service_name:
                    cmd_out = subprocess.run(
                        ["dpkg", "-l", service_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    cmd_out = cmd_out.stdout
                else:
                    continue
                if cmd_out:
                    filtered_out = cmd_out.rstrip().split("\n")[-1]
                    version = re.sub(" +", " ", filtered_out).split(" ")

                    if not (service_name in versions.keys()):
                        versions[service_name] = version[2].split("-")[0]
            return versions

    
    def HasNumbers(self, inString):
        return any(char.isdigit() for char in inString)
    
    def clean_service_name(self, service):
        pattern = "(\S+)(?=.service)"
        match = re.search(pattern, service)
        if match:
            service_name = match.group(1)
        else:
            service_name = ""
        return service_name