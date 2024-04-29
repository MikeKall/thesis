import subprocess
import re

class WinServicesScanner:
          
    def GetServices(self):
        cmd = [
            "powershell.exe",
            "-Command",
            'Get-Service | Where-Object {$_.Status -eq "Running"} | select name',
        ]

        proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
        services = []
        for line in proc:
            stripped_line = line.rstrip()
            if stripped_line:
                if stripped_line == "Name" or stripped_line == "----":
                    continue
                services.append(stripped_line)
        return services

    def GetVersions(self, services):
        service_version = {}  # service_name:version
        services_paths = {}  # service_name:exe path

        # Get the paths of every service exe
        for service in services:
            cmd = [
                "powershell.exe",
                "-Command",
                f"(Get-cimInstance -ClassName win32_service -Filter 'Name like \"{service}\"').PathName",
            ]
            proc = ((subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n"))

            if not "svchost.exe" in proc[0]:
                services_paths[service] = proc[0].rstrip()
            else:
                services_paths[service] = "Unknown"

        # Parse the full path of the exe and get the version
        pattern = "(C:.*?exe)"
        for service in services_paths:
            services_paths[service] = services_paths[service].replace("\\", "\\\\")
            match = re.search(pattern, services_paths[service])
            if match:
                filtered_service_path = match.group(1)
            else:
                filtered_service_path = ""

            if filtered_service_path:
                cmd = f"wmic datafile where 'name=\"{filtered_service_path}\"' get version"
                proc = (
                    (subprocess.run(cmd, capture_output=True))
                    .stdout.decode()
                    .split("\n")
                )
                service_version[service] = proc[1].strip()
            else:
                service_version[service] = "Unknown"

        return service_version