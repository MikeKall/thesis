import lib.WinServicesScanner as WinServicesScanner
import lib.LinuxServicesScanner as LinuxServicesScanner

class ServiceScanController:

    def __init__(self, distro):
        self.distro = distro
        self.WinServices_obj = WinServicesScanner.WinServicesScanner()
        self.LinuxServices_obj = LinuxServicesScanner.LinuxServicesScanner(distro)

    
    def FindServices(self):
        # Check the services for the running OS
        if self.distro == "windows":
            services = self.WinServices_obj.GetServices()
        else:
            services = self.LinuxServices_obj.GetServices()
        return services
            

    def FindVersions(self, services):
        versions = {}
        if self.distro == "windows":
            versions = self.WinServices_obj.GetVersions(services)
            return versions
        else:
            versions = self.LinuxServices_obj.GetVersions(services)