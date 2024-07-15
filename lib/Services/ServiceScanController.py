class ServiceScanController:

    def __init__(self, distro):
        if distro == "windows":
            import lib.Services.WinServicesScanner as WinServicesScanner
            self.WinServices_obj = WinServicesScanner.WinServicesScanner()
        elif distro in ["rh", "debian"]:
            import lib.Services.LinuxServicesScanner as LinuxServicesScanner
            self.LinuxServices_obj = LinuxServicesScanner.LinuxServicesScanner(distro)
    
        self.distro = distro
        

    
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
        else:
            versions = self.LinuxServices_obj.GetVersions(services)
        return versions