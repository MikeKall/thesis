class ConfigController():
    
    def __init__(self, distro, os):
        super(ConfigController, self).__init__()
        self.distro = distro
        self.os = os
        if os == "windows":
            import lib.Configurations.WinConfigScanner as WinConfigs
            self.WinConfigs_Obj = WinConfigs.WinConfigs()
        elif os == "linux":
            import lib.Configurations.LinuxConfigScanner as LinuxConfigs
            self.LinuxConfigs_Obj = LinuxConfigs.LinuxConfigs(distro)


    def ChooseConfigs(self):
        results = list
        if self.os == "windows":
            services_dict = {"1":"Apache", 
                             "2":"PostgreSQL",
                             "3":"Registry"
                        }
        else:
            services_dict = {"1":"Apache", 
                             "2":"PostgreSQL",
                             "3":"Nftables"
                        }
            
        for key, value in services_dict.items():
            print(f"{key}. {value}")

        configs2check = input("Choose (for multiple e.g 1,2): ")
        choices = configs2check.split(",")
        if choices:
            results = self.CheckConfigs(choices, services_dict)
        else:
            results = None
        return results


    def CheckConfigs(self, choices, services):
        apache = None
        postgresql = None
        nftables = None
        registry = None

        for num in choices:
            try:
                if self.distro == "windows":
                    if services[num] == "Registry":
                        registry = self.WinConfigs_Obj.Registry()

                    if services[num] == "Apache":
                        apache = self.WinConfigs_Obj.Apache()

                    if services[num] == "PostgreSQL":
                        postgresql = self.WinConfigs_Obj.PostgreSQL()
                    
                else:
                    if services[num] == "Apache":
                        apache = self.LinuxConfigs_Obj.Apache()

                    if services[num] == "PostgreSQL":
                        postgresql = self.LinuxConfigs_Obj.PostgreSQL()
                    
                    if services[num] == "Nftables":
                        nftables  = self.LinuxConfigs_Obj.nftables()
            except Exception as e:
                continue

        return apache, postgresql, nftables, registry