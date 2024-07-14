import lib.Configurations.LinuxConfigScanner as LinuxConfigs
import lib.Configurations.WinConfigScanner as WinConfigs

class ConfigController():
    
    def __init__(self, distro, os):
        super(ConfigController, self).__init__()
        self.distro = distro
        self.os = os
        self.LinuxConfigs_Obj = LinuxConfigs.LinuxConfigs(distro)
        self.WinConfigs_Obj = WinConfigs.WinConfigs()


    def ChooseConfigs(self):
        results = list
        if self.os == "windows":
            services_dict = {"1":"Apache", 
                             "2":"PostgreSQL"
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
        mysql = None
        postgresql = None
        nftables = None
        
        for num in choices:
            try:
                if self.distro == "windows":
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

        return apache, mysql, postgresql, nftables