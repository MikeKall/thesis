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
        services_dict = {"1":"Apache", 
                         "2":"PostgreSQL", 
                         "3":"Filezilla"
                        }
        for key, value in services_dict.items():
            print(f"{key}. {value}")

        configs2check = input("Choose (for multiple e.g 1,2,3): ")
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
        filezilla = None
        for num in choices:
            try:
                if self.distro == "windows":
                    if services[num] == "Apache":
                        apache = self.WinConfigs_Obj.Apache()

                    if services[num] == "MySQL":
                        mysql = self.WinConfigs_Obj.MySQL()

                    if services[num] == "PostgreSQL":
                        postgresql = self.WinConfigs_Obj.PostgreSQL()
                    
                    if services[num] == "Filezilla":
                        filezilla = self.WinConfigs_Obj.Filezilla()
                else:
                    if services[num] == "Apache":
                        apache = self.LinuxConfigs_Obj.Apache()
                    
                    if services[num] == "MySQL":
                        mysql = self.LinuxConfigs_Obj.MySQL()

                    if services[num] == "PostgreSQL":
                        postgresql = self.LinuxConfigs_Obj.PostgreSQL()
                    
                    if services[num] == "Filezilla":
                        filezilla = self.LinuxConfigs_Obj.Filezilla()
            except:
                continue

        return apache, mysql, postgresql, filezilla