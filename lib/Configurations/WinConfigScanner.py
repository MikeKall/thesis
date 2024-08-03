import re
from os import listdir
from os.path import isfile, join
import winreg

class WinConfigs():
    
    def __init__(self):
        super(WinConfigs, self).__init__()

    def Filezilla(self):
        postgresql_config_path = input("Please specify the configuration path for filezilla: ")
        config_files = self.Get_Config_Files(postgresql_config_path, "filezilla", "xml")
        hardening = {}
        if not config_files:
            print("No configuration files were found in the specified directory")
            return hardening
        
        try:
            for file in config_files:
                hardening[file] = {"MinPasswordLen": False,
                                   "TLSRequired": False,
                                   "MaxClients": False,
                                   "DirList": False}
                
            with open(file, "r") as conf_file:
                    lines = conf_file.readlines()
                    for line in lines:
                        line = line.strip()
                        MinPassLen = re.match(r"MinPasswordLen.*=(.\d+)", line)
                        TLSRequired = re.match(r"TLSRequired.*=(.\d+)", line)
                        DirList = re.match(r"DirList.*=.*(on)", line)
                        if TLSRequired:
                            try:
                                if int(TLSRequired.group(1).strip()) != 0:
                                    hardening[file]["TLSRequired"] = True
                            except Exception as e:
                                pass

                        if MinPassLen:
                            try:
                                if int(MinPassLen.group(1).strip()) > 12:
                                    hardening[file]["MinPasswordLen"] = True
                            except Exception as e:
                                pass   
                                                                
                        if "MaxClients" in line:
                            hardening[file]["MaxClients"] = True

                        if DirList:
                            hardening[file]["DirList"] = True

        except Exception as e:
            print(e)

        return hardening

    def Registry(self):
        reg_keys = {"SOFTWARE\Microsoft\Windows\CurrentVersion\Run": None, 
                    "System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile": None}
        values = []
        try:
            i = 0
            for reg_key in reg_keys: 
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key) as key:
                    try:
                        value, reg_type = winreg.QueryValueEx(key, "EnableFirewall")
                        if int(value) != 1:
                            reg_keys[reg_key] = [f"EnableFirewall#{value}"]
                        continue
                    except Exception as e:
                        pass
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            values.append(f"{name}#{value}")
                            i += 1
                        except OSError:
                            break
                    reg_keys[reg_key] = values
                    values = []
        except OSError as e:
            print(f"Failed to access {reg_key}: {e}")
        
        return reg_keys


    def Apache(self):
        apache_config_path = input("Please specify the configuration path for apache: ")
        config_files = self.Get_Config_Files(apache_config_path, "apache")
        hardening = {}

        if not config_files:
            print("No configuration files were found in the specified directory")
            return hardening
        try:
            for file in config_files:
                hardening[file] = {"ServerTokens Prod": False, 
                                    "ServerSignature Off": False, 
                                    "ApacheOptions": False,
                                    "Etag": False,
                                    "TraceReq": False,
                                    "CookieProtection": False,
                                    "ClickJacking Attack": False,
                                    "X-XSS protection": False,
                                    "SSL": False,
                                    "Browser Listing": False,
                                    "System Setting Protection": False,
                                    "HTTP Request Methods Restriction": False
                                    }

                with open(file, "r") as conf_file:
                    browser_listing_flag = False
                    sys_setting_protection_flag = False
                    multiline_check = False
                    lines = conf_file.readlines()
                    for line in lines:
                        if not line.startswith("#"): # if line is commented out then don't evaluate
                            if "ServerTokens Prod" in line:
                                hardening[file]["ServerTokens Prod"] = True
                            if "ServerSignature Off" in line:
                                hardening[file]["ServerSignature Off"] = True
                            if "FileETag None" in line:
                                hardening[file]["Etag"] = True
                            if "TraceEnable off" in line:
                                hardening[file]["TraceReq"] = True
                            if "Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure" in line:
                                hardening[file]["CookieProtection"] = True
                            if "Header always append X-Frame-Options SAMEORIGIN" in line:
                                hardening[file]["ClickJacking Attack"] = True
                            if 'Header set X-XSS-Protection "1; mode=block"' in line:
                                hardening[file]["X-XSS protection"] = True
                            if "SSLCertificateFile" in line or "SSLCertificateKeyFile" in line or "SSLCertificateChainFile" in line:
                                hardening[file]["SSL"] = True
                            if "<LimitExcept" in line:
                                hardening[file]["HTTP Request Methods Restriction"] = True


                            if multiline_check:
                                if browser_listing_flag:
                                    if "Options -Indexes" in line or "Options None" in line:
                                        hardening[file]["Browser Listing"] = True
                                        multiline_check = False
                                        browser_listing_flag = False
                                elif sys_setting_protection_flag:
                                    if "Options -Indexes" in line or "AllowOverride None" in line:
                                        hardening[file]["System Setting Protection"] = True
                                        multiline_check = False
                                        browser_listing_flag = False

                            if "<Directory /opt/apache/htdocs>" in line:
                                browser_listing_flag = True
                                multiline_check = True
                            
                            if "<Directory /> " in line:
                                sys_setting_protection_flag = True
                                multiline_check = True
        except Exception as e:
            print(e)
                
        return hardening
    
    def PostgreSQL(self):
        postgresql_config_path = input("Please specify the configuration path for postgresql: ")
        config_files = self.Get_Config_Files(postgresql_config_path, "postgresql")
        hardening = {}
        if not config_files:
            print("No configuration files were found in the specified directory")
            return hardening
        
        try:
            for file in config_files:
                hardening[file] = {"unrestricted_listening":False,
                                   "ssl":False}
                
            with open(file, "r") as conf_file:
                    lines = conf_file.readlines()
                    
                    for line in lines:
                        line = line.strip()
                        if not line.startswith("#"): # if line is commented out then don't evaluate
                            if "listen_addresses" in line and "*" in line:
                                hardening[file]["unrestricted_listening"] = True
                            if re.match("^ssl.*=.*on$", line):
                                hardening[file]["ssl"] = True

            
        except Exception as e:
            print(e)

        return hardening


    def Get_Config_Files(self, path, service, extention="conf"):
        config_files = []
        retry_flag = False

        while True:
            if retry_flag:
                path = input(f"Please specify the configuration path for {service} (q to quit): ")
                if path.lower() == "q":
                    exit()
            try:
                files = [f for f in listdir(path) if isfile(join(path, f))]
                break
            except OSError as e:
                print("The specified path doesn't exist")
                retry_flag = True
                continue

        if extention == "conf":
            for file in files:
                match = re.match("^.*\.conf$", file)
                if match:
                    full_path = join(path, file)
                    config_files.append(full_path)
        elif extention == "xml":
            for file in files:
                match = re.match("^.*\.xml$", file)
                if match:
                    full_path = join(path, file)
                    config_files.append(full_path)
        
      
        return config_files