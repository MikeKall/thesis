import re
from os import listdir
from os.path import isfile, join
import subprocess

class LinuxConfigs():
    
    def __init__(self, distro):
        super(LinuxConfigs, self).__init__()
        self.distro = distro

    def Apache(self):
        apache_config_path = input("Specify the configurations Full Path: ")
        config_files = self.Get_Config_Files(apache_config_path, "apache")
        hardening = {}

        if not config_files:
            print("No configuration files were found in the specified directory")
            return hardening
      
        for file in config_files:
            hardening[file] = {"ServerTokens Prod":False, 
                                "ServerSignature Off":False, 
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
                        
                        if "<Directory />" in line:
                            sys_setting_protection_flag = True
                            multiline_check = True
        return hardening

    
    def PostgreSQL(self):
        postgresql_config_path = input("Specify the configurations Full Path: ")
        config_files = self.Get_Config_Files(postgresql_config_path, "postgresql")
        hardening = {}
        if not config_files:
            print("No configuration files were found in the specified directory")
            return hardening

        try:
            for file in config_files:
                hardening[file] = {"unrestricted_listening": False,
                                   "ssl": False,
                                   "keep_alive": False,
                                   "noauth_connections": False}
                
                with open(file, "r") as conf_file:
                        lines = conf_file.readlines()
                        for line in lines:
                            if not line.startswith("#"): # if line is commented out then don't evaluate
                                if "listen_addresses" in line and "*" in line:
                                    hardening[file]["unrestricted_listening"] = True
                                if re.match("^ssl.*=.*on", line):
                                    hardening[file]["ssl"] = True
                                keep_alive = re.match("^tcp_keepalives_idle.*=(.\d+)", line)
                                if keep_alive:
                                    try:
                                        if int(keep_alive.group(1).strip()) > 0:
                                            hardening[file]["keep_alive"] = True
                                    except Exception as e:
                                        pass
                                if "trust" in line:
                                    print("correct")
                                    hardening[file]["noauth_connections"] = True
        except Exception as e:
            print(e)

        return hardening

    def nftables(self):
        bad_rules = []
        try:
            result = subprocess.run(['systemctl', 'is-active', 'nftables'], capture_output=True, text=True)
            is_active = result.stdout.strip() == 'active'
            if is_active:
                result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
                rules = result.stdout.strip()
                if rules:
                    bad_rules = self.analyze_rules(rules)
                else:
                    return is_active, "No rule detected"
            else:
                bad_rules = "No rules detected"
            

            return is_active, bad_rules

        except Exception as e:
            print(f"Error listing nftables rules: {e}")
            return False, ""

    def analyze_rules(self, rules):
        bad_rules = []
        lines = rules.split('\n')
        for line in lines:
            if 'accept' in line and 'ip saddr 0.0.0.0/0' in line and 'ip daddr 0.0.0.0/0' in line:
                bad_rules.append(line.strip())
            elif 'accept' in line and 'ip saddr 0.0.0.0/0' in line:
                bad_rules.append(line.strip())
        
        return bad_rules


    def Get_Config_Files(self, path, service):
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

        for file in files:
            match = re.match(r"^.*\.conf$", file)                       
            if match:
                full_path = join(path, file)
                config_files.append(full_path)
        
      
        return config_files
