import subprocess
import time
import re
from pprint import pprint 

class assess_configs():
    
    def __init__(self, distro, os):
        super(assess_configs, self).__init__()
        self.distro = distro
        self.os = os

    def apache_configs(self):
        if self.os == "windows":
            return self.winApache()
        elif self.os == "linux":
            return self.linuxApache()
        
    def winApache(self):
        print("Windows apache")
    

    def linuxApache(self):
            if self.distro == "rh":
                apache_config_path = input("Apache configs path (default:/etc/httpd/conf/): ")
                config_files = []
                if not apache_config_path:
                    apache_config_path = "/etc/httpd/conf/"
                cmd = [f"find", apache_config_path, "-type", "f", "-name", "*.conf"]
                configs = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode().split("\n")
                for config_file in configs:
                        if config_file: 
                            config_files.append(config_file)

            hardening = {}      
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

                        


            pprint(hardening)