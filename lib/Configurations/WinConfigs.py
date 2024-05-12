import subprocess
import re
from pprint import pprint 
from os import listdir
from os.path import isfile, join

class WinConfigs():
    
    def __init__(self):
        super(WinConfigs, self).__init__()


    def Apache(self):
        apache_config_path = input("Specify the Apache config Full Path: ")
        config_files = []
        hardening = {}
        try:
            while not apache_config_path:
                apache_config_path = input("Please specify the Apache config Full Path (q to quit): ")
                if apache_config_path.lower() == "q":
                    exit()
        except Exception as e:
            print(e)
            exit()
       
        files = [f for f in listdir(apache_config_path) if isfile(join(apache_config_path, f))]
        
        for file in files:
            print(file)
            match = re.match("^.*\.conf$", file)
            if match:
                full_path = join(apache_config_path, file)
                config_files.append(full_path)


        try:
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
                            
                            if "<Directory /> " in line:
                                sys_setting_protection_flag = True
                                multiline_check = True
        except Exception as e:
            print(e)
                
        return hardening
    
    def PostgreSQL(self):
        return "Windows Postgresql"

    def Filezila(self):
        return "Windows Filezila"