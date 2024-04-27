import subprocess
from pprint import pprint 

class WinConfigs():
    
    def __init__(self):
        super(WinConfigs, self).__init__()


    def Apache(self):
           print("Windows Apache")
    
    def MySQL(self):
        return "Windows Mysql"
    
    def PostgreSQL(self):
        return "Windows Postgresql"

    def Filezilla(self):
        return "Windows Filezilla"