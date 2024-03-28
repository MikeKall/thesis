import subprocess
from progressbar import ProgressBar, Percentage, Bar, RotatingMarker, ETA, Timer, AdaptiveETA
import time
import re

class assess_users():
    
    def __init__(self, distro, os):
        super(assess_users, self).__init__()
        self.distro = distro
        self.os = os

    def GetUsers(self):
        if self.os == "windows":
            return self.GetWinUsers()
        
        elif self.os == "linux":
            pattern = "^(.*?):"
            local_users = []
            users = subprocess.run(["cat", "/etc/passwd"], stdout=subprocess.PIPE).stdout.decode().split("\n")
            for user in users:
                user = re.findall(pattern, user)
                if user:
                    local_users.append(user[0])
            
            return local_users
        else:
            print(f"Couldn't find os {self.os}")

    def GetWinUsers(self):
        cmd = ['powershell', '-c', 'Get-WmiObject -Class Win32_UserAccount | foreach { $_.Caption }']
        proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
        local_users = []
        for local_user in proc:
            local_users.append(local_user)
        
        return local_users
    
    def ReadWordlist(self):
        wordlist = []
        print("Loading wordlist. This might take a while.")
        with open('wordlist', 'r', encoding="utf8") as file:
            content = file.read().splitlines()
        
        for line in content:
            wordlist.append(line)

        print("Wordlist loaded\n")
        return wordlist
    
    def WinPassCracker(self, wordlist, local_user):
        length = len(wordlist)
        count = 0
        widgets = ['Progress: ', Percentage(), ' | ', Timer(), ' | ', AdaptiveETA()]
        bar = ProgressBar(widgets=widgets, max_value=100).start()

        for password in wordlist:
            #password = ""
            scriptBlockLine1 = "{"+f'$pass="{password}"|ConvertTo-SecureString -AsPlainText -Force'
            scriptBlockLine2 =  f"\n$Cred=New-Object System.Management.Automation.PsCredential('{local_user}',$pass)"
            scriptBlockLine3 = '\nStart-Process -FilePath cmd.exe /c -Credential $Cred }'
            scriptBlock = scriptBlockLine1 + scriptBlockLine2 + scriptBlockLine3
            
            cmd = ['powershell', '-c', f'Invoke-Command -ScriptBlock {scriptBlock}']
            proc = (subprocess.run(cmd, capture_output=True))
            error = proc.stderr.decode().split("\n")
            output = proc.stdout.decode().split("\n")
            time.sleep(1) # Depends on how fast the PC is. If it's slow, without a built in delay, there will be false positives
            if not error[0] and not output[0]:
                bar.update(100)
                return True, password
            
            count+=1
            bar.update(self.TranslateTo100(count, length))

        return False, password
    

    def LinuxPassCracker(self, wordlist, local_user):
        #
        # yescript nightmare
        #

        length = len(wordlist)
        count = 0
        widgets = ['Progress: ', Percentage(), ' | ', Timer(), ' | ', AdaptiveETA()]
        bar = ProgressBar(widgets=widgets, max_value=100).start()
        for password in wordlist:
                     
            
            cmd = [f"su", "-l", local_user]
            
            proc = subprocess.run(cmd, input=password.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)            
            #time.sleep(1) # Depends on how fast the PC is. If it's slow, without a built in delay, there will be false positives
            if proc.returncode == 0:
                bar.update(100)
                return True, password
            
            count+=1
            bar.update(self.TranslateTo100(count, length))

        return False, password


    def PassCracker(self, wordlist, local_user):
        if self.os == "windows":
            return self.WinPassCracker(wordlist, local_user)
        elif self.os == "linux":
            return self.LinuxPassCracker(wordlist, local_user)


    def PrivilagedGroupsMember(self, vulnerable_user):
        cmd1 = ['powershell', '-c', 'Get-LocalGroupMember -name "Administrators" | foreach {$_.Name}']
        cmd2 = ['powershell', '-c', 'Get-LocalGroupMember -name "Backup Operators" | foreach {$_.Name}']
        admins_members = (subprocess.run(cmd1, capture_output=True)).stdout.decode().split("\n")
        bo_members = (subprocess.run(cmd2, capture_output=True)).stdout.decode().split("\n")
        for member in admins_members:
            if vulnerable_user in member.strip():
                return "Administrators"
        
        for member in bo_members:
            if vulnerable_user in member.strip():
                return "Backup Operators"
        return "-"
    

    def TranslateTo100(self, count, length):
        return int((count/length)*100)
