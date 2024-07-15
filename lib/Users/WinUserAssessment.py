import subprocess
from progressbar import ProgressBar, Percentage, Timer, AdaptiveETA
import time

class WinUserAssessment():
    
    def GetUsers(self):
        cmd = ['powershell', '-c', 'Get-cimInstance -Class Win32_UserAccount | foreach { $_.Caption }']
        proc = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
        local_users = []
        for local_user in proc:
            local_users.append(local_user)
        
        return local_users
    
    
    def PassCracker(self, wordlist, local_user):
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
            time.sleep(1) # Rate limiter to avoid overwhelming the target PC
            if not error[0] and not output[0]:
                bar.update(100)
                return True, password
            
            count+=1
            bar.update(self.TranslateTo100(count, length))

        return False, password
    
    def PrivilagedGroupsMember(self, vulnerable_user):
        cmd1 = ['powershell', '-c', 'Get-LocalGroupMember -name "Administrators" | foreach {$_.Name}']
        cmd2 = ['powershell', '-c', 'Get-LocalGroupMember -name "Backup Operators" | foreach {$_.Name}']
        admins_members = (subprocess.run(cmd1, capture_output=True)).stdout.decode().split("\n")
        bo_members = (subprocess.run(cmd2, capture_output=True)).stdout.decode().split("\n")

        for member in admins_members:
            if vulnerable_user.strip().lower() in member.strip().lower():
                return "Administrators"
        
        for member in bo_members:
            if vulnerable_user.strip().lower() in member.strip().lower():
                return "Backup Operators"
        return "-"
    

    def TranslateTo100(self, count, length):
        return int((count/length)*100)
