import subprocess
import progressbar
import time

class assess_users():
    
    def __init__(self, distro):
        super(assess_users, self).__init__()
        self.distro = distro

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
        bar = progressbar.ProgressBar(max_value=length)
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
                return True, password
            
            count+=1
            bar.update(count)

        return False, password

    def PrivilagedGroupsMember(self, vulnerable_user):
        cmd = ['powershell', '-c', 'Get-LocalGroupMember -name "Administrators" | foreach {$_.Name}']
        group_members = (subprocess.run(cmd, capture_output=True)).stdout.decode().split("\n")
        for member in group_members:
            if vulnerable_user == member.strip():
                return vulnerable_user
    