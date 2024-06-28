import subprocess
from progressbar import ProgressBar, Percentage, Bar, RotatingMarker, ETA, Timer, AdaptiveETA
import time
import re

class LinuxUserAssessment():
    
    def GetUsers(self):
        pattern = r"^(.*?):(.*?):"
        local_users = []
        users = subprocess.run(["cat", "/etc/shadow"], stdout=subprocess.PIPE).stdout.decode().split("\n")
        for user in users:
            captures = re.search(pattern, user)
            if captures:
                if captures.groups()[0] and len(captures.groups()[1])>=3:
                    local_users.append(captures.groups()[0])
        
        return local_users          

    def PassCracker(self, wordlist, local_user):
        #
        # yescript
        #

        length = len(wordlist)
        count = 0
        widgets = ['Progress: ', Percentage(), ' | ', Timer(), ' | ', AdaptiveETA()]
        bar = ProgressBar(widgets=widgets, max_value=100).start()
        for password in wordlist:
            cmd = [f"su", "-l", local_user]
            
            proc = subprocess.run(cmd, input=password.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1) # Rate limiter to avoid overwhelming the target PC
            if proc.returncode == 0:
                bar.update(100)
                return True, password
            
            count+=1
            bar.update(self.TranslateTo100(count, length))

        return False, password
  
    def PrivilagedGroupsMember(self, vulnerable_user):
        return "-"



    def TranslateTo100(self, count, length):
        return int((count/length)*100)
