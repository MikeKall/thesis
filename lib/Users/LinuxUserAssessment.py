import subprocess
from progressbar import ProgressBar, Percentage, Bar, RotatingMarker, ETA, Timer, AdaptiveETA
import time
import re
import pam
import grp
#from subprocess import Popen, PIPE, STDOUT
#from pexpect import pxssh

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
            #cmd = [ "echo", password, "|", "su", "-l", local_user]
            
            #subprocess.check_call("lib/Users/executor.sh %s %s" % (str(password), str(local_user)), shell=True)
            #proc = subprocess.check_output(cmd, shell=True)#, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            p = pam.pam()
            auth = p.authenticate(local_user, password)
            if auth:
                bar.update(100)
                return True, password
            time.sleep(0.5) # Rate limiter to avoid overwhelming the target PC
            
            count+=1
            bar.update(self.TranslateTo100(count, length))

        return False, password
  
    def PrivilagedGroupsMember(self, vulnerable_user, distro):
        if distro == "rh":
            try:
                sudoers = grp.getgrnam("wheel").gr_mem
                if vulnerable_user in sudoers:
                    return "wheel"
            except KeyError:
                # Group 'wheel' does not exist
                return "-"
        else:
            try:
                sudoers = grp.getgrnam("sudo").gr_mem
                if vulnerable_user in sudoers:
                    return "sudoers"
            except KeyError:
                # Group 'sudo   ' does not exist
                return "-"
        return "-"  



    def TranslateTo100(self, count, length):
        return int((count/length)*100)
