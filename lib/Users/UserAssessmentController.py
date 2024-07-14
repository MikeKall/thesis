import subprocess
import re

class UserAssessmentController():
    
    def __init__(self, distro, os):
        self.distro = distro
        self.os = os

        if os == "windows":
            import lib.Users.WinUserAssessment as WinUserAssessment
            self.WinUsers_obj = WinUserAssessment.WinUserAssessment()
        elif os == "linux":
            import lib.Users.LinuxUserAssessment as LinuxUserAssessment
            self.LinuxUsers_obj = LinuxUserAssessment.LinuxUserAssessment()

    def GetVulnerableUsers(self):
        local_users = []
        if self.os == "windows":
            local_users = self.WinUsers_obj.GetUsers()

        elif self.os == "linux":
            pattern = r"^(.*?):(.*?):"
            local_users = []
            users = subprocess.run(["cat", "/etc/shadow"], stdout=subprocess.PIPE).stdout.decode().split("\n")
            for user in users:
                captures = re.search(pattern, user)
                if captures:
                    if captures.groups()[0] and len(captures.groups()[1])>=3:
                        local_users.append(captures.groups()[0])

        else:
            print(f"Couldn't find os {self.os}")
        
        return local_users


    def PrivilagedGroupsMember(self, user):
        if self.os == "windows":
            return self.WinUsers_obj.PrivilagedGroupsMember(user)
        
        elif self.os == "linux":
            return self.LinuxUsers_obj.PrivilagedGroupsMember(user, self.distro)


    def ReadWordlist(self, wordlist_f):
        wordlist = []
        print("Loading wordlist. This might take a while.")
        with open(wordlist_f, 'r', encoding="utf8") as file:
            content = file.read().splitlines()
        
        for line in content:
            wordlist.append(line)

        print("Wordlist loaded\n")
        return wordlist

    def PassCracker(self, wordlist, local_user):
        if self.os == "windows":
            return self.WinUsers_obj.PassCracker(wordlist, local_user)
        elif self.os == "linux":
            return self.LinuxUsers_obj.PassCracker(wordlist, local_user)
