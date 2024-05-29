import platform

class os_prober():
    def __init__(self, distro, os):
        super(os_prober, self).__init__()
        self.distro = distro
        self.os = os
    
    # Determine in which OS the script is running
    def find_os():
        os = platform.system().lower()
        if os == 'linux':
            with open('/etc/os-release') as f:
                data = [line.strip() for line in f if line.startswith(('PRETTY_NAME='))]
                distro_name = [line.split('=')[1].strip('"') for line in data][0].lower()
                if 'fedora' in distro_name or 'centos' in distro_name:
                    print(f'Running on RedHat based')
                    distro = "rh"                
                elif 'debian' in distro_name or 'ubuntu' in distro_name:
                    print(f'Running on Debian based')
                    distro = "debian" 
                return distro, os
        elif os == 'windows':
            print(f'Running on Windows')
            distro = "windows" 
            return distro, os
        else:
            print(f'OS {os} is not supported by the tool')
            exit()