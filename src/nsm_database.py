# THIS MODULE WILL BE RESPONSIBLE FOR TOUCHING FILES



# ETC IMPORTS
import json, datetime
from pathlib import Path


# NSM IMPORTS
from nsm_vars import Variables


# CONSTANTS
console = Variables.console

dir_database = Path(__file__).parent.parent / "database" / "results"
dir_database.mkdir(exist_ok=True, parents=True)



class DataBase():
    """This method will be responsible for opening and closing files"""



    @classmethod
    def _push_json(cls, data, name, verbose=True):
        """This method will be responsible for pushing json file"""


        try:

            dir_database.mkdir(exist_ok=True, parents=True)
            path = dir_database / name

            with open(str(path), "w") as file:

                json.dump(data, file, indent=4)

                if verbose: console.print(f"\n[bold green][+] Successfully saved file:[yellow] {path}")



        except Exception as e: console.print(f"[bold red][-] Exception Error:[yellow] {e}")



    @classmethod
    def push_bruteforce(cls, data):
        """This method will be responsible for saving bruteforce results"""


        name = datetime.datetime.now().strftime("%d_%m_%Y-%H_%M_%S")
        name = f"bruteforce{name}"
        cls._push_json(data=data, name=name)


    @classmethod
    def push_port_19000(cls, data):
        """This method will be responsible for saving port 19000 results"""


        name = datetime.datetime.now().strftime("%d_%m_%Y-%H_%M_%S")
        name = f"udp_port_{name}"
        cls._push_json(data=data, name=name)


    @classmethod
    def push_information_discolure(cls, data):
        """This method will be responsible for push information discolure"""

        name = datetime.datetime.now().strftime("%d_%m_%Y-%H_%M_%S")
        name = f"info_discolure_{name}"
        cls._push_json(data=data, name=name)



"""

=== I WILL BE WRITING AND KEEPING MY NOTES HERE FOR THE PROCCESS OF HOW I FOUND THESE VULNERABILITIES ===



step 1.

    Firmware download url: https://www.flashforge.com/blogs/download-document/adventurer-5m-pro

    Download for firmware of current vulnerabilites in this framework: https://flashforge-resource.oss-us-east-1.aliyuncs.com/AD5MP%E5%9B%BA%E4%BB%B6/Adventurer5MPro-5.1.7-2.2.3-20260605.tgz


step 2.

    extract the firmware/archive
    tar -xvf Adventurer5MPro-*.tgz 


step 3.

    Got the files: firmwareExe (main binary), flashforge_init.sh, auto_run.sh, shadow, etc.


step 4.

    strings firmwareExe — dumps every readable text string out of the compiled binary

    
step 5.

    - grep -E "^[A-Za-z0-9]{32,64}$" → found the 3 API keys
    - grep "rtmp://" → found the Chinese RTMP servers
    - grep "flashforge.com" → found cloud endpoints
    - grep "password\|passwd\|key\|secret" → found hardcoded creds


step 6.

    Read the shell scripts (flashforge_init.sh, auto_run.sh) directly — they're plaintext bash, showed us the root password deployment, RSA key
    generation with hardcoded passphrase, and the unsigned update chain


"""


"""
DNS SPOOFING TO CAPTURE API ENDPOINT SENT FROM 3D PRINTER UPON IT BOOTING UP


step 1.
# Security Research -> 3D Printer - Flash Forge Adventurer 5M Pro
192.168.1.92 api.fdmcloud.flashforge.com


step 2.

dig +short api.fdmcloud.flashforge.com
192.168.1.92

step 3. 

sudo mitmdump --mode reverse:https://104.18.12.167:443 --listen-port 443 --ssl-insecure -w flashforge_capture.flow
"""