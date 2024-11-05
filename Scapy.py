import scapy.all as scapy
import paramiko
import os
import ftplib
import socket
from typing import List


def scan_network(ip_range: str) -> List[str]:
    """Scan the network and return a list of active IPs."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                            timeout=2, verbose=False)[0]

    active_ips = []
    for element in answered_list:
        active_ips.append(element[1].psrc)

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
            sftp = client.open_sftp()
            sftp.get(os.path.join(remote_path, file), file)
            print(f'Downloaded {file} from {ip}')
            sftp.close()

        client.close()
    except Exception as e:
        print(f"SSH Error: {e}")


def ftp_file_extraction(ip: str, username: str, password: str, remote_path: str):
    """Extract files over FTP."""
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login(user=username, passwd=password)
            ftp.cwd(remote_path)
            files = ftp.nlst()

            for file in files:
                with open(file, 'wb') as f:
                    ftp.retrbinary(f'RETR {file}', f.write)
                    print(f'Downloaded {file} from {ip}')
    except Exception as e:
        print(f"FTP Error: {e}")


def main():
    # Define the target IP range or specific IP
    ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
    active_ips = scan_network(ip_range)

    print(f"Active IPs: {active_ips}")

    # Loop through each active IP and attempt file extraction
    for ip in active_ips:
        protocol = input(
            f"Enter protocol for {ip} (ssh/ftp): ").strip().lower()
        username = input("Enter username: ")
        password = input("Enter password: ")
        remote_path = input("Enter remote directory path: ")

        if protocol == "ssh":
            ssh_file_extraction(ip, username, password, remote_path)
        elif protocol == "ftp":
            ftp_file_extraction(ip, username, password, remote_path)
        else:
            print("Unsupported protocol.")


if __name__ == "__main__":
    main()
