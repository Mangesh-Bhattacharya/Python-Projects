######################################################################################
#####           Mangesh Bhattacharya                                             #####
#####       WAS600: Web Application Security                                     #####
#####           Prof. Mike Martin                                                #####
#####       Assignment 1B:  Description and  Submission                          #####
######################################################################################

import requests
import socket
import whois
from bs4 import BeautifulSoup

# Function to fetch HTML content
def fetch_html_content(url, headers=None):
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to fetch {url}. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred while fetching {url}: {e}")
        return None

# Function to find subdomains
def find_subdomains(html_content):
    subdomains = set()
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and 'http' in href:
                subdomain = href.split('/')[2]
                if subdomain:
                    subdomains.add(subdomain)
    except Exception as e:
        print(f"An error occurred while extracting subdomains: {e}")
    return list(subdomains)

# Function to scan ports
def scan_ports(domain):
    open_ports = []
    ip_addresses = []
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[-1]
        for ip_address in ip_addresses:
            print(f"Scanning ports for domain: {domain} ({ip_address})")
            for port in range(1, 1025):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip_address, port))
                    if result == 0:
                        service = socket.getservbyport(port) if port != 0 else None
                        open_ports.append({'ip_address': ip_address, 'port': port, 'service': service})
    except socket.timeout:
        print("Connection timed out. Skipping port.")
    except socket.error as e:
        print(f"Socket error occurred while scanning ports: {e}")
    except Exception as e:
        print(f"An error occurred while scanning ports for {domain}: {e}")

    if open_ports:
        print("Open ports found:")
        for port_info in open_ports:
            print(f"IP: {port_info['ip_address']}, Port: {port_info['port']}, Service: {port_info['service']}")
    else:
        print("No open ports found.")
    return ip_addresses, open_ports

# Function to perform WHOIS lookup
def perform_whois_lookup(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        return None

# Function to analyze response headers
def analyze_response_headers(url):
    try:
        response = requests.head(url)
        headers = response.headers
        print("Response Headers:")
        for header, value in headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        print(f"An error occurred while analyzing response headers: {e}")

# Function to perform directory and file enumeration
def enumerate_directories_files(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("Directory and File Enumeration:")
            # Example: Extracting links from HTML content for demonstration
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [link.get('href') for link in soup.find_all('a')]
            for link in links:
                print(link)
        else:
            print(f"Failed to fetch {url}. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while enumerating directories and files: {e}")

# Function to discover users
def discover_users(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Example: Extracting email addresses from HTML content for demonstration
            soup = BeautifulSoup(response.text, 'html.parser')
            emails = [email.text for email in soup.find_all('a', href=lambda href: href and 'mailto:' in href)]
            print("Discovered users (email addresses):")
            for email in emails:
                print(email)
        else:
            print(f"Failed to fetch {url}. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while discovering users: {e}")

# Main function
def main():
    target_url = "https://www.wemix.com"
    print(f"Performing reconnaissance on: {target_url}")

    # Define custom headers to bypass WAF
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    # Fetch HTML content of the website with custom headers
    print("Fetching HTML content...")
    html_content = fetch_html_content(target_url, headers=headers)
    if html_content:
        # Extract subdomains
        print("Extracting subdomains...")
        subdomains = find_subdomains(html_content)
        print("Subdomains:")
        for subdomain in subdomains:
            print("-", subdomain)

        # Scan ports of the main domain
        print("Scanning ports...")
        domain = target_url.split("//")[-1].split("/")[0]
        ip_addresses, open_ports = scan_ports(domain)

        # Perform WHOIS lookup
        print("Performing WHOIS lookup...")
        whois_info = perform_whois_lookup(domain)
        if whois_info:
            print("WHOIS Information:")
            print(whois_info)

        # Analyze response headers
        print("Analyzing response headers...")
        analyze_response_headers(target_url)

        # Perform directory and file enumeration
        print("Enumerating directories and files...")
        enumerate_directories_files(target_url)

        # Discover users
        print("Discovering users...")
        discover_users(target_url)

if __name__ == "__main__":
    main()
