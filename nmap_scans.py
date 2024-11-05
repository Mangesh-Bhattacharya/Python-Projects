import nmap

# Create an instance of nmap.PortScanner
scanner = nmap.PortScanner()
# Enter the Target IP address or Hostname
target = "10.10.67.67"

# Change the arguments as per your requirement
scanner.scan(target, arguments="-sV")

# Print the results of the scan
for host in scanner.all_hosts():
    print("Host: %s (%s)" % (host, scanner[host].hostname()))
    print("State: %s" % scanner[host].state())

    for proto in scanner[host].all_protocols():
        print("Protocol: %s" % proto)

        lport = scanner[host][proto].keys()
        for port in lport:
            print("port: %s\tstate: %s" % (port, scanner[host][proto][port]["state"]))

    print()