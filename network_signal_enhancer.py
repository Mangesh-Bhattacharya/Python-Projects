import psutil
from prettytable import PrettyTable
import socket


def collect_network_data():
    """Collect network data including interface names, addresses, and statistics."""
    network_data = []

    # Get all network interfaces and their addresses
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Get only IPv4 addresses
                # Collect network statistics
                interface_stats = stats[interface]
                data = {
                    'Interface': interface,
                    'IP Address': addr.address,
                    'Netmask': addr.netmask,
                    'Broadcast': addr.broadcast,
                    'Is Up': interface_stats.isup,
                    'Speed (Mbps)': interface_stats.speed,
                    'MTU': interface_stats.mtu,
                }
                network_data.append(data)

    return network_data


def display_network_data(network_data):
    """Display collected network data in a table format with explanations."""
    print("Network Signal Enhancer Report")
    print("=" * 40)
    print("This report summarizes the current state of your network interfaces.\n")

    table = PrettyTable()
    table.field_names = ["Interface", "IP Address",
                         "Netmask", "Broadcast", "Is Up", "Speed (Mbps)", "MTU"]

    for data in network_data:
        table.add_row([
            data['Interface'],
            data['IP Address'],
            data['Netmask'],
            data['Broadcast'],
            data['Is Up'],
            data['Speed (Mbps)'],
            data['MTU']
        ])

    print(table)

    print("\nLegend:")
    print("Interface: The name of the network interface (e.g., eth0, wlan0).")
    print("IP Address: The current IP address assigned to the interface.")
    print("Netmask: The subnet mask of the network.")
    print("Broadcast: The broadcast address used by the network.")
    print("Is Up: Indicates if the interface is active (True) or inactive (False).")
    print("Speed (Mbps): The speed of the interface in megabits per second.")
    print("MTU: The maximum transmission unit size in bytes.")


def main():
    """Main function to run the Network Signal Enhancer."""
    print("Starting Network Signal Enhancer...\n")

    # Collect network data
    network_data = collect_network_data()

    # Check if any network data was collected
    if not network_data:
        print("No active network interfaces found.")
    else:
        # Display the collected data
        display_network_data(network_data)


if __name__ == "__main__":
    main()
