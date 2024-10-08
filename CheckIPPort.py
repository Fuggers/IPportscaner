# Author: Cody Jones
# Email: Cody28353@gmail.com
# Copyright: Copyright Red Opal Innovations
# License: Proprietary
# Last Updated: [21/06/24]
# Version: 1.0.1
# Status: Development

# Overview: This script is an IP port scanner. It scans a target IP address for open ports within a given subnet mask.
# The script reads a list of ports from a file and attempts to establish a connection to each port on the target IP.
# If the connection is successful, it logs that the port is open; otherwise, it logs that the port is closed.
# The script handles various scenarios such as invalid user input,
# unavailable IP address, and provides a method for the user to exit the script gracefully.

import pyfiglet
import sys
import socket
import datetime
import ipaddress
import win32evtlogutil

ascii_banner = pyfiglet.figlet_format("IP PORT SCANNER")
print(ascii_banner)


def write_windows_event_log(mylist, event_type):
    ip_evt_app_name = "My Port Scanner"
    ip_evt_id = 7040
    ip_evt_category = 9876
    ip_evt_strs = [status for status in mylist]
    ip_evt_data = b"Scan IP Address Event Data"
    win32evtlogutil.ReportEvent(ip_evt_app_name, ip_evt_id,
                                eventCategory=ip_evt_category, eventType=event_type,
                                strings=ip_evt_strs, data=ip_evt_data)


try:
    subnet_prefix = input("Enter Subnet Prefix (e.g., 192.168.0): ")
    subnet_mask = input("Enter Subnet Mask (e.g., 255.255.255.0): ")

    # Validate subnet prefix and mask
    try:
        subnet = f"{subnet_prefix}.0/{subnet_mask}"
        network = ipaddress.IPv4Network(subnet, strict=False)
        validation_message = "The subnet prefix and mask were valid. Now scanning the range of IPs."
        print(validation_message)
    except ValueError as ve:
        validation_error_message = f"Invalid subnet prefix or subnet mask. Each octet must be in the range 0-255: {ve}"
        print(validation_error_message)
        raise ValueError(validation_error_message)

    # Prompt for termination input
    terminate_input = input("Enter 'x' to terminate the script or any other key to continue: ")
    if terminate_input.lower() == 'x':
        exit_message = "Exiting due to user request."
        print(exit_message)
        sys.exit()

    start_message = f"Scanning Target Range: {network.network_address} to {network.broadcast_address}"
    print("_" * 50)
    print(start_message)
    print("Scanning started at: " + datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"))
    print("_" * 50)

    # Read ports from ports.txt file assuming ports.txt is in the same directory as this script
    ports_file_path = "ports.txt"
    with open(ports_file_path, 'r') as ports_file:
        ports = [int(port.strip()) for port in ports_file.readlines()]

    with open("ip_port_log.txt", "w") as log_file:
        for ip in network.hosts():
            if ip.packed[-1] <= 10 or ip.packed[-1] % 2 == 0:  # Skip reserved IPs (first 10 for printers) and even IPs
                continue

            target_ip = str(ip)
            print(f"Scanning IP: {target_ip}")
            log_file.write(f"[{datetime.datetime.now()}] Scanning IP: {target_ip}\n")
            log_file.flush()  # Ensure data is written to the file immediately

            for port in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        socket.setdefaulttimeout(2)
                        result = s.connect_ex((target_ip, port))
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
                        if result == 0:
                            open_port_message = f"[*] Port {port} open on {target_ip} - {timestamp}"
                            print(open_port_message)
                            log_file.write(f"[{timestamp}] Port {port} is open on {target_ip}\n")
                        else:
                            closed_port_message = f"[*] Port {port} closed on {target_ip} - {timestamp}"
                            print(closed_port_message)
                            log_file.write(f"[{timestamp}] Port {port} is closed on {target_ip}\n")
                        log_file.flush()  # Ensure data is written to the file immediately
                except KeyboardInterrupt:
                    exit_message = "\nExiting :("
                    print(exit_message)
                    log_file.write(f"[{datetime.datetime.now()}] {exit_message}\n")
                    log_file.flush()  # Ensure data is written to the file immediately
                    sys.exit()
                except ConnectionRefusedError:
                    refused_message = f"Port {port} is closed on {target_ip}"
                    print(refused_message)
                    log_file.write(f"[{datetime.datetime.now()}] {refused_message}\n")
                    log_file.flush()  # Ensure data is written to the file immediately
                except socket.error:
                    unreachable_message = f"Cannot reach IP address: {target_ip}"
                    print(unreachable_message)
                    log_file.write(f"[{datetime.datetime.now()}] {target_ip} unavailable\n")
                    log_file.flush()  # Ensure data is written to the file immediately

except ValueError as ve:
    error_message = f"Invalid subnet prefix or subnet mask: {ve}"
    print(error_message)
    with open("ip_port_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.datetime.now()}] {error_message}\n")
        log_file.flush()  # Ensure data is written to the file immediately
except KeyboardInterrupt:
    exit_message = "\nExiting :("
    print(exit_message)
    with open("ip_port_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.datetime.now()}] {exit_message}\n")
        log_file.flush()  # Ensure data is written to the file immediately
    sys.exit()
except Exception as e:
    generic_error_message = f"An error occurred: {e}"
    print(generic_error_message)
    with open("ip_port_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.datetime.now()}] {generic_error_message}\n")
        log_file.flush()  # Ensure data is written to the file immediately
