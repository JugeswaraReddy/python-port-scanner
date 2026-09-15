#!/usr/bin/env python3

import socket
import nmap
from datetime import datetime


def network_scan(target, start_port, end_port):
    print(f"\nStarting scan for: {target}")
    print("-" * 50)

    start_time = datetime.now()

    # Resolve hostname
    try:
        hostname = socket.gethostbyaddr(target)[0]
    except socket.herror:
        hostname = "Unknown"

    print(f"Host/IP      : {target}")
    print(f"Hostname     : {hostname}")

    # Nmap scanner
    scanner = nmap.PortScanner()

    print("\nScanning ports and detecting OS...")

    try:
        scanner.scan(
            target,
            arguments=f"-sV -O -p {start_port}-{end_port}"
        )
    except Exception as e:
        print(f"Nmap error: {e}")
        return

    if target not in scanner.all_hosts():
        print("Host appears to be down or unreachable.")
        return

    host = scanner[target]

    # OS detection
    os_name = "Unknown"

    if "osmatch" in host and host["osmatch"]:
        os_name = host["osmatch"][0]["name"]

    print(f"OS           : {os_name}")

    # Open ports
    print("\nOpen Ports:")
    print("-" * 50)

    for protocol in host.all_protocols():
        ports = host[protocol].keys()

        for port in sorted(ports):
            state = host[protocol][port]["state"]
            service = host[protocol][port]["name"]
            product = host[protocol][port].get("product", "")
            version = host[protocol][port].get("version", "")

            if state == "open":
                print(
                    f"{port:<8} {protocol:<8} "
                    f"{service:<12} {product} {version}"
                )
    end_time = datetime.now()

    print("\n" + "-" * 50)
    print(f"Scan completed in: {end_time - start_time}")


if __name__ == "__main__":

    target_ip = input("Enter the target IP or hostname: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))

    network_scan(target_ip, start_port, end_port)
