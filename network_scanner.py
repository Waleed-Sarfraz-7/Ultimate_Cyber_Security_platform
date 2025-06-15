from scapy.all import ARP, Ether, srp, conf, IP, ICMP, sr1
import ipaddress
import socket
import os
import time

# Get local IP
def get_my_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

# ARP scan function
def arp_scan(network_cidr):
    print(f"🔍 Scanning network: {network_cidr}")
    
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Increase timeout and retry
    result = srp(packet, timeout=7, retry=5, verbose=0)[0]

    active_devices = []
    seen_ips = set()

    for sent, received in result:
        if received.psrc not in seen_ips:
            active_devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            seen_ips.add(received.psrc)
    
    return active_devices

# Ping scan function (combined with ARP)
def ping_scan(network_cidr):
    active_devices = []
    print(f"🌐 Pinging devices in network: {network_cidr}")
    
    # Loop through each IP in the subnet and ping it
    for ip in ipaddress.IPv4Network(network_cidr, strict=False):
        ip_str = str(ip)
        response = sr1(IP(dst=ip_str)/ICMP(), timeout=1, verbose=0)
        if response:
            print(f"✔️ Device found at {ip_str} (responded to ping)")
            active_devices.append({'ip': ip_str, 'mac': "N/A (ping only)"})  # No MAC via ping
        
    return active_devices

# Main logic for ARP + Ping Scan
if __name__ == "__main__":
    conf.verb = 0  # Disable Scapy verbosity globally
    
    my_ip = get_my_ip()
    network = ipaddress.IPv4Network(my_ip + '/24', strict=False)
    
    # First, try ARP scan to find devices with MAC addresses
    devices = arp_scan(str(network))
    
    if not devices:
        print("⚠ No devices found via ARP. Trying Ping scan instead.")
        devices = ping_scan(str(network))

    # Display found devices
    if devices:
        print("\n--- 🖥️ Active Devices ---")
        for device in devices:
            print(f"IP: {device['ip']} \tMAC: {device['mac']}")
    else:
        print("⚠ No active devices found. Consider increasing timeout or checking connection.")
