import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import ipaddress

# ---------------- VPN Detection Logic ---------------- #

VPN_PROTOCOLS = {
    'OpenVPN': 1194,
    'IKEv2': 500,
    'PPTP': 1723,
    'L2TP': 1701,
    'WARP': 443,
}

VPN_PORTS = [1194, 500, 4500, 1701, 1723, 51820]

VPN_IP_RANGES = [
    '185.5.230.0/24',
    '185.8.230.0/24',
    '104.28.0.0/16',
    '162.159.192.0/24',
    '8.25.96.0/24',
    '8.47.15.0/24',
    '8.41.6.0/24',
    '8.21.110.0/24',
    '8.41.7.0/24',
    '51.158.253.0/24'
]

def is_vpn_packet(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
            dst_port = transport_layer.dport
            src_port = transport_layer.sport
            if dst_port in VPN_PORTS or src_port in VPN_PORTS:
                return True
    return False

def is_vpn_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        for vpn_range in VPN_IP_RANGES:
            if ip_addr in ipaddress.ip_network(vpn_range):
                return True
        if ip.startswith('51.'):
            return True
    except ValueError:
        return False
    return False

def detect_vpn(packet):
    if is_vpn_packet(packet):
        return "⚡ VPN traffic suspected based on port behavior."
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if is_vpn_ip(ip_src) or is_vpn_ip(ip_dst):
            return f"⚡ VPN Detected: {ip_src} or {ip_dst} is in a known VPN range."
    return None

# ---------------- Tkinter GUI Setup ---------------- #

class VPNDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN Traffic Detector")
        self.root.geometry("700x500")
        self.sniffing = False

        self.start_button = tk.Button(root, text="Start Sniffing", bg="green", fg="white", width=20, command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", bg="red", fg="white", width=20, command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=25, font=("Courier", 10))
        self.text_area.pack(pady=10)

    def packet_callback(self, packet):
        result = detect_vpn(packet)
        if result:
            self.text_area.insert(tk.END, result + "\n")
            self.text_area.see(tk.END)
        else:
            self.text_area.insert(tk.END, f"Packet: {packet.summary()}\n")
            self.text_area.see(tk.END)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, filter="ip", promisc=True, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, "🚀 Started packet sniffing...\n")
            self.text_area.see(tk.END)
            threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.text_area.insert(tk.END, "🛑 Stopping sniffing...\n")
            self.text_area.see(tk.END)
            messagebox.showinfo("Stopped", "Packet sniffing stopped successfully!")

# ---------------- Main Execution ---------------- #

if __name__ == "__main__":
    root = tk.Tk()
    app = VPNDetectorApp(root)
    root.mainloop()
