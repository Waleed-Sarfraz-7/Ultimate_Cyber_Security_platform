import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import os
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_if_addr, Raw
import time
import csv

# === Globals ===
selected_interface = None
protocol_filter = "all"
sniffing = False
interface_frames = {}
interface_status = {}
animation_running = True
csv_file = None
csv_writer = None

# === Packet Handler ===
def handle_packet(packet):
    global csv_writer

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if protocol_filter == "tcp" and not packet.haslayer(TCP):
            return
        if protocol_filter == "udp" and not packet.haslayer(UDP):
            return
        if protocol_filter == "icmp" and not packet.haslayer(ICMP):
            return

        # Prepare packet details for display
        output = "\n[+] Packet Captured\n"
        output += f"From: {src_ip} -> To: {dst_ip}\n"

        if packet.haslayer(TCP):
            output += f"TCP Segment: {packet[TCP].sport} -> {packet[TCP].dport}\n"
        elif packet.haslayer(UDP):
            output += f"UDP Segment: {packet[UDP].sport} -> {packet[UDP].dport}\n"
        elif packet.haslayer(ICMP):
            output += "ICMP Packet\n"

        # Try extracting and decoding the payload (just for display, not saving to CSV)
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                decoded_data = raw_data.decode('utf-8')
                output += f"Payload Data:\n{decoded_data}\n"
            except UnicodeDecodeError:
                output += f"Payload Data (hex):\n{raw_data.hex()}\n"
        else:
            output += "No Payload Data\n"

        # Display packet in the output box
        output_box.insert(tk.END, output)
        output_box.see(tk.END)

        # Save packet details to CSV (excluding payload)
        if csv_writer:
            if packet.haslayer(TCP):
                csv_writer.writerow([src_ip, dst_ip, "TCP", packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                csv_writer.writerow([src_ip, dst_ip, "UDP", packet[UDP].sport, packet[UDP].dport])
            elif packet.haslayer(ICMP):
                csv_writer.writerow([src_ip, dst_ip, "ICMP", "N/A", "N/A"])

# === Sniff Functions ===
def start_sniffing():
    global sniffing, csv_writer, csv_file

    sniffing = True
    output_box.insert(tk.END, f"\n[*] Sniffing on {selected_interface} | Filter: {protocol_filter.upper()}\n")

    # Open the CSV file to write packet data (Only open once during sniffing)
    if csv_file is None:
        csv_file = open("packet_data.csv", "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])  # Write header

    # Start sniffing
    sniff(prn=handle_packet, iface=selected_interface, store=False, stop_filter=lambda x: not sniffing)

def start_sniffing_thread():
    global sniffing
    if selected_interface:
        thread = threading.Thread(target=start_sniffing)
        thread.daemon = True
        thread.start()
    else:
        messagebox.showerror("Error", "Please select a network interface first.")

def stop_sniffing():
    global sniffing, csv_file
    sniffing = False
    output_box.insert(tk.END, "\n[!] Sniffing stopped.\n")

    # Close CSV file when sniffing stops
    if csv_file:
        csv_file.close()
        csv_file = None
        csv_writer = None
        output_box.insert(tk.END, "[+] Packet data saved to packet_data.csv\n")

# === Interface Functions ===
def list_interfaces():
    interfaces = get_if_list()
    iface_info = []
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "N/A"

        try:
            stats = psutil.net_if_stats()[iface]
            status = "UP" if stats.isup else "DOWN"
        except:
            status = "UNKNOWN"

        iface_info.append((iface, ip, status))
    return iface_info

def select_interface(iface):
    global selected_interface
    selected_interface = iface
    interface_label.config(text=f"Selected Interface: {iface}")

def update_interface_status():
    while animation_running:
        interfaces = list_interfaces()
        for iface, ip, status in interfaces:
            color = "green" if status == "UP" else "grey"
            if iface in interface_frames:
                label, color_frame = interface_frames[iface]
                color_frame.config(bg=color)
        time.sleep(1)  # Update every 1 second

def refresh_interfaces():
    for widget in scrollable_frame.winfo_children():
        widget.destroy()

    interface_frames.clear()

    for iface, ip, status in list_interfaces():
        frame = tk.Frame(scrollable_frame, pady=5)
        frame.pack(fill="x", padx=5)

        color = "green" if status == "UP" else "grey"
        
        color_frame = tk.Frame(frame, width=15, height=15, bg=color)
        color_frame.pack(side="left", padx=5)

        label = tk.Label(frame, text=f"{iface} ({ip})", font=("Arial", 11), anchor="w")
        label.pack(side="left", fill="x", expand=True)
        label.bind("<Button-1>", lambda e, iface=iface: select_interface(iface))

        interface_frames[iface] = (label, color_frame)

# === Protocol Functions ===
def set_protocol(event):
    global protocol_filter
    selected = protocol_combo.get()
    protocol_filter = selected.lower()
    protocol_label.config(text=f"Filter: {selected}")

# === Tkinter App ===
import time

app = tk.Tk()
app.title("Packet Sniffer")
app.geometry("1100x700")
app.minsize(900, 600)
app.columnconfigure(1, weight=1)
app.rowconfigure(1, weight=1)

# Left Frame (Interfaces)
frame_left = tk.Frame(app, bd=2, relief="sunken", width=1000)
frame_left.grid(row=0, column=0, rowspan=2, sticky="ns")
frame_left.grid_propagate(False)

tk.Label(frame_left, text="Network Interfaces", font=("Arial", 14)).pack(pady=5)

interface_canvas = tk.Canvas(frame_left)
scrollbar = ttk.Scrollbar(frame_left, orient="vertical", command=interface_canvas.yview)
scrollable_frame = tk.Frame(interface_canvas)

scrollable_frame.bind(
    "<Configure>",
    lambda e: interface_canvas.configure(
        scrollregion=interface_canvas.bbox("all")
    )
)

interface_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
interface_canvas.configure(yscrollcommand=scrollbar.set)

interface_canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Top Frame (Protocol selection, Buttons)
frame_top = tk.Frame(app)
frame_top.grid(row=0, column=1, sticky="ew", pady=10)
frame_top.columnconfigure(4, weight=1)

tk.Label(frame_top, text="Protocol Filter:").grid(row=0, column=0, padx=5)
protocols = ["ALL", "TCP", "UDP", "ICMP"]
protocol_combo = ttk.Combobox(frame_top, values=protocols)
protocol_combo.grid(row=0, column=1)
protocol_combo.bind("<<ComboboxSelected>>", set_protocol)

protocol_label = tk.Label(frame_top, text="Filter: ALL")
protocol_label.grid(row=0, column=2, padx=10)

start_button = tk.Button(frame_top, text="Start Sniffing", command=start_sniffing_thread, bg="green", fg="white", width=15)
start_button.grid(row=0, column=3, padx=5)

stop_button = tk.Button(frame_top, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15)
stop_button.grid(row=0, column=4, padx=5)

interface_label = tk.Label(frame_top, text="Selected Interface: None")
interface_label.grid(row=1, column=0, columnspan=5, pady=5)

# Main Frame (Output)
frame_main = tk.Frame(app)
frame_main.grid(row=1, column=1, sticky="nsew")
frame_main.columnconfigure(0, weight=1)
frame_main.rowconfigure(0, weight=1)

output_box = scrolledtext.ScrolledText(frame_main, wrap="word")
output_box.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

# Start the App
refresh_interfaces()

# Start thread for updating interface status live
thread = threading.Thread(target=update_interface_status)
thread.daemon = True
thread.start()

app.mainloop()

# Close the CSV file when the app exits
if csv_file:
    csv_file.close()
