import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import *
import threading
import ipaddress
import queue
import os
import random
import string

# Function to send a fuzzed packet (generalized)
def send_fuzzed_packet(packet, target_ip, output_queue):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        fuzzed_packet = fuzz(packet)  # Fuzz the packet
        send(fuzzed_packet, verbose=False)  # Send the fuzzed packet
        output_queue.put(f"Fuzzed packet sent to {target_ip}")
    except Exception as e:
        output_queue.put(f"Error sending fuzz packet: {e}")

def generate_random_hostname(length=10):
    """Generate a random hostname for fuzzing, consisting of random letters."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_domain(length=15):
    """Generate a random domain name."""
    return f"{''.join(random.choices(string.ascii_lowercase, k=length))}.com"

# Function to send SYN packet
def send_syn_packet(target_ip, target_port, output_queue):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        if not (0 <= target_port <= 65535):
            raise ValueError("Invalid port number. Port must be between 0 and 65535.")
            
        ip = IP(dst=target_ip)
        tcp = TCP(dport=target_port, flags='S', sport=RandShort(), seq=1000)
        syn_packet = ip/tcp
        send(syn_packet, verbose=False)
        output_queue.put(f"SYN packet sent to {target_ip}:{target_port}")
    except Exception as e:
        output_queue.put(f"Error sending SYN packet: {e}")

# Function to handle DNS Fuzzing
def send_dns_fuzzer(target_ip, output_queue, payload):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        
        # Construct a DNS packet
        ip = IP(dst=target_ip)
        udp = UDP(dport=53)  # DNS uses port 53
        
        # Fuzz the DNS packet (the domain name or query type)
        fuzzed_domain_name = payload if payload else generate_random_domain()
        dns = DNS(rd=1, qd=DNSQR(qname=fuzzed_domain_name.encode(), qtype="A"))  # Standard DNS query
        
        # Send the fuzzed DNS packet
        threading.Thread(target=send_fuzzed_packet, args=(ip/udp/dns, target_ip, output_queue), daemon=True).start()
    except Exception as e:
        output_queue.put(f"Error sending DNS fuzz packet: {e}")

# Function to handle DHCP Fuzzing
def send_dhcp_fuzzer(target_ip, output_queue, payload):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        
        # Construct a DHCP Discover packet
        eth = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        ip = IP(dst=target_ip, src="0.0.0.0")  # Source IP 0.0.0.0 (DHCP Discover)
        udp = UDP(sport=68, dport=67)  # DHCP Discover uses UDP port 67 and 68
        
        hostname = payload if payload else generate_random_hostname()
        dhcp = DHCP(options=[("message-type", "discover"), ("hostname", hostname.encode()), "end"])  # Fuzzing hostname as an example

        dhcp_packet = eth/ip/udp/dhcp
        
        # Send the fuzzed DHCP packet
        threading.Thread(target=send_fuzzed_packet, args=(dhcp_packet, target_ip, output_queue), daemon=True).start()
    except Exception as e:
        output_queue.put(f"Error sending DHCP fuzz packet: {e}")

# Function to handle ICMP Fuzzing
def send_icmp_fuzzer(target_ip, output_queue, payload):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        
        # Construct a basic ICMP Echo Request (ping)
        ip = IP(dst=target_ip)
        icmp_type = random.randint(0, 255)  # Randomize ICMP type for fuzzing
        icmp = ICMP(type=icmp_type, id=RandShort(), seq=RandShort())
        
        if payload:
            icmp = ICMP(type=icmp_type, id=RandShort(), seq=RandShort()) / Raw(load=payload.encode())  # Adding fuzzed payload
        
        icmp_packet = ip/icmp
        
        # Send the fuzzed ICMP packet
        threading.Thread(target=send_fuzzed_packet, args=(icmp_packet, target_ip, output_queue), daemon=True).start()
    except Exception as e:
        output_queue.put(f"Error sending ICMP fuzz packet: {e}")

def on_send_button_click():
    target_ip = ip_entry.get()
    target_port = port_entry.get()
    src_ip = src_ip_entry.get()
    src_port = src_port_entry.get()
    payload = payload_entry.get()
    selected_option = packet_type.get()
    output_text.delete(1.0, tk.END)  # Clear previous output

    output_queue = queue.Queue()  # Create a queue for output messages

    # Validate inputs and send packets
    error_message = ""
    if not target_ip:
        error_message += "Target IP is required.\n"
    if selected_option in ["SYN Packet", "NTP Fuzzer", "Custom UDP Packet"] and not target_port:
        error_message += "Target Port is required for selected packet types.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet"] and not src_ip:
        error_message += "Source IP is required for NTP and Custom UDP packets.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet"] and not src_port:
        error_message += "Source Port is required for NTP and Custom UDP packets.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet", "DHCP Fuzzer", "ICMP Fuzzer"] and payload == "":
        error_message += "Payload is required for the selected packet types.\n"

    if error_message:
        output_text.insert(tk.END, f"Errors:\n{error_message}")
        return  # Exit if there are errors

    if selected_option == "SYN Packet":
        try:
            target_port = int(target_port)
            threading.Thread(target=send_syn_packet, args=(target_ip, target_port, output_queue), daemon=True).start()

        except ValueError as e:
            output_text.insert(tk.END, f"Invalid port number: {e}\n")
            return

    elif selected_option == "NTP Fuzzer":
        try:
            target_port = int(target_port)
            src_port = int(src_port)

            ip = IP(src=src_ip, dst=target_ip)
            udp = UDP(sport=src_port, dport=target_port)

            # If the payload is a file, read it; otherwise, treat it as a string
            if os.path.isfile(payload):
                with open(payload, "rb") as file:
                    custom_payload = Raw(load=file.read())
            else:
                custom_payload = Raw(load=payload.encode())

            ntp_packet = ip/udp/custom_payload
            threading.Thread(target=send_fuzzed_packet, args=(ntp_packet, target_ip, output_queue), daemon=True).start()

        except ValueError as e:
            output_text.insert(tk.END, f"Error: {e}\n")

    elif selected_option == "DNS Fuzzer":
        # Call the DNS fuzzer function
        send_dns_fuzzer(target_ip, output_queue, payload)

    elif selected_option == "DHCP Fuzzer":
        # Call the DHCP fuzzer function
        send_dhcp_fuzzer(target_ip, output_queue, payload)

    elif selected_option == "ICMP Fuzzer":
        # Call the ICMP fuzzer function
        send_icmp_fuzzer(target_ip, output_queue, payload)

    # Updating output text every 100ms
    def update_output_text():
        try:
            while True:  # Consume all messages in the queue
                message = output_queue.get_nowait()
                output_text.insert(tk.END, message + "\n")
            root.after(100, update_output_text)
        except queue.Empty:
            root.after(100, update_output_text)

    # Start updating output text
    update_output_text()

def update_port_fields(*args):
    selected_option = packet_type.get()
    show_port_fields = selected_option in ["SYN Packet", "Custom UDP Packet", "NTP Fuzzer", "DNS Fuzzer", "DHCP Fuzzer", "ICMP Fuzzer"]
    
    if show_port_fields:
        port_entry_label.pack(pady=5)
        port_entry.pack(pady=5)
        src_ip_entry_label.pack(pady=5)
        src_ip_entry.pack(pady=5)
        src_port_entry_label.pack(pady=5)
        src_port_entry.pack(pady=5)
        payload_entry_label.pack(pady=5)
        payload_entry.pack(pady=5)
    else:
        port_entry_label.pack_forget()
        port_entry.pack_forget()
        src_ip_entry_label.pack_forget()
        src_ip_entry.pack_forget()
        src_port_entry_label.pack_forget()
        src_port_entry.pack_forget()
        payload_entry_label.pack_forget()
        payload_entry.pack_forget()

# Create the main window
root = tk.Tk()
root.title("Packet Fuzzer Tool")

# Warning Message
messagebox.showwarning("Warning", """
WARNING: 
Sending unsolicited packets or fuzzing protocols to networks you do not own or have permission to test is illegal and unethical.
Ensure you have authorization to conduct your tests.
""")

# Instruction Labels
tk.Label(root, text="Enter the Target IP Address").pack(pady=5)
ip_entry = tk.Entry(root)
ip_entry.pack(pady=5)

packet_type = tk.StringVar()
packet_type.set("SYN Packet")  # Default to SYN Packet

# Dropdown for Packet Type Selection
packet_type_menu = tk.OptionMenu(root, packet_type, "SYN Packet", "NTP Fuzzer", "DNS Fuzzer", "DHCP Fuzzer", "ICMP Fuzzer", "Custom UDP Packet")
packet_type_menu.pack(pady=10)

# Update port fields when packet type changes
packet_type.trace("w", update_port_fields)

# Port-related fields
port_entry_label = tk.Label(root, text="Target Port:")
port_entry = tk.Entry(root)

src_ip_entry_label = tk.Label(root, text="Source IP:")
src_ip_entry = tk.Entry(root)

src_port_entry_label = tk.Label(root, text="Source Port:")
src_port_entry = tk.Entry(root)

payload_entry_label = tk.Label(root, text="Payload (or file path):")
payload_entry = tk.Entry(root)

# Checkbox to save packets to pcap
save_pcap_var = tk.BooleanVar()
save_pcap_checkbox = tk.Checkbutton(root, text="Save to pcap", variable=save_pcap_var)
save_pcap_checkbox.pack(pady=10)

# Send Packet Button
send_button = tk.Button(root, text="Send Packet", command=on_send_button_click)
send_button.pack(pady=10)

# Output text widget with scrolling capability
output_text = scrolledtext.ScrolledText(root, height=10, width=50)
output_text.pack(pady=5)

# Status bar (optional)
status_label = tk.Label(root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Start the Tkinter main loop
root.mainloop()
