import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import filedialog  # Import filedialog for file selection
from scapy.all import *
import threading
import ipaddress
import queue
import os
import random
import string

# Function to create an entry with a placeholder
def create_entry_with_placeholder(parent, label_text, placeholder_text):
    label = tk.Label(parent, text=label_text)
    label.pack(pady=5)
    
    entry = tk.Entry(parent)
    entry.placeholder = placeholder_text
    entry.insert(0, placeholder_text)
    entry.config(fg='grey')
    
    # Bind focus in and focus out events to handle placeholders
    entry.bind("<FocusIn>", lambda event: clear_placeholder(event))
    entry.bind("<FocusOut>", lambda event: set_placeholder(event))
    
    entry.pack(pady=5)
    return entry

def clear_placeholder(event):
    if event.widget.get() == event.widget.placeholder:
        event.widget.delete(0, 'end')
        event.widget.config(fg='black')

def set_placeholder(event):
    if event.widget.get() == "":
        event.widget.insert(0, event.widget.placeholder)
        event.widget.config(fg='grey')

# Function to read content from a text file
def load_payload_from_text_file():
    filepath = filedialog.askopenfilename(title="Select a Payload File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    if filepath:
        with open(filepath, 'r') as file:
            payload = file.read()  # Read the content of the file
            payload_entry.delete(0, tk.END)  # Clear the existing entry
            payload_entry.insert(0, payload)  # Insert the file content into the entry

# Function to read content from a JSON file
def load_payload_from_json_file():
    filepath = filedialog.askopenfilename(
        title="Select a Payload File", 
        filetypes=(("JSON Files", "*.json"), ("All Files", "*.*"))
    )
    if filepath:
        try:
            import json
            with open(filepath, 'r') as file:
                payloads = json.load(file)  # Parse JSON file
                # Example: Load the first DNS payload
                payload = payloads['dns_payloads'][0] if 'dns_payloads' in payloads else ""
                payload_entry.delete(0, tk.END)  # Clear existing entry
                payload_entry.insert(0, payload)  # Insert the payload
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load payload: {e}")

# Main application window setup
root = tk.Tk()
root.title("Packet Fuzzer Tool")

# Warning Message
messagebox.showwarning("Warning", """
WARNING: 
Sending unsolicited packets or fuzzing protocols to networks you do not own or have permission to test is illegal and unethical.
Ensure you have authorization to conduct your tests.
""")

# Input Fields
ip_entry = create_entry_with_placeholder(root, "Enter the Target IP Address:", "192.168.1.1")
port_entry = create_entry_with_placeholder(root, "Target Port (for TCP/UDP):", "53")
src_ip_entry = create_entry_with_placeholder(root, "Source IP (for custom packets):", "192.168.1.10")
src_port_entry = create_entry_with_placeholder(root, "Source Port (for custom packets):", "12345")
payload_entry = create_entry_with_placeholder(root, "Custom Payload (or leave blank for random):", "example.com")

# Buttons to load payload from files
load_text_payload_button = tk.Button(root, text="Load Text Payload from File", command=load_payload_from_text_file)
load_text_payload_button.pack(pady=5)

load_json_payload_button = tk.Button(root, text="Load JSON Payload from File", command=load_payload_from_json_file)
load_json_payload_button.pack(pady=5)

packet_type = tk.StringVar()
packet_type.set("SYN Packet")  # Default selection
packet_type_menu = tk.OptionMenu(root, packet_type, "SYN Packet", "NTP Fuzzer", "DNS Fuzzer", "DHCP Fuzzer", "ICMP Fuzzer", "Custom UDP Packet")
packet_type_menu.pack(pady=10)

# Function to send a fuzzed packet (generalized)
def send_fuzzed_packet(packet, target_ip, output_queue):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        fuzzed_packet = fuzz(packet)  # Fuzz the packet
        send(fuzzed_packet, verbose=False)  # Send the fuzzed packet
        output_queue.put(f"Fuzzed packet sent to {target_ip}")
    except Exception as e:
        output_queue.put(f"Error sending fuzz packet: {e}")

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
        ip = IP(dst=target_ip)
        udp = UDP(dport=53)
        fuzzed_domain_name = payload if payload else generate_random_domain()
        dns = DNS(rd=1, qd=DNSQR(qname=fuzzed_domain_name.encode(), qtype="A"))
        threading.Thread(target=send_fuzzed_packet, args=(ip/udp/dns, target_ip, output_queue), daemon=True).start()
    except Exception as e:
        output_queue.put(f"Error sending DNS fuzz packet: {e}")

# Function to handle sending custom UDP packets
def send_custom_udp_packet(target_ip, target_port, src_ip, src_port, payload, output_queue):
    try:
        ipaddress.ip_address(target_ip)  # Validate target IP
        ipaddress.ip_address(src_ip)  # Validate source IP
        if not (0 <= target_port <= 65535) or not (0 <= int(src_port) <= 65535):
            raise ValueError("Invalid port number. Ports must be between 0 and 65535.")

        ip = IP(src=src_ip, dst=target_ip)
        udp = UDP(sport=int(src_port), dport=target_port)
        custom_packet = ip/udp/payload.encode()  # Set the payload
        threading.Thread(target=send_fuzzed_packet, args=(custom_packet, target_ip, output_queue), daemon=True).start()
    except Exception as e:
        output_queue.put(f"Error sending custom UDP packet: {e}")

# Function to handle sending the packet on button click
def on_send_button_click():
    target_ip = ip_entry.get()
    target_port = port_entry.get()
    src_ip = src_ip_entry.get()
    src_port = src_port_entry.get()
    payload = payload_entry.get()
    selected_option = packet_type.get()
    output_text.delete(1.0, tk.END)  # Clear previous output

    output_queue = queue.Queue()  # Create a queue for output messages

    # Validate inputs and prepare to send packets
    error_message = ""
    if not target_ip:
        error_message += "Target IP is required.\n"
    if selected_option in ["SYN Packet", "NTP Fuzzer", "Custom UDP Packet"] and not target_port:
        error_message += "Target Port is required for selected packet types.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet"] and not src_ip:
        error_message += "Source IP is required for NTP and Custom UDP packets.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet"] and not src_port:
        error_message += "Source Port is required for NTP and Custom UDP packets.\n"
    if selected_option in ["NTP Fuzzer", "Custom UDP Packet", "DHCP Fuzzer", "ICMP Fuzzer"] and not payload:
        error_message += "Payload is required for the selected packet types.\n"

    if error_message:
        output_text.insert(tk.END, f"Errors:\n{error_message}")
        return  # Exit if there are errors

    # Logic for sending packets based on selected option
    if selected_option == "SYN Packet":
        try:
            target_port = int(target_port)
            threading.Thread(target=send_syn_packet, args=(target_ip, target_port, output_queue), daemon=True).start()
        except ValueError as e:
            output_text.insert(tk.END, f"Invalid port number: {e}\n")
            return

    elif selected_option == "DNS Fuzzer":
        send_dns_fuzzer(target_ip, output_queue, payload)

    elif selected_option == "Custom UDP Packet":
        try:
            target_port = int(target_port)
            src_port = int(src_port)
            threading.Thread(target=send_custom_udp_packet, args=(target_ip, target_port, src_ip, src_port, payload, output_queue), daemon=True).start()
        except ValueError as e:
            output_text.insert(tk.END, f"Invalid port number: {e}\n")
            return

    # Additional elif cases for other packet types would go here...

    # Function to update output text in the GUI
    def update_output_text():
        try:
            while not output_queue.empty():  # Consume all messages in the queue
                message = output_queue.get_nowait()
                output_text.insert(tk.END, message + "\n")
            root.after(100, update_output_text)
        except queue.Empty:
            root.after(100, update_output_text)

    update_output_text()

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
