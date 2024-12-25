---

# Scapy-Payloader a Packet Fuzzer Tool and Payload Tester

This Python-based Packet Fuzzer Tool is designed to help security researchers and developers test the robustness of network protocols. It allows users to generate and send fuzzed packets over the network to identify potential vulnerabilities in various protocols.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Protocols Supported](#protocols-supported)
- [Warning](#warning)


## Features

- Send fuzzed SYN packets to test TCP stack robustness.
- Fuzz DNS queries with random domain names and custom payloads.
- Generate DHCP Discover packets with customizable hostnames and options.
- Fuzz ICMP packets with random message types and custom payloads.
- User-friendly GUI with real-time output display.
- Support for file-based payloads for fuzzing.

## Requirements

- Python 3.x
- Required libraries:
  - Tkinter (usually comes pre-installed with Python)
  - Scapy
  - Other standard libraries (`queue`, `os`, `threading`, `ipaddress`, `random`, `string`)

You can install the required libraries using pip:

```bash
pip install scapy
```

## Installation

1. Clone or download this repository to your local machine.

   ```bash
   git clone https://github.com/fish-hue/scapy-payloader.git
   cd scapy-payloader
   ```

2. Ensure that Python 3.x and required libraries are installed on your system.

3. Run the application:

   ```bash
   python scapy-payloader
   ```

## Usage

1. Enter the target IP address you wish to test.
2. Select the type of packet to send from the dropdown menu.
3. For certain protocols (e.g., SYN Packet, NTP Fuzzer), enter the target port.
4. For DHCP and ICMP, you can provide your custom payload or use random values generated by the tool.
5. Click on the "Send Packet" button to send the fuzzed packet.
6. Observe the output in the text area below for error messages or confirmations of sent packets.

## Protocols Supported

- **SYN Packet**: Sends a TCP SYN packet to the target IP and port.
- **DNS Fuzzer**: Sends fuzzed DNS queries to the target IP.
- **DHCP Fuzzer**: Sends DHCP Discover packets with customizable options.
- **ICMP Fuzzer**: Sends fuzzed ICMP Echo Requests with random types and payloads.

## Warning

**WARNING**: Sending unsolicited packets or fuzzing protocols to networks you do not own or have permission to test is illegal and unethical. Ensure you have proper authorization before conducting any tests.

---
