# Example for a TCP packet with SYN and FIN flags set
ip = IP(dst="192.168.1.1")
tcp = TCP(sport=12345, dport=80, flags="S+F")  # SYN and FIN both set, which is nonsensical
packet = ip / tcp
