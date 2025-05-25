from scapy.all import sniff, IP, TCP, UDP

# Callback function to process each captured packet
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol mapping
        protocol = "Others"
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        
        print(f"[+] {ip_src} -> {ip_dst} ({protocol})")

        # Display TCP/UDP specific info
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"    TCP: Source Port={tcp_sport}, Destination Port={tcp_dport}")
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"    UDP: Source Port={udp_sport}, Destination Port={udp_dport}")

        print("-" * 50)

# Start sniffing
def start_sniffer():
    print("Starting network sniffer... (Press Ctrl+C to stop)")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping network sniffer...")

if __name__ == "__main__":
    start_sniffer()