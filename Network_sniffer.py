from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("="*60)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = f"Other ({proto})"
        print(f"Protocol: {protocol}")

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload (first 50 bytes): {payload[:50]}")
        except:
            pass

print("Packet sniffer started... Press CTRL+C to stop.\n")
sniff(prn=packet_callback, count=0)
