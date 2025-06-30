from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = packet.proto if hasattr(packet, 'proto') else 'N/A'

        print(f"\n[+] Packet:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")

        if TCP in packet:
            print("    Protocol       : TCP")
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("    Protocol       : UDP")
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")
        else:
            print("    Protocol       : Other")

        payload = bytes(packet[IP].payload)
        print(f"    Payload (First 50 bytes): {payload[:50]}")

# Start sniffing
print("=== Network Packet Analyzer ===")
print("Sniffing packets... Press Ctrl+C to stop.\n")

sniff(prn=process_packet, store=False)
