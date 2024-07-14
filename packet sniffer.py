from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
        elif UDP in packet:
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload).decode('utf-8', errors='ignore')
        else:
            proto_name = "Other"
            payload = ""

        print(f"IP Source: {ip_src}")
        print(f"IP Destination: {ip_dst}")
        print(f"Protocol: {proto_name}")
        print(f"Payload: {payload}")
        print("-" * 80)


def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)


if __name__ == "__main__":
    main()
