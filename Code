from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime

def packet_callback(packet):
    # Get current time
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        protocol = ip_layer.proto  # 6 for TCP, 17 for UDP

        print(f"Timestamp: {timestamp}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dest_ip}")

        if TCP in packet:
            print(f"Protocol: TCP")
            print(f"Payload: {str(packet[TCP].payload)}")
        elif UDP in packet:
            print(f"Protocol: UDP")
            print(f"Payload: {str(packet[UDP].payload)}")
        else:
            print(f"Protocol: Other")

        print("-" * 50)

def main():
    print("Starting packet sniffer...")
    print("Press Ctrl+C to stop.")

    # Sniff packets, filter for IP packets
    sniff(filter="ip", prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
