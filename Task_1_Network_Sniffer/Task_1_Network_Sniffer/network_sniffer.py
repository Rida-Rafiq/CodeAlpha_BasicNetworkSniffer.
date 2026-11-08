import argparse
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        proto_name = "Unknown"
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"

        print(f"\n[+] Packet Captured: {src_ip} -> {dst_ip} | Protocol: {proto_name}")

        if TCP in packet or UDP in packet:
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]}...")
            else:
                print("    Payload: None")

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets", default=10)
    args = parser.parse_args()

    print(f"[*] Starting network sniffer on interface: {args.interface or 'Default'}")
    
    try:
        sniff(iface=args.interface, prn=packet_callback, store=False, count=args.count)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")
    except PermissionError:
        print("\n[!] Error: Run with Administrator/Root privileges.")

if __name__ == "__main__":
    main()
