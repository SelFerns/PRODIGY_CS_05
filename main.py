from scapy.all import sniff, IP, TCP, UDP, raw

def process_packet(packet):
    try:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        protocol = "Unknown"
        protocol_info = ""

        if proto == 6:
            # TCP packet
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags
            protocol_info = (f"Source Port: {src_port}\n"
                             f"Destination Port: {dst_port}\n"
                             f"Flags: {flags}\n")
        elif proto == 17:
            # UDP packet
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol_info = (f"Source Port: {src_port}\n"
                             f"Destination Port: {dst_port}\n")

        # Prepare packet info
        packet_info = (f"Protocol: {protocol}\n"
                       f"Source IP: {src_ip}\n"
                       f"Destination IP: {dst_ip}\n"
                       f"{protocol_info}"
                       f"Payload (Hex): {raw(packet[IP]).hex()}\n")

        # Print packet info to the terminal
        print("-" * 50)
        print(packet_info)
        print("-" * 50)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start sniffing


def start_sniffing():
    try:
        print("Starting packet capture. Press Ctrl+C to stop.")
        sniff(prn=process_packet, filter="ip", store=0)
    except Exception as e:
        print(f"Error while sniffing packets: {e}")


if __name__ == "__main__":
    start_sniffing()
