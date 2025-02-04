import socket
import struct

# Define protocol constants
ETH_P_ALL = 0x0003  # Captures all Ethernet packets

def mac_format(mac_bytes):
    """Convert MAC address bytes to human-readable format."""
    return ':'.join(map('{:02x}'.format, mac_bytes))

def parse_ethernet_header(raw_data):
    """Parse Ethernet header and extract source & destination MAC addresses."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(proto), raw_data[14:]

def parse_ip_header(raw_data):
    """Parse IP header to extract source & destination IPs."""
    ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
    version = ip_header[0] >> 4
    header_length = (ip_header[0] & 15) * 4
    ttl = ip_header[5]
    proto = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return version, header_length, ttl, proto, src_ip, dest_ip, raw_data[header_length:]

def sniff_packets():
    """Capture and analyze network packets."""
    try:
        # Create a raw socket to capture packets
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))

        print("📡 Packet Sniffer Started... Press Ctrl+C to stop.\n")

        while True:
            raw_data, addr = conn.recvfrom(65535)

            # Parse Ethernet Header
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
            print(f"\n🔹 Ethernet Frame: Src MAC: {src_mac} ➝ Dest MAC: {dest_mac} | Protocol: {eth_proto}")

            # Parse IP Packets
            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)
                print(f"   🌐 IPv{version} | Src IP: {src_ip} ➝ Dest IP: {dest_ip} | TTL: {ttl} | Protocol: {proto}")

    except KeyboardInterrupt:
        print("\n🛑 Packet Sniffing Stopped.")
    except PermissionError:
        print("\n❌ Permission Denied! Run the script as Admin/Root.")

if __name__ == "__main__":
    sniff_packets()