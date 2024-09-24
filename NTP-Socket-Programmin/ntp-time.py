import os
import pyshark
import struct
import datetime

NTP_TIMESTAMP_DELTA = 2208988800  # NTP epoch (1900-01-01) to UNIX epoch (1970-01-01)

def parse_ntp_timestamp(raw_timestamp):
    """Parse a 64-bit NTP timestamp from raw data."""
    int_part, frac_part = struct.unpack('!II', raw_timestamp)
    return int_part + frac_part / 2**32

def ntp_to_unix(ntp_timestamp):
    """Convert an NTP timestamp to UNIX time."""
    return ntp_timestamp - NTP_TIMESTAMP_DELTA

def unix_to_human(unix_timestamp):
    """Convert UNIX timestamp to a human-readable format in UTC."""
    return datetime.datetime.fromtimestamp(unix_timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

def analyze_ntp_packets(pcap_file):
    """Analyze NTP packets from a specified PCAP file."""
    capture = pyshark.FileCapture(pcap_file, display_filter='ntp', use_json=True, include_raw=True)

    for packet in capture:
        try:
            if hasattr(packet, 'ntp'):
                ntp_raw_data = packet.get_raw_packet()

                # Extract source IP address and port
                src_ip = packet.ip.src
                src_port = packet[packet.transport_layer].srcport
                
                # Extract LI, VN, and Mode from the raw data
                li_vn_mode = ntp_raw_data[42]
                li = (li_vn_mode >> 6) & 0x3  # Leap Indicator
                vn = (li_vn_mode >> 3) & 0x7   # Version Number
                mode = li_vn_mode & 0x7        # Mode
                
                # Extract other NTP fields
                stratum = ntp_raw_data[43]
                poll = ntp_raw_data[44]
                precision = struct.unpack('b', ntp_raw_data[45:46])[0]
                root_delay = struct.unpack('!HH', ntp_raw_data[46:50])
                root_dispersion = struct.unpack('!HH', ntp_raw_data[50:54])
                reference_id = ntp_raw_data[54:58]

                # Parse NTP timestamps
                reference_timestamp = parse_ntp_timestamp(ntp_raw_data[58:66])
                originate_timestamp = parse_ntp_timestamp(ntp_raw_data[66:74])
                receive_timestamp = parse_ntp_timestamp(ntp_raw_data[74:82])
                transmit_timestamp = parse_ntp_timestamp(ntp_raw_data[82:90])

                # Convert timestamps to UNIX time
                reference_time_unix = ntp_to_unix(reference_timestamp)
                originate_time_unix = ntp_to_unix(originate_timestamp)
                receive_time_unix = ntp_to_unix(receive_timestamp)
                transmit_time_unix = ntp_to_unix(transmit_timestamp)

                # Check for sent request
                if mode == 3:  # Client mode
                    print("NTP client request on remote NTP server:")
                    print("=======================================")
                    print(f"('{src_ip}', {src_port}) sent ntp request packet to ('pool.ntp.org', 123):")
                    print(f"Leap Indicator: {li:02b} -> {'No warning' if li == 0 else 'Warning'}")
                    print(f"NTP protocol version: {vn}")
                    print(f"Mode: Client")
                    print(f"Stratum: {stratum}, Poll interval: {poll}, Precision: {precision}")
                    print(f"Root delay: {root_delay}, Root dispersion: {root_dispersion}")
                    print(f"Reference Identifier: {reference_id.hex()}")
                    print(f"Reference Timestamp in UTC: {reference_time_unix} -> {unix_to_human(reference_time_unix)}")
                    print(f"Origin Timestamp in UTC: {originate_time_unix} -> {unix_to_human(originate_time_unix)}")
                    print(f"Receive Timestamp in UTC: {receive_time_unix} -> {unix_to_human(receive_time_unix)}")
                    print(f"Transmit Timestamp in UTC: {transmit_time_unix} -> {unix_to_human(transmit_time_unix)}")
                    print()

                # Check for received response
                elif mode == 4:  # Server mode
                    print(f"('{src_ip}', {src_port}) received ntp response packet from ('pool.ntp.org', 123):")
                    print(f"Leap Indicator: {li:02b} -> {'No warning' if li == 0 else 'Warning'}")
                    print(f"NTP protocol version: {vn}")
                    print(f"Mode: Server")
                    print(f"Stratum: {stratum}, Poll interval: {poll}, Precision: {precision}")
                    print(f"Root delay: {root_delay}, Root dispersion: {root_dispersion}")
                    print(f"Reference Identifier: {reference_id.hex()}")
                    print(f"Reference Timestamp in UTC: {reference_time_unix} -> {unix_to_human(reference_time_unix)}")
                    print(f"Origin Timestamp in UTC: {originate_time_unix} -> {unix_to_human(originate_time_unix)}")
                    print(f"Receive Timestamp in UTC: {receive_time_unix} -> {unix_to_human(receive_time_unix)}")
                    print(f"Transmit Timestamp in UTC: {transmit_time_unix} -> {unix_to_human(transmit_time_unix)}")
                    print()

        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    pcap_file_path = '/home/ubuntu/Desktop/CNP/netpro/labs/lab02/ntp_packet_capture.pcapng'  # Path to the PCAPNG file
    analyze_ntp_packets(pcap_file_path)
