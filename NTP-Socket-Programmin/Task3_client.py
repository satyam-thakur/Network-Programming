import socket
import struct
import time
import datetime

# Constants
NTP_SERVER = 'localhost'  # Change this to the IP of your NTP server if not on the same machine
NTP_PORT = 123
NTP_TIMESTAMP_DELTA = 2208988800  # NTP epoch (1900-01-01) to UNIX epoch (1970-01-01)

def parse_ntp_timestamp(raw_data, start_index):
    int_part, frac_part = struct.unpack('!II', raw_data[start_index:start_index+8])
    return int_part + frac_part / 2**32

def ntp_to_unix(ntp_timestamp):
    return ntp_timestamp - NTP_TIMESTAMP_DELTA

def unix_to_human(unix_timestamp):
    return datetime.datetime.utcfromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' UTC'

def unix_to_local(unix_timestamp):
    return datetime.datetime.fromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def print_ntp_packet_info(is_sent, src_ip, src_port, dst_ip, dst_port, mode, stratum, poll, precision, root_delay, root_dispersion, reference_id, reference_timestamp, originate_timestamp, receive_timestamp, transmit_timestamp, corrected_time=None):
    packet_type = "sent ntp request" if is_sent else "received ntp response"
    print(f"('{src_ip}', {src_port}) {packet_type} packet {'to' if is_sent else 'from'} ('{dst_ip}', {dst_port}):")
    print(f"Leap Indicator: {mode >> 6:02b} -> {'No warning' if mode >> 6 == 0 else 'Warning'}")
    print(f"NTP protocol version: {(mode >> 3) & 0x7}")
    print(f"Mode: {'Client' if mode & 0x7 == 3 else 'Server'}")
    print(f"Stratum: {stratum}, Poll interval: {poll}, Precision: {precision} seconds")
    print(f"Root delay: {root_delay:.10f} seconds.")
    print(f"Root dispersion: {root_dispersion:.10f} seconds.")
    print(f"Reference Identifier: {reference_id.hex()}")
    print(f"Reference Timestamp in UTC: {reference_timestamp} -> {unix_to_human(reference_timestamp)}")
    print(f" in local time zone: {unix_to_local(reference_timestamp)}")
    print(f"Origin Timestamp in UTC: {originate_timestamp} -> {unix_to_human(originate_timestamp)}")
    print(f" in local time zone: {unix_to_local(originate_timestamp)}")
    print(f"Receive Timestamp in UTC: {receive_timestamp} -> {unix_to_human(receive_timestamp)}")
    print(f" in local time zone: {unix_to_local(receive_timestamp)}")
    print(f"Transmit Timestamp in UTC: {transmit_timestamp} -> {unix_to_human(transmit_timestamp)}")
    print(f" in local time zone: {unix_to_local(transmit_timestamp)}")
    if corrected_time is not None:
        print(f"Corrected time in UTC: {corrected_time} -> {unix_to_human(corrected_time)}")
        print(f" in local time zone: {unix_to_local(corrected_time)}")
    print()

def ntp_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Prepare NTP request packet
    ntp_data = bytearray(48)
    ntp_data[0] = 0x1b  # LI = 0, VN = 3, Mode = 3 (client)

    local_time_sent = time.time()
    print(f"Local time when request is sent: {unix_to_local(local_time_sent)}")

    # Get the actual local IP
    local_ip = get_local_ip()
    
    # Send the packet and get the local port
    client.sendto(ntp_data, (NTP_SERVER, NTP_PORT))
    local_port = client.getsockname()[1]

    print("Request sent to server")

    # Print sent packet info
    print_ntp_packet_info(
        True, local_ip, local_port, NTP_SERVER, NTP_PORT,
        0x1b, 0, 0, 0, 0, 0, b'\x00\x00\x00\x00',
        local_time_sent, local_time_sent, local_time_sent, local_time_sent
    )
    
    ntp_response, server_address = client.recvfrom(1024)
    print("Response received from server")

    local_time_received = time.time()
    
    # Extract fields from received packet
    mode = ntp_response[0]
    stratum = ntp_response[1]
    poll = ntp_response[2]
    precision = struct.unpack('b', ntp_response[3:4])[0]
    root_delay = struct.unpack('!I', ntp_response[4:8])[0] / 2**16
    root_dispersion = struct.unpack('!I', ntp_response[8:12])[0] / 2**16
    reference_id = ntp_response[12:16]

    reference_timestamp = ntp_to_unix(parse_ntp_timestamp(ntp_response, 16))
    originate_timestamp = ntp_to_unix(parse_ntp_timestamp(ntp_response, 24))
    receive_timestamp = ntp_to_unix(parse_ntp_timestamp(ntp_response, 32))
    transmit_timestamp = ntp_to_unix(parse_ntp_timestamp(ntp_response, 40))
    
    corrected_time = local_time_received + ((receive_timestamp - local_time_sent) + (transmit_timestamp - local_time_received)) / 2

    # Print received packet info
    print_ntp_packet_info(
        False, server_address[0], server_address[1], local_ip, local_port,
        mode, stratum, poll, precision, root_delay, root_dispersion, reference_id,
        reference_timestamp, originate_timestamp, receive_timestamp, transmit_timestamp, corrected_time
    )

if __name__ == '__main__':
    ntp_client()