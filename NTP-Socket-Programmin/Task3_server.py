import socket
import struct
import time
import threading
import logging
from datetime import datetime

# NTP-specific constants
NTP_PORT = 120
NTP_VERSION = 4
NTP_MODE_SERVER = 4
NTP_MODE_CLIENT = 3
NTP_EPOCH = 2208988800  # 1970-01-01 00:00:00

# Configure logging
logging.basicConfig(filename='ntp_server.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def system_to_ntp_time(timestamp):
    """Convert system time to NTP time."""
    return int((timestamp + NTP_EPOCH) * 2**32)

def ntp_to_system_time(timestamp):
    """Convert NTP time to system time."""
    return timestamp / 2**32 - NTP_EPOCH

def handle_client(data, addr, sock):
    """Handle incoming NTP request."""
    if len(data) < 48:
        logging.warning(f"Received invalid packet from {addr}")
        return

    unpacked = struct.unpack('!B B B b 11I', data[0:48])
    
    recv_timestamp = system_to_ntp_time(time.time())
    
    # Prepare response packet
    response = bytearray(48)
    
    response[0] = (NTP_VERSION << 3) | NTP_MODE_SERVER
    response[1] = 1      # Stratum 1 (primary reference)
    response[2] = 0      # Poll interval
    response[3] = -18    # Precision (-18 corresponds to about 1 microsecond)
    
    # Root delay, root dispersion, and reference ID
    struct.pack_into('!I', response, 4, 0)
    struct.pack_into('!I', response, 8, 0)
    struct.pack_into('!4s', response, 12, b'PPS')  # Reference ID 'PPS' for Pulse Per Second
    
    # Timestamps
    now = system_to_ntp_time(time.time())
    struct.pack_into('!Q', response, 16, now)  # Reference timestamp
    struct.pack_into('!Q', response, 24, unpacked[10])  # Origin timestamp (client's transmit time)
    struct.pack_into('!Q', response, 32, recv_timestamp)  # Receive timestamp
    struct.pack_into('!Q', response, 40, now)  # Transmit timestamp
    
    sock.sendto(response, addr)
    
    # Log the request
    client_ip, client_port = addr
    log_message = f"Request from {client_ip}:{client_port} - "
    log_message += f"Client send time: {datetime.fromtimestamp(ntp_to_system_time(unpacked[10]))}, "
    log_message += f"Server receive time: {datetime.fromtimestamp(ntp_to_system_time(recv_timestamp))}, "
    log_message += f"Server send time: {datetime.fromtimestamp(ntp_to_system_time(now))}"
    logging.info(log_message)

def run_server():
    """Run the NTP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', NTP_PORT))
    print(f"NTP server running on port {NTP_PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)
        client_thread = threading.Thread(target=handle_client, args=(data, addr, sock))
        client_thread.start()

if __name__ == "__main__":
    run_server()