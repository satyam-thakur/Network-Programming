import socket
import struct
import time
import logging

# Constants
NTP_PORT = 120  # Changed from 120 to the standard NTP port
NTP_TIMESTAMP_DELTA = 2208988800  # NTP epoch (1900-01-01) to UNIX epoch (1970-01-01)

# Set up logging
logging.basicConfig(filename='ntp_server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def handle_client(server_socket):
    while True:
        try:
            # Receive an NTP request
            data, address = server_socket.recvfrom(1024)
            
            # Log the request with a timestamp and client information
            logging.info(f"Received request from {address}")
            
            # Get the current time
            current_time = time.time() + NTP_TIMESTAMP_DELTA
            
            # Create the NTP response packet
            ntp_data = struct.pack(
                '!12I',  # 12 unsigned integers (each 4 bytes)
                0b00100100,  # LI, VN, Mode (0b00100100 -> LI=0, VN=4, Mode=4)
                0,  # Stratum
                0,  # Poll interval
                0,  # Precision
                0,  # Root Delay
                0,  # Root Dispersion
                0,  # Reference ID
                0,  # Reference Timestamp
                0,  # Originate Timestamp
                0,  # Receive Timestamp
                int(current_time),  # Transmit Timestamp (seconds)
                int((current_time % 1) * 2**32)  # Transmit Timestamp (fractional part)
            )
            
            # Send the response back to the client
            server_socket.sendto(ntp_data, address)
        except Exception as e:
            logging.error(f"Error handling client request: {e}")

def ntp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Bind the socket to all available interfaces on port 123
        server_socket.bind(('0.0.0.0', NTP_PORT))
        print("NTP server running...")
        
        # Handle client requests in the main thread
        handle_client(server_socket)
    except KeyboardInterrupt:
        print("Server shutting down...")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == '__main__':
    ntp_server()