import socket
import struct
import time

# Constants
# NTP_SERVERS = ['pool.ntp.org', 'time.google.com', 'time.windows.com']  # List of NTP servers
NTP_SERVERS = ['0.0.0.0']
NTP_PORT = 120
LOCAL_TIME_LENGTH = 19  # Length of the local time string
NTP_TIMESTAMP_DELTA = 2208988800  # Difference between NTP epoch (1900-01-01) and UNIX epoch (1970-01-01)
TIMEOUT = 5  # Timeout in seconds

def create_custom_ntp_packet(local_time_str):
    # Create the standard NTP request packet
    ntp_request = b'\x1b' + 47 * b'\0'
    
    # Append local time to the NTP request packet
    # Ensure that the packet length does not exceed the maximum size
    local_time_bytes = local_time_str.ljust(LOCAL_TIME_LENGTH, '\0').encode('utf-8')
    return ntp_request + local_time_bytes

def ntp_client(servers):
    for server in servers:
        try:
            # Create a UDP socket
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(TIMEOUT)  # Set a timeout for the socket

            # Capture the local time
            t0 = time.time()
            local_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t0))

            # Create a custom NTP packet with the local time included
            custom_ntp_packet = create_custom_ntp_packet(local_time_str)
            
            # Send the packet to the NTP server
            client.sendto(custom_ntp_packet, (server, NTP_PORT))
            
            # Receive the response from the server
            ntp_response, _ = client.recvfrom(1024)
            
            # Capture the time when the response is received (t3)
            t3 = time.time()
            
            # Unpack the received data
            unpacked_data = struct.unpack('!12I', ntp_response[:48])
            
            # Extract the transmit timestamp (t2)
            transmit_timestamp = unpacked_data[10] + float(unpacked_data[11]) / 2**32

            # Convert the transmit timestamp to UNIX time
            t2 = transmit_timestamp - NTP_TIMESTAMP_DELTA

            # Calculate the round-trip delay and clock offset
            round_trip_delay = (t3 - t0) - (t2 - t0)
            clock_offset = (t2 - t0) + (t3 - t2) / 2

            # Corrected time = t3 + clock_offset
            corrected_time = t3 + clock_offset

            # Print the results
            print(f"Using NTP Server: {server}")
            print(f"Local Time (when request was sent): {local_time_str}")
            print(f"Original NTP Timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(t2))}")
            print(f"Corrected Time (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(corrected_time))}")
            return  # Exit after successfully getting time from one server

        except socket.timeout:
            print(f"Request to {server} timed out")
        except Exception as e:
            print(f"Error with server {server}: {e}")

    print("All servers failed to respond")

if __name__ == '__main__':
    ntp_client(NTP_SERVERS)
