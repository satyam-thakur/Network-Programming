import struct
import time

def _parse_timestamp(raw_timestamp):
    """Convert a 64-bit NTP timestamp to a floating point number of seconds since the epoch."""
    # Unpack the 8-byte raw_timestamp into two 32-bit unsigned integers (big-endian format)
    int_part, frac_part = struct.unpack('!II', raw_timestamp)
    
    # Convert the NTP timestamp to Unix time:
    # - int_part represents the number of seconds since 1900.
    # - frac_part / 2**32 converts the fractional part to seconds.
    # - Subtract 2208988800 to adjust from the 1900 epoch to the Unix epoch (1970).
    return int_part + frac_part / 2**32 - 2208988800

def convert_ntp_to_unix(hex_timestamp):
    """Convert a hexadecimal NTP timestamp to Unix time."""
    # Convert the hexadecimal timestamp to bytes.
    # Replace '.' with '' to handle hexadecimal representation without separators.
    raw_timestamp = bytes.fromhex(hex_timestamp.replace('.', ''))
    
    # Use the _parse_timestamp function to convert raw bytes to Unix time.
    return _parse_timestamp(raw_timestamp)

# Example hexadecimal values (these would be extracted from Wireshark)
# Transmit Timestamp (T4): The time at which the NTP server sent the response.
# Receive Timestamp (T3): The time at which the NTP server received the request.
# Send Timestamp (T2): The time at which the NTP client sent the request.
# Originate Timestamp (T1): The time at which the NTP client received the response.
t1_hex = 'ea8b109b3f693df6'
t2_hex = 'ea8b109b3f693df6'
t3_hex = 'ea8b109b42607b11'  
t4_hex = 'ea8b109b42625a1f'  

# Convert the NTP timestamps to Unix time
t0 = convert_ntp_to_unix(t1_hex)
t1 = convert_ntp_to_unix(t2_hex)
t2 = convert_ntp_to_unix(t3_hex)
t3 = convert_ntp_to_unix(t4_hex)

# print (t1_unix,t2_unix,t3_unix,t4_unix)

#Calculating corrected Time
corrected_time = t3 + ((t1-t0) + (t2-t3))/2
print ('corrected_time:',corrected_time)
print('correct time:', {time.ctime(corrected_time)})