import socket
import struct
import subprocess
import threading

def icmp_listener():
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("Server started.")
    while True:
        try:
            packet, addr = icmp_socket.recvfrom(65565)
            icmp_header = packet[20:28]
            icmp_type, icmp_code, _, _, _ = struct.unpack("bbHHh", icmp_header)
            if icmp_type == 8 and icmp_code == 0:
                # ICMP Echo Request (ping request) received
                print(f"Received a ping request from client through upf mec ({addr})")
        except socket.timeout:
            pass

if __name__ == "__main__":
    icmp_listener()
