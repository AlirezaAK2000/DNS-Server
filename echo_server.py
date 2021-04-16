import socket
import binascii

HOST = '127.0.0.1'  
PORT = 5333

"""
simple echo server for UDP protocol
"""

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        while True:
            data, info = s.recvfrom(4096)
            data = binascii.hexlify(data).decode("utf-8")
            print(f'info : {info}')
            print(f'Message : {data}')
            s.sendto(binascii.unhexlify(data), info)
            