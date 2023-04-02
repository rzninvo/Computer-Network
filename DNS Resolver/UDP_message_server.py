import binascii
import socket
import sys
from collections import OrderedDict


def recieve_udp_message():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 64251))
        sock.listen()
        connection, address = sock.accept()
        with connection:
            print("New client connected: ", address)
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                print("Data= ", data)
                connection.sendall(data)
    finally:
        sock.close()


recieve_udp_message()