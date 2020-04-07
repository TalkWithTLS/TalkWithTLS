#!/usr/bin/python3

import os
import sys
import socket

SUT_IP = "127.0.0.1"
SUT_PORT = 25100
def connect_to_sut(ip, port):
    sfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sfd.connect((ip, port))
    return sfd

if __name__ == "__main__":
    if (len(sys.argv) > 1):
        SUT_PORT = int(sys.argv[1])
    print('TWT_TC>', end=" ", flush=True)
    for line in sys.stdin:
        if 'exit' == line.rstrip() or 'e' == line.rstrip():
            break
        sfd = connect_to_sut(SUT_IP, SUT_PORT)
        sfd.send(str.encode(line.rstrip()))
        buf_bytes = sfd.recv(16)
        print("Received " + str(buf_bytes))
        sfd.close()
        print('TWT_TC>', end=" ", flush=True)
