#!/usr/bin/python3

import os
import sys
import socket
import struct

TC_CMD_TYPE_TC_START = 1
TC_CMD_TYPE_TC_ARG = 2
TC_CMD_TYPE_TC_RESULT = 3
TC_HDR_FMT = '>BH'
TC_HDR_SIZE = 3
TC_RESULT_FMT = TC_HDR_FMT + 'B'
TC_RESULT_SUCCESS = 0
TC_RESULT_FAILURE = 1

SUT_IP = "127.0.0.1"
SUT_PORT = 25100
def connect_to_sut(ip, port):
    sfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sfd.connect((ip, port))
    return sfd

def send_tc_name(tc_name, sfd):
    hdr_bytes = struct.pack(TC_HDR_FMT, TC_CMD_TYPE_TC_START, len(tc_name))
    sfd.send(hdr_bytes)
    sfd.send(str.encode(tc_name))

if __name__ == "__main__":
    if (len(sys.argv) > 1):
        SUT_PORT = int(sys.argv[1])
    print('TWT_TC>', end=" ", flush=True)
    for line in sys.stdin:
        if 'exit' == line.rstrip() or 'e' == line.rstrip():
            break
        sfd = connect_to_sut(SUT_IP, SUT_PORT)
        send_tc_name("manual", sfd)
        send_bytes = str.encode(line.rstrip())
        hdr = struct.pack(TC_HDR_FMT, TC_CMD_TYPE_TC_ARG, len(send_bytes))
        sfd.send(hdr)
        sfd.send(send_bytes)
        result = sfd.recv(16)
        if result[3] == TC_RESULT_SUCCESS:
            print("TC Success")
        else:
            print("TC Failure")
        sfd.close()
        print('TWT_TC>', end=" ", flush=True)
