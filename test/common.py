#!/usr/bin/python3

import subprocess
import os
import time
import struct
import socket

from log import *

BIN_DIR='./bin'
TEST_OPENSSL=BIN_DIR + '/test_openssl'
TEST_OPENSSL_PORT=25100

TEST_RESULT_WAIT_TIME_SEC = 5.0

TC_CMD_TYPE_TC_START = 1
TC_CMD_TYPE_TC_ARG = 2
TC_CMD_TYPE_TC_RESULT = 3
TC_CMD_TYPE_TC_STOP = 4
TC_HDR_FMT = '>BH'
TC_HDR_SIZE = 3
TC_RESULT_FMT = TC_HDR_FMT + 'B'
TC_SUCCESS = 0
TC_FAILURE = 1

SUT_IP = "127.0.0.1"

def connect_to_sut(ip, port):
    fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fd.connect((ip, port))
    fd.settimeout(TEST_RESULT_WAIT_TIME_SEC)
    return fd

def stop_sut(port):
    hdr_bytes = struct.pack(TC_HDR_FMT, TC_CMD_TYPE_TC_STOP, 0)
    fd = connect_to_sut(SUT_IP, port)
    fd.send(hdr_bytes)
    fd.close()

def do_test(sarg, carg, sport, cport):
    sarg_bytes = str.encode(sarg.rstrip())
    carg_bytes = str.encode(carg.rstrip())
    shdr_bytes = struct.pack(TC_HDR_FMT, TC_CMD_TYPE_TC_ARG, len(sarg_bytes))
    chdr_bytes = struct.pack(TC_HDR_FMT, TC_CMD_TYPE_TC_ARG, len(carg_bytes))
    sfd = connect_to_sut(SUT_IP, sport)
    cfd = connect_to_sut(SUT_IP, cport)
    sfd.send(shdr_bytes)
    sfd.send(sarg_bytes)
    cfd.send(chdr_bytes)
    cfd.send(carg_bytes)
    sres_bytes = sfd.recv(4)
    cres_bytes = cfd.recv(4)
    sfd.close()
    cfd.close()
    sres_param = struct.unpack(TC_RESULT_FMT, sres_bytes)
    cres_param = struct.unpack(TC_RESULT_FMT, cres_bytes)
    TWT_LOG('Server [Port=' + str(sport) + '] Result Param' + str(sres_param) + '\n')
    TWT_LOG('Client [Port=' + str(cport) + '] Result Param' + str(cres_param) + '\n')
    if sres_param[2] != TC_SUCCESS or cres_param[2] != TC_SUCCESS:
        return TC_FAILURE
    else:
        return TC_SUCCESS

def run_test(sarg, carg, flags=0):
    return do_test(sarg, carg, TEST_OPENSSL_PORT + 1, TEST_OPENSSL_PORT)
