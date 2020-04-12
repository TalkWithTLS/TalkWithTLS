#/usr/bin/python3

import sys
import socket

from common import *

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " <starting_port> <num_of_sut_instance>")
    port = int(sys.argv[1])
    num = int(sys.argv[2])
    print("Stopping SUT at port[" + str(port) + "]")
    stop_sut(port)
