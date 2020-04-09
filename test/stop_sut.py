#/usr/bin/python3

import sys
import socket

from common import *

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " <starting_port> <num_of_sut_instance>")
    print(sys.argv[1] + sys.argv[2])
    port = int(sys.argv[1])
    num = int(sys.argv[2])
    stop_sut(port)
    stop_sut(port + 1)
