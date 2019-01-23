#!/usr/bin/python

import subprocess
import os

g_bin_dir="bin"
g_log_file='log.txt'

g_t13_testcases = [ ['tls13_server', 'tls13_client'],
                    ['tls13_server_dhe', 'tls13_client_dhe'] ]

def run_tc(tc):
    proc1 = subprocess.Popen([g_bin_dir + "/" + tc[0]], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen([g_bin_dir + "/" + tc[1]], stdout=subprocess.PIPE)
    print 'Waiting for ' + str(proc1.pid) + ' ...'
    ret1 = proc1.wait()
    print 'Waiting for ' + str(proc2.pid) + ' ...'
    ret2 = proc2.wait()
    if ret1 != 0 or ret2 != 0:
        print ' - FAILED!!!'
    else:
        print ' - Succeeded'
    #(out, err) = proc1.communicate()



if __name__ == "__main__":
    for tc in g_t13_testcases:
        if len(tc) != 2:
            print 'Cant run ' + tc;
        print 'Running ' + tc[0]  + ' vs ' + tc[1] + ' ...'
        run_tc(tc)

