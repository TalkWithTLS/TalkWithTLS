#!/usr/bin/python

import subprocess
import os

g_bin_dir='bin'
g_log_file='log.txt'
global g_log_file_f;

def log_std_out_and_err(exe, out, err):
    g_log_file_f.write(exe + '\n')
    g_log_file_f.write('-----------------------------------------------\n')
    if out != None:
        g_log_file_f.write(str(out) + '\n')
    if err != None:
        g_log_file_f.write('-----------------------------------------------\n')
        g_log_file_f.write(str(err) + '\n')

def log_procs(proc1, proc2):
    (out, err) = proc1.communicate()
    log_std_out_and_err('Server', out, err)
    (out, err) = proc2.communicate()
    log_std_out_and_err('Client', out, err)

def log_tc(tc):
    print('Running [' + tc[0]  + ' vs ' + tc[1] + ']'),
    g_log_file_f.write('===============================================\n')
    g_log_file_f.write('Running ' + tc[0]  + ' vs ' + tc[1] + ' ...\n')
    g_log_file_f.write('===============================================\n')

def validate_tc_result(ret1, ret2):
    g_log_file_f.write('===============================================\n')
    if ret1 != 0 or ret2 != 0:
        print(' - FAILED!!!')
        g_log_file_f.write('FAILED !!!!\n')
    else:
        print(' - Succeeded')
        g_log_file_f.write('Succeeded\n')
    g_log_file_f.write('===============================================\n')

def run_tc(tc):
    log_tc(tc)
    proc1 = subprocess.Popen([g_bin_dir + "/" + tc[0]], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen([g_bin_dir + "/" + tc[1]], stdout=subprocess.PIPE)
    #print('Waiting for ' + str(proc1.pid) + ' ...')
    ret1 = proc1.wait()
    #print('Waiting for ' + str(proc2.pid) + ' ...')
    ret2 = proc2.wait()
    log_procs(proc1, proc2)
    validate_tc_result(ret1, ret2)

def log_file_init():
    global g_log_file_f
    g_log_file_f = open(g_log_file, 'w')

def log_file_fini():
    global g_log_file_f
    g_log_file_f.close()

g_t13_testcases = [
                    ['tls12_server', 'tls12_client'],
                    ['tls12_verify_cb_server', 'tls12_verify_cb_client'],
                    ['tls13_server', 'tls13_client'],
                    ['tls13_server_dhe', 'tls13_client_dhe'],
                    ['wolfssl_tls13_server_sample', 'wolfssl_tls13_client_sample']
                  ]

if __name__ == "__main__":
    log_file_init()
    for tc in g_t13_testcases:
        if len(tc) != 2:
            print('Cant run ' + tc)
        run_tc(tc)
    log_file_fini()

