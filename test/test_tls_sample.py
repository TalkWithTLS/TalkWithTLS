#!/usr/bin/python3

import pytest

from common import *

log_filename = log_dir + '/' + os.path.basename(__file__) + '.txt'

global log_fd;

def log_std_out_and_err(exe, out, err):
    log_fd.write(exe + '\n')
    log_fd.write('-----------------------------------------------\n')
    if out != None:
        log_fd.write(str(out) + '\n')
    if err != None:
        log_fd.write('-----------------------------------------------\n')
        log_fd.write(str(err) + '\n')

def log_procs(proc1, proc2):
    (out, err) = proc1.communicate()
    log_std_out_and_err('Server', out, err)
    (out, err) = proc2.communicate()
    log_std_out_and_err('Client', out, err)

def log_tc(apps):
    log_fd.write('===============================================\n')
    log_fd.write('Running ' + apps[0]  + ' vs ' + apps[1] + ' ...\n')
    log_fd.write('===============================================\n')

def validate_tc_result(ret1, ret2):
    log_fd.write('===============================================\n')
    if ret1 != 0 or ret2 != 0:
        log_fd.write('FAILED !!!!\n')
        result = -1
    else:
        log_fd.write('Succeeded\n')
        result = 0
    log_fd.write('===============================================\n')
    return result

def run_serv_clnt_app(apps):
    log_tc(apps)
    proc1 = subprocess.Popen([bin_dir + "/" + apps[0]], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen([bin_dir + "/" + apps[1]], stdout=subprocess.PIPE)
    ret1 = proc1.wait()
    ret2 = proc2.wait()
    log_procs(proc1, proc2)
    return validate_tc_result(ret1, ret2)

def tc_setup():
    global log_fd
    log_fd = open(log_filename, 'a')

def tc_teardown():
    global log_fd
    log_fd.close()

# Test Sample Code
t12_testcases = [
                    ['tls12_server', 'tls12_client'],
                    ['tls12_verify_cb_server', 'tls12_verify_cb_client'],
                ]

def test_tls12_sample_code():
    tc_setup()
    for apps in t12_testcases:
        result = run_serv_clnt_app(apps)
        assert result == 0
    tc_teardown()

t13_testcases = [
                    ['tls13_server', 'tls13_client'],
                    ['tls13_server_dhe', 'tls13_client_dhe'],
                    ['wolfssl_tls13_server_sample', 'wolfssl_tls13_client_sample']
                ]

def test_tls13_sample_code():
    tc_setup()
    for apps in t13_testcases:
        result = run_serv_clnt_app(apps)
        assert result == 0
    tc_teardown()
