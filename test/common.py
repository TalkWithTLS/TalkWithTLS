#!/usr/bin/python3

import subprocess
import os

from log import *

bin_dir='./bin'

def log_std_out_and_err(exe, out, err):
    TWT_LOG(exe + '\n')
    TWT_LOG('-----------------------------------------------\n')
    if out != None:
        TWT_LOG(str(out) + '\n')
    if err != None:
        TWT_LOG('-----------------------------------------------\n')
        TWT_LOG(str(err) + '\n')

def log_procs(proc1, proc2):
    (out, err) = proc1.communicate()
    log_std_out_and_err('Server', out, err)
    (out, err) = proc2.communicate()
    log_std_out_and_err('Client', out, err)

def log_tc(apps):
    TWT_LOG('===============================================\n')
    TWT_LOG('Running ' + apps[0]  + ' vs ' + apps[1] + ' ...\n')
    TWT_LOG('===============================================\n')

def validate_tc_result(ret1, ret2):
    if ret1 != 0 or ret2 != 0:
        TWT_LOG('###FAILED !!!!\n\n')
        result = -1
    else:
        TWT_LOG('###Succeeded\n\n')
        result = 0
    return result

def validate_app(app):
    if not os.path.isfile(bin_dir + '/' + app):
        TWT_LOG('Test Apps [' + bin_dir + '/' + app + '] not found !!!\n')
        return -1
    return 0

def validate_apps(apps):
    log_tc(apps)
    if len(apps) < 2:
        TWT_LOG('Count [' + str(len(apps)) + 'of Apps passed is invalid !!!\n');
    assert validate_app(apps[0]) == 0
    assert validate_app(apps[1]) == 0

def run_serv_clnt_app(apps):
    validate_apps(apps)
    serv_cmd = bin_dir + "/" + apps[0]
    clnt_cmd = bin_dir + "/" + apps[1]
    if len(apps) > 2:
        serv_cmd = serv_cmd + " " + apps[2]
    if len(apps) > 3:
        clnt_cmd = clnt_cmd + " " + apps[3]
    TWT_LOG("Serv Cmd: " + serv_cmd + "\n")
    TWT_LOG("Clnt Cmd: " + clnt_cmd + "\n")
    proc1 = subprocess.Popen(serv_cmd.split(' '), stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(clnt_cmd.split(' '), stdout=subprocess.PIPE)
    ret1 = proc1.wait()
    ret2 = proc2.wait()
    log_procs(proc1, proc2)
    return validate_tc_result(ret1, ret2)

