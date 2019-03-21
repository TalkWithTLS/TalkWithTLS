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

def log_procs(servProc, clntProc):
    (out, err) = servProc.communicate()
    log_std_out_and_err('Server', out, err)
    (out, err) = clntProc.communicate()
    log_std_out_and_err('Client', out, err)

def log_tc(apps):
    TWT_LOG('===============================================\n')
    TWT_LOG('Running ' + apps[0]  + ' vs ' + apps[1] + ' ...\n')
    TWT_LOG('===============================================\n')

def validate_tc_result(testParam):
    if testParam.servResult != testParam.servExpectedResult \
            or testParam.clntResult != testParam.clntExpectedResult:
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

class TestParam(object):
    def initialize(self):
        # Update Idx of apps
        self.appsServCmdIdx = 0
        self.appsClntCmdIdx = 1
        self.appsServCmdArgIdx = 2
        self.appsClntCmdArgIdx = 3
        self.appsServExpectedResultIdx = 4
        self.appsClntExpectedResultIdx = 5
        # Update default expected result value 
        self.servExpectedResult = 0;
        self.clntExpectedResult = 0;

    def updateCommand(self, apps):
        self.initialize()
        self.servCmd = bin_dir + "/" + apps[self.appsServCmdIdx]
        self.clntCmd = bin_dir + "/" + apps[self.appsClntCmdIdx]
        TWT_LOG("Serv Cmd: " + self.servCmd + "\n")
        TWT_LOG("Clnt Cmd: " + self.clntCmd + "\n")
        # Get optional params
        if len(apps) > self.appsServCmdArgIdx:
            self.servCmd = self.servCmd + " " + apps[self.appsServCmdArgIdx]
        if len(apps) > self.appsClntCmdArgIdx:
            self.clntCmd = self.clntCmd + " " + apps[self.appsClntCmdArgIdx]
        if len(apps) > self.appsServExpectedResultIdx:
            self.servExpectedResult = apps[self.appsServExpectedResultIdx]
        if len(apps) > self.appsClntExpectedResultIdx:
            self.clntExpectedResult = apps[self.appsClntExpectedResultIdx]

    def updateProcHandlers(self, servProc, clntProc):
        self.servProc = servProc
        self.clntProc = clntProc

    def updateProcResult(self, servProcRes, clntProcRes):
        self.servResult = servProcRes
        self.clntResult = clntProcRes

def run_serv_clnt_app(apps):
    validate_apps(apps)
    testParam = TestParam()
    testParam.updateCommand(apps)
    servProc = subprocess.Popen(testParam.servCmd.split(' '), stdout=subprocess.PIPE)
    clntProc = subprocess.Popen(testParam.clntCmd.split(' '), stdout=subprocess.PIPE)
    testParam.updateProcHandlers(servProc, clntProc)
    ret1 = servProc.wait()
    ret2 = clntProc.wait()
    testParam.updateProcResult(ret1, ret2)
    log_procs(servProc, clntProc)
    return validate_tc_result(testParam)

