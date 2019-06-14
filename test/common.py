#!/usr/bin/python3

import subprocess
import os
import time

from log import *

bin_dir='./bin'

PROC_DEFAULT_WAIT_TIME_SEC = 0.2
PROC_DEFAULT_POLLING_TIME_SEC = 3

class TestLog(object):
    def logStdOutAndErr(self, exe, out, err):
        TWT_LOG(exe + '\n')
        TWT_LOG('-----------------------------------------------\n')
        if out != None:
            TWT_LOG(str(out) + '\n')
        if err != None:
            TWT_LOG('-----------------------------------------------\n')
            TWT_LOG(str(err) + '\n')

    def logProcs(self, testParam, servProc, clntProc):
        out = err = None
        if testParam.servResult != None:
            (out, err) = servProc.communicate()
        self.logStdOutAndErr('Server', out, err)
        if testParam.clntResult != None:
            (out, err) = clntProc.communicate()
        self.logStdOutAndErr('Client', out, err)

    def logTC(self, apps):
        TWT_LOG('===============================================\n')
        TWT_LOG('Running ' + apps[0]  + ' vs ' + apps[1] + ' ...\n')
        TWT_LOG('===============================================\n')

class TestParam(object):
    def initialize(self, apps):
        self.testLog = TestLog()
        self.apps = apps
        self.validateApps()
        # Update Idx of apps
        self.appsServCmdIdx = 0
        self.appsClntCmdIdx = 1
        self.appsServCmdArgIdx = 2
        self.appsClntCmdArgIdx = 3
        self.appsServExpectedResultIdx = 4
        self.appsClntExpectedResultIdx = 5
        # Update default expected result value 
        self.servExpectedResult = 0
        self.clntExpectedResult = 0
        self.servResult = None 
        self.clntResult = None 
        self.result = -1

    def validateApps(self):
        self.testLog.logTC(self.apps)
        if len(self.apps) < 2:
            TWT_LOG('Count [' + str(len(self.apps)) + 'of Apps passed is invalid !!!\n');
        assert self.validateApp(self.apps[0]) == 0
        assert self.validateApp(self.apps[1]) == 0

    def validateApp(self, app):
        if not os.path.isfile(bin_dir + '/' + app):
            TWT_LOG('Test Apps [' + bin_dir + '/' + app + '] not found !!!\n')
            return -1
        return 0

    def updateCommand(self, apps):
        self.initialize(apps)
        self.servCmd = bin_dir + "/" + self.apps[self.appsServCmdIdx]
        self.clntCmd = bin_dir + "/" + self.apps[self.appsClntCmdIdx]
        TWT_LOG("Serv Cmd: " + self.servCmd + "\n")
        TWT_LOG("Clnt Cmd: " + self.clntCmd + "\n")
        # Get optional params
        if len(self.apps) > self.appsServCmdArgIdx:
            self.servCmd = self.servCmd + " " + self.apps[self.appsServCmdArgIdx]
        if len(self.apps) > self.appsClntCmdArgIdx:
            self.clntCmd = self.clntCmd + " " + self.apps[self.appsClntCmdArgIdx]
        if len(self.apps) > self.appsServExpectedResultIdx:
            self.servExpectedResult = self.apps[self.appsServExpectedResultIdx]
            TWT_LOG('Expected serv res ' + str(self.servExpectedResult) + '\n')
        if len(self.apps) > self.appsClntExpectedResultIdx:
            self.clntExpectedResult = self.apps[self.appsClntExpectedResultIdx]
            TWT_LOG('Expected clnt res ' + str(self.clntExpectedResult) + '\n')

    def updateProcHandlers(self, servProc, clntProc):
        self.servProc = servProc
        self.clntProc = clntProc

    def updateProcResult(self, servProcRes, clntProcRes):
        self.servResult = servProcRes
        self.clntResult = clntProcRes

    def waitForProc(self):
        servRet = clntRet = None
        timetaken = 0
        while (1):
            time.sleep(PROC_DEFAULT_WAIT_TIME_SEC)
            timetaken += PROC_DEFAULT_WAIT_TIME_SEC
            TWT_LOG('Time taken ' + str(timetaken) + '\n')
            if servRet == None:
                servRet = self.servProc.poll()
            if clntRet == None:
                clntRet = self.clntProc.poll()
            if servRet != None and clntRet != None:
                break
            if timetaken > PROC_DEFAULT_POLLING_TIME_SEC:
                TWT_LOG('Proc waiting time expired')
                if servRet == None:
                    self.servProc.kill()
                if clntRet == None:
                    self.clntProc.Kill()
            #Even after Kill if process is not quiting, just break and come out
            if timetaken > PROC_DEFAULT_POLLING_TIME_SEC + 1:
                TWT_LOG('Even after kill proc is not quitting')
                break
        self.updateProcResult(servRet, clntRet)

    def validateTCResult(self):
        TWT_LOG('Serv Result' + str(self.servResult) + '\n')
        TWT_LOG('Clnt Result' + str(self.clntResult) + '\n')
        if self.servResult != self.servExpectedResult \
                or self.clntResult != self.clntExpectedResult:
            TWT_LOG('###FAILED !!!!\n\n')
            self.result = -1
        else:
            TWT_LOG('###Succeeded\n\n')
            self.result = 0
        return self.result

def run_serv_clnt_app(apps):
    testParam = TestParam()
    testParam.updateCommand(apps)
    servProc = subprocess.Popen(testParam.servCmd.split(' '), stdout=subprocess.PIPE)
    clntProc = subprocess.Popen(testParam.clntCmd.split(' '), stdout=subprocess.PIPE)
    testParam.updateProcHandlers(servProc, clntProc)
    testParam.waitForProc()
    testParam.testLog.logProcs(testParam, servProc, clntProc)
    testParam.validateTCResult()
    return testParam.result
