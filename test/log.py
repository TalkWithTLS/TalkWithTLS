#!/usr/bin/python3

import os

report_dir='./report'
log_dir=report_dir + '/log'

default_log_filename = log_dir + '/log.txt'
log_filename = default_log_filename

def TWT_set_log_filename(filename):
    global log_filename
    log_filename = log_dir + '/' + filename + '.txt'

def TWT_LOG(str):
    global log_filename
    fd = open(log_filename, 'a')
    fd.write(str)
    fd.close()
