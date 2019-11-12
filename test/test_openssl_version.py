#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("ver_app1, ver_app2, app1_args, app2_args", [
    #Test with max version as TLS1.0
    ('test_openssl', 'test_openssl', '-serv -ver 10 -msgcb', '-ver 10 -msgcb'),
    ('test_openssl', 'test_openssl', '-serv -ver 11 -msgcb', '-ver 11 -msgcb'),
    ('test_openssl', 'test_openssl', '-serv -ver 12 -msgcb', '-ver 12 -msgcb'),
    ('test_openssl', 'test_openssl', '-serv -ver 13 -msgcb', '-ver 13 -msgcb'),
    #Test with max ver on server as TLS1.3, and max ver on client as TLS1.2
    ('test_openssl', 'test_openssl', '-serv -ver 1312 -msgcb', '-ver 1312 -msgcb'),
    ('test_openssl', 'test_openssl', '-serv -ver 1213 -msgcb', '-ver 1213 -msgcb'),
])

def test_openssl_version(tc_setup, ver_app1, ver_app2, app1_args, app2_args):
    assert run_serv_clnt_app([ver_app1, ver_app2, app1_args, app2_args]) == 0
