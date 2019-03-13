#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("ver_apps_and_args", [
    #Test with max version as TLS1.0
    (['test_openssl', 'test_openssl', '-S -V 10 -m', '-V 10 m']),
    (['test_openssl', 'test_openssl', '-S -V 11 -m', '-V 11 m']),
    (['test_openssl', 'test_openssl', '-S -V 12 -m', '-V 12 m']),
    (['test_openssl', 'test_openssl', '-S -V 13 -m', '-V 13 m']),
    #Test with max ver on server as TLS1.3, and max ver on client as TLS1.2
    (['test_openssl', 'test_openssl', '-S -V 1312 -m', '-V 1312 m']),
    (['test_openssl', 'test_openssl', '-S -V 1213 -m', '-V 1213 m']),
])

def test_openssl_version(tc_setup, ver_apps_and_args):
    assert run_serv_clnt_app(ver_apps_and_args) == 0
