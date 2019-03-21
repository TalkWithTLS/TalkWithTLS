#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("kexch_apps_and_args", [
    (['test_openssl', 'test_openssl', '-S -k 1 -m', '-k 1 m', 0, 0]), #Test with all ECDHE alg
    #(['test_openssl', 'test_openssl', '-S -k 2 -m', '-k 2 m', 0, 0]), #Test with all FFDHE alg
    # TODO Pass SSL error code to valide in testcode
    #(['test_openssl', 'test_openssl', '-S -k 2 -V 12 -m', '-k 2 -V 12 -m', 255, 255]), #Test with all FFDHE alg
    #(['test_openssl', 'test_openssl', '-S -k 2 -V 13 -m', '-k 2 -V 12 -m', 255, 255]), #Test with all FFDHE alg
])

def test_openssl_kexch(tc_setup, kexch_apps_and_args):
    assert run_serv_clnt_app(kexch_apps_and_args) == 0
