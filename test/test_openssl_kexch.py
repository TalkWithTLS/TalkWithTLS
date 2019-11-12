#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("app1, app2, app1_args, app2_args, app1_res, app2_res", [
    # Test with all ecdhe kexch alg
    ('test_openssl', 'test_openssl', ' -serv -kex 1 -msgcb ', ' -kex 1 -msgcb ', 0, 0),

    # Test with kexchange set as string using SSL_set1_groups_list API on client
    ('test_openssl', 'test_openssl', ' -serv -kex 1 -msgcb ', ' -kex 3 -msgcb ', 0, 0),

    #('test_openssl', 'test_openssl', ' -serv -kex 2 -msgcb ', ' -kex 2 m ', 0, 0), #Test with all FFDHE alg

    # Test with kexchange set as string using SSL_set1_groups_list API on both client and server
    ('test_openssl', 'test_openssl', ' -serv -kex 3 -msgcb ', ' -kex 3 m ', 0, 0), #ECDHE kexch
    #('test_openssl', 'test_openssl', ' -serv -kex 4 -msgcb ', ' -kex 4 m ', 0, 0), #FFDHE kexch

    # TODO Pass SSL error code to valide in testcode
    # Test with only FFDHE kexch alg on TLS1.2 server and client
    #('test_openssl', 'test_openssl', ' -serv -kex 2 -ver 12 -msgcb ', ' -kex 2 -ver 12 -msgcb ', 255, 255),
    # Test with only FFDHE kexch alg on TLS1.2 client
    #('test_openssl', 'test_openssl', ' -serv -kex 2 -ver 13 -msgcb ', ' -kex 2 -ver 12 -msgcb ', 255, 255),
])

def test_openssl_kexch(tc_setup, app1, app2, app1_args, app2_args, app1_res, app2_res):
    assert run_serv_clnt_app([app1, app2, app1_args, app2_args, app1_res, app2_res]) == 0
