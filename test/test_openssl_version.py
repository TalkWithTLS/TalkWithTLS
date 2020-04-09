#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    #Test with max version as TLS1.0
    ('-serv -ver 10 -msgcb', '-ver 10 -msgcb'),
    ('-serv -ver 11 -msgcb', '-ver 11 -msgcb'),
    ('-serv -ver 12 -msgcb', '-ver 12 -msgcb'),
    ('-serv -ver 13 -msgcb', '-ver 13 -msgcb'),
    #Test with max ver on server as TLS1.3, and max ver on client as TLS1.2
    ('-serv -ver 1312 -msgcb', '-ver 1312 -msgcb'),
    ('-serv -ver 1213 -msgcb', '-ver 1213 -msgcb'),
])

def test_openssl_version(tc_setup, sarg, carg):
    assert run_test(sarg, carg) == TC_SUCCESS
