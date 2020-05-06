#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv ', ' '),
    (' -serv -nbsock ', ' -nbsock '),
])

def test_openssl_basic(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv -psk -msgcb ', ' -psk -msgcb '),
])

def test_openssl_psk(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
