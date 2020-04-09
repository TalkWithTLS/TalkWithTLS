#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv -cauth -msgcb ', ' -cauth -msgcb '),
])

def test_openssl_tls13_auth(tc_setup, sarg, carg):
    assert run_test(sarg, carg) == TC_SUCCESS
