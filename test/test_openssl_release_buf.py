#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    #TODO Dont know how to verify whether actually release buffer is getting invoked
    # Enable Release buff mode on SSL Context
    (' -serv -relbuf 1 ', '-clnt'),
    (' -serv ', ' -relbuf 1 '),

    # Enable Release buff mode on SSL
    (' -serv -relbuf 2 ', '-clnt'),
    (' -serv ', ' -relbuf 2 '),

    # Enable Release buff mode on SSL
    (' -serv -relbuf 1 -ver 13', ' -relbuf 1 -ver 13 '),
    (' -serv -relbuf 1 -ver 12', ' -relbuf 1 -ver 12 '),
    (' -serv -relbuf 1 -ver 11', ' -relbuf 1 -ver 11 '),
    (' -serv -relbuf 1 -ver 10', ' -relbuf 1 -ver 10 '),
])

def test_openssl_tls_release_buf(tc_setup, sarg, carg):
    assert run_test(sarg, carg) == TC_SUCCESS
