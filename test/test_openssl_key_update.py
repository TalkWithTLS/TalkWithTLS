#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    # Server initiates key update after first handshake and data transfer.
    # And perfroms data transfer again
    (' -serv -kupda 1 -msgcb ', ' -kupda 1 -msgcb '),
    # Key update on client
    (' -serv -kupda 2 -msgcb ', ' -kupda 2 -msgcb '),
    # Non request key update on server
    (' -serv -kupda 3 -msgcb ', ' -kupda 3 -msgcb '),
    # Non request key update on client 
    (' -serv -kupda 4 -msgcb ', ' -kupda 4 -msgcb '),
])

def test_openssl_kupdate(tc_setup, sarg, carg):
    assert run_test(sarg, carg) == TC_SUCCESS
