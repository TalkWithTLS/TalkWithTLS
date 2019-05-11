#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("app1, app2, app1_args, app2_args, app1_res, app2_res", [
    # Server initiates key update after first handshake and data transfer.
    # And perfroms data transfer again
    ('test_openssl', 'test_openssl', ' -S -K 1 -m ', ' -K 1 -m ', 0, 0),
    # Key update on client
    ('test_openssl', 'test_openssl', ' -S -K 2 -m ', ' -K 2 -m ', 0, 0),
    # Non request key update on server
    ('test_openssl', 'test_openssl', ' -S -K 3 -m ', ' -K 3 -m ', 0, 0),
    # Non request key update on client 
    ('test_openssl', 'test_openssl', ' -S -K 4 -m ', ' -K 4 -m ', 0, 0),
])

def test_openssl_kupdate(tc_setup, app1, app2, app1_args, app2_args, app1_res, app2_res):
    assert run_serv_clnt_app([app1, app2, app1_args, app2_args, app1_res, app2_res]) == 0
