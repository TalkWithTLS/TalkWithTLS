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
    ('test_openssl', 'test_openssl', ' -s --keyupdate 1 --msgcb ', ' --keyupdate 1 --msgcb ', 0, 0),
    # Key update on client
    ('test_openssl', 'test_openssl', ' -s --keyupdate 2 --msgcb ', ' --keyupdate 2 --msgcb ', 0, 0),
    # Non request key update on server
    ('test_openssl', 'test_openssl', ' -s --keyupdate 3 --msgcb ', ' --keyupdate 3 --msgcb ', 0, 0),
    # Non request key update on client 
    ('test_openssl', 'test_openssl', ' -s --keyupdate 4 --msgcb ', ' --keyupdate 4 --msgcb ', 0, 0),
])

def test_openssl_kupdate(tc_setup, app1, app2, app1_args, app2_args, app1_res, app2_res):
    assert run_serv_clnt_app([app1, app2, app1_args, app2_args, app1_res, app2_res]) == 0
