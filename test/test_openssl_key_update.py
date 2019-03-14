#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("kupdate_apps_and_args", [
    # Server initiates key update after first handshake and data transfer.
    # And perfroms data transfer again
    (['test_openssl', 'test_openssl', '-S -K 1 -m', '-K 1 m']),
    # Key update on client
    (['test_openssl', 'test_openssl', '-S -K 2 -m', '-K 2 m']),
    # Non request key update on server
    (['test_openssl', 'test_openssl', '-S -K 3 -m', '-K 3 m']),
    # Non request key update on client 
    (['test_openssl', 'test_openssl', '-S -K 4 -m', '-K 4 m']),
])

def test_openssl_kupdate(tc_setup, kupdate_apps_and_args):
    assert run_serv_clnt_app(kupdate_apps_and_args) == 0
