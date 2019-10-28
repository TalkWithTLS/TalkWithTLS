#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("basic_app1, basic_app2, app1_args, app2_args", [
    ('test_openssl', 'test_openssl', ' -serv ', ''),
    ('test_openssl', 'test_openssl', ' -serv -nbsock ', ' -nbsock '),
])

def test_openssl_basic(tc_setup, basic_app1, basic_app2, app1_args, app2_args):
    assert run_serv_clnt_app([basic_app1, basic_app2, app1_args, app2_args]) == 0

@pytest.mark.parametrize("psk_app1, psk_app2, app1_args, app2_args", [
    ('test_openssl', 'test_openssl', ' -serv -psk -msgcb ', ' -psk -msgcb '),
])

def test_openssl_psk(tc_setup, psk_app1, psk_app2, app1_args, app2_args):
    assert run_serv_clnt_app([psk_app1, psk_app2, app1_args, app2_args]) == 0
