#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("app1, app2, app1_args, app2_args, app1_res, app2_res", [
    # Test DTLS 1.0
    ('test_openssl', 'test_openssl', ' --serv --ver 910', ' --ver 910 ', 0, 0),
    # Test DTLS 1.2
    ('test_openssl', 'test_openssl', ' --serv --ver 912', ' --ver 912 ', 0, 0),
])

def test_openssl_dtls_basic(tc_setup, app1, app2, app1_args, app2_args, app1_res, app2_res):
    assert run_serv_clnt_app([app1, app2, app1_args, app2_args, app1_res, app2_res]) == 0
