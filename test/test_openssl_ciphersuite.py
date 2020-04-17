#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv ', ' -ciph TLS_CHACHA20_POLY1305_SHA256'),
    (' -serv ', ' -ciph TLS_AES_128_GCM_SHA256'),
])

def test_openssl_tls13_ciphersuite(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
