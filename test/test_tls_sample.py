#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("t12_apps", [
    (['openssl_tls12_server', 'openssl_tls12_client']),
    (['openssl_tls12_server', 'openssl_nb_client']),
    (['openssl_tls12_verify_cb_server', 'openssl_tls12_verify_cb_client']),
])

def test_tls12_sample_code(tc_setup, t12_apps):
    run_serv_clnt_app(t12_apps) == 0

@pytest.mark.parametrize("t13_apps", [
    (['openssl_tls13_server', 'openssl_tls13_client']),
    #(['openssl_tls13_dhe_server', 'openssl_tls13_dhe_client']),
    (['wolfssl_tls13_server', 'wolfssl_tls13_client']),
])

def test_tls13_sample_code(tc_setup, t13_apps):
    run_serv_clnt_app(t13_apps) == 0

