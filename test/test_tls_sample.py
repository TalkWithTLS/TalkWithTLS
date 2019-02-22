#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    TWT_set_log_filename(filename)

t12_testcases = [
                    ['openssl_tls12_server', 'openssl_tls12_client'],
                    ['openssl_tls12_verify_cb_server', 'openssl_tls12_verify_cb_client'],
                ]

# Test TLS1.2 Sample Code
def test_tls12_sample_code(tc_setup):
    for apps in t12_testcases:
        assert run_serv_clnt_app(apps) == 0

t13_testcases = [
                    ['openssl_tls13_server', 'openssl_tls13_client'],
                    #['openssl_tls13_dhe_server', 'openssl_tls13_dhe_client'],
                    ['wolfssl_tls13_server', 'wolfssl_tls13_client']
                ]

# Test TLS1.3 Sample Code
def test_tls13_sample_code(tc_setup):
    for apps in t13_testcases:
        assert run_serv_clnt_app(apps) == 0
