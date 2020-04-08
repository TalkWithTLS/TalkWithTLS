#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("d12_app1, d12_app2", [
    ('sample/openssl_dtls12_server', 'sample/openssl_dtls12_client'),
    ('sample/openssl_dtls12_server', 'sample/openssl_dtls12_custom_bio_client'),
    ('sample/openssl_dtls12_nb_server', 'sample/openssl_dtls12_client'),
    ('sample/openssl_dtls12_nb_server', 'sample/openssl_dtls12_nb_client'),
])

def test_dtls12_sample_code(tc_setup, d12_app1, d12_app2):
    assert run_serv_clnt_app([d12_app1, d12_app2]) == 0

