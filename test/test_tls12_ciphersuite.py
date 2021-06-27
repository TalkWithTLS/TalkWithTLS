#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    # Test with ECDHE ECDSA ciphersuite
    (' -serv -ver 12 -ciph TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        ' -ver 12 -ciph TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
    (' -serv -ver 12 -ciph TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        ' -ver 12-ciph TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),

    # Test with ECDHE RSA ciphersuite
    (' -serv -ver 12 -ciph TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' \
        ' -cert ./certs/RSA2048_Certs/serv_cert.pem' \
        ' -priv-key ./certs/RSA2048_Certs/serv_key_unencrypted.pem',
        ' -ver 12 -ciph TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' \
        ' -trust-certs ./certs/RSA2048_Certs/rootcert.pem'),
    (' -serv -ver 12 -ciph TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' \
        ' -cert ./certs/RSA2048_Certs/serv_cert.pem' \
        ' -priv-key ./certs/RSA2048_Certs/serv_key_unencrypted.pem',
        ' -ver 12 -ciph TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' \
        ' -trust-certs ./certs/RSA2048_Certs/rootcert.pem'),

    # Test with RSA ciphersuite
    (' -serv -ver 12 -ciph TLS_RSA_WITH_AES_128_GCM_SHA256' \
        ' -cert ./certs/RSA2048_Certs/serv_cert.pem' \
        ' -priv-key ./certs/RSA2048_Certs/serv_key_unencrypted.pem',
        ' -ver 12 -ciph TLS_RSA_WITH_AES_128_GCM_SHA256' \
        ' -trust-certs ./certs/RSA2048_Certs/rootcert.pem'),
    (' -serv -ver 12 -ciph TLS_RSA_WITH_AES_256_GCM_SHA384' \
        ' -cert ./certs/RSA2048_Certs/serv_cert.pem' \
        ' -priv-key ./certs/RSA2048_Certs/serv_key_unencrypted.pem',
        ' -ver 12 -ciph TLS_RSA_WITH_AES_256_GCM_SHA384' \
        ' -trust-certs ./certs/RSA2048_Certs/rootcert.pem'),
])

def test_t12_ciphersuite(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
