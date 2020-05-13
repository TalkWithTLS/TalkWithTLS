#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    # Arg '1' means passing only PSK ID and Key to TLSv1.3
    # In openssl this is done using psk_client_cb and psk_server_cb
    (' -serv -psk 1 ', ' -psk 1'),
    # Arg '2' means passing PSK ID and Key along with ciphersuite to TLSv1.3.
    # In openssl this is done using psk_use_sess_cb and psk_find_sess_cb.
    # If no cipher is passed with '2' in 'psk' option means default AES 128 GCM
    # is used.
    (' -serv -psk 2 ', ' -psk 2'),
    (' -serv -psk 2 -ciph TLS_AES_128_GCM_SHA256 ',
        ' -psk 2 -ciph TLS_AES_128_GCM_SHA256'),
    (' -serv -psk 2 -ciph TLS_AES_256_GCM_SHA384 ',
        ' -psk 2 -ciph TLS_AES_256_GCM_SHA384'),
    (' -serv -psk 2 -ciph TLS_CHACHA20_POLY1305_SHA256 ',
        ' -psk 2 -ciph TLS_CHACHA20_POLY1305_SHA256'),
    (' -serv -psk 2 -ciph TLS_AES_128_CCM_SHA256 ',
        ' -psk 2 -ciph TLS_AES_128_CCM_SHA256'),
    (' -serv -psk 2 -ciph TLS_AES_128_CCM_8_SHA256 ',
        ' -psk 2 -ciph TLS_AES_128_CCM_8_SHA256'),
    # Interop with PSK default cipher vs PSK specific cipher
    # In openssl interop with psk_client_cb/psk_server_cb vs
    # psk_use_sess_cb/psk_find_sess_cb
    (' -serv -psk 1 ', ' -psk 2 -ciph TLS_AES_128_GCM_SHA256 '),
    (' -serv -psk 2 -ciph TLS_AES_128_GCM_SHA256', ' -psk 1 '),
])

def test_t13_psk(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)

# Enable after #11785 merged in openssl
'''
@pytest.mark.parametrize("sarg, carg", [
    # Arg '1' means passing only PSK ID and Key to TLSv1.3
    # In openssl this is done using psk_client_cb and psk_server_cb
    #(' -serv -psk 1 -earlydata ', ' -psk 1'),
    # Arg '2' means passing PSK ID and Key along with ciphersuite to TLSv1.3.
    # In openssl this is done using psk_use_sess_cb and psk_find_sess_cb.
    # If no cipher is passed with '2' in 'psk' option means default AES 128 GCM
    # is used.
    (' -serv -psk 2 -earlydata ', ' -psk 2'),
    (' -serv -psk 2 -ciph TLS_AES_128_GCM_SHA256 -earlydata ',
        ' -psk 2 -ciph TLS_AES_128_GCM_SHA256 -earlydata'),
    (' -serv -psk 2 -ciph TLS_AES_256_GCM_SHA384 -earlydata ',
        ' -psk 2 -ciph TLS_AES_256_GCM_SHA384 -earlydata'),
    (' -serv -psk 2 -ciph TLS_CHACHA20_POLY1305_SHA256 -earlydata ',
        ' -psk 2 -ciph TLS_CHACHA20_POLY1305_SHA256 -earlydata'),
    (' -serv -psk 2 -ciph TLS_AES_128_CCM_SHA256 -earlydata ',
        ' -psk 2 -ciph TLS_AES_128_CCM_SHA256 -earlydata'),
    (' -serv -psk 2 -ciph TLS_AES_128_CCM_8_SHA256 -earlydata ',
        ' -psk 2 -ciph TLS_AES_128_CCM_8_SHA256 -earlydata'),
])

def test_t13_psk_early_data(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
'''
