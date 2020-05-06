#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    # Test with all ecdhe kexch alg
    (' -serv -kex 1 -msgcb ', ' -kex 1 -msgcb '),

    # Test with kexchange set as string using SSL_set1_groups_list API on client
    (' -serv -kex 1 -msgcb ', ' -kex 3 -msgcb '),

    #(' -serv -kex 2 -msgcb ', ' -kex 2 m '), #Test with all FFDHE alg

    # Test with kexchange set as string using SSL_set1_groups_list API on both client and server
    (' -serv -kex 3 -msgcb ', ' -kex 3 m '), #ECDHE kexch
    #(' -serv -kex 4 -msgcb ', ' -kex 4 m '#FFDHE kexch

    # TODO Pass SSL error code to valide in testcode
    # Test with only FFDHE kexch alg on TLS1.2 server and client
    #(' -serv -kex 2 -ver 12 -msgcb ', ' -kex 2 -ver 12 -msgcb '),
    # Test with only FFDHE kexch alg on TLS1.2 client
    #(' -serv -kex 2 -ver 13 -msgcb ', ' -kex 2 -ver 12 -msgcb '),
])

def test_t13_kexch(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
