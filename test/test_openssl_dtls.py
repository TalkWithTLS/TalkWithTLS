#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    # Test DTLS 1.0
    #TODO fix this failure in 1.1.1 vs 3.0.0
    #(' -serv -ver 910', ' -ver 910 '),
    # Test DTLS 1.2
    (' -serv -ver 912', ' -ver 912 '),
])

def test_openssl_dtls_basic(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
