#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("basic_apps_and_args", [
    (['test_openssl', 'test_openssl', '-S']),
    (['test_openssl', 'test_openssl', '-S -n', '-n']),
])

def test_openssl_basic(tc_setup, basic_apps_and_args):
    assert run_serv_clnt_app(basic_apps_and_args) == 0

@pytest.mark.parametrize("psk_apps_and_args", [
    (['test_openssl', 'test_openssl', '-SPm', '-Pm']),
])

def test_openssl_psk(tc_setup, psk_apps_and_args):
    assert run_serv_clnt_app(psk_apps_and_args) == 0
