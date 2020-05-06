#!/usr/bin/python3

import pytest

from common import *

filename = os.path.basename(__file__)

@pytest.fixture
def tc_setup():
    '''Initializes log file in TWT log module'''
    TWT_set_log_filename(filename)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv -res ', ' -res ')
])

def test_t13_resumption(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)

@pytest.mark.parametrize("sarg, carg", [
    (' -serv -res -earlydata ', ' -res -earlydata ')
])

def test_t13_resumption_early_data(tc_setup, sarg, carg):
    run_test(inspect.stack()[0][3], sarg, carg)
