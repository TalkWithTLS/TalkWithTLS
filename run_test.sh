#!/bin/bash

TEST_DIR=test
ENV_SETUP_SCRIPT=./${TEST_DIR}/setup_test_env.sh
if [ ! -f ${ENV_SETUP_SCRIPT} ]; then
    echo "${ENV_SETUP_SCRIPT} not found"
    exit -1
fi
. "${ENV_SETUP_SCRIPT}"

python -m pytest ${TEST_DIR} -v --html=${REPORT_DIR}/TalkWithTLS.html
