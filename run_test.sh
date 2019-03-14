#!/bin/bash

TEST_DIR=test
ENV_SETUP_SCRIPT=./${TEST_DIR}/setup_test_env.sh
if [ ! -f ${ENV_SETUP_SCRIPT} ]; then
    echo "${ENV_SETUP_SCRIPT} not found"
    exit -1
fi
. "${ENV_SETUP_SCRIPT}"

if (( $# > 0 )); then
    TS=$1
else
    TS=${TEST_DIR}
fi

python -m pytest ${TS} -v --html=${REPORT_DIR}/TalkWithTLS.html
