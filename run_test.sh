#!/bin/bash

TEST_DIR=test
ENV_SETUP_SCRIPT=./${TEST_DIR}/setup_test_env.sh
if [ ! -f ${ENV_SETUP_SCRIPT} ]; then
    echo "${ENV_SETUP_SCRIPT} not found"
    exit -1
fi
. "${ENV_SETUP_SCRIPT}"

test_suites=('test_tls_sample.py')

for ts in "${test_suites[@]}"
do
    echo "Testing ${ts}...."
    python -m pytest ${TEST_DIR}/${ts} -v
done
