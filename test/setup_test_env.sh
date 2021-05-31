#!/bin/bash

BIN_DIR=bin
TEST_OSSL_111=${BIN_DIR}/test_openssl_111
TEST_OSSL_300=${BIN_DIR}/test_openssl_300
export REPORT_DIR=report
export LOG_DIR=report/log

# TODO SUT_IP also should go from here to test/common.py

# Two ports for each SUT (test exe)
# - One (xxx_AUTOMATION_PORT) port for communicating test control msgs between
#   python script and SUT (test exe)
# - Another port for the actual port [D]TLS connection is made
export OSSL_111_CLNT_AUTOMATION_PORT=25100
export OSSL_111_SERV_AUTOMATION_PORT=25200
export OSSL_111_CLNT_PORT=15100
export OSSL_111_SERV_PORT=15200
OSSL_111_CLNT=(${OSSL_111_CLNT_AUTOMATION_PORT},${OSSL_111_CLNT_PORT})
OSSL_111_SERV="${OSSL_111_SERV_AUTOMATION_PORT},${OSSL_111_SERV_PORT}"

export OSSL_300_CLNT_AUTOMATION_PORT=25300
export OSSL_300_SERV_AUTOMATION_PORT=25400
export OSSL_300_CLNT_PORT=15300
export OSSL_300_SERV_PORT=15400
OSSL_300_CLNT=(${OSSL_300_CLNT_AUTOMATION_PORT},${OSSL_300_CLNT_PORT})
OSSL_300_SERV="${OSSL_300_SERV_AUTOMATION_PORT},${OSSL_300_SERV_PORT}"

col_size=4
SUTS_INFO=(${TEST_OSSL_111} ${OSSL_111_CLNT} test_openssl_111_clnt
                            ${OSSL_111_CLNT_AUTOMATION_PORT}
           ${TEST_OSSL_111} ${OSSL_111_SERV} test_openssl_111_serv
                            ${OSSL_111_SERV_AUTOMATION_PORT}
           ${TEST_OSSL_300} ${OSSL_300_CLNT} test_openssl_300_clnt
                            ${OSSL_300_CLNT_AUTOMATION_PORT}
           ${TEST_OSSL_300} ${OSSL_300_SERV} test_openssl_300_serv
                            ${OSSL_300_SERV_AUTOMATION_PORT}
          )

# Get nth row and update to 2nd arg
get_sut()
{
    row=$1
    local -n a=$2
    start_idx=$((row * col_size))
    for ((i = 0; i < ${col_size}; i++)); do
        idx=$((start_idx + i))
        a+=(${SUTS_INFO[${idx}]})
    done
}

export LD_LIBRARY_PATH=${BIN_DIR}:$LD_LIBRARY_PATH

if [ -d ${REPORT_DIR} ]; then
    rm -rf ${REPORT_DIR}
fi
mkdir -p ${REPORT_DIR}
mkdir -p ${LOG_DIR}
