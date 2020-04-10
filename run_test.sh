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

PORT=25100

./${TEST_OPENSSL} -tc-automation > ${REPORT_DIR}/test_openssl_0.txt 2>&1 &
ossl_pid1=$!
./${TEST_OPENSSL} -tc-automation=1 > ${REPORT_DIR}/test_openssl_1.txt 2>&1 &
ossl_pid2=$!
echo "Spawned OpenSSL PIDs=${ossl_pid1}, ${ossl_pid2}"

python -m pytest ${TS} -v --maxfail=1 --html=${REPORT_DIR}/TalkWithTLS.html
python_res=$?

ps -ef | grep ${ossl_pid1}
ps -ef | grep ${ossl_pid2}
python test/stop_sut.py ${PORT} 1

echo "Waiting for PIDs=${ossl_pid1}, ${ossl_pid2}"
wait ${ossl_pid1}
sut1_res=$?
wait ${ossl_pid2}
sut1_res=$?
[[ ${python_res} -eq 0 ]] && [[ ${sut1_res} -eq 0 ]] && [[ ${sut2_res} -eq 0 ]] && exit 0
exit -1
