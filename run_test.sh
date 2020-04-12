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

ins_id=0 #Instance ID
pids=()
echo "Spawning SUTs..."
./${TEST_OPENSSL} -tc-automation="${OSSL_111_CLNT},${ins_id}" \
                    > ${REPORT_DIR}/ossl_111_clnt_${ins_id}.txt 2>&1 &
pids+=($!)
./${TEST_OPENSSL} -tc-automation="${OSSL_111_SERV},${ins_id}" \
                    > ${REPORT_DIR}/ossl_111_serv_${ins_id}.txt 2>&1 &
pids+=($!)
for pid in "${pids[@]}"
do
    echo "Spawned PID ${pid}"
done

python -m pytest ${TS} -v --maxfail=1 --html=${REPORT_DIR}/TalkWithTLS.html
python_res=$?

echo "Shutting down SUTs"
python test/stop_sut.py ${OSSL_111_CLNT_AUTOMATION_PORT} ${ins_id}
python test/stop_sut.py ${OSSL_111_SERV_AUTOMATION_PORT} ${ins_id}

sut_res=0
for pid in "${pids[@]}"
do
    wait ${pid}
    if [ $? -ne 0 ]; then
        sut_res=-1
    fi
done
echo "All SUTs closed"

[[ ${python_res} -eq 0 ]] && [[ ${sut_res} -eq 0 ]] && exit 0
exit -1
