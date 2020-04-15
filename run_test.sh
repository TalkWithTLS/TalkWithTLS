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

row_idx=0
arr=()
while [ true ]; do
    arr=()
    # Get each SUT info
    get_sut ${row_idx} arr
    echo "row ${row_idx}"
    if [ -z "${arr}" ]; then
        echo "Arr is empty"
        break
    else
        # Spawn each SUT
        SUT_EXE=${arr[0]}
        SUT_OPTVAL=${arr[1]}
        SUT_LOG=${arr[2]}
        ./${SUT_EXE} -tc-automation="${SUT_OPTVAL},${ins_id}" \
            > ${REPORT_DIR}/${SUT_LOG}${ins_id}.txt 2>&1 &
        pid=$!
        echo "Spawned ${SUT_EXE} [${SUT_OPTVAL}], PID=${pid}"
        pids+=(${pid})
    fi
    echo ""
    ((row_idx++))
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
