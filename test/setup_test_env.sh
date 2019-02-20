#!/bin/bash

BIN_DIR=bin
LOG_DIR=log

export LD_LIBRARY_PATH=${BIN_DIR}:$LD_LIBRARY_PATH

if [ -d ${LOG_DIR} ]; then
    rm -rf ${LOG_DIR}
fi
mkdir -p ${LOG_DIR}
