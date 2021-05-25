#!/bin/bash

err_report()
{
    echo "Error on line $1"
    exit -1
}

trap 'err_report $LINENO' ERR

git submodule init
echo "Fetching submodule from remote..."
git submodule update --recursive --remote 1>/dev/null
echo "Fetched latest code from remote"
git submodule status
