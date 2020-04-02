#!/bin/bash

err_report()
{
    echo "Error on line $1"
    exit -1
}

trap 'err_report $LINENO' ERR

git submodule init
git submodule update
git submodule foreach git pull origin master 1>/dev/null 2>&1
echo "Pulled latest code from origin"
echo ""
git submodule foreach git log -n 1 --oneline
