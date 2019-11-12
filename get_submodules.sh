#!/bin/bash

git submodule init
git submodule update
echo ""

DEPENDENCY_DIR=dependency

declare -a dep_modules=('openssl-master'
                        'wolfssl-master')

for module in "${dep_modules[@]}"
do
    echo "Updating git submodule ${DEPENDENCY_DIR}/${module}..."
    cd ${DEPENDENCY_DIR}/${module}
    if [ $? -eq 0 ]; then
        git remote update > /dev/null
        git checkout master > /dev/null
        git pull origin master > /dev/null
        git log -n 1 --oneline
        cd -
    fi
    echo ""
done
