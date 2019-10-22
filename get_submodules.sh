#!/bin/bash

git submodule init
git submodule update

DEPENDENCY_DIR=dependency

declare -a dep_modules=('wolfssl-master')

for module in "${dep_modules[@]}"
do
    echo "Updating git submodule ${DEPENDENCY_DIR}/${module}"
    cd ${DEPENDENCY_DIR}/${module}
    if [ $? -eq 0 ]; then
        git remote update
        git checkout master
        git rebase origin/master
        cd -
    fi
done
