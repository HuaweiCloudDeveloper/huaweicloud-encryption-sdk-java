#!/usr/bin/env bash

PROJECT_ROOT=$(cd `dirname $0/`/../..;pwd)
CURDIR=$(cd `dirname $0`;pwd)
APP_NAME="EncryptionSDK"

function assertExitCode()
{
    if [ $1 -ne 0 ]; then
        echo "Failed."
        exit 1
    fi
}


cd ${PROJECT_ROOT}
mvn -Dmaven.test.skip=true clean install