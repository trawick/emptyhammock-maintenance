#!/usr/bin/env bash

DATASETS=`zfs list -H | awk -e '{print $1}'`

for DS in ${DATASETS}; do
    if test ${DS} = "netstore/emptyhammock"; then
	zfs set com.sun:auto-snapshot=true ${DS}
    else
	zfs set com.sun:auto-snapshot=false ${DS}
    fi
done
