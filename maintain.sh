#!/usr/bin/env bash
cd $HOME/git/maintenance
. env/bin/activate
./maintain.py /netstore/emptyhammock/backups /netstore/emptyhammock/logs /netstore/emptyhammock/config "$@"
