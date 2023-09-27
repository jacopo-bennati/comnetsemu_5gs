#!/bin/bash

if [ $# -gt 0 ]; then
  if [ $1 -gt 0 ]; then
    echo "Argomento valido: $1"
    N="_$1"
  else
    N=""
  fi
fi

sleep 20
./nr-gnb -c /mnt/ueransim/open5gs-gnb$N.yaml > /mnt/log/gnb$N.log 2>&1
