#!/bin/bash

# export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

if [ $# -gt 0 ]; then
  if [ $1 -gt 0 ]; then
    echo "Argomento valido: $1"
    N="_$1"
  else
    N=""
  fi
fi

sleep 25
./nr-ue -c /mnt/ueransim/open5gs-ue$N.yaml > /mnt/log/ue$N.log 2>&1