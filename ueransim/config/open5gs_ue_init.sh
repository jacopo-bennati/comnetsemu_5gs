#!/bin/bash

# export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

sleep 25
./nr-ue -c /mnt/ueransim/open5gs-ue.yaml -n 2 -i imsi-001011234567895 > /mnt/log/ue.log 2>&1