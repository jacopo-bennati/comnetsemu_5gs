#!/bin/bash

# export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

sleep 25
./nr-ue -c /mnt/ueransim/open5gs-ue_2.yaml -n 2 -i imsi-001011234567897 > /mnt/log/ue_2.log 2>&1