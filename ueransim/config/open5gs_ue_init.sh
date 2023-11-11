#!/bin/bash

# export IP_ADDR=$(awk 'END{print $1}' /etc/hosts)

sleep 25

./nr-ue -c /mnt/ueransim/open5gs-ue.yaml -i imsi-001011234567895 > /mnt/log/ue1_1.log 2>&1 &
(
    sleep 5
    # rm -rf /tmp/UERANSIM.proc-table/ >> /mnt/log/ue1_1.log 2>&1
    ./nr-ue -c /mnt/ueransim/open5gs-ue_2.yaml -i imsi-001011234567896 > /mnt/log/ue1_2.log 2>&1
)