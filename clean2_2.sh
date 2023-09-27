#!/bin/bash

sudo mn -c

docker stop $(docker ps -aq)

docker container prune -f

if [ "$1" == "log" ]; then
    cd log && sudo rm *.log 
fi

sudo ip link delete s1-s2
sudo ip link delete s2-s3
sudo ip link delete cp-s3
sudo ip link delete upf-s3
sudo ip link delete upf_mec-s2

sudo ip link delete ue_1-s1
sudo ip link delete ue_2-s1
sudo ip link delete gnb_1-s1
sudo ip link delete ue_3-s1
sudo ip link delete ue_4-s1
sudo ip link delete gnb_2-s1

sudo ip link delete s1-ue_1
sudo ip link delete s1-ue_2
sudo ip link delete s1-gnb_

sudo ip link delete s1-ue_3
sudo ip link delete s1-ue_4
sudo ip link delete s1-gnb_2
