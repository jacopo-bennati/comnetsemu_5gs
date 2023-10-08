#!/bin/bash

sudo mn -c

docker stop $(docker ps -aq)

docker container prune -f

if [ "$1" == "log" ]; then
    cd log && sudo rm *.log 
fi

sudo ip link delete s1-s2
sudo ip link delete s2-s1
sudo ip link delete s2-s3
sudo ip link delete s3-s2

sudo ip link delete cp-s3
sudo ip link delete s3-cp
sudo ip link delete upf-s3
sudo ip link delete s3-upf
sudo ip link delete upf_mec-s2
sudo ip link delete s2-upf_mec

sudo ip link delete ue-s1
sudo ip link delete s1-ue

sudo ip link delete gnb_1-s1
sudo ip link delete s1-gnb_1
sudo ip link delete gnb_2-s1
sudo ip link delete s1-gnb_2
