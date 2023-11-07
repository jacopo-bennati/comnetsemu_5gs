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

### first logical link

sudo ip link delete ue1-s1
sudo ip link delete s1-ue1
sudo ip link delete gnb1-s1
sudo ip link delete s1-gnb1

### second logical link

sudo ip link delete ue2-s1
sudo ip link delete s1-ue2
sudo ip link delete gnb2-s1
sudo ip link delete s1-gnb2

sudo ip link delete s2-mec_server
sudo ip link delete mec_server-s2