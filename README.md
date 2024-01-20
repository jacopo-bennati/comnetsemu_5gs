
# Comnetsmu_5gs [Networking II]


>Emulate a 5G network deployment in comnetsemu.
Demonstrate distributed UPF deployment and slice-base UPF selection.

![topology](/images/newTopology.png)

#### Networking II project team:
* Bennati Jacopo (mat. 209869)
* Finetti Emiliano (mat. 209076)
* Arrondo Diego (mat. 209176)

### Prerequisites

- Comnetsemu [[link](https://git.comnets.net/public-repo/comnetsemu)]
- PyMongo
- Tabulate
- PyFiGlet 

## Build Instructions

Clone repository in the comnetsemu VM.

```
cd ~
git clone https://github.com/jacopo-bennati/comnetsemu_5gs.git
```
Build the necessary docker images:

```
cd comnetsemu_5gs/build
./dockerhub_pull.sh
```

Build the mec server docker image:

```
cd comnetsemu_5gs/mec_server
./build.sh
```


## Libraries

### Run install script

Installs all prerequired python modules
```
cd comnetsemu_5gs/build
./pyModules.sh
```
*If doesn't work try with __sudo__*

*All set :)*

## Run the network topology

Inside the root folder of the repository run the bash script to perform a ___clean and safe start___:
```
./runTopology.sh
```

#### Or instead run it manually

Inside the root folder of the repository run the script as ___sudo___:
```
sudo python3 2gnb_4ue_network.py
```

#### Runtime issues

If started manually and getting issues try running the clean script located in the root folder: 
```
./clean.sh
```

## Testing connections

### Testnet

To run tests simply type:

```
sudo python3 TestNet5G.py
```

## Test with Wireshark

Verify if it's correctly installed with all dependencies:

```
sudo apt-get install wireshark
```

To run it simply type:
```
wireshark
```
### Permission issues

To enable non-root user to listen to devices use this command and add user to ___'wireshark'___ group:
```
sudo dpkg-reconfigure wireshark-common
sudo adduser $USER wireshark
sudo chmod +x /usr/bin/dumpcap
```
note that if you don't have $USER variable you can find it running:
```
whoami
```
in my case output is : <br>
___vagrant___

---
