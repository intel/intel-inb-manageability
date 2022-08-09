# Introduction

integration-reloaded is sub-project within 'inb' which helps create a Ubuntu 20.04 or 22.04 server environment 
with a BTRFS file system (mounted as / )

# Uses

1. It can be used as a test box for testing 'inb' artifacts
2. Demo machine
3. Currently being used as a part of iotg-inb's CI system.

# Local setup

If you want to setup a system ready to go with a click of a button...you will have to perform a one-time setup 
on your local dev system

## Pre-requistes:
Installing Vagrant, Vagrant-libvirt, Qmenu-KVM and the plugins etc

1. Download vagrant from vagrant https://www.vagrantup.com/downloads.html and
  install by `dpkg -i <yourvagrantdownload>.deb`

2. Edit the /etc/apt/sources.list and uncomment all the deb-src lines

3. Run the below commands in sequence (preferrably as root)
``` 
    apt update
    apt install qemu qemu-kvm libvirt-bin
    apt-get build-dep vagrant ruby-libvirt
    apt-get install qemu libvirt-bin ebtables dnsmasq
    apt-get install libxslt-dev libvirt-dev zlib1g-dev ruby-dev
```

4. Install the vagrant plugins:
```
vagrant plugin install vagrant-share
vagrant plugin install vagrant-libvirt
```

## How to use it
1. Clone the iotg-inb repo
2. `cd ~/iotg-inb/integration-reloaded`
3. Create a folder in integration-reloaded called `input`
4. Download all the iotg-inb artifacts in that `input` folder and unzip the artifacts 
5. export your docker username as DOCKER_USERNAME and your docker password as DOCKER_PASSWORD
6. Run vagrant up... this can take some time depending on your system. Time to get some coffee..

NOTE: if the plugins are installed as root, run `sudo vagrant up`

This should download a VM image from one of our image servers, unbox and install artifacts on it.

Note: This provisions dispatcher with test adapter

## Additional steps for Integration
1. run ./setup.sh
2. run ./launchers/install-framework-quick.sh


## To mimic TeamCity build
1. run sudo ./run.sh

Yes, the order does not matter except for general-test.sh which should be at the end. it spits out all the apparmor logs

## Other Integration test suites

* ./run-quicker: Faster suite biased towards good run time to fail ratio.
* ./run-quick: Fairly comprehensive suite but skips extremely long tests like SOTA upgrade to new Ubuntu vevrsion.
* ./run-slow.sh: Runs any skipped tests from above.
