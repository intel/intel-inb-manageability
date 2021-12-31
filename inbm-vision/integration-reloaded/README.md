# Introduction

Integration-reloaded is a sub-project which creates an Ubuntu 18.04 or 20.04 server environment
with a BTRFS file system (mounted as / )

# Uses

1. It can be used as a test box for testing bit-creek artifacts
2. Demo machine
3. Used as part of BitCreek's CI system.

# Local setup

Sets up a system ready to go with a click of a button...you will have to perform a one-time setup 
on your local dev system

## Pre-requisites:
Installing Vagrant, libvirt, Qmenu-KVM and the plugins etc

1. Download vagrant from vagrant https://www.vagrantup.com/downloads.html and
  install by `dpkg -i <yourvagrantdownload>.deb`

2. Edit the /etc/apt/sources.list and uncomment all the deb-src lines

3. Run the below commands in sequence (preferably as root)
``` 
    apt update
    apt install qemu qemu-kvm libvirt-deamon
    apt-get build-dep vagrant ruby-libvirt
    apt-get install qemu libvirt-daemon ebtables dnsmasq
    apt-get install libxslt-dev libvirt-dev zlib1g-dev ruby-dev
```

4. Install the vagrant plugins:
```
vagrant plugin install vagrant-proxyconf
vagrant plugin install vagrant-share
vagrant plugin install vagrant-libvirt
```

if you run into some errors at this point, most likely you did step 1 of pre-requisites wrong.Check if you have installed
the right version of vagrant. For me, Vagrant 2.0.0 works well.

For me, these plugins work best:
vagrant-libvirt (0.0.45, global)
vagrant-proxyconf (2.0.7, global)
vagrant-share (1.1.9, global)

## How to use it
1. Clone the iotg-manageability repository
2. Run `sudo ./dev-mode.sh`
3. Run `sudo ./build.sh`
4. Run `sudo cp -rf output integration-reloaded/input`
5. Go to integration-reloaded folder
6. Run `sudo ./setup.sh`
7. Run 'sudo ./launchers/install-framework-slow.sh'
8. Run `sudo vagrant ssh` to enter VM.
