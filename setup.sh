#!/bin/sh

pip3 install NetfilterQueue
pip3 install python-iptables
pip3 install scapy

sudo apt-get update -y
sudo apt-get install yum -y
yum install libnetfilter_queue-devel -y