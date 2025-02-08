#!/bin/bash

/sbin/tc qdisc del dev br0 root
/sbin/tc qdisc add dev br0 root handle 1: htb default 1000
/sbin/tc class add dev br0 parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:99 htb rate 1mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:5 htb rate 5mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:10 htb rate 10mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:50 htb rate 50mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:100 htb rate 100mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:500 htb rate 500mbit burst 15k
/sbin/tc class add dev br0 parent 1:1 classid 1:1000 htb rate 1000mbit burst 15k
/sbin/tc qdisc add dev br0 parent 1:5 handle 5: sfq perturb 10
/sbin/tc qdisc add dev br0 parent 1:10 handle 10: sfq perturb 10
/sbin/tc qdisc add dev br0 parent 1:50 handle 50: sfq perturb 10
/sbin/tc qdisc add dev br0 parent 1:100 handle 100: sfq perturb 10
/sbin/tc qdisc add dev br0 parent 1:500 handle 500: sfq perturb 10
/sbin/tc qdisc add dev br0 parent 1:1000 handle 1000: sfq perturb 10

for each in /home/kontrolvm/tc/* ; do bash $each ; done