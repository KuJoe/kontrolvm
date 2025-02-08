#!/bin/sh
# Script Name:  buildnet

sudo /sbin/ebtables -F

if mkdir /home/kontrolvm/bnetlock; then
  for i in `/bin/ls /home/kontrolvm/addrs/`; do
        ip=`/bin/cat /home/kontrolvm/addrs/$i`
        addr=`sudo /usr/bin/virsh dumpxml $i | grep "mac address" | awk '{print $2}' | cut -c 10- | rev | cut -c4- | rev`
        sudo /sbin/ebtables -X $i
        sudo /sbin/ebtables -N $i
        sudo /sbin/ebtables -P $i DROP
        sudo /sbin/ebtables -A INPUT -i $i -j $i
        sudo /sbin/ebtables -A FORWARD -i $i -j $i
        while read ip; do
        if [[ $ip =~ .*:.* ]]; then
                                sudo /sbin/ebtables -A $i -p ip6 --ip6-src $ip -j ACCEPT
                                sudo /sbin/ebtables -A $i -p ip6 --ip6-dst $ip -j ACCEPT
        else
                sudo /sbin/ebtables -A $i -p ip --ip-src $ip -j ACCEPT
                                sudo /sbin/ebtables -A $i -p ip --ip-dst $ip -j ACCEPT
                                sudo /sbin/ebtables -A $i -p arp --arp-op Reply --arp-ip-src $ip -j ACCEPT
        fi
        done </home/kontrolvm/addrs/$i
                sudo /sbin/ebtables -A $i -p arp --arp-op Request -j ACCEPT
        sudo /sbin/ebtables -A FORWARD -i $i -s ! $addr -j DROP
  done
  sudo /sbin/iptables -F INPUT
  for i in `/bin/ls /home/kontrolvm/disabledvnc/`; do
        sudo /sbin/iptables -A INPUT -p tcp --destination-port $i -j DROP
  done
  rm -rf /home/kontrolvm/bnetlock
else
  echo "Lock failed - exit" >&2
  exit 1
fi