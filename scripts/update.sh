#!/bin/bash

exec 1>kontrolvm.log 2>&1

echo "Kicking off the update script, you can check the kontrolvm.log file for more details." > /dev/tty 

echo "Updating KontrolVM..." > /dev/tty 
cd /home/kontrolvm/
wget -O killconsole.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/killconsole.sh
wget -O buildnet.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/buildnet.sh
wget -O cleandata.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/cleandata.sh
wget -O destroyvps.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/destroyvps.sh
wget -O iolimits.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/iolimits.sh
wget -O tc_start.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/tc_start.sh
wget -O tc_stop.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/tc_stop.sh
wget -O backup_vm.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/backup_vm.sh
wget -O restore_vm.sh https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/restore_vm.sh
new_version=$(/usr/bin/curl -s https://kontrolvm.com/version)
sed -i "s/kontrolvm_version=[^[:space:]]\+/kontrolvm_version=$new_version/" /home/kontrolvm/conf/kontrolvm.conf

echo "Set permissions for KontrolVM..." > /dev/tty 
chmod 0755 /home/kontrolvm/*.sh
chmod 0700 /home/kontrolvm/.ssh
chmod 0600 /home/kontrolvm/.ssh/*

echo "KontrolVM node update completed, a full log is available in kontrolvm.log" > /dev/tty 