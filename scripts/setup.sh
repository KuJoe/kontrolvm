#!/bin/bash

exec 1>kontrolvm.log 2>&1

echo "Kicking off the setup script, you can check the kontrolvm.log file for more details." > /dev/tty 

echo "Installing required software via yum (this might take a while)..." > /dev/tty 
yum install epel-release -y
/usr/bin/crb enable
yum install --skip-broken -y wget gcc make tar bind-utils zlib-devel openssl-devel pam pam-devel krb5-devel ncurses-devel e4fsprogs openssh-clients rrdtool smartmontools bridge-utils qemu-kvm libvirt virt-manager virt-install virt-top libguestfs-tools virt-viewer libvirt-daemon-kvm novnc ncurses-compat-libs iptables-services unzip net-tools

echo "Setting up KontrolVM user..." > /dev/tty 
adduser kontrolvm
chown -R kontrolvm:kontrolvm /home/kontrolvm
/usr/bin/setfacl -m u:qemu:rx /home/kontrolvm
echo "kontrolvm  ALL = NOPASSWD: /usr/bin/virsh, /usr/bin/virt-install, /sbin/iptables, /sbin/ip6tables, /sbin/ebtables, /bin/sh, /bin/sed, /sbin/ifconfig, /usr/bin/qemu-img, /home/kontrolvm/destroyvps.sh, /usr/bin/test, /usr/bin/novnc_proxy, /usr/bin/nohup, /usr/sbin/dmidecode" | sudo EDITOR='tee -a' visudo

echo "Disabling firewalld..." > /dev/tty 
systemctl stop firewalld
systemctl disable firewalld
systemctl mask firewalld

echo "Enabling iptables services..." > /dev/tty 
systemctl enable --now iptables
systemctl enable --now ip6tables
iptables -F
service iptables save

echo "Configuring network..." > /dev/tty 
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.conf
echo 'net.ipv6.conf.default.forwarding = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.proxy_arp = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.conf
echo 'kernel.sysrq = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.send_redirects = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
echo 'kernel.panic = 5' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.proxy_ndp = 1' >> /etc/sysctl.conf
echo 'net.core.rmem_max=16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max=16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem=4096 87380 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem=4096 65536 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
echo "net.bridge.bridge-nf-call-iptables = 1" >> /etc/sysctl.conf

BRIDGE_NAME="br0"
INTERFACE_NAME=`ip a show | grep 'state UP' | awk 'NR==1{print $2}' | sed 's/:$//'`
/usr/bin/nmcli connection add type bridge autoconnect yes con-name br0 ifname br0
/usr/bin/nmcli connection add type bridge-slave autoconnect yes con-name br0-slave ifname $INTERFACE_NAME master br0
/usr/bin/nmcli connection modify br0 bridge.stp no
/usr/bin/nmcli connection down $INTERFACE_NAME
/usr/bin/nmcli connection up br0
echo "allow all" > /etc/qemu-kvm/bridge.conf

echo "Updating sshd Config..." > /dev/tty 
echo "Match User kontrolvm" >> /etc/ssh/sshd_config
echo "     PasswordAuthentication no" >> /etc/ssh/sshd_config

echo "Creating directories/files for KontrolVM..." > /dev/tty 
cd
mkdir /home/kontrolvm/.ssh
touch /home/kontrolvm/.ssh/authorized_keys
mkdir /home/kontrolvm/tc
mkdir /home/kontrolvm/traffic
mkdir /home/kontrolvm/addrs
mkdir /home/kontrolvm/conf
mkdir /home/kontrolvm/data
mkdir /home/kontrolvm/iow
mkdir /home/kontrolvm/isos
mkdir /home/kontrolvm/xmls
mkdir /home/kontrolvm/kvm_backups
mkdir /home/kontrolvm/backups_tmp
touch /home/kontrolvm/ip4
touch /home/kontrolvm/ip6

echo "Configuring KontrolVM (this might take a while)..." > /dev/tty 
cd /home/kontrolvm/
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/killconsole.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/buildnet.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/cleandata.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/destroyvps.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/iolimits.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/tc_start.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/tc_stop.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/backup_vm.sh
wget -N https://raw.githubusercontent.com/KuJoe/kontrolvm/refs/heads/main/scripts/restore_vm.sh
echo "/usr/bin/wget -O /home/kontrolvm/isos/systemrescue-amd64.iso https://sourceforge.net/projects/systemrescuecd/files/sysresccd-x86/11.03/systemrescue-11.03-amd64.iso/download" > /home/kontrolvm/isos/wget_isos.sh
chmod 0755 /home/kontrolvm/isos/wget_isos.sh
echo "kontrolvm_version=1.2" > /home/kontrolvm/conf/kontrolvm.conf
echo '#!/bin/sh' > /home/kontrolvm/create_console.sh
echo "# Script Name:  create_console" >> /home/kontrolvm/create_console.sh
echo " " >> /home/kontrolvm/create_console.sh

/usr/bin/openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Online/L=Web/O=Web/CN=example.com" -keyout /home/kontrolvm/key.pem -out /home/kontrolvm/cert.pem
echo 'sudo /usr/bin/nohup /usr/bin/novnc_proxy --listen $1 --vnc localhost:$2 --ssl-only --cert /home/kontrolvm/cert.pem --key /home/kontrolvm/key.pem > /dev/null 2>&1 &' >> /home/kontrolvm/create_console.sh

echo "Set permissions for KontrolVM..." > /dev/tty 
cd
chown -R kontrolvm:kontrolvm /home/kontrolvm
chmod 0755 /home/kontrolvm/*.sh
chmod 0700 /home/kontrolvm/.ssh
chmod 0600 /home/kontrolvm/.ssh/*

echo "Setting up Websockify and noVNC..." > /dev/tty 
cd
wget https://github.com/novnc/websockify/archive/refs/tags/v0.11.0.zip
unzip v0.11.0.zip
rm v0.11.0.zip
cd websockify-0.11.0/
python3 setup.py install

systemctl restart sshd
systemctl enable --now libvirtd

echo "Setting up cronjobs..." > /dev/tty 
echo 'MAILTO=""' >> /var/spool/cron/root
echo '*/30 * * * * sh /home/kontrolvm/tc_start.sh' >> /var/spool/cron/root
echo '*/5 * * * * sh /home/kontrolvm/vz_traffic.sh' >> /var/spool/cron/root
echo '*/15 * * * * sh /home/kontrolvm/buildnet.sh' >> /var/spool/cron/root
echo '*/15 * * * * sh /home/kontrolvm/iolimits.sh' >> /var/spool/cron/root
echo '0 * * * * sh /home/kontrolvm/traffic.sh' >> /var/spool/cron/root
echo '0 0 * * * sh /home/kontrolvm/isos/wget_isos.sh' >> /var/spool/cron/root

echo "KontrolVM node setup completed, a full log is available in kontrolvm.log" > /dev/tty 
echo "Please reboot this server to complete the install." > /dev/tty
