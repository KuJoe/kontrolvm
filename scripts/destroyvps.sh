# Script Name:  destroyvps

sudo /usr/bin/virsh destroy $1
sudo /usr/bin/virsh undefine $1
sudo /usr/bin/virsh undefine $1 --nvram
/bin/rm -rf /home/kontrolvm/xmls/$1.xml
sudo /usr/bin/sh /home/kontrolvm/cleandata.sh $1
/bin/rm -rf /home/kontrolvm/addrs/$1
/bin/rm -rf /home/kontrolvm/tc/$1
sudo /bin/sh /home/kontrolvm/tc_stop.sh
sudo /bin/sh /home/kontrolvm/tc_start.sh