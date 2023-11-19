#!/bin/bash
function bbr_install(){
apt-get clean
apt-get update
apt-get install dpkg
UBK_BASE=http://kernel.ubuntu.com/~kernel-ppa/mainline/
UBK_LAST_BASE=`wget -qO- $UBK_BASE | grep -o "<a href=.*" | grep -v "\-rc" | tail -n1 | cut -d '"' -f2 | cut -d '/' -f1`
UBK_LAST_FIND=`wget -qO- $UBK_BASE | grep -o "<a href=.*" | grep -v "\-rc" | grep -o "$UBK_LAST_BASE../\"" | tail -n1 | cut -d '"' -f1`
UBK_LAST=$UBK_LAST_BASE
[[ -n $UBK_LAST_FIND ]] && UBK_LAST=$UBK_LAST_FIND
echo $UBK_LAST
UBK_ARCH="amd64"
UBK_DOWN=`wget -qO- $UBK_BASE$UBK_LAST | grep -o ">.*linux-image.*\.deb" | awk '{print substr($1,2)}' | grep generic | grep $UBK_ARCH | head -n1`
if [[ $UBK_DOWN =~ "unsigned" ]];then
    echo "install kernel modules..."  
    UBK_DOWN_MOD=`wget -qO- $UBK_BASE$UBK_LAST | grep -o ">.*linux-modules.*\.deb" | awk '{print substr($1,2)}' | grep generic | grep $UBK_ARCH | head -n1`
    wget $UBK_BASE$UBK_LAST'/'$UBK_DOWN_MOD
    UBK_DOWN_MOD=`echo $UBK_DOWN_MOD | grep -o "linux.*deb"`
    dpkg -i $UBK_DOWN_MOD
fi  
UBK_VER=`echo $UBK_DOWN |  cut -d "-" -f4`
echo $UBK_VER
wget $UBK_BASE$UBK_LAST'/'$UBK_DOWN
UBK_DOWN=`echo $UBK_DOWN | grep -o "linux.*deb"`
dpkg -i $UBK_DOWN
# delete old kernel
# grep -o print match pattern -v print dismatch pattern
apt remove -y `dpkg -l | grep -o "linux-image.*-generic" | grep -v $UBK_VER`
update-grub
systemctl enable rc-local
if [ ! -f "/etc/rc.local" ]; then
    echo '#!/bin/sh" > /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
fi
systemctl status rc-local

if [ ! -f "/etc/rc.local.old.bbr" ]; then
    echo "first time run this script, backup the sources.list"
    cp /etc/rc.local /etc/rc.local.old.bbr
fi
cp /etc/rc.local /etc/rc.local.old.bbr
sed -i '/^exit/,$d' /etc/rc.local
echo "bash `pwd`/$0 install" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
chmod 0755 /etc/rc.local
chmod 0755 /etc/rc.local.old.bbr
reboot
}
function bbr_conf(){
uname -r
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
sysctl net.ipv4.tcp_available_congestion_control | grep bbr
lsmod | grep bbr
cp /etc/rc.local.old.bbr /etc/rc.local
}
function bbr_del(){
sed -i '$d' /etc/sysctl.conf
sed -i '$d' /etc/sysctl.conf
echo "reboot to disable bbr service"
}
function bbr_status(){
sysctl net.ipv4.tcp_available_congestion_control | grep bbr
lsmod | grep bbr
}
if [ "$1" = "install" ]; then  
    echo "install bbr"  
    bbr_conf
elif [ "$1" = "uninstall" ]; then  
    echo "uninstall bbr"
    bbr_del
elif [ "$1" = "check" ]; then  
    echo "check bbr status"
    bbr_status
else
    bbr_install
fi  
