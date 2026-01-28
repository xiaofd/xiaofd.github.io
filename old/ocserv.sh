#!/bin/bash
# ocserv+锐速一键脚本(锐速已注释掉)附带用户管理. 使用说明没有完整的写入脚本,详情请看介绍,或自行摸索. 此脚本仅在Debian7和Debian8上进行了测试,其他请自测. 注意:支持OpenVZ,但不会自动安装锐速.
# 安装并添加no-route路由表.
# bash ocserv.sh -install -noroute
# 安装并添加route路由表.（*）
# bash ocserv.sh -install -route
# 添加no-route路由表和一个用户名和密码均为Test的用户.
# bash ocserv.sh -noroute -add Test Test
# 删除一个用户名为Test的用户.
# bash ocserv.sh -del Test
# 切换使用证书登陆(cret不区分大小写.需要安装时选择配置为证书登录,否则可能无法正常运行.)
# bash ocserv.sh -use Cert
# 切换使用密码登陆(password不区分大小写.)
# bash ocserv.sh -use password

function Welcome()
{
clear
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
clear
echo -n "                      Local Time :   " && date "+%F [%T]       ";
echo "            ======================================================";
echo "            |         OpenConnect(ocserv) & serverSpeeder        |";
echo "            |                                                    |";
echo "            |                                         for Debian |";
echo "            |----------------------------------------------------|";
echo "            |                           -- By MoeClub.org(Vicer) |";
echo "            ======================================================";
echo;
}

function pause()
{
echo;
read -n 1 -p "Press Enter to Continue..." INP
if [ "$INP" != '' ] ; then
echo -ne '\b \n'
echo;
fi
}

function ETHER()
{
sysBits=x$(getconf LONG_BIT);
ifname=`cat /proc/net/dev | awk -F: 'function trim(str){sub(/^[ \t]*/,"",str); sub(/[ \t]*$/,"",str); return str } NR>2 {print trim($1)}'  | grep -Ev '^lo|^sit|^stf|^gif|^dummy|^vmnet|^vir|^gre|^ipip|^ppp|^bond|^tun|^tap|^ip6gre|^ip6tnl|^teql' | awk 'NR==1 {print $0}'`
}

function OWNNET()
{
echo -ne "\nSelect a IP Address from \e[33m[\e[32m0\e[0m.\e[35m${MACIP}\e[33m/\e[33m1\e[0m.\e[35m${PublicIP}\e[33m]\e[0m. \nIt will be regard as default IP Address: "
read OWNNETIP
if [ -n "$OWNNETIP" ]; then
if [ "$OWNNETIP" == '0' ]; then
    DefaultIP="${MACIP}"
elif [ "$OWNNETIP" == '1' ]; then
    DefaultIP="${PublicIP}"
else
    OWNNET;
fi
else
    DefaultIP="${MACIP}"
fi
}

function ServerIP()
{
PublicIP="$(wget -qO- checkip.amazonaws.com)"
echo -ne "Default Server IP: \e[36m${PublicIP}\e[0m .\nIf Default Server IP \e[31mcorrect\e[0m, Press Enter .\nIf Default Server IP \e[31mincorrect\e[0m, Please input Server IP :"
read iptmp
if [[ -n "$iptmp" ]]; then
    PublicIP=$iptmp
fi
sysBits=x$(getconf LONG_BIT);
ifname=`cat /proc/net/dev | awk -F: 'function trim(str){sub(/^[ \t]*/,"",str); sub(/[ \t]*$/,"",str); return str } NR>2 {print trim($1)}'  | grep -Ev '^lo|^sit|^stf|^gif|^dummy|^vmnet|^vir|^gre|^ipip|^ppp|^bond|^tun|^tap|^ip6gre|^ip6tnl|^teql' | awk 'NR==1 {print $0}'`;
echo -n $ifname |grep -q 'venet';
[ $? -eq '0' ] && oVZ='y' || oVZ='n';
MACIP="$(ifconfig $ifname |awk -F ':' '/inet addr/{ print $2}' |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}')";
[ "${PublicIP}" != "${MACIP}" ] && OWNNET
[ "${PublicIP}" == "${MACIP}" ] && DefaultIP="${PublicIP}";
echo -ne "Server IP: \e[35m${DefaultIP}\e[0m .\n";
MyDomain="${PublicIP}"
echo -ne "\nIf you \e[31mdo not have\e[0m a domain name, \e[33mPress Enter\e[0m! \nIf you \e[31mhave\e[0m a domain name, Please \e[32mInput your domain name\e[0m :"
read DomainTMP
if [[ -n "$DomainTMP" ]]; then
    MyDomain=$DomainTMP
    echo -ne "Domain name: \e[35m$MyDomain\e[0m .\n"
fi
DOMAIN=`echo "$MyDomain" |awk -F"[.]" '{print $(NF-1)"."$NF}'`
echo "$DOMAIN" |grep -q '[0-9]\{1,3\}.[0-9]\{1,3\}'
[ $? -eq '0' ] && DOMAIN='' || echo -ne "\nPlease put your \e[33mdomain certificate\e[0m and \e[33mprivate key\e[0m into \e[33m/etc/ocserv\e[0m when the shell script install finish! \n\e[31mrename\e[0m \e[33mcertificate\e[0m with \e[32mserver.cert.pem\e[0m\n\e[31mrename\e[0m \e[33mprivate key\e[0m with \e[32mserver.key.pem\e[0m\n"
[ $oVZ == 'y' ] && {
echo -ne "\nIt will install \e[35mocserv\e[0m and \e[35mserverSpeeder\e[0m automaticly." 
}
[ $oVZ == 'n' ] && {
echo -ne "\nIt will install \e[35mocserv\e[0m automaticly." 
}
pause;
}

function Ask_ocserv_port()
{
echo -ne "\n\e[35mInstall OpenConnect...\e[0m\n"
SSLTCP=443;
SSLUDP=443;
echo -ne "\n\e[35mPlease enter AnyConnet port\e[33m[Default:\e[32m443\e[33m]\e[0m: "
read myPORT
if [[ -n "$myPORT" ]]; then
    SSLTCP=$myPORT
    SSLUDP=$myPORT
fi
}

function Ask_ocserv_type()
{
echo -ne "\n\e[35mPlease select a type to login AnyConnet.\e[33m[\e[33m0\e[0m.\e[35mcertificate\e[33m/\e[32m1\e[0m.\e[35mpassword\e[33m]\e[0m: "
read logintype
if [ -n "$logintype" ]; then
if [ "$logintype" == '0' ]; then
    MyType='certificate'
elif [ "$logintype" == '1' ]; then
    MyType='password'
else
    Ask_ocserv_type;
fi
else
    MyType='password'
fi
}

function Ask_ocserv_password()
{
[ $MyType == 'certificate' ] && {
FILL1='CANAME'
FILL2='ORGANIZATION'
}
[ $MyType == 'password' ] && {
FILL1='UserName'
FILL2='PassWord'
}
[ -n "$FILL1" -a -n "$FILL2" ] && {
FILLIT1='MoeClub.org'
echo -ne "\n\e[35mPlease input AnyConnet $FILL1\e[33m[Default:\e[32mMoeClub.org\e[33m]\e[0m: "
read tmpFILL1
if [[ -n "$tmpFILL1" ]]; then
    FILLIT1=$tmpFILL1
fi
FILLIT2='Vicer'
echo -ne "\n\e[35mPlease input AnyConnet $FILL2\e[33m[Default:\e[32mVicer\e[33m]\e[0m: "
read tmpFILL2
if [[ -n "$tmpFILL2" ]]; then
    FILLIT2=$tmpFILL2
fi
}
}

function SYSCONF()
{
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sed -i '/soft nofile/d' /etc/security/limits.conf
echo "* soft nofile 51200" >> /etc/security/limits.conf
sed -i '/hard nofile/d' /etc/security/limits.conf
echo "* hard nofile 51200" >> /etc/security/limits.conf
[ $oVZ == 'n' ] && {
cat >/etc/sysctl.conf<<EOFSYS
#This line below add by user.
#sysctl net.ipv4.tcp_available_congestion_control
#modprobe tcp_htcp
net.ipv4.ip_forward = 1
fs.file-max = 51200
net.core.wmem_max = 8388608
net.core.rmem_max = 8388608
net.core.rmem_default = 131072
net.core.wmem_default = 131072
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_rmem = 10240 81920 8388608
net.ipv4.tcp_wmem = 10240 81920 8388608
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_congestion_control = htcp
net.ipv4.icmp_echo_ignore_all = 1
#net.ipv4.tcp_fastopen = 3
EOFSYS
[ -f "/proc/sys/net/ipv4/tcp_fastopen" ] && [ -f /etc/sysctl.conf ] && sed -i 's/#net.ipv4.tcp_fastopen/net.ipv4.tcp_fastopen/g' /etc/sysctl.conf
}
sysctl -p >/dev/null 2>&1
}

function ins_ocserv()
{
BitVer='';
mkdir -p /tmp;
[ $sysBits == 'x32' ] && BitVer='i386'
[ $sysBits == 'x64' ] && BitVer='amd64'
[ -n "$BitVer" ] && {
wget --no-check-certificate -qO "/tmp/libradcli4_1.2.6-3~bpo8+1_$BitVer.deb" "https://moeclub.org/attachment/DebianPackage/ocserv/libradcli4_1.2.6-3~bpo8+1_$BitVer.deb"
wget --no-check-certificate -qO "/tmp/ocserv_0.11.6-1~bpo8+2_$BitVer.deb" "https://moeclub.org/attachment/DebianPackage/ocserv/ocserv_0.11.6-1~bpo8+2_$BitVer.deb"
} || {
echo "Error, download fail! "
exit 1
}
bash -c "$(wget --no-check-certificate -qO- 'https://moeclub.org/attachment/LinuxShell/src.sh')"
DEBIAN_FRONTEND=noninteractive apt-get install -y -t jessie dbus init-system-helpers libc6 libev4 libgnutls-deb0-28 libgssapi-krb5-2 libhttp-parser2.1 liblz4-1 libnettle4 libnl-3-200 libnl-route-3-200 liboath0 libopts25 libpcl1 libprotobuf-c1 libsystemd0 libtalloc2 gnutls-bin ssl-cert
dpkg -i /tmp/libradcli4_*.deb
dpkg -i /tmp/ocserv_*.deb
which ocserv >/dev/null 2>&1
[ $? -ne '0' ] && echo 'Error, Install ocerv.' && exit 1
sed -i '/exit .*/d' /etc/rc.local
sed -i '$a\iptables -t nat -A POSTROUTING -o '${ifname}' -j MASQUERADE' /etc/rc.local
sed -i '$a\iptables -I INPUT -p tcp --dport '${SSLTCP}' -j ACCEPT' /etc/rc.local
sed -i '$a\iptables -I INPUT -p udp --dport '${SSLUDP}' -j ACCEPT' /etc/rc.local
sed -i '$a\iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' /etc/rc.local
sed -i '$a\exit 0' /etc/rc.local
cat >/etc/ocserv/ocserv.conf<<EOF
#Login Type
#auth = "plain[passwd=/etc/ocserv/ocpasswd]"
auth = "certificate"
 
# TCP and UDP port number
tcp-port = $SSLTCP
#udp-port = $SSLUDP
 
server-cert = /etc/ocserv/server.cert.pem
server-key = /etc/ocserv/server.key.pem
ca-cert = /etc/ocserv/ca.cert.pem
dh-params = /etc/ocserv/dh.pem
 
socket-file = /var/run/ocserv.socket
occtl-socket-file = /var/run/occtl.socket
pid-file = /var/run/ocserv.pid
user-profile = /etc/ocserv/profile.xml
run-as-user = nobody
cert-user-oid = 2.5.4.3
isolate-workers = false
max-clients = 192
max-same-clients = 192
keepalive = 32400
dpd = 300
mobile-dpd = 1800
#output-buffer = 1000
try-mtu-discovery = true
compression = true
no-compress-limit = 256
auth-timeout = 40 
idle-timeout = 1200
mobile-idle-timeout = 1200
cookie-timeout = 43200
persistent-cookies = true
deny-roaming = false
rekey-time = 43200
rekey-method = ssl
use-utmp = true
use-occtl = true
device = ocserv
predictable-ips = false
ping-leases = false
cisco-client-compat = true
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"
ipv4-network = 192.168.8.0
ipv4-netmask = 255.255.255.0
dns = 192.168.8.1
 
EOF
cat >/etc/ocserv/profile.xml<<EOF
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
 
 <ClientInitialization>
 <UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
 <StrictCertificateTrust>false</StrictCertificateTrust>
 <RestrictPreferenceCaching>false</RestrictPreferenceCaching>
 <RestrictTunnelProtocols>false</RestrictTunnelProtocols>
 <BypassDownloader>true</BypassDownloader>
 <WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
 <CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
 <CertificateMatch>
 <KeyUsage>
 <MatchKey>Digital_Signature</MatchKey>
 </KeyUsage>
 <ExtendedKeyUsage>
 <ExtendedMatchKey>ClientAuth</ExtendedMatchKey>
 </ExtendedKeyUsage>
 </CertificateMatch>
 
 <BackupServerList>
             <HostAddress>$MyDomain</HostAddress>
 </BackupServerList>
 </ClientInitialization>
</AnyConnectProfile>
EOF

mkdir -p /etc/ocserv/template
cat >/etc/ocserv/template/ca.tmp<<EOF
cn = "$FILLIT1"
organization = "$FILLIT2"
serial = 1
expiration_days = 1825
ca
signing_key
cert_signing_key
crl_signing_key
EOF
openssl genrsa -out /etc/ocserv/template/ca.key.pem 2048
certtool --generate-self-signed --hash SHA256 --load-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/ca.tmp --outfile /etc/ocserv/ca.cert.pem
certtool --generate-dh-params --outfile /etc/ocserv/dh.pem

cat >/etc/ocserv/template/server.tmp<<EOF
cn = "$MyDomain" 
organization = "MoeClub.org" 
serial = 2
expiration_days = 1825
signing_key 
encryption_key
tls_www_server
EOF
openssl genrsa -out /etc/ocserv/server.key.pem 2048
certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/server.key.pem --load-ca-certificate /etc/ocserv/ca.cert.pem --load-ca-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/server.tmp --outfile /etc/ocserv/server.cert.pem
cat /etc/ocserv/ca.cert.pem >>/etc/ocserv/server.cert.pem
}

function login_ocserv()
{
[ $MyType == 'certificate' ] && {
cat >/etc/ocserv/template/user.tmp<<EOF
cn = "$FILLIT1"
unit = "$FILLIT2"
expiration_days = 1825
signing_key
tls_www_client
EOF
openssl genrsa -out /etc/ocserv/template/user.key.pem 2048
certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/template/user.key.pem --load-ca-certificate /etc/ocserv/ca.cert.pem --load-ca-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/user.tmp --outfile /etc/ocserv/template/user.cert.pem
cat /etc/ocserv/ca.cert.pem >>/etc/ocserv/template/user.cert.pem
openssl pkcs12 -export -inkey /etc/ocserv/template/user.key.pem -in /etc/ocserv/template/user.cert.pem -name "Vicer" -certfile /etc/ocserv/ca.cert.pem -caname "$FILLIT1" -out /etc/ocserv/AnyConnect.p12 -passout pass:
[ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "certificate".*/auth = "certificate"/g' /etc/ocserv/ocserv.conf
}
[ $MyType == 'password' ] && {
[ -f /etc/ocserv/ocpasswd ] && sed -i '/'${FILLIT1}':/d' /etc/ocserv/ocpasswd
echo -n "$FILLIT1:*:" >>/etc/ocserv/ocpasswd
openssl passwd "$FILLIT2" >>/etc/ocserv/ocpasswd
[ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
}
}

function ask_ocserv()
{
Welcome
Ask_ocserv_port
Ask_ocserv_type
Ask_ocserv_password
pause
clear
}

function ins_dnsmasq()
{
apt-get install -y dnsmasq
apt-get purge --remove -y dns-root-data
apt-get purge dns-root-data
cat >/etc/dnsmasq.conf<<EOF
except-interface=$ifname
dhcp-range=192.168.8.2,192.168.8.254,255.255.255.0,24h
dhcp-option-force=option:router,192.168.8.1
dhcp-option-force=option:dns-server,192.168.8.1
dhcp-option-force=option:netbios-ns,192.168.8.1
listen-address=127.0.0.1,192.168.8.1
no-resolv
bogus-priv
no-negcache
clear-on-reload
cache-size=81920
server=208.67.220.220#5353
EOF
bash /etc/init.d/dnsmasq restart
}

function ins_serverSpeeder()
{
[ $oVZ == 'n' ] && {
wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
[ $? -eq '0' ] && {
insNum="$(awk '/^SelectKernel;/{print NR}' /tmp/appex.sh)"
echo "sed -i '/^# Set acc inf/,\$d' /tmp/appex/install.sh" >/tmp/ins.tmp
echo "echo -e 'boot=y && addStartUpLink' >>/tmp/appex/install.sh" >>/tmp/ins.tmp
[ -f /tmp/ins.tmp ] && {
sed -i ''${insNum}'r /tmp/ins.tmp' /tmp/appex.sh
sed -i '/^pause;$/d' /tmp/appex.sh
sed -i '/serverSpeeder.sh status$/d' /tmp/appex.sh
}
bash /tmp/appex.sh install
}
}
}

function add_user()
{
[ "$(grep -c '^auth =' /etc/ocserv/ocserv.conf)" != '1' ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
MyType='password'
FILLIT1="$tmpUser"
FILLIT2="$tmpPass"
[ -n "$FILLIT1" ] && [ -n "$FILLIT2" ] && login_ocserv
}

function del_user()
{
[ -f /etc/ocserv/ocpasswd ] && sed -i '/'${delUser}':/d' /etc/ocserv/ocpasswd
}

function ChangeType()
{
TheType="$(echo -n "$tmpType"|sed -r 's/(.*)/\L\1/')"
echo -n "$TheType" |grep -q '^cert'
[ $? -eq '0' ] && [ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "certificate".*/auth = "certificate"/g' /etc/ocserv/ocserv.conf
echo -n "$TheType" |grep -q '^pass'
[ $? -eq '0' ] && [ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
}

function add_route()
{
sed -i '/^route/d' /etc/ocserv/ocserv.conf
sed -i '/^no-route/d' /etc/ocserv/ocserv.conf
cat >>/etc/ocserv/ocserv.conf<<EOF
## Route List
route = 0.0.0.0/248.0.0.0
route = 8.0.0.0/254.0.0.0
route = 11.0.0.0/255.0.0.0
route = 12.0.0.0/252.0.0.0
route = 16.0.0.0/248.0.0.0
route = 24.0.0.0/254.0.0.0
route = 26.0.0.0/255.0.0.0
route = 27.0.0.0/255.128.0.0
route = 27.128.0.0/255.192.0.0
route = 27.224.0.0/255.224.0.0
route = 28.0.0.0/252.0.0.0
route = 32.0.0.0/252.0.0.0
route = 36.0.0.0/255.192.0.0
route = 36.64.0.0/255.224.0.0
route = 36.224.0.0/255.224.0.0
route = 37.0.0.0/255.0.0.0
route = 38.0.0.0/255.0.0.0
route = 39.0.0.0/255.192.0.0
route = 39.96.0.0/255.224.0.0
route = 39.192.0.0/255.192.0.0
route = 40.0.0.0/252.0.0.0
route = 44.0.0.0/254.0.0.0
route = 46.0.0.0/255.0.0.0
route = 47.0.0.0/255.192.0.0
route = 47.64.0.0/255.224.0.0
route = 47.128.0.0/255.128.0.0
route = 48.0.0.0/255.0.0.0
route = 49.0.0.0/255.192.0.0
route = 49.96.0.0/255.224.0.0
route = 49.128.0.0/255.128.0.0
route = 50.0.0.0/254.0.0.0
route = 52.0.0.0/252.0.0.0
route = 56.0.0.0/254.0.0.0
route = 58.0.0.0/255.224.0.0
route = 58.64.0.0/255.192.0.0
route = 58.128.0.0/255.192.0.0
route = 58.224.0.0/255.224.0.0
route = 59.0.0.0/255.224.0.0
route = 59.64.0.0/255.192.0.0
route = 59.128.0.0/255.192.0.0
route = 60.32.0.0/255.224.0.0
route = 60.64.0.0/255.192.0.0
route = 60.128.0.0/255.224.0.0
route = 60.192.0.0/255.192.0.0
route = 61.0.0.0/255.128.0.0
route = 61.192.0.0/255.192.0.0
route = 62.0.0.0/254.0.0.0
route = 64.0.0.0/224.0.0.0
route = 96.0.0.0/248.0.0.0
route = 104.0.0.0/252.0.0.0
route = 108.0.0.0/254.0.0.0
route = 110.0.0.0/255.192.0.0
route = 110.64.0.0/255.224.0.0
route = 110.128.0.0/255.192.0.0
route = 110.224.0.0/255.224.0.0
route = 111.64.0.0/255.192.0.0
route = 111.160.0.0/255.224.0.0
route = 111.192.0.0/255.192.0.0
route = 112.64.0.0/255.192.0.0
route = 112.128.0.0/255.192.0.0
route = 112.192.0.0/255.224.0.0
route = 113.0.0.0/255.192.0.0
route = 113.128.0.0/255.128.0.0
route = 114.0.0.0/255.128.0.0
route = 114.128.0.0/255.192.0.0
route = 114.192.0.0/255.224.0.0
route = 115.0.0.0/255.128.0.0
route = 115.128.0.0/255.192.0.0
route = 115.224.0.0/255.224.0.0
route = 116.0.0.0/255.128.0.0
route = 116.192.0.0/255.192.0.0
route = 117.0.0.0/255.128.0.0
route = 117.192.0.0/255.192.0.0
route = 118.0.0.0/254.0.0.0
route = 120.0.0.0/255.128.0.0
route = 120.128.0.0/255.192.0.0
route = 121.0.0.0/255.240.0.0
route = 121.16.0.0/255.240.0.0
route = 121.32.0.0/255.240.0.0
route = 121.48.0.0/255.254.0.0
route = 121.50.0.0/255.255.0.0
route = 121.52.0.0/255.252.0.0
route = 121.56.0.0/255.248.0.0
route = 121.64.0.0/255.192.0.0
route = 121.128.0.0/255.128.0.0
route = 122.0.0.0/255.192.0.0
route = 122.96.0.0/255.224.0.0
route = 122.128.0.0/255.128.0.0
route = 123.0.0.0/255.192.0.0
route = 123.96.0.0/255.224.0.0
route = 123.128.0.0/255.128.0.0
route = 124.0.0.0/255.0.0.0
route = 125.0.0.0/255.192.0.0
route = 125.96.0.0/255.224.0.0
route = 125.128.0.0/255.128.0.0
route = 126.0.0.0/254.0.0.0
route = 128.0.0.0/248.0.0.0
route = 136.0.0.0/252.0.0.0
route = 140.0.0.0/255.128.0.0
route = 140.128.0.0/255.192.0.0
route = 140.192.0.0/255.248.0.0
route = 140.200.0.0/255.252.0.0
route = 140.204.0.0/255.255.0.0
route = 140.208.0.0/255.240.0.0
route = 140.224.0.0/255.224.0.0
route = 141.0.0.0/255.0.0.0
route = 142.0.0.0/254.0.0.0
route = 144.0.0.0/240.0.0.0
route = 160.0.0.0/248.0.0.0
route = 168.0.0.0/255.128.0.0
route = 168.128.0.0/255.192.0.0
route = 168.192.0.0/255.224.0.0
route = 168.224.0.0/255.240.0.0
route = 168.240.0.0/255.248.0.0
route = 168.248.0.0/255.252.0.0
route = 168.252.0.0/255.254.0.0
route = 168.255.0.0/255.255.0.0
route = 169.0.0.0/255.0.0.0
route = 170.0.0.0/254.0.0.0
route = 172.0.0.0/255.240.0.0
route = 172.32.0.0/255.224.0.0
route = 172.64.0.0/255.192.0.0
route = 172.128.0.0/255.128.0.0
route = 173.0.0.0/255.0.0.0
route = 174.0.0.0/255.0.0.0
route = 175.0.0.0/255.192.0.0
route = 175.96.0.0/255.224.0.0
route = 175.128.0.0/255.128.0.0
route = 176.0.0.0/252.0.0.0
route = 180.0.0.0/255.192.0.0
route = 180.64.0.0/255.224.0.0
route = 180.128.0.0/255.128.0.0
route = 181.0.0.0/255.0.0.0
route = 182.0.0.0/255.192.0.0
route = 182.64.0.0/255.224.0.0
route = 182.128.0.0/255.128.0.0
route = 183.64.0.0/255.192.0.0
route = 183.160.0.0/255.224.0.0
route = 184.0.0.0/248.0.0.0
route = 192.0.0.0/255.128.0.0
route = 192.128.0.0/255.224.0.0
route = 192.160.0.0/255.248.0.0
route = 192.169.0.0/255.255.0.0
route = 192.170.0.0/255.254.0.0
route = 192.172.0.0/255.252.0.0
route = 192.176.0.0/255.240.0.0
route = 192.192.0.0/255.192.0.0
route = 193.0.0.0/255.0.0.0
route = 194.0.0.0/254.0.0.0
route = 196.0.0.0/252.0.0.0
route = 200.0.0.0/248.0.0.0
route = 208.0.0.0/248.0.0.0
route = 216.0.0.0/254.0.0.0
route = 218.32.0.0/255.224.0.0
route = 218.96.0.0/255.224.0.0
route = 218.128.0.0/255.128.0.0
route = 219.0.0.0/255.128.0.0
route = 219.160.0.0/255.224.0.0
route = 219.192.0.0/255.192.0.0
route = 220.0.0.0/255.128.0.0
route = 220.128.0.0/255.224.0.0
route = 220.192.0.0/255.192.0.0
route = 221.0.0.0/255.0.0.0
route = 222.0.0.0/255.224.0.0
route = 222.96.0.0/255.224.0.0
route = 222.128.0.0/255.192.0.0
route = 222.224.0.0/255.224.0.0
route = 223.0.0.0/255.192.0.0
route = 223.96.0.0/255.224.0.0
route = 223.128.0.0/255.128.0.0
route = 224.0.0.0/224.0.0.0
EOF
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
}

function add_noroute()
{
sed -i '/^route/d' /etc/ocserv/ocserv.conf
sed -i '/^no-route/d' /etc/ocserv/ocserv.conf
PublicIP="$(wget -qO- checkip.amazonaws.com)"
cat >>/etc/ocserv/ocserv.conf<<EOF
## No Route List
no-route = $PublicIP/255.255.255.255
no-route = 192.168.0.0/255.255.0.0
 
no-route = 1.0.0.0/255.192.0.0
no-route = 1.64.0.0/255.224.0.0
no-route = 1.112.0.0/255.248.0.0
no-route = 1.176.0.0/255.240.0.0
no-route = 1.192.0.0/255.240.0.0
no-route = 14.0.0.0/255.224.0.0
no-route = 14.96.0.0/255.224.0.0
no-route = 14.128.0.0/255.224.0.0
no-route = 14.192.0.0/255.224.0.0
no-route = 27.0.0.0/255.192.0.0
no-route = 27.96.0.0/255.224.0.0
no-route = 27.128.0.0/255.224.0.0
no-route = 27.176.0.0/255.240.0.0
no-route = 27.192.0.0/255.224.0.0
no-route = 27.224.0.0/255.252.0.0
no-route = 36.0.0.0/255.192.0.0
no-route = 36.96.0.0/255.224.0.0
no-route = 36.128.0.0/255.192.0.0
no-route = 36.192.0.0/255.224.0.0
no-route = 36.240.0.0/255.240.0.0
no-route = 39.0.0.0/255.255.0.0
no-route = 39.64.0.0/255.224.0.0
no-route = 39.96.0.0/255.240.0.0
no-route = 39.128.0.0/255.192.0.0
no-route = 40.72.0.0/255.254.0.0
no-route = 40.124.0.0/255.252.0.0
no-route = 42.0.0.0/255.248.0.0
no-route = 42.48.0.0/255.240.0.0
no-route = 42.80.0.0/255.240.0.0
no-route = 42.96.0.0/255.224.0.0
no-route = 42.128.0.0/255.128.0.0
no-route = 43.224.0.0/255.224.0.0
no-route = 45.65.16.0/255.255.240.0
no-route = 45.112.0.0/255.240.0.0
no-route = 45.248.0.0/255.248.0.0
no-route = 47.92.0.0/255.252.0.0
no-route = 47.96.0.0/255.224.0.0
no-route = 49.0.0.0/255.128.0.0
no-route = 49.128.0.0/255.224.0.0
no-route = 49.192.0.0/255.192.0.0
no-route = 52.80.0.0/255.252.0.0
no-route = 54.222.0.0/255.254.0.0
no-route = 58.0.0.0/255.128.0.0
no-route = 58.128.0.0/255.224.0.0
no-route = 58.192.0.0/255.224.0.0
no-route = 58.240.0.0/255.240.0.0
no-route = 59.32.0.0/255.224.0.0
no-route = 59.64.0.0/255.224.0.0
no-route = 59.96.0.0/255.240.0.0
no-route = 59.144.0.0/255.240.0.0
no-route = 59.160.0.0/255.224.0.0
no-route = 59.192.0.0/255.192.0.0
no-route = 60.0.0.0/255.224.0.0
no-route = 60.48.0.0/255.240.0.0
no-route = 60.160.0.0/255.224.0.0
no-route = 60.192.0.0/255.192.0.0
no-route = 61.0.0.0/255.192.0.0
no-route = 61.80.0.0/255.248.0.0
no-route = 61.128.0.0/255.192.0.0
no-route = 61.224.0.0/255.224.0.0
no-route = 91.234.36.0/255.255.255.0
no-route = 101.0.0.0/255.128.0.0
no-route = 101.128.0.0/255.224.0.0
no-route = 101.192.0.0/255.240.0.0
no-route = 101.224.0.0/255.224.0.0
no-route = 103.0.0.0/255.0.0.0
no-route = 106.0.0.0/255.128.0.0
no-route = 106.224.0.0/255.240.0.0
no-route = 110.0.0.0/255.128.0.0
no-route = 110.144.0.0/255.240.0.0
no-route = 110.160.0.0/255.224.0.0
no-route = 110.192.0.0/255.192.0.0
no-route = 111.0.0.0/255.192.0.0
no-route = 111.64.0.0/255.224.0.0
no-route = 111.112.0.0/255.240.0.0
no-route = 111.128.0.0/255.192.0.0
no-route = 111.192.0.0/255.224.0.0
no-route = 111.224.0.0/255.240.0.0
no-route = 112.0.0.0/255.128.0.0
no-route = 112.128.0.0/255.240.0.0
no-route = 112.192.0.0/255.252.0.0
no-route = 112.224.0.0/255.224.0.0
no-route = 113.0.0.0/255.128.0.0
no-route = 113.128.0.0/255.240.0.0
no-route = 113.192.0.0/255.192.0.0
no-route = 114.16.0.0/255.240.0.0
no-route = 114.48.0.0/255.240.0.0
no-route = 114.64.0.0/255.192.0.0
no-route = 114.128.0.0/255.240.0.0
no-route = 114.192.0.0/255.192.0.0
no-route = 115.0.0.0/255.0.0.0
no-route = 116.0.0.0/255.0.0.0
no-route = 117.0.0.0/255.128.0.0
no-route = 117.128.0.0/255.192.0.0
no-route = 118.16.0.0/255.240.0.0
no-route = 118.64.0.0/255.192.0.0
no-route = 118.128.0.0/255.128.0.0
no-route = 119.0.0.0/255.128.0.0
no-route = 119.128.0.0/255.192.0.0
no-route = 119.224.0.0/255.224.0.0
no-route = 120.0.0.0/255.192.0.0
no-route = 120.64.0.0/255.224.0.0
no-route = 120.128.0.0/255.240.0.0
no-route = 120.192.0.0/255.192.0.0
no-route = 121.0.0.0/255.128.0.0
no-route = 121.192.0.0/255.192.0.0
no-route = 122.0.0.0/254.0.0.0
no-route = 124.0.0.0/255.0.0.0
no-route = 125.0.0.0/255.128.0.0
no-route = 125.160.0.0/255.224.0.0
no-route = 125.192.0.0/255.192.0.0
no-route = 137.59.59.0/255.255.255.0
no-route = 137.59.88.0/255.255.252.0
no-route = 139.0.0.0/255.224.0.0
no-route = 139.128.0.0/255.128.0.0
no-route = 140.64.0.0/255.240.0.0
no-route = 140.128.0.0/255.240.0.0
no-route = 140.192.0.0/255.192.0.0
no-route = 144.0.0.0/255.248.0.0
no-route = 144.12.0.0/255.255.0.0
no-route = 144.48.0.0/255.248.0.0
no-route = 144.123.0.0/255.255.0.0
no-route = 144.255.0.0/255.255.0.0
no-route = 146.196.0.0/255.255.128.0
no-route = 150.0.0.0/255.255.0.0
no-route = 150.96.0.0/255.224.0.0
no-route = 150.128.0.0/255.240.0.0
no-route = 150.192.0.0/255.192.0.0
no-route = 152.104.128.0/255.255.128.0
no-route = 153.0.0.0/255.192.0.0
no-route = 153.96.0.0/255.224.0.0
no-route = 157.0.0.0/255.255.0.0
no-route = 157.18.0.0/255.255.0.0
no-route = 157.61.0.0/255.255.0.0
no-route = 157.112.0.0/255.240.0.0
no-route = 157.144.0.0/255.240.0.0
no-route = 157.255.0.0/255.255.0.0
no-route = 159.226.0.0/255.255.0.0
no-route = 160.19.0.0/255.255.0.0
no-route = 160.20.48.0/255.255.252.0
no-route = 160.202.0.0/255.255.0.0
no-route = 160.238.64.0/255.255.252.0
no-route = 161.207.0.0/255.255.0.0
no-route = 162.105.0.0/255.255.0.0
no-route = 163.0.0.0/255.192.0.0
no-route = 163.96.0.0/255.224.0.0
no-route = 163.128.0.0/255.192.0.0
no-route = 163.192.0.0/255.224.0.0
no-route = 164.52.0.0/255.255.128.0
no-route = 166.111.0.0/255.255.0.0
no-route = 167.139.0.0/255.255.0.0
no-route = 167.189.0.0/255.255.0.0
no-route = 167.220.244.0/255.255.252.0
no-route = 168.160.0.0/255.255.0.0
no-route = 170.179.0.0/255.255.0.0
no-route = 171.0.0.0/255.128.0.0
no-route = 171.192.0.0/255.224.0.0
no-route = 175.0.0.0/255.128.0.0
no-route = 175.128.0.0/255.192.0.0
no-route = 180.64.0.0/255.192.0.0
no-route = 180.128.0.0/255.128.0.0
no-route = 182.0.0.0/255.0.0.0
no-route = 183.0.0.0/255.192.0.0
no-route = 183.64.0.0/255.224.0.0
no-route = 183.128.0.0/255.128.0.0
no-route = 192.124.154.0/255.255.255.0
no-route = 192.140.128.0/255.255.128.0
no-route = 202.0.0.0/255.128.0.0
no-route = 202.128.0.0/255.192.0.0
no-route = 202.192.0.0/255.224.0.0
no-route = 203.0.0.0/255.0.0.0
no-route = 210.0.0.0/255.192.0.0
no-route = 210.64.0.0/255.224.0.0
no-route = 210.160.0.0/255.224.0.0
no-route = 210.192.0.0/255.224.0.0
no-route = 211.64.0.0/255.248.0.0
no-route = 211.80.0.0/255.240.0.0
no-route = 211.96.0.0/255.248.0.0
no-route = 211.136.0.0/255.248.0.0
no-route = 211.144.0.0/255.240.0.0
no-route = 211.160.0.0/255.248.0.0
no-route = 216.250.108.0/255.255.252.0
no-route = 218.0.0.0/255.128.0.0
no-route = 218.160.0.0/255.224.0.0
no-route = 218.192.0.0/255.192.0.0
no-route = 219.64.0.0/255.224.0.0
no-route = 219.128.0.0/255.224.0.0
no-route = 219.192.0.0/255.192.0.0
no-route = 220.96.0.0/255.224.0.0
no-route = 220.128.0.0/255.128.0.0
no-route = 221.0.0.0/255.224.0.0
no-route = 221.96.0.0/255.224.0.0
no-route = 221.128.0.0/255.128.0.0
no-route = 222.0.0.0/255.0.0.0
no-route = 223.0.0.0/255.224.0.0
no-route = 223.64.0.0/255.192.0.0
no-route = 223.128.0.0/255.128.0.0
EOF
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
}

function ins_all()
{
Welcome
ServerIP
ask_ocserv
ins_ocserv
login_ocserv
ins_dnsmasq
#ins_serverSpeeder
SYSCONF
ins_Finish
}

function ins_Finish()
{
grep '^iptables' /etc/rc.local >/tmp/iptables.tmp
[ -f /tmp/iptables.tmp ] && bash /tmp/iptables.tmp
[ -e /etc/init.d/dnsmasq ] && bash /etc/init.d/dnsmasq restart
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
#[ -e /etc/init.d/serverSpeeder ] && bash /etc/init.d/serverSpeeder restart
rm -rf /tmp/*.tmp
}

[ $# -eq '0' ] && ins_all
ins_it='0';
addroute='0';
addnoroute='0';
adduser='0';
delUser='0';
UseType='0';
tmpUser="";
tmpPass="";
tmpType="";
while [[ $# -ge 1 ]]; do
  case $1 in
    -i|ins|-ins|install|-install)
      shift
      ins_it='1'
      ;;
    -u|u|use|-use)
      shift
      UseType='1'
      tmpType="$1"
      shift
      ;;
    -a|a|-add|add)
      shift
      adduser='1'
      tmpUser="$1"
      shift
      tmpPass="$1"
      shift
      ;;
    -d|d|-del|del)
      shift
      delUser='1'
      tmpUser="$1"
      shift
      ;;
    -route|route)
      shift
      addroute="1"
      ;;
    -noroute|noroute)
      shift
      addnoroute="1"
      ;;
    *)
      echo -ne " Usage:\n\tbash $0\t\n"
      exit 1;
      ;;
    esac
  done

[ "$ins_it" == '1' ] && ins_all;
[ "$addroute" == '1' ] && add_route;
[ "$addnoroute" == '1' ] && add_noroute;
[ "$UseType" == '1' ] && [ -n "$tmpType" ] && ChangeType;
[ "$delUser" == '1' ] && [ -n "$tmpUser" ] && del_user;
[ "$adduser" == '1' ] && [ -n "$tmpUser" ] && [ -n "$tmpPass" ] && add_user;


