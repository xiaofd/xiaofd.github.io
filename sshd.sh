#!/bin/bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
# wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/openssh/openssh-portable/master/sshd_config
sed -i "s#^.*Port .*#Port 3927#g" /etc/ssh/sshd_config
if test -z "`cat /etc/ssh/sshd_config | grep "^PasswordAuthentication no$"`" ; then
    echo "Disable the password login method."
    echo -e "\nPasswordAuthentication no" >> /etc/ssh/sshd_config
    echo -e "\nAuthenticationMethods publickey" >> /etc/ssh/sshd_config  # 强制所有用户只使用publickey
else
    echo "Already disable the password."
fi
# UsePAM no 设置这个+密码不为空，则只能通过密钥登陆，如果是yes则在密钥失败后尝试口令登陆
# enable root login with rsa-key & without password
sed -i 's/^.*PermitRootLogin.*/PermitRootLogin without-password/g' /etc/ssh/sshd_config
#sed -i "s#^PermitRootLogin no#PermitRootLogin without-password#g" /etc/ssh/sshd_config
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfuo9/cfgAHy8HYEGVxY+wklHlnrAQ0bPsz6FcAahXQXqw7OdrBzFpkh4U0a7f/Ir0BVgzeYIdDIOL8Ow9Ko1UHldJRCFyy/9W8ji2MGF2YgOUMxmxrCOD1DeOOh04Xrjqx5kPxiscHDZIZEuUF6eM20h3HR+D4xN/3H0OYRkMAaUrSoR8QZVg5P5QSni+HOT6JPHfk7rocKnk/0aQbLPMhSCLjAP4iyM9Fhotn6ofjw9aJnxp/agjwvJPkYSCmC5LJY8Mrv3Xpl4/cjknN0NbxMLUEhXXPDvGnPdS+KSAfpoHDTpm2Zi/WuVtf7AUP0ao0OnWbiPpQcvlEzxXhAm88ipzlY8n4mUnkyR7wIn6nf8y3HeOo8RVwjXWxsc6hNh6gPmNMlJeJo9FGMDxmriX/dRaAqsoYMRtxW3TNxMkfLXKTGs3ykEb/H/WXirwAPpHnSxbCY9/JVvfQMYDctZO+bZ3NV6Nvv5d2ATjq+1FWWaIq6vNkgMQKqs4mxw5CZUGnx4Zd6DMM1VkfA4W3hiNedoFyhSaQWVucza2gdHT7MPDJxNV6TNJErjo6wiobHOXyWghop4UjO32MMhRWyKAhdn3iCIPUglLloEEpvYI0b/TTd5ZdobHAjh+smX9mlIJe3yaQSPlA4sp6MPOjGhC/r08u+6hkmjE1Ycmgw7W7Q== JuiceSSH" > ~/.ssh/authorized_keys
[ -n "`cat /etc/issue | grep CentOS`" ] && service sshd restart
[ -n "`cat /etc/issue | grep Alpine`" ] && service sshd restart
#[ -z "`cat /etc/issue | grep CentOS`" ] && service ssh restart
service --status-all | grep ssh && service ssh restart
systemctl restart ssh
systemctl mask ssh.socket
systemctl mask sshd.socket
systemctl disable sshd
systemctl enable ssh
echo "sshd config is done!"
