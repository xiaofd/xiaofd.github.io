#!/bin/bash
#by root user
# github的不能用

apt update && apt install dnsutils # nslookup
# mirror
bash <(curl -sSL https://gitee.com/SuperManito/LinuxMirrors/raw/main/ChangeMirrors.sh)

# docker
[[ -z "$(systemctl cat docker | grep '\-\-registry\-mirror')" ]] && 
cat >/etc/docker/daemon.json <<EOF
{
  "registry-mirrors": [
    "https://hub-mirror.c.163.com",
    "https://mirror.baidubce.com"
  ]
}
EOF
systemctl daemon-reload
systemctl restart docker
[[ -n "$(docker info | grep 'baidubce.com')" ]] && echo "docker 国内换源 成功"
[[ -z "$(docker info | grep 'baidubce.com')" ]] && echo "docker 国内换源 失败"

# docker info #  https://hub-mirror.c.163.com/

# # github DNS 目前 失效
# github_host=$(nslookup github.com.cnpmjs.org | grep Address | tail -n 1 | awk ' {print $2}')
# sed -i '/*github.com*/d' /etc/hosts
# echo "${github_host} http://github.com" >> /etc/hosts
# echo "${github_host} https://github.com" >> /etc/hosts
# # /etc/init.d/networking restart
# systemctl restart networking
# # fix network not auto start
# cat /proc/net/dev | grep ":" | cut -d':' -f1 | xargs -I {} ifup {}
# # 推荐使用ghproxy
# git clone
# git clone https://ghproxy.com/https://github.com/stilleshan/ServerStatus
# git clone 私有仓库
# Clone 私有仓库需要用户在 Personal access tokens 申请 Token 配合使用.
# git clone https://user:your_token@ghproxy.com/https://github.com/your_name/your_private_repo
# wget & curl
# wget https://ghproxy.com/https://github.com/stilleshan/ServerStatus/archive/master.zip
# wget https://ghproxy.com/https://raw.githubusercontent.com/stilleshan/ServerStatus/master/Dockerfile
# curl -O https://ghproxy.com/https://github.com/stilleshan/ServerStatus/archive/master.zip
# curl -O https://ghproxy.com/https://raw.githubusercontent.com/stilleshan/ServerStatus/master/Dockerfile

# pip
mkdir -p ~/.pip
cat >~/.pip/pip.conf <<EOF
[global]
index-url = https://pypi.mirrors.ustc.edu.cn/simple
EOF
