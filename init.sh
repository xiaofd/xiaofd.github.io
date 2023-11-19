#!/bin/bash
## 自用 ubuntu 初装init
## wget xiaofd.github.io/init.sh && bash init.sh

function _apt_install(){
  pkg="$1"
  [[ -z `which "$pkg"` ]] && apt install -y "$pkg"
}
## ipv4优先
echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

## sshd设置
wget -qO- xiaofd.github.io/sshd.sh | bash

apt update
_apt_install tmux

if [[ -z `tmux ls | grep init` ]] ; then
  tmux new -s "init" -d "wget -qO- xiaofd.github.io/init.sh | bash"
  tmux attach -t "init"
else
  ## 安装些组件
  apt install -y net-tools dnsutils curl wget tmux vim git net-tools iperf3
  git config --global user.email "jun@jun.ac.cn"
  git config --global user.name "xiaofd"

  ## rclone安装
  [[ -z `which rclone` ]] && wget -qO- xiaofd.github.io/rclone.sh | bash

  ## docker
  [[ -z `which docker` ]] && wget -qO- get.docker.com | bash

  if [[ -n `cat /etc/issue | grep "Ubuntu"` ]] ; then
    ## 配置中文
    apt install -y language-pack-zh-*
    locale-gen
    update-locale
    sed -i '/^export LANG=*/d' /root/.bashrc
    echo "export LANG=zh_CN.utf-8" >>/root/.bashrc

    sed -i '/^LANG=*/d' /etc/environment
    echo 'LANG="zh_CN.UTF-8"' >>/etc/environment

    sed -i '/^LANGUAGE=*/d' /etc/environment
    echo 'LANGUAGE="zh_CN:zh:en_US:en"' >>/etc/environment

  elif [[ -n `cat /etc/issue | grep "Debian"` ]] ; then
    sed -i '/^alias ll=*/d' ~/.bashrc
    echo "alias ll='ls -l --color=auto'" >>~/.bashrc
  fi


  ## 设置时区
  cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  
  ## 下载点儿东西
  wget xiaofd.github.io/others/ray.sh
  
  ## tmux kill-session -t "init"
fi






