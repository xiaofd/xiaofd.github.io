# -*- coding: utf-8 -*-
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
  apt install -y net-tools dnsutils curl wget tmux vim git net-tools iperf3 fuse3 p7zip-full locales
  git config --global user.email "xiaofd@ac.cn"
  git config --global user.name "xiaofd"

  ## rclone安装
  [[ -z `which rclone` ]] && wget -qO- xiaofd.github.io/rclone.sh | bash -s -- 9

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
    echo "alias ll='ls -l --color=auto'" >> ~/.bashrc
    sed -i '/^export LANG=/d' ~/.bashrc
    echo "export LANG=zh_CN.UTF-8" >> ~/.bashrc
    #touch ~/.vimrc
    #[[ -z $(grep "set encoding=utf-8" "$HOME/.vimrc") ]] && echo "set encoding=utf-8" #>> "$HOME/.vimrc"
    #[[ -z $(grep "set fileencodings=utf-8,gbk,gb2312" "$HOME/.vimrc") ]] && echo "set fileencodings=utf-8,gbk,gb2312" #>> "$HOME/.vimrc"
 
    apt install fonts-wqy-zenhei
    echo "zh_CN.UTF-8 UTF-8" > /etc/locale.gen
    locale-gen
    update-locale LANG=zh_CN.UTF-8
    echo 'LANG=zh_CN.UTF-8' > /etc/default/locale
    echo 'LANGUAGE=zh_CN:zh:en_US:en' >> /etc/default/locale
    echo 'LC_ALL=zh_CN.UTF-8' >> /etc/default/locale
  fi


  ## 设置时区
  cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  
  ## 下载点儿东西
  wget xiaofd.github.io/others/ray.sh
  
  ## tmux kill-session -t "init"
fi





