#!/bin/bash
#set default keyboard layout
#防止安装xorg时，可能要求选择键盘布局
cat > /etc/default/keyboard <<EOF
XKBMODEL="pc105"
XKBLAYOUT="us"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
EOF

apt-get update && apt-get install -y sudo
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo apt-get update
sudo apt-get install -y wget xorg lxde-core tightvncserver flashplugin-installer

mkdir -p ~/.vnc
wget xiaofd.github.io/others/passwd -P ~/.vnc/
chmod 0400 ~/.vnc/passwd
wget xiaofd.github.io/others/xstartup -P ~/.vnc/
chmod +x ~/.vnc/xstartup

export USER=~
tightvncserver :1
