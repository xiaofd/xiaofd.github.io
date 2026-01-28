#!/bin/bash
# under root user
# ubuntu 16.04
apt update
apt install -y apt-transport-https

wget 'https://github.com/OpenNebula/minione/releases/latest/download/minione'
#bash minione --help
sudo bash minione --frontend --force


