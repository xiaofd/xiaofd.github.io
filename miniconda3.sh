#!/bin/bash
# already try in
# ubuntu 20.04
# debian 11
apt update && apt install -y wget bzip2
# lastest version
if [[ 'aarch64' == $(uname -m) ]];then
  MINICONDA_DOWN="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh"
elif [[ 'x86_64' == $(uname -m) ]];then
  MINICONDA_DOWN="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
fi
# ANACONDA_URL="https://repo.continuum.io/archive/"
# ANACONDA_VERSION=`wget --no-check-certificate -qO- $ANACONDA_URL | grep -o '"Anaconda3.*-Linux-x86_64.sh"' | cut -d '"' -f 2 | sort -r | head -n 1`
#wget --no-check-certificate $ANACONDA_URL$ANACONDA_VERSION -O anaconda3-install.sh
#wget --no-check-certificate https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O anaconda3-install.sh
wget --no-check-certificate ${MINICONDA_DOWN} -O anaconda3-install.sh
#echo "export PATH=/opt/conda/bin:$PATH" > /etc/profile.d/conda.sh
/bin/bash anaconda3-install.sh -f -b -p ~/conda
rm -f anaconda3-install.sh
#export PATH=/opt/conda/bin:$PATH
#source /etc/profile
~/conda/bin/conda init
source ~/.bashrc
source ~/.profile
