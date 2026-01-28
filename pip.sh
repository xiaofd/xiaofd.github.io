#!/bin/bash

function sets()
{
mkdir /root > /dev/null 2>&1
mkdir /root/.pip > /dev/null 2>&1
mv /root/.pip/pip.conf /root/.pip/pip.conf.bak > /dev/null 2>&1
cat << EOF >> /root/.pip/pip.conf
[global]
timeout = 60
index-url = $1
EOF
}

getopts :s: OPT
if [ ! -n "$OPTARG" ];then
  echo "You can use -s with: qh|ali|ustc|douban to use different source"
  echo "Use Default Setting: Douban Pypi"
  sets "https://pypi.douban.com/simple"
elif [ "$OPTARG" == "qh" ];then
  echo "Use Tsinghua Pypi"
  sets "https://pypi.tuna.tsinghua.edu.cn/simple"
elif [ "$OPTARG" == "ali" ];then
  echo "Use Aliyun Pypi"
  sets "https://mirrors.aliyun.com/pypi/simple"
elif [ "$OPTARG" == "ustc" ];then
  echo "Use USTC Pypi"
  sets "https://pypi.mirrors.ustc.edu.cn/simple"
fi

echo "The original source has been move to pip.conf.bak"
