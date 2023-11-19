#!/usr/bin/python3
#coding:utf-8
#import sys
#print(sys.version)
from datetime import *
bjtime=str(datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=8)))).split('.')[0]
print('北京时间: ' + bjtime)

import requests
sess=requests.session()
headers={
    'Host': 'www.hostloc.com',
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Origin': 'https://www.hostloc.com',
    'Upgrade-Insecure-Requests': '1',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Referer': 'https://www.hostloc.com/forum.php',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-HK,zh;q=0.9,zh-CN;q=0.8,en-US;q=0.7,en;q=0.6,zh-TW;q=0.5'
}
data={
    'fastloginfield':'username',
    'username':'',
    'password':'',
    'cookietime':'2592000',
    'quickforward':'yes',
    'handlekey':'ls'
}

import sys
data['username']=sys.argv[1]
data['password']=sys.argv[2]

sess.post('https://www.hostloc.com/member.php?mod=logging&action=login&loginsubmit=yes&infloat=yes&lssubmit=yes&inajax=1',headers=headers,data=data)

import random
import re
bscore=re.findall('积分: ([0-9]+)',sess.get('https://www.hostloc.com/forum.php').content.decode('utf-8'))[0]
print('Hostloc签到前积分: ',bscore)

# [ sess.get('http://www.hostloc.com/space-uid-{}.html'.format(random.randint(10000,20000))) for i in range(15) ]

from multiprocessing.dummy import Pool as ThreadPool
pool = ThreadPool(10) # 10个线程
results = pool.map(lambda x: sess.get(x), [ 'https://www.hostloc.com/space-uid-{}.html'.format(random.randint(10000,20000)) for i in range(20) ]) # urls是任务列表 list，第一个参数是线程函数
# close the pool and wait for the work to finish
pool.close()
pool.join()

ascore=re.findall('积分: ([0-9]+)',sess.get('https://www.hostloc.com/forum.php').content.decode('utf-8'))[0]
print('Hostloc签到后积分: ',ascore)

from termcolor import *
print(colored('签到成功！','green')) if (int(ascore)-int(bscore)>=20) else print(colored('签到失败！','red'))
exit(0) if (int(ascore)-int(bscore)>=20) else exit(1)
