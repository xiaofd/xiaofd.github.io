# coding:utf-8
import requests
from lxml import html
import re
import random
import string
import sqlite3
import pymysql
import functools
import time
from multiprocessing.dummy import Pool as ThreadPool 

stu_success=b'''a verification code''' # status_code:1 means : domain can be used for  A1/A1p
stu_fail=b'''isn't on our list''' # status_code:0 means : domain can not be used for A1/A1p
stu_fail_1=b'''doesn't meet our academic eligibility''' # status_code:0 means : domain can not be used for A1/A1p
may_fail=b'''turned off signup''' # status_code:2 means : already have admin and close register
may_fail_1=b'''contact your IT department''' # status_code:2 means : already have admin and close register
code_a1='''94763226-9b3c-4e75-a931-5c89701abe66'''
code_a1p='''e82ae690-a2d5-4d76-8d30-7c6e01e6022e'''

# TODO: change db connection data
dbhost='localhost'
dbport=3306
dbpass='dbpass'
dbname='ms'

sqlinit='''create table if not exists dom ( 
id int(10) primary key not null auto_increment,
dom varchar(100) unique,
a1 int default -1,
suba1 int default -1,
a1p int default -1,
suba1p int default -1
);
'''
sqlinsert='''insert into dom(dom) values("{}");'''
sqlupdate='''update dom set {}={} where dom="{}";'''
sqlselect='''select dom from dom where {}=-1 limit 300;'''

# conn=sqlite3.connect('afraid.db', check_same_thread = False)

def initdb():
    conn=pymysql.connect(host=dbhost,port=dbport,password=dbpass)
    cur=conn.cursor()
    cur.execute('SET sql_notes = 0;')
    cur.execute('create database if not exists {};'.format(dbname))
    cur.execute('use ms;')
    cur.execute(sqlinit)
    cur.execute('SET sql_notes = 1;')
    conn.close()
    
def insertdb(dom=''):
    conn=pymysql.connect(host=dbhost,port=dbport,password=dbpass,db=dbname)
    try:
        cur=conn.cursor()
        cur.execute(sqlinsert.format(dom))
        conn.commit()
        return 1
    except Exception as e:
        # print(e)
        return 0
    finally:
        conn.close()

def updatedb(dom='',sku='a1',status=-1):
    conn=pymysql.connect(host=dbhost,port=dbport,password=dbpass,db=dbname)
    try:
        cur=conn.cursor()
        cur.execute(sqlupdate.format(sku,status,dom))
        conn.commit()
    except Exception as e:
        print(e)
    finally:
        conn.close()
    
def getdom(page=1,debug=False):
    # print('read dom from page.{}'.format(page))
    url = "https://freedns.afraid.org/domain/registry/?page={}&sort=4&q="
    headers = {
        'upgrade-insecure-requests': "1",
        'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
        'accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        'referer': "https://freedns.afraid.org/domain/registry/",
        'accept-encoding': "gzip, deflate, br",
        'accept-language': "zh-HK,zh;q=0.9,zh-CN;q=0.8,en-US;q=0.7,en;q=0.6,zh-TW;q=0.5",
        'cache-control': "no-cache",
        }
    try:
        cont = requests.request("GET", url.format(page), headers=headers, timeout=5).content
    except Exception as e:
        print(e)
        return 0,[]
    pages = int(re.findall(b' of (\d*)',cont)[-1])
    print(pages) if debug == True else 0
    xcont = html.fromstring(cont)
    doms = xcont.xpath('//a[contains(@href,"/subdomain/edit.php?")]/text()')
    print(doms) if debug == True else 0
    res = [ insertdb(dom) for dom in doms ]
    print('page:{},nums:{},indb:{}'.format(page,len(doms),res.count(1)))
    return pages,doms

def getalldom():
    pages,doms = getdom(1)
    for i in range(pages)[::-1]:
        getdom(i+1)
    
def checkms(dom='ccc.mit.edu',sku='a1',sub=False,proxies = {'http': '','https': ''},debug=True):
    url = "https://signup.microsoft.com/signup"
    srow=sku if sub == False else 'sub'+sku
    sku_code = code_a1 if sku=='a1' else code_a1p
    rand1 = ''.join(random.sample(string.ascii_letters + string.digits, 8)) + '@'
    rand2 = ''.join(random.sample(string.ascii_letters + string.digits, 8)) + '.' if sub==True else ''
    email = rand1+rand2+dom
    querystring = {"skug":"Education","StepsData.Email":email,"sku":sku_code}
    headers = {
        'origin': "https://signup.microsoft.com",
        'upgrade-insecure-requests': "1",
        'content-type': "application/x-www-form-urlencoded",
        'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
        'accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        'referer': "https://signup.microsoft.com/signup?sku=Education",
        'accept-encoding': "gzip, deflate, br",
        'accept-language': "en-US;q=0.7,en;",
        'cache-control': "no-cache"
        }
    try:
        cont = requests.request("POST", url, headers=headers, params=querystring, proxies=proxies, timeout=5).content
    except Exception as e:
        print(dom,'error') if debug == True else 0
        return 'error'
    if stu_success in cont:
        print(dom,'true') if debug == True else 0
        updatedb(dom,srow,1)
        return 'true'
    elif stu_fail in cont or stu_fail_1 in cont:
        print(dom,'false') if debug == True else 0
        updatedb(dom,srow,0)
        return 'false'
    elif may_fail in cont or may_fail_1 in cont:
        print(dom,'may false') if debug == True else 0
        updatedb(dom,srow,2)
        return 'may false'
    else:
        print(dom,'error') if debug == True else 0
        return 'error'
    
def checkonems(sku='a1',sub=False):
    while True:
        #proxy='http://ip:port' # TODO: add proxy like these , choose one
        #proxy='https://ip:port' # TODO: add proxy like these , choose one
        #proxy='socks://ip:port' # TODO: add proxy like these , choose one
        srow=sku if sub == False else 'sub'+sku
        conn=pymysql.connect(host=dbhost,port=dbport,password=dbpass,db=dbname)
        cur=conn.cursor()
        print(sqlselect.format(srow))
        cur.execute(sqlselect.format(srow))
        doms=cur.fetchall()
        conn.close()
        print(doms)
        if len(doms)==0:
            break
        doms=[i[0] for i in doms]        
        msfun=functools.partial(checkms, sku=sku,sub=sub,proxies = {'http': proxy,'https': proxy})
        pool = ThreadPool(100)
        results = pool.map(msfun, doms)
        pool.close() 
        pool.join()    

def checkallms():
    checkonems('a1p',True)
    checkonems('a1p',False)
    checkonems('a1',True)
    checkonems('a1',False)
    
if __name__=='__main__':
    import sys
    if len(sys.argv)==1:
        checkallms()
    elif len(sys.argv)==2 and 'init' in sys.argv[1]:
        initdb()
        getalldom()
    else:
        exit(0)
