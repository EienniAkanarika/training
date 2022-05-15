import requests
from lxml import etree
import base64
import time
from urllib.parse import quote
import sys
headers = {
        "Connection": "keep-alive",
        "cookie": "Hm_lvt_b5514a35664fd4ac6a893a1e56956c97=1650373600; fofa_token=eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltSTJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjoiSldUIn0.eyJpZCI6MTU3MzA0LCJtaWQiOjEwMDA5MTk3MiwidXNlcm5hbWUiOiJkeWhhY2tlcnMiLCJleHAiOjE2NTI2MjYxNDN9.Ipg25S6WgSNoatAE05bcPCWiFPpgD2uifObnM2t_zkzk8FN_NBk1OXJHSkXkZy8dtpH_SbNZPUA_gbpy_XHRXw; user=%7B%22id%22%3A157304%2C%22mid%22%3A100091972%2C%22is_admin%22%3Afalse%2C%22username%22%3A%22dyhackers%22%2C%22nickname%22%3A%22dyhackers%22%2C%22email%22%3A%22dyhackers%40qq.com%22%2C%22avatar_medium%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22avatar_thumb%22%3A%22https%3A%2F%2Fnosec.org%2Fmissing.jpg%22%2C%22key%22%3A%228a9635cab1a72e6c5eb6b42e1a5a7659%22%2C%22rank_name%22%3A%22%E9%AB%98%E7%BA%A7%E4%BC%9A%E5%91%98%22%2C%22rank_level%22%3A2%2C%22company_name%22%3A%22dyhackers%22%2C%22coins%22%3A0%2C%22can_pay_coins%22%3A0%2C%22credits%22%3A16049%2C%22expiration%22%3A%22-%22%2C%22login_at%22%3A1652597343%7D; refresh_token=eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltSTJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjoiSldUIn0.eyJpZCI6MTU3MzA0LCJtaWQiOjEwMDA5MTk3MiwidXNlcm5hbWUiOiJkeWhhY2tlcnMiLCJleHAiOjE2NTI4NTY1NDMsImlzcyI6InJlZnJlc2gifQ.bnb9_Cl0oai8gOFiVacx9pxY2wlUEIFy-LzSjygO7jvv1UaHwzDE6Fxgrp5cHR8p8GQIW1AlYPgk_Nb-Bwg5XQ; befor_router=",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
    }
def fofa_spider(keyword,pagenum):
    #keyword = input('请输入fofa搜索关键字 \n')
    #pagenum=input('请输入页数：\n')
    keyword_base64 = quote(str(base64.b64encode(keyword.encode()), encoding='utf-8'))
    with open('url.txt','a+') as f:#储存文件名可自行修改
        for i in range(1,int(pagenum)+1):
            print("正在提取第"+str(i)+"页")
            url='https://fofa.info/result?qbase64='+keyword_base64+'&page='+str(i)+'&page_size=10'
            respon= requests.get(url, headers=headers).text
            tree = etree.HTML(respon)
            urllist = tree.xpath('//span[@class="aSpan"]/a/@href')
            print(urllist)
            time.sleep(2)#设置延迟时间避免速度过快，IP被锁定，时间可以自行设置
            for j in urllist:
                f.write(j+'\n')
    f.close()
    print("提取完成！")
if __name__ == '__main__':
    keyword=sys.argv[1]
    pagenum=sys.argv[2]
    fofa_spider(keyword,pagenum)