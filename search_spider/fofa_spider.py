import base64
import time
import requests
from lxml import etree
from thirdparty.identywaf.identYwaf import quote


def fofa_spider():
    keyword = input('请输入fofa搜索关键字 \n')
    pagenum = input('请输入页数：\n')
    keyword_base64 = quote(str(base64.b64encode(keyword.encode()), encoding='utf-8'))
    with open('url.txt', 'a+') as f:  # 储存文件名可自行修改
        for i in range(1, int(pagenum) + 1):
            print("正在提取第" + str(i) + "页")
            url = 'https://fofa.info/result?qbase64=' + keyword_base64 + '&page=' + str(i) + '&page_size=20'
            respon = requests.get(url=url, headers=fofa_headers).text
            tree = etree.HTML(respon)
            urllist = tree.xpath('//span[@class="aSpan"]/a/@href')
            print(urllist)
            time.sleep(20)  # 设置延迟时间避免速度过快，IP被锁定，时间可以自行设置
            for j in urllist:
                f.write(j + '\n')
    f.close()
    print("提取完成！")


if __name__ == "__main__":
    fofa_headers = {
        "Connection": "keep-alive",
        "cookie": "Cookie的全部值".encode(
            'utf-8').decode('latin-1'),
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
    }
    fofa_spider()
