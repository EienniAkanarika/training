import requests
from lxml import etree
import time
import sys
def shaodan_search(keyword, pagenum):
    url = 'https://www.shodan.io/search?query='
    headers = {
        'cookie': '你的cookie',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.40 Safari/537.36'
    }
    for i in range(1, int(pagenum) + 1):
        request_url = url + keyword + '&page=' + str(i)
        print(request_url)
        try:
            result = requests.get(request_url, headers=headers).content
            soup = etree.HTML(result)
            key_url = soup.xpath('//div[@class="heading"]/a[@target="_blank"]/@href')
            print(key_url)
            key_url = '\n'.join(key_url)
            with open(r'url.txt', 'a+') as f:
                f.write(key_url + '\n')
                f.close()
                time.sleep(2)
        except Exception as e:
            pass
if __name__ == '__main__':
    keyword=sys.argv[1]
    pagenum=sys.argv[2]
    shaodan_search(keyword,pagenum)