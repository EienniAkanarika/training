import time
import requests
from lxml import etree
import sys


def src_edu(pagenum):
    url = 'https://src.sjtu.edu.cn/list/?page='
    # pagenum = eval(input("plz how many pages"))
    for i in range(1, int(pagenum) + 1):
        key_url = url + str(i)
        print(key_url)
        respon = requests.get(key_url,timeout=1).content.decode('utf-8')
        #print(respon)
        soup = etree.HTML(respon)
        result = soup.xpath('//tr[@class="row"]/td/a/text()')
        #print(result)
        result = '\n'.join(result)
        result_key = result.split()
        #print(result_key)
        for edu in result_key:
            with open(r'src_edu.txt', 'a+', encoding='utf-8') as f:
                f.write(edu + '\n')
                f.close()
                print(edu)
                time.sleep(1)
if __name__ == '__main__':
    pagenum=sys.argv[1]
    src_edu(pagenum)