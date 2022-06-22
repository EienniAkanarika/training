from xml import etree
import base64
import json
import sys
import time
import requests
from requests.packages import urllib3

from thirdparty.identywaf.identYwaf import quote

urllib3.disable_warnings()
# 配置文件区域
url = 'https://IP:Port'  # 根据具体情况设置IP与端口
scan_speed = 'moderate'  # 设置扫描速度，由慢到快:sequential slow moderate fast
'''
awvs爬虫模式配置：
user_agent	bool	UA设置
case_sensitive	string	路径大小写敏感设置 值:auto(默认)/no/yes
limit_crawler_scope	bool	将抓取限制为仅包含地址和子目录 值:true(默认)/false
excluded_paths	list	排除路径
'''
spider_data = {
    "user_agent": "Opera/9.80 (Windows NT 6.0; U; en) Presto/2.8.99 Version/11.10",
    "limit_crawler_scope": "true",
    "excluded_paths": [],
}
awvs_headers = {'X-Auth': 'awvs APIkey',
                'content-type': 'application/json',
                'User-Agent': 'curl/7.53.1'
                }
# fofa配置
fofa_headers = {
    "Connection": "keep-alive",
    "cookie": "全部cookie值",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
}

'''
    create_target函数
    功能:
        AWVS13
        新增任务接口
    Method : request
    URL : /api/v1/targets
    发送参数:
        发送参数     类型     说明
        address     string   目标网址:需要http或https开头
        criticality int      危险程度;范围:[30,20,10,0];默认为10
        description string   备注
'''

'''
    start_target
    功能:
        AWVS13
        启动扫描任务接口
    Method : request
    URL : /api/v1/scans
    发送参数:
        发送参数         类型     说明
        profile_id      string   扫描类型
        ui_session_i    string   可不传
        schedule        json     扫描时间设置（默认即时）
        report_template string   扫描报告类型（可不传）
        target_id       string   目标id
profile_id :
Full Scan 	11111111-1111-1111-1111-111111111111 	完全扫描
High Risk Vulnerabilities 	11111111-1111-1111-1111-111111111112 	高风险漏洞
Cross-site Scripting Vulnerabilities 	11111111-1111-1111-1111-111111111116 	XSS漏洞
SQL Injection Vulnerabilities 	11111111-1111-1111-1111-111111111113 	SQL注入漏洞
Weak Passwords 	11111111-1111-1111-1111-111111111115 	弱口令检测
Crawl Only 	11111111-1111-1111-1111-111111111117 	Crawl Only
Malware Scan 	11111111-1111-1111-1111-111111111120 	恶意软件扫描
'''


def check_status():  # 检查配置是否正确
    url_1 = url + '/api/v1/info'
    try:
        respon = requests.get(url=url_1, headers=awvs_headers, verify=False).status_code
        if respon == 200:
            print("成功初始化！")
        else:
            print("初始化失败，请检查配置")
    except Exception as Error:
        print("请检查网络和配置信息！")
        sys.exit()


def add_target(address, description, int_criticality):  # 批量添加URL
    global dict_info
    # dict_info = {}  # 用来存储url对应的target_id，方便后续使用
    url_2 = url + '/api/v1/targets'
    values = {
        'address': address,
        'description': description,  # 备注
        'criticality': int_criticality,  # 危险程度;范围:[30,20,10,0];默认为10
    }
    data = bytes(json.dumps(values), 'utf-8')
    respon = requests.post(url=url_2, data=data, headers=awvs_headers, verify=False)
    result = respon.json()
    # print(result)
    target_id = result['target_id']
    # print(target_id)
    # dict_info[target_id] = address
    global url_2_1
    url_2_1 = url + '/api/v1/targets/' + target_id + '/configuration'  # 配置扫描速度
    speed_config = {
        'scan_speed': scan_speed
    }
    http_proxy = {
        "enabled": "true",
        "address": "127.0.0.1",
        "protocol": "http",
        "port": "7777"
    }
    proxy_data = {
        "proxy": http_proxy
    }
    respon2 = requests.post(url=url_2_1, data=speed_config, headers=awvs_headers, verify=False).status_code
    respon3 = requests.patch(url=url_2_1, headers=awvs_headers, data=json.dumps(proxy_data), verify=False)
    if respon2 == 200:
        print("添加成功-->" + address)
    return target_id


def get_target_list():  # 查詢目标队列，返回扫描ID
    print("正在查询，请稍等......")
    target_id_list = []
    url_3 = url + '/api/v1/scans?l=100'
    respon = requests.get(url=url_3, headers=awvs_headers, verify=False)
    data_json = respon.json()  # 将数据转化成json格式
    # print(data_json)
    # print(data_json.keys())
    data_list = data_json["scans"]
    # print(data_list)
    for i in data_list:
        # print(i)
        # print(i['target_id'])
        target_id_list.append(i['target_id'])
    print("共计有" + str(len(target_id_list)) + "个！")
    return target_id_list


def get_scan_list():  # 查詢掃描队列，返回扫描ID,input_page_num为查询页数
    print("正在查询，请稍等......")
    page_num = 1
    target_id_list = []
    url_3 = url + '/api/v1/scans?l=100'
    respon = requests.get(url=url_3, headers=awvs_headers, verify=False)
    data_json = respon.json()  # 将数据转化成json格式
    print(data_json)
    print(data_json.keys())
    data_list = data_json["scans"]
    print(data_list)
    for i in data_list:
        # print(i)
        print(i['scan_id'])
        target_id_list.append(i['scan_id'])
    return target_id_list


def profiles_list():  # 获取漏洞扫描结果
    print("正在获取中，请稍等.......")
    url_4 = url + '/api/v1/scanning_profiles'
    respon = requests.get(url=url_4, headers=awvs_headers, verify=False).content.decode('utf-8')
    print(respon)


def start_target(target_id, profile_id):  # 开始扫描,target_id由添加時返回得到
    url_4 = url + '/api/v1/scans'
    values = {
        'target_id': target_id,  # 目标id
        'profile_id': profile_id,  # 扫描类型
        'schedule': {"disable": False, "start_date": None, "time_sensitive": False}
    }
    data = bytes(json.dumps(values), 'utf-8')
    respon1 = requests.post(url=url_4, data=data, headers=awvs_headers, verify=False).content.decode('utf-8')
    if profile_id == '11111111-1111-1111-1111-111111111111':  # 判断是否是爬虫模式
        respon2 = requests.post(url=url_2_1, data=spider_data, headers=awvs_headers, verify=False).status_code
        if respon2 == 200:
            print("正在为-->" + target_id + "设置爬虫模式配置")
    print("正在扫描-->" + target_id)


def del_target(choice_code):  # 删除扫描
    print("正在查询数据中，请稍等......")
    while 1:
        if choice_code == 1:
            try:
                target_id_list = get_target_list()
                for i in target_id_list:
                    del_url = url + '/api/v1/targets/' + str(i)
                    # del_url = url + '/api/v1/scans/' + str(i)
                    # print(del_url)
                    respon = requests.delete(url=del_url, headers=awvs_headers, verify=False).status_code
                    # time.sleep(1)
                    if respon == 204:
                        print("成功删除" + str(i) + "|" + str(respon))
            except Exception:
                pass
        if choice_code == 2:
            try:
                target_id_list = get_scan_list()
                for i in target_id_list:
                    del_url = url + '/api/v1/scans/' + str(i)
                    # print(del_url)
                    respon = requests.delete(url=del_url, headers=awvs_headers, verify=False).status_code
                    # time.sleep(1)
                    print(del_url + "|" + str(respon))
                    if respon == 204:
                        print("成功删除" + str(i) + "|" + str(respon))
            except Exception:
                pass
        if len(target_id_list) == 0:
            break


def check_target_status():  # 检查当前正在扫描的数量,存在延迟
    req_url = url + '/api/v1/me/stats'
    respon = requests.get(url=req_url, headers=awvs_headers, verify=False)
    result = respon.json()
    # print(result.keys())
    # print(result["scans_running_count"])
    scans_running_num = result["scans_running_count"]
    return scans_running_num


def fofa_spider():
    keyword = input('请输入fofa搜索关键字 \n')
    pagenum = input('请输入页数：\n')
    keyword_base64 = quote(str(base64.b64encode(keyword.encode()), encoding='utf-8'))
    with open('url.txt', 'a+') as f:  # 储存文件名可自行修改
        for i in range(1, int(pagenum) + 1):
            print("正在提取第" + str(i) + "页")
            url = 'https://fofa.info/result?qbase64=' + keyword_base64 + '&page=' + str(i) + '&page_size=20'
            # print(url)
            respon = requests.get(url, headers=fofa_headers).text
            # print(respon)
            tree = etree.HTML(respon)
            urllist = tree.xpath('//span[@class="aSpan"]/a/@href')
            print(urllist)
            time.sleep(20)  # 设置延迟时间避免速度过快，IP被锁定，时间可以自行设置
            for j in urllist:
                f.write(j + '\n')
    f.close()
    print("提取完成！")


def start_scan(thread_num, profile_id):  # 快速开始扫描，默认使用url.txt文件
    print("正在运行，请稍等......\n默认使用url.txt文件")
    for i in open('url.txt'):
        if 'http' not in i:
            address = ''.join('http://') + i.replace('\n', '')
        else:
            address = i.replace('\n', '')
        print("正在添加-->" + address)
        description = "test"
        int_criticality = 10
        target_id = add_target(address, description, int_criticality)
        start_target(target_id, profile_id)  # 可行设置扫描类型
        Num = check_target_status()
        while int(Num) > int(thread_num):  # 设置最多同时进行的扫描数量，避免运行过多，导致服务器卡顿
            Num = check_target_status()
            print("当前扫描数量为：" + Num + " 大于设定值，停止添加！")
            time.sleep(10)
        time.sleep(30)  # 延时一会，避免Num获取不准


if __name__ == '__main__':
    print(
        "感谢这两篇文章的作者,没有他们就没有这个脚本\n" + "https://www.sqlsec.com/2020/04/awvsapi.html#toc-heading-26\n" + "https://www.cnblogs.com/Cl0ud/p/13324781.html\n")
    print("请输入你的选择：\n"
          "快速开始扫描 --> 1\n"
          "删除全部目标 --> 2\n"
          "删除全部扫描 --> 3\n"
          "使用fofa爬虫+awvs批量扫描 --> 4")
    options = int(input("选项为："))
    if options == 1:
        check_status()
        thread_num = int(input("请输入最大同时扫描数(实际数量可能会比该数大二到三)："))
        profile_id = int(input("完全扫描-->11111111-1111-1111-1111-111111111111\n"
                               "高风险漏洞-->11111111-1111-1111-1111-111111111112\n"
                               "XSS漏洞-->11111111-1111-1111-1111-111111111116\n"
                               "SQL注入漏洞-->11111111-1111-1111-1111-111111111113\n"
                               "弱口令检测-->11111111-1111-1111-1111-111111111115\n"
                               "仅爬虫爬取-->11111111-1111-1111-1111-111111111117\n"
                               "恶意软件扫描-->11111111-1111-1111-1111-111111111120"))
        print("如需配合使用xray扫描，请将将监听端口设置127.0.0.1:7777")
        start_scan(thread_num, profile_id)
        sys.exit()
    if options == 2:
        check_status()
        del_target(1)
        sys.exit()
    if options == 3:
        check_status()
        del_target(2)
        sys.exit()
    if options == 4:
        fofa_spider()
        check_status()
        start_scan()
        sys.exit()
