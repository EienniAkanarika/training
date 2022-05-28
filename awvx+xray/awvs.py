import json
import sys
import time
import requests
from requests.packages import urllib3

urllib3.disable_warnings()

url = ''  # 根据具体情况设置IP与端口
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
headers = {'X-Auth': '你的APIKEY',
           'content-type': 'application/json',
           'User-Agent': 'curl/7.53.1'
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


def check_status():  # 检查配置是否正确
    url_1 = url + '/api/v1/info'
    try:
        respon = requests.get(url=url_1, headers=headers, verify=False).status_code
        if respon == 200:
            print("成功初始化！")
        else:
            print("初始化失败，请检查配置")
    except Exception as Error:
        print("请检查网络和配置信息！")
        sys.exit()


def add_target(address, description, int_criticality):  # 批量添加URL
    global dict_info
    url_2 = url + '/api/v1/targets'
    values = {
        'address': address,
        'description': description,  # 备注
        'criticality': int_criticality,  # 危险程度;范围:[30,20,10,0];默认为10
    }
    data = bytes(json.dumps(values), 'utf-8')
    respon = requests.post(url=url_2, data=data, headers=headers, verify=False)
    result = respon.json()
    target_id = result['target_id']
    global url_2_1
    url_2_1 = url + '/api/v1/targets/' + target_id + '/configuration'  # 配置扫描速度
    speed_config = {
        'scan_speed': scan_speed
    }
    http_proxy = {
        "enabled": "true",
        "address": "xray的地址",
        "protocol": "http",
        "port": "xray监听端口"
    }
    proxy_data = {
        "proxy": http_proxy
    }
    respon2 = requests.post(url=url_2_1, data=speed_config, headers=headers, verify=False).status_code
    respon3 = requests.patch(url=url_2_1, headers=headers, data=json.dumps(proxy_data), verify=False)
    if respon2 == 200:
        print("添加成功-->" + address)
    return target_id


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


def get_target_list(status_code):  # 查詢掃描队列，返回任务ID，address中的url一定不能有重复的，否则会导致后面字典报错！
    if status_code == 1:  # status_code用来区别后续函数调用还是人为查询 1：人为查询
        print("正在查询，请稍等......")
    url_3 = url + '/api/v1/targets'
    respon = requests.get(url=url_3, headers=headers, verify=False)
    result = respon.json()
    # print(result)
    string = str(result.values())
    if 'address' not in string:
        print("暂无内容！")
    else:
        list = string.split(",")
        global dict_url_id
        global list_keys
        global list_value
        dict_url_id = {}
        list_keys = []
        list_value = []
        for i in list:  # 将address与其target_id提取形成字典
            print(i)
            if 'address' in i:
                j = i.replace('{', '').replace("'", "").replace(' ', '').replace("[", "").replace("(", "")
                start_Num = j.index('h')
                list_keys.append(j[start_Num::])
                # print(j[start_Num::])
            if 'target_id' in i:
                k = i.replace('{', '').replace("'", "").replace(":", "").replace(' ', '')
                list_value.append(k[9::])
                # print(k[9::])
        try:
            dict_url_id = dict(zip(list_keys, list_value))
            count = 0
            for key, value in dict_url_id.items():
                count = count + 1
                if status_code == 1:
                    print("第" + str(count) + "个address：" + key + " 对应target_id为-->" + value)
        except Exception as Error:
            print("请将URL中的重复内容去掉！")


def profiles_list():  # 获取漏洞扫描结果
    print("正在获取中，请稍等.......")
    url_4 = url + '/api/v1/scanning_profiles'
    respon = requests.get(url=url_4, headers=headers, verify=False).content.decode('utf-8')
    print(respon)


def start_target(target_id, profile_id):  # 开始扫描,target_id由添加時返回得到
    url_4 = url + '/api/v1/scans'
    values = {
        'target_id': target_id,  # 目标id
        'profile_id': profile_id,  # 扫描类型
        'schedule': {"disable": False, "start_date": None, "time_sensitive": False}
    }
    data = bytes(json.dumps(values), 'utf-8')
    respon1 = requests.post(url=url_4, data=data, headers=headers, verify=False).content.decode('utf-8')
    if profile_id == '11111111-1111-1111-1111-111111111111':  # 判断是否是爬虫模式
        respon2 = requests.post(url=url_2_1, data=spider_data, headers=headers, verify=False).status_code
        if respon2 == 200:
            print("正在为-->" + target_id + "设置爬虫模式配置")
    print("正在扫描-->" + target_id)


def stop_target(target_id):  # 停止扫描
    url_5 = url + '/api/v1/scans/' + target_id + '/abort'
    respon = requests.get(url=url_5, headers=headers, verify=False)
    print(respon)


def del_target(status_code):  # 删除扫描，用status_code来判断是全部删除还是删除指定的URL地址
    if status_code == 0:
        print("正在全部删除中，请稍等......")
        get_target_list(0)
        for i in list_value:
            del_url = url + '/api/v1/scans/' + i
            respon = requests.delete(url=del_url, headers=headers, verify=False).status_code
            if str(respon) == '024':
                Num = list_value.index(i)
                j = list_keys[Num]
                print("已经删除-->" + dict_url_id[j])
    if status_code == 1:
        key_url = str(input("请输入需删除的URL："))
        get_target_list(0)
        try:
            k = dict_url_id[key_url]
            del_url = url + '/api/v1/scans/' + k
            respon = requests.delete(url=del_url, headers=headers, verify=False).status_code
            if str(respon) == '024':
                print("已经删除-->" + key_url)
        except Exception as Error:
            print("删除失败！")


def check_target_status():  # 检查当前正在扫描的数量,存在延迟
    url_req = url + '/api/v1/me/stats'
    respon = requests.get(url=url_req, headers=headers, verify=False)
    result = respon.json()
    string = str(result.values())
    new = string.split(',')
    Num = new[2]
    return Num


def get_target_result(target_id, scan_session_id):  # 查询扫描结果
    url_6 = url + target_id + '/results/' + scan_session_id + '/vulnerabilities '
    respon = requests.get(url=url_6, headers=headers, verify=False).content.decode('utf-8')
    print(respon)


def main():  #
    for i in open('url.txt'):
        if 'http' not in i:
            address = ''.join('http://') + i.replace('\n', '')
        else:
            address = i.replace('\n', '')
        print("正在添加-->" + address)
        description = "test"
        int_criticality = 10
        target_id = add_target(address, description, int_criticality)
        start_target(target_id, '11111111-1111-1111-1111-111111111117')  # 可行设置扫描类型
        Num = check_target_status()
        while int(Num) > 3:  # 设置最多同时进行的扫描数量，避免运行过多，导致服务器卡顿
            Num = check_target_status()
            print("当前扫描数量为：" + Num + " 大于设定值，停止添加！")
            time.sleep(10)
        time.sleep(30)  # 延时一会，避免Num获取不准


if __name__ == '__main__':
    print(
        "感谢这两篇文章的作者,没有他们就没有这个脚本\n" + "https://www.sqlsec.com/2020/04/awvsapi.html#toc-heading-26\n" + "https://www.cnblogs.com/Cl0ud/p/13324781.html\n")
    check_status()
    main()#默认使用awvs爬虫加上xray被动扫描
