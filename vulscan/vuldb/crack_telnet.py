# coding:utf-8
import telnetlib
import re
import time


def get_plugin_info():
    plugin_info = {
        "name": "Telnet弱口令",
        "info": "直接导致服务器或设备被入侵控制。",
        "level": "紧急",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:telnet",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    user_list = ['administrator', 'admin', 'root', 'cisco']
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            pass_ = str(pass_.replace('{user}', user))
            try:
                re = auth(ip, port, user, pass_, timeout)
                if re == 3: return
                if re == 2: return u"存在弱口令，密码：%s" % (pass_)
                if re == True:
                    if pass_ == '': pass_ = "null"
                    return u"存在弱口令，账号：%s，密码：%s" % (user, pass_)
                else:
                    if 'Errno 61' in re: return
            except Exception, e:
                pass


def auth(ip, port, user, pass_, timeout):
    try:
        tn = telnetlib.Telnet(ip, port, timeout)
        # tn.set_debuglevel(3)
        time.sleep(0.5)
        os = tn.read_some()
    except Exception, e:
        return 3
    user_match = "(?i)(login|user|username)"
    pass_match = '(?i)(password|pass)'
    login_match = '#|\$|>'
    if re.search(user_match, os):
        try:
            tn.write(str(user) + '\r\n')
            tn.read_until(pass_match, timeout=2)
            tn.write(str(pass_) + '\r\n')
            login_info = tn.read_until(login_match, timeout=3)
            tn.close()
            if re.search(login_match, login_info):
                return True
            else:
                return login_info
        except Exception, e:
            return e
    else:
        try:
            info = tn.read_until(user_match, timeout=2)
        except Exception, e:
            return e
        if re.search(user_match, info):
            try:
                tn.write(str(user) + '\r\n')
                tn.read_until(pass_match, timeout=2)
                tn.write(str(pass_) + '\r\n')
                login_info = tn.read_until(login_match, timeout=3)
                tn.close()
                if re.search(login_match, login_info):
                    return True
                else:
                    return login_info
            except Exception, e:
                return e
        elif re.search(pass_match, info):
            tn.read_until(pass_match, timeout=2)
            tn.write(str(pass_) + '\r\n')
            login_info = tn.read_until(login_match, timeout=3)
            tn.close()
            if re.search(login_match, login_info):
                return 2
            else:
                return login_info


if __name__ == "__main__":
    print check("10.101.10.74", 23, 10)
