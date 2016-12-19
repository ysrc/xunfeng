# coding:utf-8
import ftplib


def get_plugin_info():
    plugin_info = {
        "name": "FTP弱口令",
        "info": "导致敏感信息泄露，严重情况可导致服务器被入侵控制。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:ftp",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    user_list = ['ftp', 'www', 'admin', 'root', 'db', 'wwwroot', 'data', 'web']
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            pass_ = str(pass_.replace('{user}', user))
            try:
                ftp = ftplib.FTP()
                ftp.timeout = timeout
                ftp.connect(ip, port)
                ftp.login(user, pass_)
                if pass_ == '': pass_ = "null"
                if user == 'ftp' and pass_ == 'ftp': return u"可匿名登录"
                return u"存在弱口令，账号：%s，密码：%s" % (user, pass_)
            except Exception, e:
                if "Errno 10061" in str(e) or "timed out" in str(e): return