#coding:utf-8
from smb.SMBConnection import SMBConnection
import socket

def get_plugin_info():
    plugin_info = {
        "name": "SMB弱口令",
        "info": "直接导致机器被直接入侵控制。",
        "level": "紧急",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:smb",
        "source": 1
    }
    return plugin_info

def ip2hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        pass
    try:
        query_data = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        dport = 137
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.sendto(query_data, (ip, dport))
        x = _s.recvfrom(1024)
        tmp = x[0][57:]
        hostname = tmp.split("\x00", 2)[0].strip()
        hostname = hostname.split()[0]
        return hostname
    except:
        pass
def check(ip,port,timeout):
    socket.setdefaulttimeout(timeout)
    user_list = ['administrator']
    hostname = ip2hostname(ip)
    PASSWORD_DIC.insert(0,'anonymous')
    if not hostname:return
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                conn = SMBConnection(user,pass_,'xunfeng',hostname)
                if conn.connect(ip) == True:
                    if pass_ == 'anonymous':return u"存在匿名共享，请查看是否存在敏感文件。"
                    return u"存在弱口令，用户名：%s 密码：%s"%(user,pass_)
            except Exception,e:
                if "Errno 10061" in str(e) or "timed out" in str(e): return