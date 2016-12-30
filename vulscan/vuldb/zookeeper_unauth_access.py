# coding=utf-8
import socket


def get_plugin_info():
    plugin_info = {
        "name": "Zookeeper未授权访问",
        "info": "Zookeeper Unauthorized access",
        "level": "中危",
        "type": "未授权访问",
        "author": "c4bbage@qq.com",
        "url": "https://hackerone.com/reports/154369",
        "keyword": "server:Zookeeper",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        flag = "envi"
        # envi
        # dump
        # reqs
        # ruok
        # stat
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'Environment' in data:
            return u"Zookeeper Unauthorized access"
    except:
        pass


def main():
    ip = "1.1.1.1"
    print check(ip, 2181, 2)

if __name__ == '__main__':
    main()
