# coding:utf-8
import socket


def get_plugin_info():
    plugin_info = {
        "name": "Memcache-DRDOS 漏洞",
        "info": "memcached无认证可读写，且存在单键最大值问题，导致被攻击者伪造udp源地址对受害者发起dos攻击。",
        "level": "中危",
        "type": "drdos",
        "author": "bwd",
        "url": "http://www.freebuf.com/column/164095.html",
        "keyword": "server:memcache",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        data = "set i 0 0 1048501" + "\r\n" + 'i' * 1048501 + "\r\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send(data)
        result = s.recv(1024)

        udpClient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = "\x00\x00\x00\x00\x00\x01\x00\x00get VUKIC539IHDR62DS4\r\n"
        data = data.encode()
        udpClient.sendto(data, (ip, int(port)))
        data, addr = udpClient.recvfrom(1024)

        if b'STORED' in result and b'END' in data:
            return u"存在rddos漏洞"
    except Exception, e:
        pass
