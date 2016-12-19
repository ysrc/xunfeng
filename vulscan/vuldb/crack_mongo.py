# coding=utf-8
import socket
import binascii


def get_plugin_info():
    plugin_info = {
        "name": "MongoDB未授权访问",
        "info": "导致数据库敏感信息泄露。",
        "level": "中危",
        "type": "未授权访问",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:mongodb",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        data = binascii.a2b_hex(
            "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
        s.send(data)
        result = s.recv(1024)
        if "ismaster" in result:
            getlog_data = binascii.a2b_hex(
                "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
            s.send(getlog_data)
            result = s.recv(1024)
            if "totalLinesWritten" in result:
                return u"未授权访问"
    except Exception, e:
        pass
