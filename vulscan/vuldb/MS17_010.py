# coding=utf-8
import socket
import binascii


def get_plugin_info():
    plugin_info = {
        "name": "SMB远程溢出",
        "info": "MS17-010（NSA Eternalblue SMB），攻击者可通过此漏洞执行任意代码，进而导致服务器被入侵控制。",
        "level": "紧急",
        "type": "远程溢出",
        "author": "wolf@YSRC",
        "url": "http://bobao.360.cn/learning/detail/3738.html",
        "keyword": "server:smb",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout):
    negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(negotiate_protocol_request)
        s.recv(1024)
        s.send(session_setup_request)
        data = s.recv(1024)
        user_id = data[32:34]
        tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(ip)), user_id.encode('hex'), ip.encode('hex'))
        s.send(binascii.unhexlify(tree_connect_andx_request))
        data = s.recv(1024)
        allid = data[28:36]
        payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.encode('hex')
        s.send(binascii.unhexlify(payload))
        data = s.recv(1024)
        s.close()
        if "\x05\x02\x00\xc0" in data:
            return u"存在SMB远程溢出漏洞"
        s.close()
    except:
        pass
