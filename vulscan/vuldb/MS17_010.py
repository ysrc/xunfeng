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


def get_tree_connect_request(ip, tree_id):
    ipc = "005c5c" + binascii.hexlify(ip) + "5c49504324003f3f3f3f3f00"
    ipc_len_hex = hex(len(ipc) / 2).replace("0x", "")
    smb = "ff534d4275000000001801280000000000000000000000000000729c" + binascii.hexlify(
        tree_id) + "c4e104ff00000000000100" + ipc_len_hex + "00" + ipc
    tree = "000000" + hex(len(smb) / 2).replace("0x", "") + smb
    tree_connect_request = binascii.unhexlify(tree)
    return tree_connect_request


def check(ip, port, timeout):
    negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d4272000000001801280000000000000000000000000000729c0000c4e1003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "0000008fff534d4273000000001801280000000000000000000000000000729c0000c4e10cff000000dfff0200010000000000310000000000d400008054004e544c4d5353500001000000050208a2010001002000000010001000210000002e3431426c7441314e505974624955473057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(negotiate_protocol_request)
        s.recv(1024)
        s.send(session_setup_request)
        data = s.recv(1024)
        user_id = data[32:34]
        session_setup_request_2 = binascii.unhexlify(
            "00000150ff534d4273000000001801280000000000000000000000000000729c" + binascii.hexlify(
                user_id) + "c4e10cff000000dfff0200010000000000f200000000005cd0008015014e544c4d53535000030000001800180040000000780078005800000002000200d000000000000000d200000020002000d200000000000000f2000000050208a2ec893eacfc70bba9afefe94ef78908d37597e0202fd6177c0dfa65ed233b731faf86b02110137dc50101000000000000004724eed7b8d2017597e0202fd6177c0000000002000a0056004b002d005000430001000a0056004b002d005000430004000a0056004b002d005000430003000a0056004b002d00500043000700080036494bf1d7b8d20100000000000000002e003400310042006c007400410031004e005000590074006200490055004700300057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        s.send(session_setup_request_2)
        s.recv(1024)
        session_setup_request_3 = binascii.unhexlify(
            "00000063ff534d4273000000001801200000000000000000000000000000729c0000c4e10dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        s.send(session_setup_request_3)
        data = s.recv(1024)
        tree_id = data[32:34]
        smb = get_tree_connect_request(ip, tree_id)
        s.send(smb)
        s.recv(1024)
        poc = binascii.unhexlify(
            "0000004aff534d422500000000180128000000000000000000000000" + binascii.hexlify(
                user_id) + "729c" + binascii.hexlify(
                tree_id) + "c4e11000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
        s.send(poc)
        data = s.recv(1024)
        if "\x05\x02\x00\xc0" in data:
            return u"存在SMB远程溢出漏洞"
        s.close()
    except:
        pass
