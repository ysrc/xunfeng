# coding:utf-8

import socket
import re
import time
import hashlib
from itertools import product
from base64 import b64encode
from exceptions import Exception


def hex2str(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

ver_num_com = re.compile('@RSYNCD: (\d+)')

class ReqNoUnderstandError(Exception):
    pass


class VersionNotSuppError(Exception):
    '''\
    版本不支持错误,当前Rsync协议常见有三个版本，
    目前来看还不能支持小于版本30的用户登录逻辑
    如果你对该版本29的登录过程有兴趣，可以参考：
    https://git.samba.org/rsync.git/?p=rsync.git;a=blob;f=authenticate.c;h=5370cb781fd8c73f09f1e9a25fd91095f86dd1c6;hb=0c6d79528ac651ef064173327d769ba7a2b338ab#l224
    欢迎讨论
    '''
    pass


class RsyncWeakCheck(object):
    """用于检测Rsync弱口令和弱验证 beta0.1 @Nearg1e"""

    # '.'
    _list_request = hex2str('''
    0a
    ''')

    # '@RSYNCD: 29\n'
    _hello_request = '@RSYNCD: 31\n'

    def __init__(self, host='', port=0, timeout=5):
        super(RsyncWeakCheck, self).__init__()
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None


    def _rsync_init(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(self.timeout)
        sock.connect((self.host,self.port))
        sock.send(self._hello_request)
        res = sock.recv(1024)
        self.sock = sock
        return res


    def is_path_not_auth(self, path_name = ''):
        '''\
        验证某一目录是否可以被未授权访问
        >>> result = is_path_not_auth('nearg1e')
        0 # 无需登录可未授权访问
        1 # 需要密码信息进行登录
        -1 # 出现了rsync的error信息无法读取
        raisee ReqNoUnderstandError # 出现了本喵=0v0=无法预料的错误
        '''
        self._rsync_init()
        payload = path_name + '\n'
        self.sock.send(payload)
        result = self.sock.recv(1024)
        if result == '\n':
            result = self.sock.recv(1024)
        if result.startswith('@RSYNCD: OK'):
            return 0
        if result.startswith('@RSYNCD: AUTHREQD'):
            return 1
        if '@ERROR: chdir failed' in result:
            return -1
        else:
            raise ReqNoUnderstandError()


    def get_all_pathname(self):
        self._rsync_init()
        self.sock.send(self._list_request)
        time.sleep(0.5)
        result = self.sock.recv(1024)
        if result:
            for path_name in re.split('\n', result):
                if path_name and not path_name.startswith('@RSYNCD: '):
                    yield path_name.split('\t')[0].strip()

    def weak_passwd_check(self, path_name='', username='', passwd=''):
        ver_string = self._rsync_init()
        if self._get_ver_num(ver_string=ver_string) < 30:
            # print('Error info:', ver_string)
            raise VersionNotSuppError()
        payload = path_name + '\n'
        self.sock.send(payload)
        result = self.sock.recv(1024)
        if result == '\n':
            result = self.sock.recv(1024)
        if result:
            hash_o = hashlib.md5()
            hash_o.update(passwd)
            hash_o.update(result[18:].rstrip('\n'))
            auth_string = b64encode(hash_o.digest())
            send_data = username + ' ' + auth_string.rstrip('==') + '\n'
            self.sock.send(send_data)
            res = self.sock.recv(1024)
            if res.startswith('@RSYNCD: OK'):
                return (True, username, passwd)
            else:
                return False


    def _get_ver_num(self, ver_string=''):
        if ver_string:
            ver_num = ver_num_com.match(ver_string).group(1)
            if ver_num.isdigit():
                return int(ver_num)
            else: return 0
        else:
            return 0


def get_plugin_info():
    plugin_info = {
        "name":"rsync未授权访问与弱验证",
        "info":"可以通过rsync服务下载服务器上敏感数据",
        "level":"高危",
        "type":"信息泄露",
        "author":"nearg1e@ysrc",
        "source":1,
        "url":"http://drops.wooyun.org/papers/161",
        "keyword":"port:873"
    }
    return plugin_info


def check(host, port, timeout=5):
    info = ''
    not_unauth_list = []
    weak_auth_list = []
    userlist = ['test', 'root', 'www', 'web', 'rsync', 'admin']
    if __name__ == '__main__':
        passwdlist = ['test', 'neagrle']
    else:
        passwdlist = PASSWORD_DIC
    try:
        rwc = RsyncWeakCheck(host,port)
        for path_name in rwc.get_all_pathname():
            ret = rwc.is_path_not_auth(path_name)
            if ret == 0:
                not_unauth_list.append(path_name)
            elif ret == 1:
                for username, passwd in product(userlist, passwdlist):
                    try:
                        res = rwc.weak_passwd_check(path_name, username, passwd)
                        if res:
                            weak_auth_list.append((path_name, username, passwd))
                    except VersionNotSuppError as e:
                        # TODO fengxun error support
                        pass
    except Exception, e:
        pass

    if not_unauth_list:
        info += u'未授权访问目录有:%s;' %','.join(not_unauth_list)
    if weak_auth_list:
        for weak_auth in weak_auth_list:
            info += u'目录%s存在弱验证:%s:%s;' %weak_auth
    if info:
        return info

if __name__ == '__main__':
    ip_list = []
    for ip_addr in ip_list:
        print(ip_addr, check(ip_addr, 873))
