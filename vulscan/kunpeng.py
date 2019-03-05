# coding:utf-8
from ctypes import *
import _ctypes
import json
import platform
import os
import urllib2
import sys

from urllib import urlretrieve
import zipfile


class kunpeng:
    def __init__(self):
        self.kunpeng = None
        self.system = platform.system().lower()
        self.pwd = os.path.split(os.path.realpath(__file__))[0]
        self.suf_map = {
            'windows': '.dll',
            'darwin': '.dylib',
            'linux': '.so'
        }
        self._load_kunpeng()
    
    def _get_lib_path(self):
        file_list = os.listdir(self.pwd)
        for v in file_list:
            if 'kunpeng' in v and os.path.splitext(v)[1] == self.suf_map[self.system]:
                return v

    def check_version(self):
        print 'check version'
        release = self._get_release_latest()
        # print(release)
        if release['tag_name'] != self.get_version():
            print 'new version', release['tag_name']
            self._down_release(release['tag_name'])
            return release

    def update_version(self, version):
        self.close()
        os.remove(self.pwd + '/' + self._get_lib_path())
        save_path = self.pwd + \
            '/kunpeng_{}_v{}.zip'.format(self.system, version)
        z_file = zipfile.ZipFile(save_path, 'r')
        dat = z_file.read('kunpeng_c' + self.suf_map[self.system])
        print len(dat)
        new_lib = self.pwd + '/kunpeng_v' + version + self.suf_map[self.system]
        lib_f = open(new_lib,'wb')
        lib_f.write(dat)
        lib_f.close()
        z_file.close()
        print 'update success',version
        self._load_kunpeng()

    def close(self):
        if self.system == 'windows':
            _ctypes.FreeLibrary(self.kunpeng._handle)
        else:
            handle = self.kunpeng._handle
            del self.kunpeng
            _ctypes.dlclose(handle)

    def _down_release(self, version):
        print 'kunpeng update ', version
        save_path = self.pwd + \
            '/kunpeng_{}_v{}.zip'.format(self.system, version)
        down_url = 'https://github.com/opensec-cn/kunpeng/releases/download/{}/kunpeng_{}_v{}.zip'.format(
            version, self.system.lower(), version)
        print 'url', down_url
        urlretrieve(down_url, save_path, self._callbackinfo)

    def _callbackinfo(self, down, block, size):
        per = 100.0*(down*block)/size
        if per > 100:
            per = 100
        print '%.2f%%' % per

    def _get_release_latest(self):
        body = urllib2.urlopen(
            'https://api.github.com/repos/opensec-cn/kunpeng/releases/latest').read()
        release = json.loads(body)
        return release

    def get_version(self):
        return self.kunpeng.GetVersion()

    def _load_kunpeng(self):
        lib_path = self._get_lib_path()
        # 加载动态连接库
        self.kunpeng = cdll.LoadLibrary(
            self.pwd + '/' + lib_path)

        # 定义出入参变量类型
        self.kunpeng.GetPlugins.restype = c_char_p
        self.kunpeng.Check.argtypes = [c_char_p]
        self.kunpeng.Check.restype = c_char_p
        self.kunpeng.SetConfig.argtypes = [c_char_p]
        self.kunpeng.GetVersion.restype = c_char_p
        print self.get_version()

    def get_plugin_list(self):
        result = self.kunpeng.GetPlugins()
        return json.loads(result)

    def set_config(self, timeout, pass_list):
        config = {
            'timeout': timeout,
            'pass_list': pass_list
        }
        self.kunpeng.SetConfig(json.dumps(config))

    def check(self, t, netloc, kpid):
        task_dic = {
            'type': t,
            'netloc': netloc,
            'target': kpid
        }
        r = json.loads(self.kunpeng.Check(json.dumps(task_dic)))
        result = ''
        if not r:
            return ''
        for v in r:
            result += v['remarks'] + ','
        return result


if __name__ == '__main__':
    kp = kunpeng()
    print(kp.pwd)
    print(kp._get_lib_path())
    # new_release = kp.check_version()
    # if new_release:
    kp.update_version('20190225')
