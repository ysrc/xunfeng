# coding:utf-8
import paramiko


def get_plugin_info():
    plugin_info = {
        "name": "SSH弱口令",
        "info": "直接导致服务器被入侵控制。",
        "level": "紧急",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:ssh",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    user_list = ['root', 'admin', 'oracle', 'weblogic']
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            pass_ = str(pass_.replace('{user}', user))
            try:
                ssh.connect(ip, port, user, pass_, timeout=timeout)
                ssh.exec_command('whoami',timeout=timeout)
                ssh.close()
                if pass_ == '': pass_ = "null"
                return u"存在弱口令，账号：%s，密码：%s" % (user, pass_)
            except Exception, e:
                if "Unable to connect" in e or "timed out" in e: return
