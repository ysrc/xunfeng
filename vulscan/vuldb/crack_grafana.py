#-*- encoding:utf-8 -*-
import urllib
import urllib2

def get_plugin_info():
	plugin_info = {
		"name": "grafana 弱口令",
		"info": "对grafana控制台进行弱口令检测",
		"level": "高危",
		"type": "弱口令",
		"author": "hos@YSRC",
		"url": "https://hackerone.com/reports/174883",
		"keyword": "banner:grafana",
		"source": 1
	}
	return plugin_info


def check(ip,port,timeout):
	url="http://%s:%s/login"%(ip,str(port))
	header={
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
	'ContentType': 'application/x-www-form-urlencoded; chartset=UTF-8',
	'Accept-Encoding': 'gzip, deflate',
	'Accept-Language': 'zh-CN,zh;q=0.8',
	'Connection': 'close'
	}
	for password in PASSWORD_DIC:
		data={"user":"admin","email":"","password":password}
		data=urllib.urlencode(data)
		request = urllib2.Request(url=url,data=data,headers=header)
		try:
		    res=urllib2.urlopen(request,timeout=timeout)
		    if "Logged in" in res.read():
				info = u'存在弱口令，用户名：%s，密码：%s' % ("admin", password)
				return info
		except Exception,e:
			pass
