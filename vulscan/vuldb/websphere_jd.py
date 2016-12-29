#!/usr/bin/env python
#-*- coding: utf-8 -*-
import urllib2, ssl

def get_plugin_info():
	plugin_info = {
		"name": "WebSphere反序列化代码执行",
		"info": "漏洞的成因是Apache Commons Collections (ACC) 3.2.1及4.0版本未能正确验证用户输入，其InvokerTransformer类在反序列化来自可疑域的数据时存在安全漏洞，这可使攻击者在用户输入中附加恶意代码并组合运用不同类的readObject()方法，在最终类型检查之前执行Java函数或字节码（包括调用Runtime.exec()执行本地OS命令）。",
		"level": "紧急",
		"type": "代码执行",
		"author": "Dee Ng<d33.n99@gmail.com>",
		"url": "https://www-01.ibm.com/support/docview.wss?uid=swg21970575",
		"keyword": "tag:websphere",
		"source": 1
	}
	return plugin_info

def check(ip, port, timeout):
	bingo = u"可能存在WebSphere反序列化代码执行漏洞"
	try:
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		output = urllib2.urlopen('https://'+ip+":"+str(port), context=ctx, timeout=10).read()
		if "rO0AB" in output:return bingo
	except urllib2.HTTPError, e:
		if ((e.getcode() == 500) and ("rO0AB" in e.read())):return bingo
	except:pass
	try:
		output = urllib2.urlopen('http://'+ip+":"+str(port), context=ctx, timeout=10).read()
		if "rO0AB" in output:return bingo
	except urllib2.HTTPError, e:
		if ((e.getcode() == 500) and ("rO0AB" in e.read())):return bingo
	except:return
