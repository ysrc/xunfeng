# Windows 安装指南

## 一、环境安装

### 1、操作系统依赖

由于默认的kunpeng库为64位的，需要操作系统和python版本均为64位才可正常加载kunpeng漏洞库，如果有特别需要，可自行编译32位的kunpeng替换即可。

安装 `python` 解释器:

* https://sec.ly.com/mirror/python-2.7.13.amd64.msi

### 2、python 依赖库

下载并安装 `pip` 工具, https://pypi.python.org/pypi/pip#downloads 下载完解压后执行:

```
$ python setup.py install
```

使用`pip`安装 python 依赖库, 这里使用了豆瓣的 pypi 源。

```
$ pip install -r requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com
```

### 3、安装数据库

下载: https://sec.ly.com/mirror/mongodb-win32-x86_64-2008plus-ssl-3.4.0-signed.msi

## 二、部署与配置

### 1. 启动数据库

`DBData`为指定的数据库保存路径

```
> mongod.exe --port 65521 --dbpath DBData
```

### 2. mongodb 添加认证

```
$ mongo 127.0.0.1:65521/xunfeng
> db.createUser({user:'scan',pwd:'your password',roles:[{role:'dbOwner',db:'xunfeng'}]})
> exit
```

这里的 `your password` 需要更换为你的验证密码。

### 2. 导入数据库

`db` 文件夹位于xunfeng代码目录中:

```
$ mongorestore.exe -h 127.0.0.1 --port 65521 -d xunfeng db 
```

导入后关闭mongod.exe进程

### 3. 修改配置

修改系统数据库配置脚本 `config.py`:

```
class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'xunfeng321'
```

修改 `PASSWORD` 字段内的密码, 设置成你的密码。

```
class ProductionConfig(Config):
    DB = '127.0.0.1'
    PORT = 65521
    DBUSERNAME = 'scan'
    DBPASSWORD = 'scanlol66'
    DBNAME = 'xunfeng'
```

### 4. 运行系统

根据实际情况修改 `conifg.py` 和 `run.bat` 文件后, 执行:

```
> run.bat
```

_要用MASSCAN的话需要安装WinPcap_
