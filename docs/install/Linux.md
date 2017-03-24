# Linux 安装指南

## 一、环境安装

修改当前时区为 `Asia/Shanghai`:

```
$ echo TZ\='Asia/Shanghai'\; export TZ >> ~/.bash\_profile && source ~/.bash\_profile
```

### 1、操作系统依赖

**CentOS**
```
$ yum install gcc libffi-devel python-devel openssl-devel libpcap-devel
```

**Ubuntu/Debian**

```
$ sudo apt-get update && sudo apt-get install gcc libssl-dev libffi-dev python-dev libpcap-dev
```

### 2、python 依赖库

**建议使用`pip`进行管理:** 如过没有安装`pip`, 可执行如下命令进行安装:

```
$ wget https://sec.ly.com/mirror/get-pip.py --no-check-certificate && python get-pip.py
```

更新到`pip`最新版本:

```
$ pip install -U pip
```

使用`pip`安装 python 依赖库, 这里使用了豆瓣的 pypi 源。

```
$ pip install -r requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com
```

### 3、安装数据库

由于低版本不支持全文索引，需使用 `MongoDB 3.x` 版本

**CentOS**

```
$ vi /etc/yum.repos.d/mongodb-org-3.2.repo

```

编辑 `yum` 源, 输入如下内容:

```
[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=0
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.2.asc
```

保存并退出, 执行如下命令:

```bash
$ sudo yum install -y mongodb-org
```

**Ubuntu/Debian**

[参考地址](https://docs.mongodb.com/v3.0/tutorial/install-mongodb-on-ubuntu/)

```bash
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
$ sudo apt-get update && sudo apt-get install -y mongodb-org
```

_Ubuntu 12.04_

```
$ echo "deb http://repo.mongodb.org/apt/ubuntu precise/mongodb-org/3.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list
```

_Ubuntu 14.04_

```
$ echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list
```

**或者下载二进制文件直接运行**

* https://sec.ly.com/mirror/mongodb-linux-x86_64-3.4.0.tgz
* https://sec.ly.com/mirror/mongodb-linux-x86_64-ubuntu1604-3.4.0.tgz
* https://sec.ly.com/mirror/mongodb-linux-x86_64-ubuntu1404-3.4.0.tgz

## 二、部署与配置

### 1. 启动数据库

```
$ service mongodb restart
```

或者

```
$ sudo /etc/init.d/mongodb restart
```

执行如下命令查看 `mongodb` 是否成功启动:

```
$ netstat -antlp | grep 27017
```
### 2. mongodb 添加认证

```bash
$ mongo
> use xunfeng
> db.createUser({user:'scan',pwd:'your password',roles:[{role:'dbOwner',db:'xunfeng'}]})
> exit
```

这里的 `your password` 需要更换为你的验证密码。

### 2. 导入数据库

进入 `db` 文件夹, 执行如下命令:

```
$ mongorestore -h 127.0.0.1 --port 27017 -d xunfeng .
```

### 3. 修改配置

修改系统数据库配置脚本 `Config.py`:

```python
class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'xunfeng321'
```

修改 `PASSWORD` 字段内的密码, 设置成你的密码。

```python
class ProductionConfig(Config):
    DB = '127.0.0.1'
    PORT = 27017
    DBUSERNAME = 'scan'
    DBPASSWORD = 'scanlol66'
    DBNAME = 'xunfeng'
```
### 4. 运行系统

根据实际情况修改 `Conifg.py` 和 `Run.sh` 文件后, 执行:

```
$ sh Run.sh
```

