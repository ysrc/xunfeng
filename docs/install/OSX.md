# MAC OSX 安装指南

## 一、环境安装

### 1、操作系统依赖

使用 homebrew 在 Mac OSX 中进行软件的安装与管理, 执行如下命令安装 brew 工具:

```
$ ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)"
```

安装系统依赖:

```
$ brew install gcc libffi libpcap openssl
```
### 2、python 依赖库

更新`pip`到最新版本:

```
$ pip install -U pip
```

使用`pip`安装 python 依赖库, 这里使用了豆瓣的 pypi 源。

```
$ pip install -r requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com
```

### 3、安装数据库

```
$ brew install mongodb
```

## 二、部署与配置

### 1. 启动数据库

```
$ sudo mongod --port 65521 --dbpath /opt/xunfeng/log/db &
```

### 2. mongodb 添加认证

```
$ mongo 127.0.0.1:65521/xunfeng
> db.createUser({user:'scan',pwd:'your password',roles:[{role:'dbOwner',db:'xunfeng'}]})
> exit
```

这里的 `your password` 需要更换为你的验证密码。

### 2. 导入数据库

进入 `db` 文件夹, 执行如下命令:

```
$ mongorestore -h 127.0.0.1 --port 65521 -d xunfeng .
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
    PORT = 65521
    DBUSERNAME = 'scan'
    DBPASSWORD = 'scanlol66'
    DBNAME = 'xunfeng'
```
### 4. 运行系统

根据实际情况修改 `Conifg.py` 和 `Run.sh` 文件后, 执行:

```
$ sh Run.sh
```