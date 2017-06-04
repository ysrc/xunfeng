# Linux 自动安装

## 适配 64 位操作系统列表：

* Debian 7､8
* Ubuntu 14.04､14.10､16.04､16.10
* CentOS 7

> 由于 Linux 发行版较多，无法一一适配，如果不在以上列表中，请自行手动安装


## 安装

> 在安装之前，请自行更换`apt`、`yum`源

打开终端，在 root 用户 Shell 下，输入以下命令：

```
$ curl -sSL https://raw.githubusercontent.com/ysrc/xunfeng/master/install/install.sh | sh
```

或者输入以下命令：

```
$ wget -qO- https://raw.githubusercontent.com/ysrc/xunfeng/master/install/install.sh | sh
```

## 安装完毕

本脚本安装完毕后会以系统服务形式启动

### 启动服务

```
$ /etc/init.d/xunfeng start
```

### 停止服务

```
/etc/init.d/xunfeng stop
```

### 重启服务

```
/etc/init.d/xunfeng restart
```

### 查看服务运行状态

```
/etc/init.d/xunfeng status
```

## 报告问题

安装脚本在使用过程当中出现任何问题，请点击[这里](https://github.com/ysrc/xunfeng/issues/new)反馈

