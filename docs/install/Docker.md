# Docker安装
---

### 1. 创建镜像

```
$ docker build -t xunfeng .
```

或者

```bash
$ docker pull ysrc/xunfeng
```

### 2. 创建容器

```bash
$ docker run -d -p 8000:80 -v /opt/data:/data ysrc/xunfeng:latest
```

把物理机的 `/opt/data` 挂载到容器的 `/data` 目录下, 访问: `http://127.0.0.1:8000/` 正常访问则代表安装成功

### 3. Docker 镜像信息

|类型 | 用户名 | 密码 |
|----- |----- |-----| 
| Web账号 | admin | xunfeng321 |
| mongodb 数据库 | scan | scanlol66 |
| mongodb 端口 | 27017| - |
| 巡风物理路径 | /opt/xunfeng | - |
| MASSCAN 路径| /opt/xunfeng/masscan/linux_64/masscan | - |
