FROM ubuntu:14.04
MAINTAINER Medici.Yan@Gmail.com
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 换源，根据实际情况
# RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list \
#     && mkdir -p ~/.pip \
#     && echo "[global]" > ~/.pip/pip.conf \
#     && echo "timeout=60" >> ~/.pip/pip.conf \
#     && echo "index-url = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf

# install requirements

RUN set -x \
    && apt-get update \
    && apt-get install -y wget unzip gcc libssl-dev libffi-dev python-dev libpcap-dev python-pip

RUN set -x \
    && pip install Flask pymongo xlwt paramiko \
    && ln -s /usr/lib/x86_64-linux-gnu/libpcap.so /usr/lib/x86_64-linux-gnu/libpcap.so.1 

# install mongodb

ENV MONGODB_TGZ https://sec.ly.com/mirror/mongodb-linux-x86_64-3.4.0.tgz
RUN set -x \
    && wget -O /tmp/mongodb.tgz $MONGODB_TGZ \
    && mkdir -p /opt/mongodb \
    && tar zxf /tmp/mongodb.tgz -C /opt/mongodb --strip-components=1 \
    && rm -rf /tmp/mongodb.tgz

ENV PATH /opt/mongodb/bin:$PATH

# install xunfeng
RUN mkdir -p /opt/xunfeng
COPY . /opt/xunfeng
RUN set -x \
    && chmod a+x /opt/xunfeng/masscan/linux_64/masscan \
    && chmod a+x /opt/xunfeng/dockerconf/start.sh

WORKDIR /opt/xunfeng

VOLUME ["/data"]

ENTRYPOINT ["/opt/xunfeng/dockerconf/start.sh"]

EXPOSE 80

CMD ["/usr/bin/tail", "-f", "/dev/null"]
