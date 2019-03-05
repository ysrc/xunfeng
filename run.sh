#!/bin/bash
CURRENT_PATH=`dirname $0`
cd $CURRENT_PATH

XUNFENG_LOG=/var/log/xunfeng
XUNFENG_DB=/var/lib/mongodb

[ ! -d $XUNFENG_LOG ] && mkdir -p ${XUNFENG_LOG}
[ ! -d $XUNFENG_DB ] && mkdir -p ${XUNFENG_DB}

nohup mongod --port 65521 --dbpath=${XUNFENG_DB} --auth  > ${XUNFENG_LOG}/db.log &
nohup python web.py  > ${XUNFENG_LOG}/web.log &
nohup python aider/aider.py > ${XUNFENG_LOG}/aider.log &
nohup python nascan/nascan.py > ${XUNFENG_LOG}/scan.log &
nohup python vulscan/vulscan.py > ${XUNFENG_LOG}/vul.log &
