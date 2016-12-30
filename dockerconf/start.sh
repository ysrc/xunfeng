#!/bin/bash
CURRENT_PATH=`dirname $0`
cd $CURRENT_PATH
XUNFENG_BASE=`dirname ${CURRENT_PATH}`
XUNFENG_DB=/data
XUNFENG_LOG=/var/log/xunfeng

[ ! -d $XUNFENG_LOG ] && mkdir -p ${XUNFENG_LOG}

nohup mongod --bind_ip 127.0.0.1 --port 65521 --dbpath=${XUNFENG_DB} > ${XUNFENG_LOG}/db.log &

mongo 127.0.0.1:65521/xunfeng < ${XUNFENG_BASE}/dockerconf/mongoauth
if [[ $? != 0 ]]; then
    mongorestore -h 127.0.0.1 --port 65521 -d xunfeng ${XUNFENG_BASE}/db/
    mongo 127.0.0.1:65521/xunfeng < ${XUNFENG_BASE}/dockerconf/mongoauth
fi

nohup python ${XUNFENG_BASE}/Run.py > ${XUNFENG_LOG}/web.log &
nohup python ${XUNFENG_BASE}/aider/Aider.py > ${XUNFENG_LOG}/aider.log &
nohup python ${XUNFENG_BASE}/nascan/NAScan.py > ${XUNFENG_LOG}/scan.log &
nohup python ${XUNFENG_BASE}/vulscan/VulScan.py > ${XUNFENG_LOG}/vul.log &

/usr/bin/tail -f /dev/null
