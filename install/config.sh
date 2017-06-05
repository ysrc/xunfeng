#!/bin/bash
XUNFENG_PATH="/opt/xunfeng"
XUNFENG_DB_PATH="$XUNFENG_PATH/xunfengdb"
DAEMON_USER="root"
DAEMON_GROUP="root"
XUNFENG_LOG_PATH="/var/log/xunfeng"
XUNFENG_PID_PATH="/var/run/xunfeng"
XUNFENG_DB_DATA_PATH="/var/lib/xunfeng"

dbconfig() {
    # mongodb account
    XUNFENG_DB_USERNAME=$(whiptail --inputbox "Set database account name\n\ndefault: scan" 10 30 "" 3>&1 1>&2 2>&3)
    if [[ "$XUNFENG_DB_USERNAME" == "" ]]; then
        XUNFENG_DB_USERNAME="scan"
    fi

    # mongodb pass
    XUNFENG_DB_PASS=""
    XUNFENG_DB_PASS_REPEAT="scanlol66"

    while [[ "$XUNFENG_DB_PASS" != "$XUNFENG_DB_PASS_REPEAT" ]]; do
        XUNFENG_DB_PASS=$(whiptail --inputbox "Set database password\n\ndefault: scanlol66" 10 30 "" 3>&1 1>&2 2>&3)
        XUNFENG_DB_PASS_REPEAT=$(whiptail --inputbox "Repeat database password\n\ndefault: scanlol66" 10 30 3>&1 1>&2 2>&3)
    done
    if [[ "$XUNFENG_DB_PASS" == "" ]]; then
        XUNFENG_DB_PASS="scanlol66"
    fi    
}

websiteconfig() {
    # website account
    XUNFENG_USERNAME=$(whiptail --inputbox "Set xunfeng website account name\n\ndefault: admin" 10 30 "" 3>&1 1>&2 2>&3)
    if [[ "$XUNFENG_USERNAME" == "" ]]; then
        XUNFENG_USERNAME="admin"
    fi

    # website pass
    XUNFENG_USERPASS="xunfeng321"
    XUNFENG_USERPASS_REPEAT=""

    while [[ "$XUNFENG_USERPASS" != "$XUNFENG_USERPASS_REPEAT" ]]; do
        XUNFENG_USERPASS=$(whiptail --inputbox "Set xunfeng website account password\n\ndefault: xunfeng321" 10 30 "" 3>&1 1>&2 2>&3)
        XUNFENG_USERPASS_REPEAT=$(whiptail --inputbox "Repeat website account password\n\ndefault: xunfeng321" 10 30 3>&1 1>&2 2>&3)
    done

    if [[ "$XUNFENG_USERPASS" == "" ]]; then
        XUNFENG_USERPASS="xunfeng321"
    fi
}

writeconfig_confirm() {
    echo ""
    echo "    Database account:  $XUNFENG_DB_USERNAME"
    echo "    Database password: $XUNFENG_DB_PASS"
    echo "    Website  account:  $XUNFENG_USERNAME"
    echo "    Website  password: $XUNFENG_USERPASS"
    echo ""
    read -t 180 -p "Confirm your configurations[Y/n]: " configConfirm
    if ([ "${configConfirm}" == "Y" ]||[ "${configConfirm}" == "y" ]||[ "${configConfirm}" == "" ]); then
        writeconfig
    else
        echo "User interrupt, will exit..."
        sleep 1
        exit
    fi
}

writeconfig() {
    CONFIG_FILE_PATH="/opt/xunfeng/Config.py"
    cat /dev/null > $CONFIG_FILE_PATH

    echo "class Config(object):" >> ${CONFIG_FILE_PATH}
    echo "    ACCOUNT = '${XUNFENG_USERNAME}'" >> ${CONFIG_FILE_PATH}
    echo "    PASSWORD = '${XUNFENG_USERPASS}'" >> ${CONFIG_FILE_PATH}
    echo "" >> ${CONFIG_FILE_PATH}
    echo "" >> ${CONFIG_FILE_PATH}
    echo "class ProductionConfig(Config):" >> ${CONFIG_FILE_PATH}
    echo "    DB = '127.0.0.1'" >> ${CONFIG_FILE_PATH}
    echo "    PORT = 65521" >> ${CONFIG_FILE_PATH}
    echo "    DBUSERNAME = '${XUNFENG_DB_USERNAME}'" >> ${CONFIG_FILE_PATH}
    echo "    DBPASSWORD = '${XUNFENG_DB_PASS}'" >> ${CONFIG_FILE_PATH}
    echo "    DBNAME = 'xunfeng'" >> ${CONFIG_FILE_PATH}
    echo "" >> ${CONFIG_FILE_PATH}
}

setpermission() {
    # id xunfeng || useradd xunfeng -d /opt/xunfeng/ -s /bin/false
    # chown -R xunfeng:xunfeng /opt/xunfeng
    return 0
}

initdb() {
    echo "Initialized XunFeng Database..."
    INITDB_ARGS="--bind_ip 127.0.0.1 --port 65521 --dbpath=${XUNFENG_DB_DATA_PATH}"
    start-stop-daemon --start --background --quiet --pidfile $XUNFENG_PID_PATH/xunfeng_db.pid --make-pidfile --chdir $XUNFENG_DB_PATH/bin/ --chuid $DAEMON_USER --exec xunfeng_db -- $INITDB_ARGS

    while [[ true ]]; do
        echo "quit" > /tmp/xunfeng_initdb_tmp
        $XUNFENG_DB_PATH/bin/mongo 127.0.0.1:65521 < /tmp/xunfeng_initdb_tmp | grep "bye"
        if [[ $? == 0 ]]; then
            break
        fi
        echo "Wait xunfeng_db startup..."
        sleep 5
    done

    cat > /tmp/xunfeng_auth_tmp <<-EOF
    use xunfeng
    db.createUser({user:'${XUNFENG_DB_USERNAME}',pwd:'${XUNFENG_DB_PASS}',roles:[{role:'dbOwner',db:'xunfeng'}]})
    db.auth('${XUNFENG_DB_USERNAME}', '${XUNFENG_DB_PASS}')
    exit
EOF
    $XUNFENG_DB_PATH/bin/mongo 127.0.0.1:65521/xunfeng < /tmp/xunfeng_auth_tmp
    rm -f /tmp/xunfeng_initdb_tmp
    rm -f /tmp/xunfeng_auth_tmp
    $XUNFENG_DB_PATH/bin/mongorestore -h 127.0.0.1 --port 65521 -d xunfeng ${XUNFENG_PATH}/db/
    dbpid=$(cat ${XUNFENG_PID_PATH}/xunfeng_db.pid)
    kill -9 ${dbpid} && rm -f ${XUNFENG_PID_PATH}/xunfeng_db.pid
    echo "Initialized Database Success"
}


install_service() {
    test -e $XUNFENG_PID_PATH || install -m 755 -o $DAEMON_USER -g $DAEMON_GROUP -d $XUNFENG_PID_PATH
    test -e $XUNFENG_LOG_PATH || install -m 755 -o $DAEMON_USER -g $DAEMON_GROUP -d $XUNFENG_LOG_PATH
    test -e $XUNFENG_DB_DATA_PATH || install -m 755 -o $DAEMON_USER -g $DAEMON_GROUP -d $XUNFENG_DB_DATA_PATH

    cp ${XUNFENG_PATH}/install/files/xunfeng /etc/init.d/xunfeng
    chmod +x /etc/init.d/xunfeng
    cp ${XUNFENG_PATH}/install/files/xunfeng.conf /etc/xunfeng.conf
}

dbconfig
websiteconfig
writeconfig_confirm
writeconfig
install_service
initdb
/etc/init.d/xunfeng restart
