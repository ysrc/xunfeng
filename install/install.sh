#!/bin/sh
set -e
#
# This script is meant for quick & easy install via:
#   'curl -sSL https://raw.githubusercontent.com/ysrc/xunfeng/master/install/install.sh | sh'
# or:
#   'wget -qO- https://raw.githubusercontent.com/ysrc/xunfeng/master/install/install.sh | sh'
#
export MONGODB_URL="https://sec.ly.com/mirror/mongodb-linux-x86_64-3.4.0.tgz"
export XUNFENG_REPO="https://github.com/ysrc/xunfeng.git"

set_env() {
    # TZ=Asia/Shanghai
    # sudo ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && sudo echo $TZ > /etc/timezone
    export LC_ALL="C.UTF-8"
}

command_exists() {
    command -v "$@" > /dev/null 2>&1
}

install_start_stop_daemon() {
    cd /usr/local/src
    if [ ! -f /usr/local/src/dpkg_1.17.10.tar.xz ]; then
        wget https://sec.ly.com/mirror/dpkg_1.17.10.tar.xz
    fi
    tar xf dpkg_1.17.10.tar.xz && cd dpkg-1.17.10/
    ./configure
    make || echo -e "\e[1;33m[!] Don't worry, just build for start-stop-daemon\e[0m"
    if [ ! -f /usr/local/src/dpkg-1.17.10/utils/start-stop-daemon ]; then
        cd utils/
        make
    fi
    cp /usr/local/src/dpkg-1.17.10/utils/start-stop-daemon /usr/sbin/
    cd ~
    rm -rf /usr/local/src/dpkg-1.17.10/
}
do_install(){
    architecture=$(uname -m)
    case $architecture in
        # officially supported
        amd64|x86_64)
            ;;
        # unofficially supported without available repositories
        armv6l|armv7l|aarch64|arm64|ppc64le|s390x)
            cat 1>&2 <<-EOF
            Error: This install script does not support $architecture, because no
            $architecture package exists in repositories.
EOF
            exit 1
            ;;
        # not supported
        *)
            cat >&2 <<-EOF
            Error: $architecture is not a recognized platform.
EOF
            exit 1
            ;;
    esac

    user="$(id -un 2>/dev/null || true)"
    sh_c='sh -c'
    if [ "$user" != 'root' ]; then
        if command_exists sudo; then
            sh_c='sudo -E sh -c'
        elif command_exists su; then
            sh_c='su -c'
        else
            cat >&2 <<-'EOF'
            Error: this installer needs the ability to run commands as root.
            We are unable to find either "sudo" or "su" available to make this happen.
EOF
            exit 1
        fi
    fi

    curl=''
    if command_exists curl; then
        curl='curl -sSL'
    elif command_exists wget; then
        curl='wget -qO-'
    elif command_exists busybox && busybox --list-modules | grep -q wget; then
        curl='busybox wget -qO-'
    fi

   # perform some very rudimentary platform detection
    lsb_dist=''
    dist_version=''
    if command_exists lsb_release; then
        lsb_dist="$(lsb_release -si)"
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/lsb-release ]; then
        lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/debian_version ]; then
        lsb_dist='debian'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/fedora-release ]; then
        lsb_dist='fedora'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/oracle-release ]; then
        lsb_dist='oracleserver'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/centos-release ]; then
        lsb_dist='centos'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/redhat-release ]; then
        lsb_dist='redhat'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/photon-release ]; then
        lsb_dist='photon'
    fi
    if [ -z "$lsb_dist" ] && [ -r /etc/os-release ]; then
        lsb_dist="$(. /etc/os-release && echo "$ID")"
    fi

    lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"
    # Special case redhatenterpriseserver
    if [ "${lsb_dist}" = "redhatenterpriseserver" ]; then
            # Set it to redhat, it will be changed to centos below anyways
            lsb_dist='redhat'
    fi

    case "$lsb_dist" in
        ubuntu|debian|raspbian)
            export DEBIAN_FRONTEND=noninteractive

            did_apt_get_update=
            apt_get_update() {
                if [ -z "$did_apt_get_update" ]; then
                    ( set -x; $sh_c 'sleep 3; apt-get update' )
                    did_apt_get_update=1
                fi
            }
            apt_get_update
            $sh_c 'apt-get install -y -q curl wget unzip gcc libssl-dev libffi-dev python-dev libpcap-dev python-pip git whiptail supervisor'
            $sh_c 'pip install -U pip'
            if [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ]; then
                $sh_c 'ln -s /usr/lib/x86_64-linux-gnu/libpcap.so /usr/lib/x86_64-linux-gnu/libpcap.so.1'
            fi
            ;;

        fedora|centos|redhat|oraclelinux|photon)
            if [ "${lsb_dist}" = "redhat" ]; then
                # we use the centos repository for both redhat and centos releases
                lsb_dist='centos'
            fi
            if [ "$lsb_dist" = "fedora" ] && [ "$dist_version" -ge "22" ]; then
                (
                    set -x
                    $sh_c 'sleep 3; dnf -y -q install curl wget unzip gcc git libffi-devel python-devel openssl-devel libpcap-devel newt.x86_64 supervisor ncurses-devel ncurses make g++ gcc-c++ automake autoconf libtool'
                )
            elif [ "$lsb_dist" = "photon" ]; then
                (
                    set -x
                    $sh_c 'sleep 3; tdnf -y -q install curl  wget unzip gcc git libffi-devel python-devel openssl-devel libpcap-devel newt.x86_64 supervisor ncurses-devel ncurses make g++ gcc-c++ automake autoconf libtool'
                )
            else
                (
                    set -x
                    $sh_c 'sleep 3; yum -y -q install epel-release curl wget unzip gcc git libffi-devel python-devel openssl-devel libpcap-devel newt.x86_64 supervisor ncurses-devel ncurses make g++ gcc-c++ automake autoconf libtool'
                    $sh_c 'yum -y install python-pip'
                )
            fi
            if ! command_exists start-stop-daemon; then
                install_start_stop_daemon
            fi
            ;;
        *   )
            echo "Either your platform is not easily detectable, is not supported by this installer script."
            exit
        ;;
    esac
    PY_VERSION=$(expr "$(/usr/bin/env python -V 2>&1)" : '.*\([0-9]\.[0-9]\)\.[0-9]*')
    echo "Checking Python Version..."
    case "$PY_VERSION" in
        2.7 )
            echo "Python Version: `/usr/bin/env python -V`.... pass"
            ;;
        2.6 )
            echo -e "\e[1;31mError: Python 2.7.x not found in your environment.\e[0m"
            echo -e "\e[1;31mPython 2.6 is no longer supported by the Python core team, please upgrade your Python. \e[0m"
            exit
            ;;
         *  )
            echo "Error: Python 2.7.x not found in your environment."
            exit
            ;;
    esac

    if [ ! -d /opt/xunfeng ]; then
        # clone repo
        $sh_c 'git clone ${XUNFENG_REPO} /opt/xunfeng'
    fi

    if [ ! -f /opt/xunfeng/xunfengdb/bin/xunfeng_db ]; then
        echo "install mongodb"
        if [ ! -f /tmp/mongodb.tgz ]; then
            $sh_c 'wget -O /tmp/mongodb.tgz ${MONGODB_URL}'    
        fi
        $sh_c 'mkdir -p /opt/xunfeng/xunfengdb && tar zxf /tmp/mongodb.tgz -C /opt/xunfeng/xunfengdb --strip-components=1'
        $sh_c 'mv /opt/xunfeng/xunfengdb/bin/mongod /opt/xunfeng/xunfengdb/bin/xunfeng_db'
    fi
    
    # install requirements
    $sh_c 'pip install --upgrade pip'
    $sh_c 'pip install --upgrade supervisor>=3.3'
    $sh_c 'pip install meld3==1.0.0 -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com'
    # $sh_c 'wget -qO /tmp/meld3-1.0.2.tar.gz https://pypi.python.org/packages/source/m/meld3/meld3-1.0.2.tar.gz && tar -zxf /tmp/meld3-1.0.2.tar.gz -C /tmp/ && cd /tmp/meld3-1.0.2/ && /usr/bin/env python setup.py install && cd - && rm -rf /tmp/meld3*'
    $sh_c 'pip install -r /opt/xunfeng/requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com'
    sdpid=$(ps -ef | grep supervisord | grep -v grep | awk '{print $2}')
    if [ "$sdpid" -gt 0 ] 2>/dev/null; then
        kill -9 $sdpid
    fi
    $sh_c 'chmod a+x /opt/xunfeng/masscan/linux_64/masscan'
    $sh_c 'cp /opt/xunfeng/install/files/xunfeng /etc/init.d/xunfeng'
    $sh_c 'chmod +x /etc/init.d/xunfeng'
    $sh_c 'cp /opt/xunfeng/install/files/xunfeng.conf /etc/xunfeng.conf'
    $sh_c 'chmod +x /opt/xunfeng/install/config.sh'
    $sh_c '/bin/bash /opt/xunfeng/install/config.sh'
}
do_install
