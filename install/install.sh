#!/bin/sh
set -e

export MONGODB_URL="https://sec.ly.com/mirror/mongodb-linux-x86_64-3.4.0.tgz"
export XUNFENG_REPO="https://github.com/Medicean/xunfeng.git"

set_env() {
    # TZ=Asia/Shanghai
    # sudo ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && sudo echo $TZ > /etc/timezone
    export LC_ALL="C.UTF-8"
}

command_exists() {
    command -v "$@" > /dev/null 2>&1
}

do_install(){
    architecture=$(uname -m)
    case $architecture in
        # officially supported
        amd64|x86_64)
            ;;
        # unofficially supported without available repositories
        armv6l|armv7l|aarch64|arm64|ppc64le|s390x)
            # cat 1>&2 <<-EOF
            # Error: This install script does not support $architecture, because no
            # $architecture package exists in repositories.

            # EOF
            exit 1
            ;;
        # not supported
        *)
            # cat >&2 <<-EOF
            # Error: $architecture is not a recognized platform.
            # EOF
            # exit 1
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
            # cat >&2 <<-'EOF'
            # Error: this installer needs the ability to run commands as root.
            # We are unable to find either "sudo" or "su" available to make this happen.
            # EOF
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
            $sh_c 'apt-get install -y wget unzip gcc libssl-dev libffi-dev python-dev libpcap-dev python-pip git whiptail'
            $sh_c 'pip install -U pip'
            ;;

        fedora|centos|redhat|oraclelinux|photon)
            if [ "${lsb_dist}" = "redhat" ]; then
                # we use the centos repository for both redhat and centos releases
                lsb_dist='centos'
            fi
            if [ "$lsb_dist" = "fedora" ] && [ "$dist_version" -ge "22" ]; then
                (
                    set -x
                    $sh_c 'sleep 3; dnf -y -q install gcc git libffi-devel python-devel openssl-devel libpcap-devel whiptail'
                )
            elif [ "$lsb_dist" = "photon" ]; then
                (
                    set -x
                    $sh_c 'sleep 3; tdnf -y install gcc git libffi-devel python-devel openssl-devel libpcap-devel whiptail'
                )
            else
                (
                    set -x
                    $sh_c 'sleep 3; yum -y -q install gcc git libffi-devel python-devel openssl-devel libpcap-devel whiptail'
                )
            fi
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
    $sh_c 'pip install -r /opt/xunfeng/requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com'
    
    if [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ]; then
        $sh_c 'ln -s /usr/lib/x86_64-linux-gnu/libpcap.so /usr/lib/x86_64-linux-gnu/libpcap.so.1'
    fi

    $sh_c 'chmod a+x /opt/xunfeng/masscan/linux_64/masscan'
    $sh_c 'cp /opt/xunfeng/install/files/xunfeng /etc/init.d/xunfeng'
    $sh_c 'chmod +x /etc/init.d/xunfeng'
    $sh_c 'cp /opt/xunfeng/install/files/xunfeng.conf /etc/xunfeng.conf'
}
do_install
