#!/bin/bash
user="$(id -un 2>/dev/null || true)"

if [ "$user" != 'root' ]; then
    echo "Error: this uninstaller needs the ability to run commands as root."
    exit 1
fi

[[ -f "/etc/init.d/xunfeng" ]] && /etc/init.d/xunfeng stop
rm -rf /etc/init.d/xunfeng
rm -rf /etc/xunfeng.conf
rm -rf /var/log/xunfeng
rm -rf /var/run/xunfeng
rm -rf /var/lib/xunfeng
rm -rf /opt/xunfeng/
echo "Uninstall Success!"
