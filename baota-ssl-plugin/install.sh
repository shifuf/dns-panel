#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Plugin install directory
install_path=/www/server/panel/plugin/dnspanel_ssl

Install()
{
    echo '正在安装 DNS面板SSL同步插件...'
    mkdir -p $install_path
    cp -a -r ./dnspanel_ssl_main.py ./info.json ./index.html ./static ./templates $install_path/ 2>/dev/null
    # Ensure config file exists
    if [ ! -f "$install_path/config.json" ]; then
        echo '{}' > $install_path/config.json
    fi
    chmod -R 600 $install_path/config.json 2>/dev/null

    # Register a daily auto-sync cron (renew expiring certs -> deploy -> prune).
    # Uses the BaoTa python runtime so the plugin's `public` module is importable.
    bt_py=/www/server/panel/pyenv/bin/python
    [ -x "$bt_py" ] || bt_py=$(command -v python3 || command -v python)
    cron_cmd="$bt_py $install_path/dnspanel_ssl_main.py auto_sync >> $install_path/sync.log 2>&1"
    ( crontab -l 2>/dev/null | grep -v 'dnspanel_ssl_main.py auto_sync' ; echo "30 3 * * * $cron_cmd" ) | crontab - 2>/dev/null
    echo '已注册每日 03:30 自动续期/同步任务'
    echo '================================================'
    echo '安装完成，请在宝塔软件商店中打开插件并配置连接信息'
}

Uninstall()
{
    # Remove the auto-sync cron, then delete the plugin.
    ( crontab -l 2>/dev/null | grep -v 'dnspanel_ssl_main.py auto_sync' ) | crontab - 2>/dev/null
    rm -rf $install_path
}

action=$1
if [ "${action}" == 'install' ];then
    Install
elif [ "${action}" == 'uninstall' ];then
    Uninstall
else
    echo 'Error!';
fi