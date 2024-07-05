#!/bin/bash

service_name=ssh
user=$1
gphome=$2

user_home=$(eval echo ~$user)
service_dir="${user_home}/.config/systemd/user"
service_file="${service_dir}/${service_name}.service"
commond=${gphome}script/local/CheckSshAgent.py

ssh_query_flag=false
ssh_content_flag=false
db_status_flag=false
ssh_start_flag=false

# Create the service dir
if [ ! -d ${service_dir} ]; then
    mkdir -p ${service_dir}
fi

write_ssh_file() {
cat <<EOL > $service_file
[Unit]
Description=ssh service
After=network.target
[Service]
ExecStart=${commond}
Restart=always
RestartSec=1s
StartLimitInterval=0
[Install]
WantedBy=default.target
EOL
}

# 1.query ssh service status
query_ssh() {
    res=$(systemctl --user status $service_name.service)
    if [[ $res =~ ".config/systemd/user/ssh.service" ]]; then
        echo "query ssh successfully"
        ssh_query_flag=true
    else
        echo "query ssh failed"
        ssh_query_flag=false
    fi
}

# 2.query ssh service content 
query_ssh_content() {
    content=$(cat $service_file | grep ExecStart)
    if [[ $content =~ "${commond}" ]]; then
        echo "query ssh content successfully"
        ssh_content_flag=true
    else
        echo "query ssh content failed"
        ssh_content_flag=false
    fi
}

# 3.create ssh service file
create_ssh_file() {
    local max_retries=3
    local count=0
    while [ $count -lt $max_retries ]; do
        query_ssh_content
        if [ $ssh_content_flag = "true" ]; then
            echo "create ssh service file successfully"
            break
        else
            write_ssh_file
            echo "create ssh service file failed, retrying..."
        fi
        count=$(( $count + 1 ))
    done
}

check_dbus() {
    if ! dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply / org.freedesktop.DBus.ListNames > /dev/null 2>&1; then
        echo "check dbus failed"
        $db_status_flag=false
    else
        echo "check dbus sucessfully"
        $db_status_flag=true
    fi
}

start_dbus() {
    # XDG_RUNTIME_DIR是一个环境变量，用于指定用户的运行时目录。这个目录通常用于存放用户会话中的临时文件和套接字文件
    # start the D-Bus session
    export XDG_RUNTIME_DIR=/run/user/$(id -u)
    mkdir -p /run/user/$(id -u)
    chmod 700 /run/user/$(id -u)
    eval $(dbus-launch --sh-syntax)
}

clean_dbus() {
    dbus_id=$(dbus-launch) | grep DBUS_SESSION_BUS_PID | awk -F'=' '{print $2}'
    kill -9 ${dbus_id}
    ps ux|grep dbus-daemon |grep -v grep | awk '{print $2}'|xargs -r kill -9
    ps ux|grep /usr/lib/systemd/systemd |grep -v grep | awk '{print $2}'|xargs -r kill -9
    # 删除 /run/user/${id -u} 目录的文件
    # 删除进程中 /usr/bin/dbus-daemon 的进程
    # 重新创建 dbus会话，先导入环境变量
    rm -rf /run/user/${id -u}/*
}

# 3.create dbus 
create_dbus() {
    local max_retries=3
    local count=0
    while [ $count -lt $max_retries ]; do
        check_dbus
        if [ $db_status_flag = "true" ]; then
            echo "dbus is running"
            break
        else
            echo "dbus is not running"
            clean_dbus
            start_dbus
            sleep 1s
        fi
        count=$((count+1))
    done
}

# 4.reload daemon
reload_daemon() {
    local max_retries=3
    local count=0
    while [ $count -lt $max_retries ]; do
        chmod +x ${service_file}
        # Reload systemd, start and enable the service
        res=$(systemctl --user daemon-reload)
        if [ $? -ne 0 ]; then
            echo "systemctl --user daemon-reload failed"
            create_dbus
        else
            echo "systemctl --user daemon-reload successfully"
            break
        fi
        count=$((count+1))
    done
}


# 5.start ssh service
start_ssh() {
    systemctl --user start $service_name.service
    systemctl --user enable $service_name.service
}

query_ssh
if [ $ssh_query_flag = "true" ]; then
    query_ssh_content
    if [ $ssh_content_flag = "true" ]; then
        echo "ssh service is running and content is correct"
        exit 0
    else
        echo "ssh service is running but content is incorrect"
        create_ssh_file
        if [ $ssh_content_flag = "true" ]; then
            echo "ssh service is running and content is correct"
            exit 0
        else
            echo "ssh service is running but content is incorrect"
            exit 1
        fi
    fi
else
    echo "ssh service is not running"
    check_dbus
    if [ $db_status_flag = "true" ]; then
        echo "dbus is running"
    else
        echo "dbus is not running"
        create_dbus
        if [ $db_status_flag = "true" ]; then
            echo "dbus is running"
        else
            echo "dbus is not running"
            exit 1
        fi
    fi
    reload_daemon
    start_ssh
fi
