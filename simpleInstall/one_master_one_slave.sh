#!/bin/bash

if [ `id -u` -ne 0 ];then
    echo "only a user with the root permission can run this script."
    exit 1
fi

declare -r SCRIPT_PATH=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
declare -r SCRIPT_NAME=$0
echo "SCRIPT_PATH : ${SCRIPT_PATH}"
declare PACKAGE_PATH=`dirname ${SCRIPT_PATH}`
declare USER_NAME=""
declare HOST_IPS=""
declare HOST_IPS_ARR=""
declare HOST_IPS_ARRAY=""
declare HOST_NAMES=""
declare HOST_NAMES_ARRAY=
declare USER_GROUP="dbgrp"
declare PORT="20050"
declare XML_DIR=${SCRIPT_PATH}/one_master_one_slave_template.xml
declare INSTALL_PATH=""
declare SYSTEM_ARCH=""
declare SYSTEM_NAME=""
declare PASSWORD=""

function print_help()
{
    echo "Usage: $0 [OPTION]
    -?|--help                         show help information
    -U|--user_name                    cluster user
    -H|--host_ip                      intranet ip address of the host in the backend storage network(host1,host2)
    -G|--user_grp                     group of the cluster user(default value dbgrp)
    -p|--port                         database server port(default value 20050)
    -D|--install_location             installation directory of the openGauss program(default value ~/cluser)
    -X|--xml_location                 cluster xml configuration file path
    "
}

function die()
{
    echo -e "\033[31merror:\033[0m $1"
    exit 1
}

function warn()
{
    echo -e "\033[33mwarnning:\033[0m $1"
    sleep 2s
}

function info()
{
    echo -e "\033[32minfo:\033[0m $1"
}

# 安全地构建 shell 命令字符串
# 使用数组和 printf %q 确保所有参数都被正确转义
build_safe_command() {
    local cmd=("$@")
    local result=""
    local first=true
    for arg in "${cmd[@]}"; do
        if $first; then
            first=false
        else
            result+=" "
        fi
        result+=$(printf "%q" "$arg")
    done
    echo "$result"
}

function expect_ssh()
{
        # 用环境变量方式传递密码，避免转义问题
        export EXPECT_PASS="$2"
        export EXPECT_CMD="$1"
        export EXPECT_EXPECTED="$3"
        
        /usr/bin/expect <<-'EOF'
        set timeout -1
        set pass $env(EXPECT_PASS)
        set cmd $env(EXPECT_CMD)
        set expected_str $env(EXPECT_EXPECTED)
        eval spawn $cmd
        expect {
                "*yes/no" { send "yes\r"; exp_continue }
                -nocase "*The password is incorrect*" { exit 1 }
                -nocase "*The password can only contain*" { exit 1 }
                -nocase "*assword:" { send "$pass\r"; exp_continue }
                -nocase "*password*" { send "$pass\r"; exp_continue }
                -nocase "*Please enter password*" { send "$pass\r"; exp_continue }
                -nocase "*Notice*" { exp_continue }
                -glob "*$expected_str*" { }
                eof { }
        }
EOF
        local ret=$?
        unset EXPECT_PASS EXPECT_CMD EXPECT_EXPECTED
        return $ret
}

function expect_hostname()
{
        export EXPECT_PASS="$2"
        export EXPECT_CMD="$1"
        
        expect <<-'EOF' > expectFile
        set timeout -1
        set pass $env(EXPECT_PASS)
        set cmd $env(EXPECT_CMD)
        eval spawn $cmd
        expect {
                "*yes/no" { send "yes\r"; exp_continue }
                -nocase "*assword:" { send "$pass\r"; exp_continue }
                -nocase "*password*" { send "$pass\r"; exp_continue }
                eof { }
        }
EOF
        local ret=$?
        unset EXPECT_PASS EXPECT_CMD
        return $ret
}


# Verify legal username: letters, numbers, underscores only
# Length: 1-32 characters, cannot start with a number
validate_username() {
    local username=$1
    if [[ ! $username =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,31}$ ]]; then
        die "Invalid username: only letters, numbers and underscores are allowed, length 1-32, cannot start with a number"
    fi
}

# Verify legal user group name (same rules as username)
validate_groupname() {
    local groupname=$1
    if [[ ! $groupname =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,31}$ ]]; then
        die "Invalid group name: only letters, numbers and underscores are allowed, length 1-32, cannot start with a number"
    fi
}

# Verify valid IPv4 addresses
# Support two comma-separated IPs for one-master-one-slave cluster
validate_host_ips() {
    local ips=$1
    local ip_arr=(${ips//,/ })
    # Strictly check only two nodes are supported
    if [ ${#ip_arr[@]} -ne 2 ]; then
        die "Invalid host count: this script only supports 2-node deployment (one master, one slave)"
    fi
    # Verify each IPv4 address format
    for ip in "${ip_arr[@]}"; do
        if [[ ! $ip =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
            die "Invalid IPv4 address format: ${ip}"
        fi
    done
}

# Verify valid port range
# Valid port: 1024-65535, numeric only
validate_port() {
    local port=$1
    if [[ ! $port =~ ^[0-9]+$ ]] || [ $port -lt 1024 ] || [ $port -gt 65535 ]; then
        die "Invalid port: must be a number between 1024 and 65535"
    fi
}

# Verify valid installation path
# Absolute path only, no special injection characters
validate_install_path() {
    local path=$1
    # Check it's an absolute path and doesn't have double slashes
    if [[ ! $path = /* || $path == *//* ]]; then
        die "Invalid installation path: absolute path only, no special/suspicious characters"
    fi
    # Check for forbidden characters
    if [[ $path == *';'* || $path == *'&'* || $path == *'|'* || $path == *'`'* || $path == *'$'* || $path == *'('* || $path == *')'* || $path == *'['* || $path == *']'* || $path == *'{'* || $path == *'}'* ]]; then
        die "Invalid installation path: absolute path only, no special/suspicious characters"
    fi
}

# Verify password complexity and security (暂时禁用)
validate_password() {
    local pwd=$1
    # 暂时跳过所有密码校验，直接通过
    return 0
}

# Verify XML template file path
# Ensure file exists and no suspicious characters
validate_xml_path() {
    local xml=$1
    if [[ ! -f $xml ]]; then
        die "Invalid XML path: file not exists or contains suspicious characters"
    fi
    # Check for forbidden characters
    if [[ $xml == *';'* || $xml == *'&'* || $xml == *'|'* || $xml == *'`'* || $xml == *'$'* || $xml == *'('* || $xml == *')'* || $xml == *'['* || $xml == *']'* || $xml == *'{'* || $xml == *'}'* ]]; then
        die "Invalid XML path: file not exists or contains suspicious characters"
    fi
}



function main()
{
    while [ $# -gt 0 ]
    do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -U|--user_name)
            if [ "$2"X = X ]
            then
                die "no cluster user values"
            fi
            USER_NAME=$2
            shift 2
            ;;
        -G|--user_grp)
            if [ "$2"X = X ]
            then
                die "no group values"
            fi
            USER_GROUP=$2
            shift 2
            ;;
        -H|--host_ip)
            if [ "$2"X = X ]
            then
                die "no intranet ip address of the host values"
            fi
            HOST_IPS=$2
            shift 2
            HOST_IPS_ARR=${HOST_IPS//,/ }
            HOST_IPS_ARRAY=(${HOST_IPS_ARR})
            if [ ${#HOST_IPS_ARRAY[*]} != 2 ]
            then
                die "the current script can be installed only on two nodes, one active node and one standby node"
            fi
            ;;
        -X|--xml_location)
            if [ "$2"X = X ]
            then
                die "no cluster xml configuration file values"
            fi
            XML_DIR=$2
            shift 2
            ;;
        -D|--install_location)
            if [ "$2"X = X ]
            then
                die "no installation directory of the openGauss program values"
            fi
            INSTALL_PATH=$2
            shift 2
            ;;
        -p|--port)
            if [ "$2"X = X ]
            then
                die "the port number cannot be empty."
            fi
            PORT=$2
            shift 2
            ;;
        -P|--password)
            if [ "$2"X = X ]
            then
                die "the password cannot be empty."
            fi
            PASSWORD="$2"
            shift 2
            ;;
         *)
            echo "Internal Error: option processing error" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "sh active_standby_nodes_install.sh --help or sh active_standby_nodes_install.sh -h"
            exit 1
    esac
    done

    if [ "${USER_NAME}"X == X ]
    then
        die "no cluster user values"
    fi

    if [ -z ${INSTALL_PATH} ]
    then
        INSTALL_PATH="/home/${USER_NAME}"
    fi

    if [ "${PASSWORD}"X == X ]
    then
        echo "please enter the password of the root user&the password of a common user(the two passwords must be the same)"
        echo -n "password:"
        read PASSWORD
        while [ -z ${PASSWORD} ]
        do
            echo "the value cannot be null, please enter the password again"
            echo -n "password:"
            read PASSWORD
        done
    fi

    if [ "${HOST_IPS}"X == X ]
    then
        die "no intranet ip address values"
    else
        len=${#HOST_IPS_ARRAY[*]}
        index=0
        while [ ${index} -lt ${len} ]
        do
            expect_hostname "ssh ${HOST_IPS_ARRAY[${index}]} hostname" ${PASSWORD}
            if [ $? == 0 ]
            then
                expectResult=$(tail -1 expectFile|head -1| tr -d "\r"| tr -d "\n")
                if [ -z ${expectResult} ]
                then
                    die "failed to obtain the hostname based on the ip address of ${HOST_IPS_ARRAY[${index}]}."
                fi
                HOST_NAMES_ARRAY[${index}]=${expectResult}
            else
                die "failed to obtain the hostname based on the ip address of ${HOST_IPS_ARRAY[${index}]}."
            fi
            index=$[ ${index} + 1 ]
        done
    fi
    rm -rf expectFile
    HOST_NAMES="${HOST_NAMES_ARRAY[0]},${HOST_NAMES_ARRAY[1]}"
    SYSTEM_ARCH=`uname -p`
    SYSTEM_NAME=`cat /etc/*-release | grep '^ID=".*'|awk -F "[=\"]" '{print $3}'`
    if [ "${SYSTEM_NAME}" == "openEuler" ] && [ "${SYSTEM_ARCH}" == "aarch64" ]
    then
        info "the current system environment is openEuler + arm"
    elif [ "${SYSTEM_NAME}" == "openEuler" ] && [ "${SYSTEM_ARCH}" == "x86_64" ]
    then
        info "the current system environment is openEuler + x86"
    elif [ "${SYSTEM_NAME}" == "centos" ] && [ "${SYSTEM_ARCH}" == "x86_64" ]
    then
        info "the current system environment is CentOS + x86"
    elif [ "${SYSTEM_NAME}" == "redhat" ] && [ "${SYSTEM_ARCH}" == "x86_64" ]
    then
        info "the current system environment is redhat + x86"
    elif [ "${SYSTEM_NAME}" == "redhat" ] && [ "${SYSTEM_ARCH}" == "aarch64" ]
    then
        info "the current system environment is redhat + arm"
    elif [ "${SYSTEM_NAME}" == "kylin" ] && [ "${SYSTEM_ARCH}" == "x86_64" ]
    then
        info "the current system environment is kylin + x86"
    elif [ "${SYSTEM_NAME}" == "kylin" ] && [ "${SYSTEM_ARCH}" == "aarch64" ]
    then
        info "the current system environment is kylin + arm"
    else
        warn "the current system environment is ${SYSTEM_NAME} + ${SYSTEM_ARCH}, \
 you are advised to use the centos, openEuler, redhat, or kylin system. because OpenGauss may not adapt to the current system."
    fi

     validate_username "${USER_NAME}"
     validate_groupname "${USER_GROUP}"
     validate_host_ips "${HOST_IPS}"
     validate_port "${PORT}"
     validate_install_path "${INSTALL_PATH}"
     validate_password "${PASSWORD}"
     validate_xml_path "${XML_DIR}"

    info "installation parameter verification completed."
}

function checks()
{
    system_arch=`uname -p`
    system_name=`cat /etc/*-release | grep '^ID=".*'|awk -F "[=\"]" '{print $3}'`
    if [ ${system_arch} != "$8" -o ${system_name} != "$9" ]
    then
        warn "inconsistency between the system and the execution machine"
    fi

    egrep "^$3" /etc/group >& /dev/null
    if [ $? != 0 ];then
        groupadd $3
    fi
    egrep "^$4" /etc/passwd >& /dev/null
    if [ $? != 0 ];then
        useradd -g $3 -d /home/$4 -m -s /bin/bash $4 2>/dev/null
        if [ $? != 0 ]
        then
            die "failed to create the user on the node $2."
        fi
        expect_ssh "passwd $4" "$5" "passwd:"
        if [ $? != 0 ]
        then
            die "an error occurred when setting the user password on the node $2"
        fi
    fi

    sed -i "s/SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config && firewall-cmd --permanent --add-port="$6/tcp" && firewall-cmd --reload
    if [ $? != 0 ]
    then
        warn "some errors occur during system environment setting on host $2"
    fi

    umask 0022
    INSTALL_PATH=$7
    if [ ! -e ${INSTALL_PATH} ]
    then
        mkdir -p ${INSTALL_PATH}
    else
        rm -rf ${INSTALL_PATH}/*
    fi
    chmod -R 755 ${INSTALL_PATH}/
    chown -R $4:$3 ${INSTALL_PATH}/
    if [ -f /${10} ]
    then
        mv /${10} $(eval echo ~$4)/
    fi
    echo "check end"
}

function pre_checks()
{
    if [ ${#HOST_IPS_ARRAY[*]} == 0 ]
    then
        die "the number of internal IP addresses of the host is incorrect."
    fi
    localips=$(/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:")
    for ip in ${HOST_IPS_ARRAY[@]}
    do
        info "start to check the installation environment of host ${ip}."
        sleep 2s
        # standby node
        if [[ $localips != *${ip}* ]]
        then
            sshcmd="scp ${SCRIPT_PATH}/${SCRIPT_NAME} root@${ip}:/"
            expect_ssh "${sshcmd}" "${PASSWORD}" "100%"
            if [ $? != 0 ]
            then
                die "an error occurred when copying the script to the target host ${ip}."
            fi
            # 使用数组和 printf %q 安全构建远程命令
            # 将所有参数放入数组，然后用 printf %q 统一转义，避免引号嵌套问题
            local -a remote_cmd_args=(
                "sh" "/${SCRIPT_NAME}" "inner" "${ip}"
                "${USER_GROUP}" "${USER_NAME}" "${PASSWORD}"
                "${PORT}" "${INSTALL_PATH}" "${SYSTEM_ARCH}"
                "${SYSTEM_NAME}" "${SCRIPT_NAME}"
            )
            local remote_cmd=$(build_safe_command "${remote_cmd_args[@]}")
            # 使用双引号确保远程命令作为一个整体传递给 SSH
            sshcmd="ssh ${ip} ${remote_cmd}"
            expect_ssh "${sshcmd}" "${PASSWORD}" "check end"
            if [ $? != 0 ]
            then
                die "an error occurred during the pre-installation check on the target host ${ip}."
            fi
        else
            # local
            checks "" ${ip} ${USER_GROUP} ${USER_NAME} "${PASSWORD}" ${PORT} "${INSTALL_PATH}" ${SYSTEM_ARCH} ${SYSTEM_NAME} ${SCRIPT_NAME}
            if [ $? != 0 ]
            then
                die "an error occurred during the pre-installation check on the target host ${ip}."
            fi
        fi
        info "succeeded in checking the installation environment of host ${ip}."
    done
    return 0
}

function xmlconfig()
{
    info "start to automatically configure the installation file."
    # 使用 awk 替代 sed，避免特殊字符问题
    local tmp_xml=$(mktemp)
    if [ -e ${XML_DIR} ]
    then
        # 使用 awk 进行安全替换
        awk -v nodeNames="${HOST_NAMES}" \
            -v backIpls="${HOST_IPS}" \
            -v clusterName="${USER_NAME}" \
            -v port="${PORT}" \
            -v installPath="${INSTALL_PATH}" \
            -v nodeName1="${HOST_NAMES_ARRAY[0]}" \
            -v backIp1="${HOST_IPS_ARRAY[0]}" \
            -v nodeName2="${HOST_NAMES_ARRAY[1]}" \
            -v backIp2="${HOST_IPS_ARRAY[1]}" \
            '{
                gsub(/@{nodeNames}/, nodeNames);
                gsub(/@{backIpls}/, backIpls);
                gsub(/@{clusterName}/, clusterName);
                gsub(/@{port}/, port);
                gsub(/@{installPath}/, installPath);
                gsub(/@{nodeName1}/, nodeName1);
                gsub(/@{backIp1}/, backIp1);
                gsub(/@{nodeName2}/, nodeName2);
                gsub(/@{backIp2}/, backIp2);
                print;
            }' "${XML_DIR}" > "$tmp_xml" && mv "$tmp_xml" "$(eval echo ~${USER_NAME})/one_master_one_slave.xml"
    else
        die "cannot find one_master_one_slave_template.xml in ${XML_DIR}"
    fi
    cat $(eval echo ~${USER_NAME})/one_master_one_slave.xml
    info "the installation file is automatically configured"
    return 0
}

function install()
{
    info "preparing for preinstallation"
    home_path=$(eval echo ~${USER_NAME})
    export LD_LIBRARY_PATH="${PACKAGE_PATH}/script/gspylib/clib:"$LD_LIBRARY_PATH
    sshcmd="python3 "${PACKAGE_PATH}"/script/gs_preinstall -U "${USER_NAME}" \
 -G "${USER_GROUP}" -X "${home_path}"/one_master_one_slave.xml --sep-env-file="${home_path}"/env_master_slave"
    info "cmd \"${sshcmd}\""
    expect_ssh "${sshcmd}" "${PASSWORD}" "Preinstallation succeeded"
    if [ $? != 0 ]
    then
        die "preinstall failed."
    fi
    info "preinstallation succeeded."
    chmod 755 ${home_path}'/one_master_one_slave.xml'
    chown ${USER_NAME}:${USER_GROUP} ${home_path}'/one_master_one_slave.xml'
    info "start the installation."
    su - ${USER_NAME} -c"source ${home_path}/env_master_slave;gs_install -X ${home_path}/one_master_one_slave.xml;gs_om -t status --detail"
    if [ $? -ne 0 ]
    then
        die "install failed."
    else
        info "install success."
    fi
    exit 0
}

if [ "$1" == "inner" ]
then
    # 在 inner 模式下，确保所有参数都正确传递
    checks "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"
else
    main "$@"
    pre_checks
    xmlconfig
    install
fi
exit 0
