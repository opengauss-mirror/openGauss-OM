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

function expect_ssh()
{
        /usr/bin/expect <<-EOF
        set timeout -1
        spawn $1
        expect {
                "*yes/no" { send "yes\r"; exp_continue }
                "*assword:" { send "$2\r"; exp_continue }
                "*$3*" { exit }
        }
        expect eof
EOF
        if [ $? == 0 ]
        then
            return 0
        else
            return 1
        fi
}

function expect_hostname()
{
        expect <<EOF  > expectFile
        set timeout -1
        spawn $1
        expect {
                "*yes/no" { send "yes\r"; exp_continue }
                "*assword:" {send "$2\r"; exp_continue}
        }
EOF
        if [ $? == 0 ]
        then
            return 0
        else
            return 1
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
            PASSWORD=$2
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
                expectResult=`tail -1 expectFile|head -1| tr -d "\r"| tr -d "\n"`
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
    localips=`/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
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
            sshcmd="ssh ${ip} \"sh /${SCRIPT_NAME} inner ${ip} ${USER_GROUP} ${USER_NAME} ${PASSWORD} ${PORT} ${INSTALL_PATH} ${SYSTEM_ARCH} ${SYSTEM_NAME} ${SCRIPT_NAME}\""
            expect_ssh "${sshcmd}" "${PASSWORD}" "check end"
            if [ $? != 0 ]
            then
                die "an error occurred during the pre-installation check on the target host ${ip}."
            fi
        else
            # local
            checks "" ${ip} ${USER_GROUP} ${USER_NAME} ${PASSWORD} ${PORT} ${INSTALL_PATH} ${SYSTEM_ARCH} ${SYSTEM_NAME} ${SCRIPT_NAME}
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
    install_localtion=${INSTALL_PATH//\//\\\/}
    if [ -e ${XML_DIR} ]
    then
        sed 's/@{nodeNames}/'${HOST_NAMES}'/g' ${XML_DIR} |
        sed 's/@{backIpls}/'${HOST_IPS}'/g' |
        sed 's/@{clusterName}/'${USER_NAME}'/g' |
        sed 's/@{port}/'${PORT}'/g' |
        sed 's/@{installPath}/'${install_localtion}'/g' |
        sed 's/@{nodeName1}/'${HOST_NAMES_ARRAY[0]}'/g' |
        sed 's/@{backIp1}/'${HOST_IPS_ARRAY[0]}'/g' |
        sed 's/@{nodeName2}/'${HOST_NAMES_ARRAY[1]}'/g' |
        sed 's/@{backIp2}/'${HOST_IPS_ARRAY[1]}'/g' > $(eval echo ~${USER_NAME})/one_master_one_slave.xml
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

if [ $1 == "inner" ]
then
    checks $@
else
    main $@
    pre_checks
    xmlconfig
    install
fi
exit 0

