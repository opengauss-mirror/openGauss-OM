#!/bin/bash
# *************************************************************************
# Copyright: (c) Huawei Technologies Co., Ltd. 2020. All rights reserved
#
#  description: the script is to get platform string value
#  date: 2020-06-01
#  version: 1.0
#  history:
#
# *************************************************************************

function get_os_str() {
    if [ -f "/etc/os-release" ]; then
        os_name=$(source /etc/os-release; echo $ID)
    else
        echo "Can not get /etc/os-release file, please check it!"
        exit 1
    fi

    cpu_arc=$(uname -p)

    if [ "$os_name"x = "centos"x ] && [ "$cpu_arc"x = "x86_64"x ]; then
        os_str=centos7.6_x86_64
    elif [ "$os_name"x = "euleros"x ] && [ "$cpu_arc"x = "aarch64"x ]; then
        os_str=euleros2.0_sp8_aarch64
    elif [ "$os_name"x = "openEuler"x ] && [ "$cpu_arc"x = "aarch64"x ]; then
        os_str=openeuler_aarch64
    elif [ "$os_name"x = "openEuler"x ] && [ "$cpu_arc"x = "x86_64"x ]; then
        os_str=openeuler_x86_64
    elif [ "$os_name"x = "ubuntu"x ] && [ "$cpu_arc"x = "x86_64"x ]; then
        os_str=ubuntu18.04_x86_64
    elif [ "$os_name"x = "asianux"x ] && [ "$cpu_arc"x = "x86_64"x ]; then
        os_str=asianux7.6_x86_64
    elif [ "$os_name"x = "asianux"x ] && [ "$cpu_arc"x = "aarch64"x ]; then
        os_str=asianux7.5_aarch64
    else
        os_str="Failed"
    fi

    echo $os_str
}

get_os_str
