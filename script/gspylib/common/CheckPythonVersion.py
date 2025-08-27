#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
import sys
import sysconfig
import platform
import re
import os
import subprocess


from os_platform.linux_distro import LinuxDistro
from domain_utils.cluster_file.package_info import PackageInfo
from base_diff.comm_constants import CommConstants
from base_utils.os.cmd_util import CmdUtil


def check_python_version():
    python_version = sys.version_info[0:2]
    dist_name = platform.platform()
    if python_version < (3, 0):
        raise Exception("[GAUSS-52200] : version of python"
                        " is not correct: %s." %
                        dist_name + " should use Python 3.*")
    return True

def check_python_compiler_option():
    config_args = sysconfig.get_config_var("CONFIG_ARGS")
    if "--enable-shared" not in config_args:
        raise Exception("[GAUSS-52200] : When compiling python, \
            carry the -enable-shared parameters")
    return True

def check_os_and_package_arch():
    """
    check os and package arch
    """
    clib_path = os.path.realpath(
                os.path.join(os.path.realpath(__file__), "../../clib"))
    package_cmd = "cd " + clib_path + "&& file libstdc++.so.6 2>/dev/null"
    (status, output) = subprocess.getstatusoutput(package_cmd)
    if status != 0:
        raise Exception("%s command failed." % (package_cmd))
    package_arch = ""
    if ("x86-64" in output):
        package_arch = "x86_64"
    if ("aarch64" in output):
        package_arch = "aarch64"

    output, error, status = CmdUtil.execCmdList(['uname', '-m'])
    if status != 0:
        raise Exception("[uname -m] command failed.")
    os_arch = output
    
    if (package_arch == os_arch):
        return
    raise Exception("System and software package architecture mismatch.\n" +  
        "Error: os architecture is %s, package architecture is %s" % (os_arch, package_arch))

def check_package_name():
    """
    check package name
    """
    # if os is openeuler, check package name
    dist_name, version, _ = LinuxDistro.linux_distribution()
    if dist_name.lower() != "openeuler":
        return
    server_file = PackageInfo.getPackageFile(CommConstants.PKG_SERVER)
    server_file_name = os.path.basename(server_file)
    if version not in server_file_name:
        raise Exception("Error: package name is %s, the os version is %s" % (server_file_name, version))

if __name__ == '__main__':
    try:
        CHECK_PYTHON = check_python_version()
        if CHECK_PYTHON:
            check_python_compiler_option()
    except Exception as e:
        raise Exception(e)
