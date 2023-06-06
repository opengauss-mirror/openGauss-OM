# -*- coding:utf-8 -*-
#############################################################################
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
#############################################################################

import os

from base_utils.common.constantsbase import ConstantsBase
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.file_util import FileUtil
from os_platform.gsservice import g_service
from os_platform.linux_distro import LinuxDistro


class OsFile:
    """
    operation with os file
    """
    @staticmethod
    def getOSInitFile():
        """
        function : Get the OS initialization file
        input : NA
        output : String
        """
        distname, _, _ = LinuxDistro.linux_distribution()
        system_dir = "/usr/lib/systemd/system/"
        system_file = "/usr/lib/systemd/system/gs-OS-set.service"
        # OS init file
        #     now we only support SuSE and RHEL/CentOS
        init_file_suse = "/etc/init.d/boot.local"
        init_file_kylin = "/etc/rc.local"
        init_file_redhat = "/etc/rc.d/rc.local"
        # system init file
        init_system_file = "/usr/local/gauss/script/gauss-OS-set.sh"
        init_system_path = "/usr/local/gauss/script"
        dir_name = os.path.dirname(os.path.realpath(__file__))

        #Get the startup file of suse or redhat os
        if os.path.isdir(system_dir):
            # Judge if cgroup para 'Delegate=yes' is written in systemFile
            cgroup_gate = False
            cgroup_gate_para = "Delegate=yes"
            if os.path.exists(system_file):
                with open(system_file, 'r') as fp:
                    ret_value = fp.readlines()
                for line in ret_value:
                    if line.strip() == cgroup_gate_para:
                        cgroup_gate = True
                        break

            if not os.path.exists(system_file) or not cgroup_gate:
                src_file = "%s/../../gspylib/etc/conf/gs-OS-set.service" % dir_name
                FileUtil.cpFile(src_file, system_file)
                FileUtil.changeMode(ConstantsBase.KEY_FILE_MODE, system_file)
                # only support RHEL/Centos/Euler
                if distname != "SuSE":
                    # enable gs-OS-set.service
                    (status, output) = g_service.manageOSService("gs-OS-set", "enable")
                    if status != 0:
                        raise Exception(ErrorCode.GAUSS_508["GAUSS_50802"] % "enable gs-OS-set"
                                        + " Error: \n%s" % output)

            if not os.path.exists(init_system_path):
                FileUtil.createDirectory(init_system_path)
            if not os.path.exists(init_system_file):
                FileUtil.createFile(init_system_file, False)
                FileUtil.writeFile(init_system_file, ["#!/bin/bash"], "w")
            FileUtil.changeMode(ConstantsBase.KEY_DIRECTORY_MODE, init_system_file)
            return init_system_file
        if distname == "SuSE" and os.path.isfile(init_file_suse):
            init_file = init_file_suse
        elif distname in ("redhat", "centos", "euleros", "oracle", "openEuler", "FusionOS") \
                and os.path.isfile(init_file_redhat):
            init_file = init_file_redhat
        elif distname == "kylin" and os.path.isfile(init_file_kylin):
            init_file = init_file_kylin
        else:
            init_file = ""

        return init_file
