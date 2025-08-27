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
import platform
import subprocess
from gspylib.inspection.common import SharedFuncs
from gspylib.inspection.common.CheckItem import BaseItem
from gspylib.inspection.common.CheckResult import ResultStatus
from os_platform.gsservice import g_service
from os_platform.UserPlatform import g_Platform
from base_utils.os.cmd_util import CmdUtil

EXPECTED_VALUE = "disabled"
SUSE_FLAG = "SuSEfirewall2 not active"
REDHAT6_FLAG = "Firewall is not running"
REDHAT7_FLAG = "Active: inactive (dead)"


class CheckFirewall(BaseItem):
    def __init__(self):
        super(CheckFirewall, self).__init__(self.__class__.__name__)

    def doCheck(self):
        (status, output) = g_service.manageOSService("firewall", "status")
        firewallStatus = "disabled" if (
                output.find(SUSE_FLAG) > 0 or
                output.find(REDHAT6_FLAG) > 0 or
                output.find(REDHAT7_FLAG) > 0
        ) else "enabled"

        self.result.raw = output
        self.result.val = firewallStatus

        if firewallStatus == EXPECTED_VALUE:
            self.result.rst = ResultStatus.OK
        else:
            self.result.rst = ResultStatus.NG if firewallStatus else ResultStatus.OK

    def doSet(self):
        if g_Platform.isPlatFormEulerOSOrRHEL7X():
            cmd_list = ['systemctl', 'stop', 'firewalld.service']
        elif SharedFuncs.isSupportSystemOs():
            cmd_list = ['service', 'iptables', 'stop']
        else:
            cmd_list = ['SuSEfirewall2', 'stop']

        (output, error, status) = CmdUtil.execCmdList(cmd_list)
        if status:
            self.result.val = "Failed to stop firewall service. Error: %s\n" \
                              % output + "The cmd is %s " % (cmd_list)
        else:
            self.result.val = "Successfully stopped the firewall service.\n"
