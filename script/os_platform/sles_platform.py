# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2020 Huawei Technologies Co.,Ltd.
# Portions Copyright (c) 2007 Agendaless Consulting and Contributors.
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
# Description  : suse os platform interface.
#############################################################################

import os
import subprocess

import platform
from gspylib.common.ErrorCode import ErrorCode
from os_platform.common import SUPPORT_RHEL12X_VERSION_LIST, \
    SUPPORT_SUSE11X_VERSION_LIST, SUSE12, SUSE11, BIT_VERSION, \
    SUPPORT_SUSE_VERSION_LIST, SUSE, BLANK_SPACE
from os_platform.linux_distro import LinuxDistro
from os_platform.linux_platform import LinuxPlatform


class SLESPlatform(LinuxPlatform):
    """
    manage SUSE Linux Enterprise Server command,
    config or service for muti-platform
    """

    def __init__(self):
        self.SuSEReleaseFile = "/etc/SuSE-release"
        self.OSReleaseFile = "/etc/SuSE-release"

    def getNetWorkConfPath(self):
        """get network config file path"""
        return "/etc/sysconfig/network/"

    def isPlatFormEulerOSOrRHEL7X(self):
        """
        function: the patform is euleros or rhel7x
        input  : NA
        output : bool
        """
        return False

    def getManageFirewallCmd(self, action):
        """
        function: get manage firewall cmd
        input  : action
        output : str
        """
        return self.findCmdInPath('SuSEfirewall2') + BLANK_SPACE + action

    def getManageCrondCmd(self, action):
        """
        function: get manage crond cmd
        input  : action
        output : str
        """
        return self.getServiceCmd("cron", action)

    def getManageSshdCmd(self, action):
        """
        function: get manage sshd cmd
        input  : action
        output : str
        """
        return self.getServiceCmd("sshd", action)

    def getManageSyslogCmd(self, action):
        """
        function: get manage syslog cmd
        input  : action
        output : str
        """
        return self.getServiceCmd("syslog", action)

    def getManageRsyslogCmd(self, action):
        """
        function: get manage rsyslog cmd
        input  : action
        output : str
        """
        return self.getServiceCmd("rsyslog", action)

    def getManageSystemdJournaldCmd(self, action):
        """
        function: get systemd-jorunald cmd
        input  : action
        output : str
        """
        return self.getServiceCmd("systemd-journald", action)

    def getManageGsOsServerCmd(self, action):
        """
        function: get rhel/centos cmd
        input  : action
        output : NA
        """
        try:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53021"]
                            % ("gs-OS-set service", "RHEL/CentOS"))
        except Exception as e:
            raise Exception(str(e))

    def getCurrentPlatForm(self):
        """
        function: get current platform
        input:  NA
        output: str, str
        """
        try:
            dist_name, version, _ = LinuxDistro.linux_distribution()
            bits = platform.architecture()[0]
            if (dist_name.lower() != SUSE or
                    version not in SUPPORT_SUSE_VERSION_LIST):
                raise Exception(ErrorCode.GAUSS_530["GAUSS_53022"]
                                % (dist_name.lower(), version))

            # os-release is added since SLE 12; SuSE-release will
            # be removed in a future service pack or release
            if os.path.exists(self.SuSEReleaseFile):
                cmd = "%s -i 'PATCHLEVEL' %s  | " \
                      "%s -F '=' '{print $2}'" % (self.getGrepCmd(),
                                                  self.SuSEReleaseFile,
                                                  self.getAwkCmd())
            else:
                cmd = "%s -i 'VERSION_ID' %s  | " \
                      "%s -F '.' '{print $2}' | %s 's/\"//'" % (
                          self.getGrepCmd(), self.OSReleaseFile,
                          self.getAwkCmd(), self.getSedCmd())
            (status, output) = subprocess.getstatusoutput(cmd)
            if status == 0 and output != "":
                patchlevel = output.strip()
            else:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)

            if (bits == BIT_VERSION and
                    ((version == SUSE11 and
                      patchlevel in SUPPORT_SUSE11X_VERSION_LIST) or
                     (version == SUSE12 and
                      patchlevel in SUPPORT_RHEL12X_VERSION_LIST))):
                platform_version = "%s.%s" % (version, patchlevel)
                return dist_name.lower(), platform_version
            else:
                raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                                " The current system is: %s%s.%s" % (
                                    dist_name.lower(), version, patchlevel))
        except Exception as e:
            raise Exception(str(e))
