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
# Description  : redhat os platform interface.
#############################################################################

import os

import platform
from gspylib.common.ErrorCode import ErrorCode
from os_platform.common import BIT_VERSION, EULEROS, SUPPORT_EULEROS_VERSION_LIST, \
    FUSIONOS, SUPPORT_RHEL_SERIES_PLATFORM_LIST, \
    SUPPORT_RHEL_SERIES_VERSION_LIST, OPENEULER, CENTOS, \
    SUPPORT_RHEL7X_VERSION_LIST, DEBIAN, BLANK_SPACE
from os_platform.linux_distro import LinuxDistro
from os_platform.linux_platform import LinuxPlatform


class RHELPlatform(LinuxPlatform):
    """
    manage Red Hat Enterprise Linux command,config or service for muti-platform
    """
    def __init__(self):
        """
        function: constructor
        """
        pass

    def getNetWorkConfPath(self):
        return "/etc/sysconfig/network-scripts/"

    def isSupportSystemctl(self):
        """
        function: isSupportSystemctl
        input:  NA
        output: bool
        """
        dist_name, version, _ = LinuxDistro.linux_distribution()
        if ((dist_name.lower() == EULEROS and version[0:3] in
             SUPPORT_EULEROS_VERSION_LIST) or
                (dist_name.lower() in SUPPORT_RHEL_SERIES_PLATFORM_LIST and
                 version[0:3] in SUPPORT_RHEL7X_VERSION_LIST) or
                (dist_name.lower() == CENTOS and version[0:3] ==
                 SUPPORT_EULEROS_VERSION_LIST and
                 os.path.isfile(os.path.join("/etc", "euleros-release"))) or
                (dist_name.lower() == OPENEULER) or
                (dist_name.lower() == FUSIONOS)
            ):
            return True
        return False

    def isPlatFormEulerOSOrRHEL7X(self):
        """
        function: check is PlatForm EulerOS Or RHEL7X
        """
        return self.isSupportSystemctl()

    def getManageFirewallCmd(self, action):
        """
        function: get manage firewall cmd
        input  : action
        output : str
        """
        if self.isSupportSystemctl():
            return self.getSystemctlCmd("firewalld.service", action)
        return self.getServiceCmd("iptables", action)

    def getManageCrondCmd(self, action):
        """
        function: get crond.server cmd
        input  : action
        output : str
        """
        # get system information
        distname, version = LinuxDistro.linux_distribution()[0:2]
        if self.isSupportSystemctl():
            return self.getSystemctlCmd("crond.service", action)
        elif distname == "debian" and version == "buster/sid":
            return self.getServiceCmd("cron", action)
        return self.getServiceCmd("crond", action)

    def getManageSshdCmd(self, action):
        """
        function: get sshd.server cmd
        input  : action
        output : str
        """
        if self.isSupportSystemctl():
            return self.getSystemctlCmd("sshd.service", action)
        return self.getServiceCmd("sshd", action)

    def getManageGsOsServerCmd(self, action):
        """
        function: get gs-OS-set.service cmd
        input  : action
        output : str
        """
        if self.isSupportSystemctl():
            return self.getSystemctlCmd("gs-OS-set.service", action)
        return self.getServiceCmd("gs-OS-set", action)

    def getManageSyslogCmd(self, action):
        """
        function: get syslog service cmd
        """
        try:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53021"]
                            % ("Syslog service", "SuSE"))
        except Exception as excep:
            raise Exception(str(excep))

    def getManageRsyslogCmd(self, action):
        """
        function: get syslog cmd
        """
        try:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53021"]
                            % ("Rsyslog service", "SuSE"))
        except Exception as excep:
            raise Exception(str(excep))

    def getManageSystemdJournaldCmd(self, action):
        """
        function: get systemd journal cmd
        """
        try:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53021"]
                            % ("systemd-journald", "SuSE"))
        except Exception as e:
            raise Exception(str(e))
    
    def getBlockdevCmd(self, device, value="", isSet=False):
        """
        function: get block dev cmd
        input  :  device, value, isSet
        output : str
        """
        if isSet and value != "":
            return self.findCmdInPath('blockdev') + " --setra " + value + \
                   BLANK_SPACE + device
        else:
            return self.findCmdInPath('blockdev') + " --getra " + device

    def getCurrentPlatForm(self):
        """
        function: get current platform
        """
        try:
            dist_name, version, current_id = LinuxDistro.linux_distribution()
            bits = platform.architecture()[0]

            if ((bits == BIT_VERSION and
                 ((dist_name.lower() == EULEROS and version[0:3] in
                   SUPPORT_EULEROS_VERSION_LIST) or
                  (dist_name.lower() in SUPPORT_RHEL_SERIES_PLATFORM_LIST and
                   version[0:3] in SUPPORT_RHEL_SERIES_VERSION_LIST)) or
                 (dist_name.lower() == OPENEULER) or
                 (dist_name.lower() == FUSIONOS) or
                 (dist_name.lower() == DEBIAN and version == "buster/sid")
            )):
                return dist_name.lower(), version[0:3]
            else:
                if dist_name.lower() == CENTOS and os.path.isfile(
                        os.path.join("/etc", "euleros-release")) and \
                        (version[0:3] in SUPPORT_EULEROS_VERSION_LIST):
                    return EULEROS, version[0:3]
                if dist_name.lower() == EULEROS:
                    raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                                    " The current system is: %s%s%s" % (
                                        dist_name.lower(),
                                        version[0:3], current_id))
                if dist_name.lower() == DEBIAN:
                    raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                                    " The current system is: %s/%s" % (
                                        dist_name.lower(), version))
                else:
                    raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                                    " The current system is: %s%s" % (
                                        dist_name.lower(), version[0:3]))
        except Exception as e:
            raise Exception(str(e))
