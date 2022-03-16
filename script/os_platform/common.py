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
# Description  : global variable for our platform.
#############################################################################

# ---------------platforms--------------------
# global variable for our platform
SUSE = "suse"
REDHAT = "redhat"
CENTOS = "centos"
EULEROS = "euleros"
KYLIN = "kylin"
OPENEULER = "openeuler"
ASIANUX = "asianux"
DEBIAN = "debian"
UBUNTU = "ubuntu"
SUPPORT_WHOLE_PLATFORM_LIST = [SUSE, REDHAT, CENTOS, EULEROS, OPENEULER, KYLIN,
                               ASIANUX, DEBIAN, UBUNTU]
# RedhatX platform
SUPPORT_RHEL_SERIES_PLATFORM_LIST = [REDHAT, CENTOS, "kylin", "asianux"]
SUPPORT_RHEL6X_VERSION_LIST = ["6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "10"]
SUPPORT_RHEL7X_VERSION_LIST = ["7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "10"]
SUPPORT_RHEL_SERIES_VERSION_LIST = (SUPPORT_RHEL6X_VERSION_LIST + SUPPORT_RHEL7X_VERSION_LIST)
# EulerOS 2.3 -> 2.0 SP3
SUPPORT_EULEROS_VERSION_LIST = ["2.0"]
# SuSE platform
SUSE11 = "11"
SUSE12 = "12"
SUPPORT_SUSE_VERSION_LIST = [SUSE11, SUSE12]
SUPPORT_SUSE11X_VERSION_LIST = ["1", "2", "3", "4"]
SUPPORT_RHEL12X_VERSION_LIST = ["0", "1", "2", "3"]
BIT_VERSION = "64bit"

# ---------------command path--------------------
CMD_PATH = ['/bin', '/usr/local/bin', '/usr/bin', '/sbin', '/usr/sbin']
CMD_CACHE = {}
BLANK_SPACE = " "
COLON = ":"
# Need to be consistent with the packaging script
PAK_CENTOS = "CentOS"
PAK_EULER = "Euler"
PAK_OPENEULER = "openEuler"
PAK_REDHAT = "RedHat"
PAK_ASIANUX = "asianux"
PAK_UBUNTU = "Ubuntu"

#######################################################
_supported_dists = (
    'SuSE', 'debian', 'fedora', 'redhat', 'centos', 'euleros', "openEuler",
    'mandrake', 'mandriva', 'rocks', 'slackware', 'yellowdog', 'gentoo',
    'UnitedLinux', 'turbolinux',  'ubuntu')
