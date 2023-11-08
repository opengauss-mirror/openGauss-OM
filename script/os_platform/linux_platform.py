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
# Description  : os platform interface.
#############################################################################

import os

from gspylib.common.ErrorCode import ErrorCode
from os_platform.common import REDHAT, PAK_REDHAT, BIT_VERSION, \
    CENTOS, UOS, PAK_EULER, PAK_CENTOS, ASIANUX, SUSE, PAK_ASIANUX, \
    EULEROS, OPENEULER, KYLIN, PAK_OPENEULER, SUPPORT_WHOLE_PLATFORM_LIST,\
    BLANK_SPACE, PAK_UBUNTU, DEBIAN, PAK_KYLIN, PAK_UOS, PAK_SUSE, PAK_DEBIAN, \
    FUSIONOS, PAK_FUSIONOS
from os_platform.linux_distro import LinuxDistro


class LinuxPlatform(object):
    """
    manage Linux command,config or service for muti-platform
    """

    def __init__(self):
        """
        function: constructor
        """
        pass

    def getNetWorkConfPath(self):
        """get network config file path"""
        pass

    def isPlatFormEulerOSOrRHEL7X(self):
        """
        function: the patform is euleros or rhel7x
        input  : NA
        output : bool
        """
        pass

    def getManageFirewallCmd(self, action):
        """
        function: get manage firewall cmd
        input  : action
        output : str
        """
        pass

    def getManageCrondCmd(self, action):
        """
        function: get manage crond cmd
        input  : action
        output : str
        """
        pass

    def getManageSshdCmd(self, action):
        """
        function: get manage sshd cmd
        input  : action
        output : str
        """
        pass

    def getManageGsOsServerCmd(self, action):
        """get gs os server cmd"""
        pass

    def getManageSyslogCmd(self, action):
        """
        function: get manage syslog cmd
        input  : action
        output : str
        """
        pass

    def getManageRsyslogCmd(self, action):
        """
        function: get manage rsyslog cmd
        input  : action
        output : str
        """
        pass

    def getManageSystemdJournaldCmd(self, action):
        """
        function: get systemd-jorunald cmd
        input  : action
        output : str
        """
        pass

    def getCurrentPlatForm(self):
        """
        function: get rhel/centos cmd
        input  : action
        output : NA
        """
        pass

    
    def get_euler_package_name(self, dir_path, perfix, postfix):
        """
        Get package name of Euler OS
        """
        file_name = os.path.join(dir_path, "./../../../",
                                "%s-%s-%s" % (perfix, PAK_EULER, postfix))
        if not os.path.isfile(file_name):
            file_name = os.path.join(dir_path, "./../../../",
                                    "%s-%s-%s" % (perfix, PAK_CENTOS, postfix))

        return file_name

    def package_file_path(self, prefix_str, packageVersion, distro, postfix_str):
        dir_name = os.path.dirname(os.path.realpath(__file__))
        return os.path.join(dir_name, "./../../", "%s-%s-%s-%s.%s" % (
                                    prefix_str, packageVersion, distro,
                                    BIT_VERSION, postfix_str))


    def getPackageFile(self, packageVersion, productVersion, fileType="tarFile"):
        """
        function : Get the path of binary file version.
        input : packageVersion, productVersion, fileType
        output : String
        """
        distname, version, idnum = LinuxDistro.linux_distribution()
        distname = distname.lower()
        dir_name = os.path.dirname(os.path.realpath(__file__))
        prefix_str = productVersion
        if fileType == "tarFile":
            postfix_str = "tar.gz"
        elif fileType == "binFile":
            postfix_str = "bin"
        elif fileType == "sha256File":
            postfix_str = "sha256"
        elif fileType == "bz2File":
            postfix_str = "tar.bz2"
        else:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50024"] % "fileType")

        # RHEL and CentOS have the same kernel version,
        # So RHEL cluster package can run directly on CentOS.
        # Installation packages vary with operating systems
        
        if distname == REDHAT:
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_REDHAT, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                ]
            if version[0] == "8":
                file_name_list = [
                    self.package_file_path(prefix_str, packageVersion, PAK_OPENEULER, postfix_str),
                    ]

        elif distname == EULEROS:
            if idnum in ["SP2", "SP3", "SP5"]:
                new_prefix_str = "%s-%s" % (prefix_str, packageVersion)
                new_postfix_str = "%s.%s" % (BIT_VERSION, postfix_str)
                file_name_list = [
                    self.get_euler_package_name(dir_name, new_prefix_str, new_postfix_str),
                    self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                    ]
            elif idnum == "SP8":
                file_name_list = [
                    self.package_file_path(prefix_str, packageVersion, PAK_EULER, postfix_str)
                    ]
            else:
                file_name_list = [
                    self.package_file_path(prefix_str, packageVersion, PAK_EULER, postfix_str),
                    self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                    ]

        elif distname == CENTOS:
            if os.path.isfile(os.path.join("/etc", "euleros-release")):
                file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_EULER, postfix_str)
                ]
            elif version[0] == "8":
                file_name_list = [
                    self.package_file_path(prefix_str, packageVersion, PAK_OPENEULER, postfix_str),
                    ]
            else:
                file_name_list = [
                    self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                    ]
        
        elif distname == ASIANUX:
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_ASIANUX, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                ]
        
        elif distname == SUSE and version.split('.')[0] in ("11", "12"):
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_SUSE, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_CENTOS, postfix_str)
                ]
        
        elif distname == OPENEULER or distname == KYLIN or distname == UOS:
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_OPENEULER, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_KYLIN, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_UOS, postfix_str)
                ]
        
        elif distname == DEBIAN:
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_DEBIAN, postfix_str),
                self.package_file_path(prefix_str, packageVersion, PAK_OPENEULER, postfix_str)
                ]
        
        elif distname == FUSIONOS:
            file_name_list = [
                self.package_file_path(prefix_str, packageVersion, PAK_FUSIONOS, postfix_str)
                ]
        
        else:
            raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                            "Supported platforms are: %s." % str(
                SUPPORT_WHOLE_PLATFORM_LIST))
        
        # Find the installation package that exists on the current node
        package_name_list = []
        for file_name in file_name_list:
            package_name = os.path.basename(file_name)
            package_name_list.append(package_name)
            if os.path.exists(file_name) and os.path.isfile(file_name):
                return file_name
        
        for file_name in file_name_list:
            try:
                directory_to_search = os.path.join(dir_name, "./../../../")
                matched_files = self.compare_files_in_directory(directory_to_search, file_name)
                
                if len(matched_files) == 1:
                    return matched_files[0]
                elif len(matched_files) > 1:
                    print("Multiple matching files found,"
                                      "please select one:")
                    
                    for i, file in enumerate(matched_files, 1):
                        print(f"{i}. {file}")
                        
                    while True:
                        try:
                            choice = int(input("Please enter the serial number"
                                               "of the option:"))
                            if 1 <= choice <= len(matched_files):
                                return matched_files[choice - 1]
                            else:
                                print("Invalid input: Please re-enter")
                        except ValueError:
                            print("Invalid input: Please re-enter")
                else:
                    raise Exception("No matching files found in the directory.")
            except Exception as e:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % file_name)
                
        raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % package_name_list)
        
    def compare_files_in_directory(directory, file_to_compare):
        """
        function: The function is to recursively search for files in the 
                   specified directory and compare them with the given file,
        input:
            directory: Directory path to traverse
            file_to_compare: The file path to compare with files in the directory
        output:
            matched_files
        """
        matched_files = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path) and file_to_compare.lower() == file_path.lower():
                    matched_files.append(file_path)

        if matched_files:
            return matched_files
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % file_to_compare)

    def getGrepCmd(self):
        """
        function: get grep cmd
        input  : NA
        output : str
        """
        return self.findCmdInPath('grep')

    def getAwkCmd(self):
        """
        function: get awk cmd
        input  : NA
        output : str
        """
        return self.findCmdInPath('awk')

    def getSedCmd(self):
        """
        function: get sed cmd
        input  : NA
        output : str
        """
        return self.findCmdInPath('sed')

    def findCmdInPath(self, cmd):
        """
        function: find cmd in path
        input: cmd
        output: NA
        """
        CMD_PATH = ['/bin', '/usr/local/bin', '/usr/bin', '/sbin', '/usr/sbin']

        for bin_path in CMD_PATH:
            file_path = os.path.join(bin_path, cmd)
            if os.path.exists(file_path):
                return file_path

        raise Exception("cmd :%s can not find." % cmd)

    def getServiceCmd(self, service_name, action):
        """
        function: get service cmd
        input  : service_name, action
        output : str
        """
        return self.findCmdInPath('service') + BLANK_SPACE + service_name + \
               BLANK_SPACE + action

    def getSystemctlCmd(self, service_name, action):
        """
        function: get systemctl cmd
        input  : service_name, action
        output : str
        """
        return self.findCmdInPath('systemctl') + BLANK_SPACE + action + \
               BLANK_SPACE + service_name

