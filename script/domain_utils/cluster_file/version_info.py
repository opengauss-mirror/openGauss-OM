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
"""
This file is for Gauss version things.
"""

import os
import re
import subprocess

from base_diff.comm_constants import CommConstants
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.user_util import UserUtil


class VersionInfo(object):
    """
    Info about current version
    """

    def __init__(self):
        pass

    # package version
    __PACKAGE_VERSION = ""
    # OM version string
    COMMON_VERSION = "Gauss200 OM VERSION"
    # It will be replaced with the product version, such as "Gauss200",
    # while being packaged by mpp_package.sh
    PRODUCT_NAME = "openGauss"
    PRODUCT_NAME_PACKAGE = "-".join(PRODUCT_NAME.split())
    COMMITID = ""

    @staticmethod
    def getPackageVersion():
        """
        function: Get the current version from version.cfg
        input : NA
        output: String
        """
        if VersionInfo.__PACKAGE_VERSION != "":
            return VersionInfo.__PACKAGE_VERSION
        # obtain version file
        version_file = VersionInfo.get_version_file()
        version, _, _ = VersionInfo.get_version_info(version_file)
        # the 2 value is package version
        VersionInfo.__PACKAGE_VERSION = version
        return VersionInfo.__PACKAGE_VERSION

    @staticmethod
    def getCommitid():
        """
        function: Get the current commit id from version.cfg
        input : NA
        output: String
        """
        if VersionInfo.COMMITID != "":
            return VersionInfo.COMMITID
        versionFile = VersionInfo.get_version_file()
        _, _, commit_id = VersionInfo.get_version_info(versionFile)
        # the 2 value is package version
        VersionInfo.COMMITID = commit_id
        return VersionInfo.COMMITID

    @staticmethod
    def get_version_file():
        """
        function: Get version.cfg file
        input : NA
        output: String
        """
        # obtain version file
        dir_name = os.path.dirname(os.path.realpath(__file__))
        version_file = os.path.join(dir_name, "./../../../", "version.cfg")
        version_file = os.path.realpath(version_file)
        if not os.path.exists(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % version_file)
        if not os.path.isfile(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % version_file)
        return version_file

    @staticmethod
    def get_version_info(version_file):
        """
        function: the infomation of version_file format
        :param version_file:
        :return: version info
        """
        if not os.path.exists(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % version_file)
        if not os.path.isfile(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % version_file)
        with open(version_file, 'r') as file_p:
            ret_lines = file_p.readlines()
        if len(ret_lines) < 3:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] % version_file)

        version = re.compile(CommConstants.VERSION_PATTERN).search(
            ret_lines[0].strip()).group()
        number = ret_lines[1].strip()
        commit_id = ret_lines[2].strip()

        if version is None:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] %
                            "version.cfg" + "Does not have version "
                                            "such as " + CommConstants.VERSION_EXAMPLE)
        try:
            float(number)
        except Exception as excep:
            raise Exception(str(excep) + ErrorCode.GAUSS_516["GAUSS_51628"]
                            % number)

        if float(number) < CommConstants.FIRST_GREY_UPGRADE_NUM:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51629"] % number)

        if not (commit_id.isalnum() and len(commit_id) == 8):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] % version_file
                            + " Commit id is wrong.")
        return version, number, commit_id

    @staticmethod
    def getAppVersion(appPath=""):
        """
        function : Get the version of application by $GAUSS_VERSION
        input : String
        output : String
        """
        # get user and group
        (user, group) = UserUtil.getPathOwner(appPath)
        if user == "" or group == "":
            return ""

        # build shell command
        # get the version of application by $GAUSS_VERSION
        return EnvUtil.getEnvironmentParameterValue("GAUSS_VERSION", user)

    @staticmethod
    def getAppBVersion(appPath=""):
        """
        function :Get the version of application by $GAUSS_VERSION
        input : String
        output : String
        """
        # get user and group
        (user, group) = UserUtil.getPathOwner(appPath)
        if user == "" or group == "":
            return ""
        # build shell command
        user_profile = EnvUtil.getMpprcFile()
        execute_cmd = "gaussdb -V"
        cmd = CmdUtil.getExecuteCmdWithUserProfile(user, user_profile, execute_cmd, False)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            return ""
        return output.replace('gaussdb ', '').strip()

