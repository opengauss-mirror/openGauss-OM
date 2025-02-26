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
    def get_release_date_from_app(app, lib_path=""):
        """
        function: get the infomation of gaussdb release date
        :param: gaussdb absolute path
        :return: gaussdb release date
        """
        if not os.path.exists(app):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % app)
        if not os.path.isfile(app):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % app)
        cmd = ""
        if lib_path == "":
            cmd = app + " -V"
        else:
            cmd = "export LD_LIBRARY_PATH={}:$LD_LIBRARY_PATH && {} -V".format(lib_path, app)
        
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50110"] % cmd)
        
        release_date = re.compile(CommConstants.RELEASE_DATE_PATTERN).search(output)
        if release_date is None:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50110"] % cmd)

        return release_date.group()
    
    @staticmethod
    def get_release_date():
        """
        function: Get release date from compressed pack
        input : NA
        output: String
        """
        def _parse_pkg_prefix(_cfg):
            _cmd = f'cat {_cfg}'
            _status, _output = subprocess.getstatusoutput(_cmd)
            if _status != 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50217"] %
                                        "version.cfg" + "The cmd is %s. " % _cmd +
                                        "The output is %s." % _output)
            _lines = _output.splitlines()
            return _lines[0]
        # obtain gaussdb
        root = os.path.join(os.path.dirname(os.path.realpath(__file__)), './../../../')
        version_file = os.path.join(root, 'version.cfg')
        if not os.path.exists(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % version_file)
        if not os.path.isfile(version_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % version_file)
        
        pkg_prefix = _parse_pkg_prefix(version_file)
        # upack and read version.cfg of openGauss-server package
        # the existing om version.cfg will be overwritten
        cmd = 'cd {} && mkdir temp && cd temp && tar -xpf ../{}*.tar.bz2 ./bin/gaussdb ./lib'.format(root, pkg_prefix)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            cmd = 'cd {} && mkdir temp && cd temp && tar -xpf `ls ../openGauss-Server*.tar.bz2 | tail -1` ./bin/gaussdb ./lib'.format(root)
            status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50217"] % "bin/gaussdb" +
                                   "The cmd is %s. " % cmd +
                                   "The output is %s." % output)
        
        gaussdb_file = os.path.join(root, 'temp/bin/gaussdb')
        lib_path = os.path.join(root, 'temp/lib')
        release_date = VersionInfo.get_release_date_from_app(gaussdb_file, lib_path)

        cmd = 'cd {} && rm -rf temp'.format(root)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50217"] % "bin/gaussdb" +
                                   "The cmd is %s. " % cmd +
                                   "The output is %s." % output)

        return release_date

    @staticmethod
    def cmp_cluster_version(version1, version2):
        v1_parts = version1.split('.')
        v2_parts = version2.split('.')
        
        if len(v1_parts) != CommConstants.VERSION_LENGTH or len(v2_parts) != CommConstants.VERSION_LENGTH: 
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52946"])
        
        # compare major version
        if int(v1_parts[CommConstants.MAJOR_IDX]) < int(v2_parts[CommConstants.MAJOR_IDX]):
            return -1
        elif int(v1_parts[CommConstants.MAJOR_IDX]) > int(v2_parts[CommConstants.MAJOR_IDX]):
            return 1
        
        # compare minor version
        if int(v1_parts[CommConstants.MINOR_IDX]) < int(v2_parts[CommConstants.MINOR_IDX]):
            return -1
        elif int(v1_parts[CommConstants.MINOR_IDX]) > int(v2_parts[CommConstants.MINOR_IDX]):
            return 1
        
        # compare revision version
        v1_revision = v1_parts[CommConstants.REVISION_IDX].split('-')
        v2_revision = v2_parts[CommConstants.REVISION_IDX].split('-')

        if int(v1_revision[0]) < int(v2_revision[0]):
            return -1
        elif int(v1_revision[0]) > int(v2_revision[0]):
            return 1
        
        # compare debug version
        if len(v1_revision) > len(v2_revision):
            return -1
        elif len(v1_revision) < len(v2_revision):
            return 1

        return 0

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

