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

from base_diff.comm_constants import CommConstants
from base_diff.single_inst_diff import SingleInstDiff
from base_utils.common.constantsbase import ConstantsBase
from gspylib.common.ErrorCode import ErrorCode
from base_utils.executor.local_remote_cmd import LocalRemoteCmd
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.compress_util import CompressUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo
from os_platform.UserPlatform import g_Platform

import impl.upgrade.UpgradeConst as Const


class PackageInfo(object):
    """
    This file is for Gauss package things.
    """
    @staticmethod
    def getPackageFile(fileType="tarFile"):
        """
        function : Get the path of binary file version.
        input : NA
        output : String
        """
        return g_Platform.getPackageFile(VersionInfo.getPackageVersion(),
                                         VersionInfo.PRODUCT_NAME_PACKAGE,
                                         fileType)

    @staticmethod
    def getSHA256FilePath():
        """
        function : Get the path of sha256 file version..
        input : NA
        output : str
        """
        return PackageInfo.getPackageFile("sha256File")

    @staticmethod
    def get_package_file_path():
        """
        function : Get the path of bin file version.
        input : NA
        output : str
        """
        return PackageInfo.getPackageFile(CommConstants.PACKAGE_TYPE)

    @staticmethod
    def getFileSHA256Info():
        """
        function: get file sha256 info
        input:  NA
        output: str, str
        """
        try:
            bz2_path = PackageInfo.get_package_file_path()
            sha256_path = PackageInfo.getSHA256FilePath()

            file_sha256 = FileUtil.getFileSHA256(bz2_path)
            value_list = FileUtil.readFile(sha256_path)
            if len(value_list) != 1:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                                sha256_path)
            sha256_value = value_list[0].strip()
            return file_sha256, sha256_value
        except Exception as excep:
            raise Exception(str(excep))

    @staticmethod
    def checkPackageOS():
        """
        function : get and check binary file
        input : NA
        output : boolean
        """
        try:
            (file_sha256, sha256_value) = PackageInfo.getFileSHA256Info()
            if file_sha256 != sha256_value:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51635"] +
                                "The SHA256 value is different. \nBin file: "
                                "%s\nSHA256 file: %s." % (file_sha256,
                                                          sha256_value))
            return True
        except Exception as excep:
            raise Exception(str(excep))

    @staticmethod
    def get_package_back_name():
        """ get package backup name"""
        return "%s-Package-bak_%s.tar.gz" % (
            VersionInfo.PRODUCT_NAME_PACKAGE, VersionInfo.getCommitid())

    @staticmethod
    def distributePackagesToRemote(g_sshTool, srcPackageDir, destPackageDir,
                                   hostname=[], mpprcFile=""):
        '''
        function: distribute the package to remote nodes
        input: g_sshTool, hostname, srcPackageDir, destPackageDir, mpprcFile,
               clusterType
        output:NA
        '''
        try:
            # check the destPackageDir is existing on hostname
            LocalRemoteCmd.checkRemoteDir(g_sshTool, destPackageDir, hostname,
                                        mpprcFile)

            # Send compressed package to every host
            g_sshTool.scpFiles("%s/%s" % (
                srcPackageDir, PackageInfo.get_package_back_name()),
                               destPackageDir, hostname, mpprcFile)
            # Decompress package on every host
            srcPackage = "'%s'/'%s'" % (destPackageDir,
                                        PackageInfo.get_package_back_name())
            cmd = CompressUtil.getDecompressFilesCmd(srcPackage, destPackageDir)
            g_sshTool.executeCommand(cmd,
                                     ConstantsBase.SUCCESS, hostname, mpprcFile)

            # change owner and mode of packages
            dest_path = "'%s'/*" % destPackageDir
            cmd = CmdUtil.getChmodCmd(str(ConstantsBase.MAX_DIRECTORY_MODE),
                                      dest_path, True)
            g_sshTool.executeCommand(cmd,
                                     ConstantsBase.SUCCESS, hostname, mpprcFile)

        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def makeCompressedToolPackage(package_path, is_single_inst=False):
        """
        function: make compressed tool package
        input: NA
        output: NA
        """
        # init bin file name, integrity file name and tar list names
        package_path = os.path.normpath(package_path)
        bz2_file_name = PackageInfo.getPackageFile("bz2File")
        integrity_file_name = PackageInfo.getSHA256FilePath()
        cm_package = "%s-cm.tar.gz" % PackageInfo.getPackageFile(
            "bz2File").replace(".tar.bz2", "")
        om_package = "%s-om.tar.gz" % PackageInfo.getPackageFile(
            "bz2File").replace(".tar.bz2", "")

        tar_lists = SingleInstDiff.get_package_tar_lists(is_single_inst,
                                                         os.path.normpath(package_path))
        upgrade_sql_file_path = os.path.join(package_path,
                                             Const.UPGRADE_SQL_FILE)
        if os.path.exists(upgrade_sql_file_path):
            tar_lists += " %s %s" % (Const.UPGRADE_SQL_SHA,
                                     Const.UPGRADE_SQL_FILE)
        try:
            # make compressed tool package
            cmd = "%s && " % CmdUtil.getCdCmd(package_path)
            # do not tar *.log files
            cmd += CompressUtil.getCompressFilesCmd(PackageInfo.get_package_back_name(),
                                                    tar_lists)
            cmd += " %s %s %s " % (os.path.basename(bz2_file_name),
                                os.path.basename(integrity_file_name), os.path.basename(om_package))
            # add CM package to bak package
            if os.path.isfile(os.path.realpath(os.path.join(package_path, cm_package))):
                cmd += "%s " % os.path.basename(cm_package)
            cmd += "&& %s " % CmdUtil.getChmodCmd(
                str(ConstantsBase.KEY_FILE_MODE),
                PackageInfo.get_package_back_name())
            cmd += "&& %s " % CmdUtil.getCdCmd("-")
            (status, output) = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s" % output)
        except Exception as e:
            raise Exception(str(e))
