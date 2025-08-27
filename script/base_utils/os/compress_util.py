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
# ----------------------------------------------------------------------------
# Description  : compress_util.py is utility to support compress and decompress.
#############################################################################

import os
import subprocess
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil


class CompressUtil:
    """compress util"""

    @staticmethod
    def getCompressFilesCmd(tar_name, file_src):
        """
        function: get compress file cmd
        input  : tar_name, file_src
        output : str
        """
        return "%s -zvcf '%s' %s" % (CmdUtil.getTarCmd(), tar_name, file_src)

    @staticmethod
    def getDecompressFilesCmd(src_package, dest):
        """
        function: get decompress file cmd
        input  : src_package, dest
        output : str
        """
        return "%s -zxvf '%s' -C '%s'" % (CmdUtil.getTarCmd(), src_package, dest)
    
    @staticmethod
    def getDecompressFilesCmdList(src_package, dest):
        """
        function: get decompress file cmd
        input  : src_package, dest
        output : list
        """
        return [CmdUtil.getTarCmd(), '-zxvf', src_package, '-C', dest]

    @staticmethod
    def getCompressZipFilesCmd(zip_name, file_src):
        """
        function: get compress zip files cmd
        input  : zip_name, file_src
        output : str
        """
        return "cd %s && %s -r '%s.zip' ./*" % (file_src, CmdUtil.getZipCmd(),
                                                zip_name)

    @staticmethod
    def getDecompressZipFilesCmd(src_package, dest):
        """
        function: get decompress zip files cmd
        input  : src_package, dest
        output : str
        """
        return "%s -o '%s' -d '%s'" % (CmdUtil.getUnzipCmd(), src_package, dest)

    @staticmethod
    def getDecompressZipFilesCmdList(src_package, dest):
        """
        function: get decompress zip files cmd
        input  : src_package, dest
        output : list
        """
        return [CmdUtil.getUnzipCmd(), '-o', src_package, '-d', dest]

    @staticmethod
    def decompressFiles(src_package, dest):
        """
        function:decompress package to files
        input:src_package, dest
        output:NA
        """
        if not os.path.exists(src_package):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % src_package)
        if not os.path.exists(dest):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % dest)
        cmd_list = CompressUtil.getDecompressFilesCmdList(src_package, dest)
        output, error, status = CmdUtil.execCmdList(cmd_list)
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50231"] % src_package +
                            " Error:\n%s" % output + "\nThe cmd is %s" % ' '.join(cmd_list))

    @staticmethod
    def compressZipFiles(zip_name, dir_path):
        """
        function:compress directory to a package
        input:zip_name, directory
        output:NA
        """
        if not os.path.exists(dir_path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % dir_path)
        cmd = CompressUtil.getCompressZipFilesCmd(zip_name, dir_path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50227"] % cmd +
                            " Error:\n%s" % output)

    @staticmethod
    def decompressZipFiles(src_package, dest):
        """
        function:decompress package to files
        input:src_package, dest
        output:NA
        """
        if not os.path.exists(src_package):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % src_package)
        if not os.path.exists(dest):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % dest)
        cmd_list = CompressUtil.getDecompressZipFilesCmdList(src_package, dest)
        output, error, status = CmdUtil.execCmdList(cmd_list)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50231"] % src_package +
                            " Error:\n%s" % output + "\nThe cmd is %s" % ' '.join(cmd_list))
