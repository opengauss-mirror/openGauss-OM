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
# Description  : memory.py is a utility to do something for memory information.
#############################################################################
try:
    import sys
    import psutil
    import subprocess
    sys.path.append(sys.path[0] + "/../../")
    from base_utils.os.cmd_util import CmdUtil
    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class MemoryUtil(object):
    """
    function: Init the MemInfo options
    """

    MEM_INFO_FILE = '/proc/meminfo'

    @staticmethod
    def getMemTotalSize():
        """
        function : Get system virtual memory total size
        input  : null
        output : total virtual memory(byte)
        """
        try:
            return psutil.virtual_memory().total
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_505["GAUSS_50502"] %
                            "system memory usage" + "Error: %s" % str(excep))

    @staticmethod
    def getMemAvailableSize():
        """
        function : Get system virtual memory available size
        input  : null
        output : available virtual memory(byte)
        """
        try:
            return psutil.virtual_memory().available
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_505["GAUSS_50502"] %
                            "system memory usage" + "Error: %s" % str(excep))

    @staticmethod
    def getMemUsage():
        """
        function : Get system virtual memory usage
        input  : null
        output : memory usage
        """
        try:
            return psutil.virtual_memory().percent
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_505["GAUSS_50502"] %
                            "system memory usage" + "Error: %s" % str(excep))

    @staticmethod
    def selectMemInfo(attr=None):
        """

        :param attr:
        :return:
        """
        if attr is None:
            output, error, status = CmdUtil.execCmdList([CmdUtil.getCatCmd(), MemoryUtil.MEM_INFO_FILE])
            res = {}
            for line in output.split('\n'):
                kv = line.split(':')
                res[kv[0].strip()] = kv[1].strip()
            return res

        cmd = "%s %s | %s '%s' | %s '{print $2}'" % (
            CmdUtil.getCatCmd(),
            MemoryUtil.MEM_INFO_FILE,
            CmdUtil.getGrepCmd(),
            attr,
            CmdUtil.getAwkCmd()
        )
        output = CmdUtil.execCmd(cmd)
        return output

    @staticmethod
    def getPhysicalMemTotalSize():
        """
        function : Get system physical memory total size
        input  : null
        output : total physical memory(byte)
        """
        cmd = "%s | %s Mem | %s '{print $2}'" % (
            CmdUtil.findCmdInPath('free'),
            CmdUtil.getGrepCmd(),
            CmdUtil.getAwkCmd()
        )
        output = CmdUtil.execCmd(cmd)
        return int(output)

    @staticmethod
    def getPhysicalMemUsedSize():
        """
        function : Get system physical memory total size
        input  : null
        output : total physical memory(byte)
        """
        cmd = "%s | %s Mem | %s '{print $3}'" % (
            CmdUtil.findCmdInPath('free'),
            CmdUtil.getGrepCmd(),
            CmdUtil.getAwkCmd()
        )
        output = CmdUtil.execCmd(cmd)
        return int(output)
