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
# Description  : cpu.py is a utility to do something for cpu information.
#############################################################################

try:
    import os
    import subprocess
    import sys
    import multiprocessing
    from enum import Enum
    sys.path.append(sys.path[0] + "/../../")
    from base_utils.common.constantsbase import ConstantsBase
    from base_utils.os.cmd_util import CmdUtil

    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))

"""
Requirements:
1. getCpuNum():  get real cpu number.
2. getCpuOnlineOfflineInfo(is_onnline_cpu): get cpu online/offline information
"""


class CpuArchitecture(Enum):
    UNKNOWN = 0
    AARCH64 = 1
    X86_64 = 2

    @staticmethod
    def parse(arch):
        if arch == CpuArchitecture.AARCH64.name.lower():
            return CpuArchitecture.AARCH64
        elif arch == CpuArchitecture.X86_64.name.lower():
            return CpuArchitecture.X86_64
        else:
            return CpuArchitecture.UNKNOWN


class CpuUtil(object):
    """
    function: Init the CpuInfo options
    """

    @staticmethod
    def getCpuNum():
        """
        function : get cpu set of current board
        input  : null
        output : total CPU count
        """
        try:
            return multiprocessing.cpu_count()
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_523["GAUSS_52301"] + str(excep))

    @staticmethod
    def getCpuOnlineOfflineInfo(is_onnline_cpu=True):
        """
        cat /sys/devices/system/cpu/online or /sys/devices/system/cpu/offline
        """
        online_file_name = "/sys/devices/system/cpu/online"
        offline_file_name = "/sys/devices/system/cpu/offline"

        if is_onnline_cpu:
            file_name = online_file_name
        else:
            file_name = offline_file_name

        if not os.path.exists(file_name):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % file_name)
        if not os.path.isfile(file_name):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % file_name)

        cmd = "cat '%s' 2>/dev/null" % file_name
        status, output = subprocess.getstatusoutput(cmd)
        if status == 0:
            return output
        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s" % str(output))

    @staticmethod
    def getCpuSet():
        """
        function: get cpu set of current board
                  cat /proc/cpuinfo |grep processor
        input: NA
        output: cpuSet
        """
        # do this function to get the parallel number
        cpu_set = multiprocessing.cpu_count()
        if cpu_set > 1:
            return cpu_set
        return ConstantsBase.DEFAULT_PARALLEL_NUM

    @staticmethod
    def getCpuArchitecture():
        """
        function: get cpu architecture of current board
                  lscpu | grep Architecture
        input: NA
        output: cpu architecture
        """
        cmd = f"{CmdUtil.getLscpuCmd()} | {CmdUtil.getGrepCmd()} Architecture"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            return CpuArchitecture.UNKNOWN
        arch = output.split(':')[1].strip()
        return CpuArchitecture.parse(arch)

    @staticmethod
    def getCpuModelName():
        """
        function: get cpu mode name of current board
                  lscpu | grep Architecture
        input: NA
        output: cpu Model name
        """
        cmd = f"{CmdUtil.getLscpuCmd()} | {CmdUtil.getGrepCmd()} 'Model name'"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            return ''
        mode_name = output.split(':')[1].strip()
        return mode_name

    @staticmethod
    def getCpuVendor():
        """
        function: get cpu vendor of current board
                  lscpu | grep 'Vendor ID'
        input: NA
        output: cpu vendor
        """
        cmd = f"{CmdUtil.getLscpuCmd()} | {CmdUtil.getGrepCmd()} 'Vendor ID'"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            return ''
        vendor = output.split(':')[1].strip()
        return vendor

    @staticmethod
    def cpuListToCpuRangeStr(cpu_list):
        """
        function: transform cpu id list to cpu range str
        input: cpu id list, like (0,1,2,3,4,5,6,11,12,13,15,16,20)
        output: cpu range str, like '0-6,11-16,20'
        """
        if len(cpu_list) == 0:
            return ''

        start = cpu_list[0]
        pre = cpu_list[0]
        cpu_range_str = []
        for cpuid in cpu_list:
            if int(cpuid) > int(pre) + 1:
                this_range = str(pre) if pre == start else '{0}-{1}'.format(start, pre)
                cpu_range_str.append(this_range)
                start = pre = cpuid
                continue
            pre = cpuid
        last_range = str(pre) if pre == start else '{0}-{1}'.format(start, pre)
        cpu_range_str.append(last_range)
        return ','.join(cpu_range_str)

    @staticmethod
    def cpuRangeStrToCpuList(cpu_range_str):
        """
        function: transform cpu range str to cpu id list
        input: cpu range str, like '0-6,11-16,20'
        output: cpu id list, like (0,1,2,3,4,5,6,11,12,13,15,16,20)
        """
        cpu_list = []
        for part_range in cpu_range_str.split(','):
            p = part_range.split('-')
            if len(p) == 1:
                cpu_list.append(int(p[0]))
                continue
            cpu_list += [i for i in range(int(p[0]), int(p[1]) + 1)]

        return tuple(cpu_list)

    @staticmethod
    def getCpuNumaList():
        """
        function: get cpu numa list of current board
                  lscpu | grep 'NUMA node' | grep 'CPU(s)'
        input: NA
        output: [[cpu id of numa 0], [cpu id of numa 1], ...]
        """
        cmd = f"{CmdUtil.getLscpuCmd()} | {CmdUtil.getGrepCmd()} 'NUMA node' | {CmdUtil.getGrepCmd()} 'CPU(s)'"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s" % str(output))
        range_info = [line.split(':')[1].strip() for line in output.split('\n')]
        numa_list = []
        for p in range_info:
            numa_list.append(CpuUtil.cpuRangeStrToCpuList(p))

        return numa_list
