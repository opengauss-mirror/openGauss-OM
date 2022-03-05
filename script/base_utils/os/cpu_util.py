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
    sys.path.append(sys.path[0] + "/../../")
    from base_utils.common.constantsbase import ConstantsBase
    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))

"""
Requirements:
1. getCpuNum():  get real cpu number.
2. getCpuOnlineOfflineInfo(is_onnline_cpu): get cpu online/offline information
"""


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
