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
    sys.path.append(sys.path[0] + "/../../")
    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class MemoryUtil(object):
    """
    function: Init the MemInfo options
    """

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
