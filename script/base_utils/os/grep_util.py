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
# Description  : grep_util.py is a utility for os grep command.
#############################################################################
import os
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil


class GrepUtil(object):
    """
    grep_util.py is a utility for os grep command.
    """
    @staticmethod
    def getGrepValue(para="", value="", path=""):
        """
        function : grep value
        input : string,value,path
        output: status, output
        """
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        cmd_list = [CmdUtil.getGrepCmd(), " %s '%s' '%s'" % (para, value, path)]
        output, error, status = CmdUtil.execCmdList(cmd_list)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % ' '.join(cmd_list) +
                            " Error:\n%s" % output)
        return status, output
