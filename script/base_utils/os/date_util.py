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
# Description  : date_util.py is a utility to do something for date
#############################################################################
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil


class DateUtil(object):
    """
    date_util.py is a utility to do something for date
    """
    @staticmethod
    def getDate():
        """
        function : Get current system time
        input : NA
        output: String
        """
        date_cmd_list = [CmdUtil.getDateCmd(), '-R']
        output, error, status = CmdUtil.execCmdList(date_cmd_list)

        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % "date" +
                            "The cmd is %s" % ' '.join(date_cmd_list))
        return output
