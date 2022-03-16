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
# Description  : crontab_util.py is a utility for os crontab.
#############################################################################

import os
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil


class CrontabUtil(object):
    """
    os crontab utility
    """
    @staticmethod
    def getAllCrontab():
        """
        function : Get the crontab
        input : NA
        output: status, output
        """
        cmd = CmdUtil.getAllCrontabCmd()
        (status, output) = subprocess.getstatusoutput(cmd)
        if output.find("no crontab for") >= 0:
            output = ""
            status = 0
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            "crontab list" + " Error:%s." % output +
                            "The cmd is %s" % cmd)
        return status, output

    @staticmethod
    def execCrontab(path):
        """
        function : Get the crontab
        input : string
        output: True or False
        """
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        file_path = os.path.dirname(path)
        file_name = os.path.basename(path)
        cmd = CmdUtil.getCdCmd(file_path)
        cmd += " && "
        cmd += CmdUtil.getCrontabCmd()
        cmd += (" ./%s" % file_name)
        cmd += " && %s" % CmdUtil.getCdCmd("-")
        # if cmd failed, then exit
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error:\n%s" % output)
        return True
