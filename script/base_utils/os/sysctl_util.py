# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
# Description  : sshd config file operation.
#############################################################################


try:
    import sys
    sys.path.append(sys.path[0] + "/../../")
    from base_utils.os.cmd_util import CmdUtil
    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class SysctlUtil(object):

    @staticmethod
    def getAll():
        cmdList = [CmdUtil.getSysctlCmd(), '-a']
        output, error, status = CmdUtil.execCmdList(cmdList)
        res = {}
        for line in output.split('\n'):
            kv = line.split(' = ')
            if len(kv) == 1:
                continue
            res[kv[0]] = ' = '.join(kv[1:])
        return res

    @staticmethod
    def get(name):
        output, error, status = CmdUtil.execCmdList([CmdUtil.getSysctlCmd(), name])
        kv = output.split(' = ')
        if len(kv) == 1:
            return
        return ' = '.join(kv[1:])

    @staticmethod
    def set(name, value):
        CmdUtil.execCmdList([CmdUtil.getSysctlCmd(), name, value])
