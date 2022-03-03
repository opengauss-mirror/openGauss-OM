# -*- coding:utf-8 -*-
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

import os
from gspylib.inspection.common import SharedFuncs
from gspylib.inspection.common.CheckItem import BaseItem
from gspylib.inspection.common.CheckResult import ResultStatus
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.process_util import ProcessUtil

STACK = 3072


class CheckStack(BaseItem):
    def __init__(self):
        super(CheckStack, self).__init__(self.__class__.__name__)

    def doCheck(self):
        parRes = ""
        flag = 0
        output = CmdUtil.getUserLimits('stack size')
        self.result.raw = output
        StackValue = output.split()[-1]
        if (StackValue == 'unlimited'):
            pass
        elif (int(StackValue) < STACK):
            flag = 1
            parRes += "The value of stack depth is %d. " \
                      "it can not be less than 3072" % int(
                StackValue)

        if (self.cluster):
            pidList = ProcessUtil.getProcess(
                os.path.join(self.cluster.appPath, 'bin/gaussdb'))
            for pid in pidList:
                limitsFile = "/proc/%s/limits" % pid
                if (not os.path.isfile(limitsFile) or not os.access(limitsFile,
                                                                    os.R_OK)):
                    continue
                output = FileUtil.readFile(limitsFile, 'Max stack size')[
                    0].strip()
                self.result.raw += '\n[pid]%s: %s' % (pid, output)
                Stack = output.split()[4]
                if (Stack == 'unlimited'):
                    pass
                else:
                    value = int(Stack) / 1024
                    if (int(value) < STACK):
                        flag = 1
                        parRes += \
                            "The value of stack depth is %s on pid %s. " \
                            "it must be larger than 3072.\n" % (
                                value, pid)

        if (flag == 1):
            self.result.rst = ResultStatus.NG
            self.result.val = parRes
        else:
            self.result.rst = ResultStatus.OK
            self.result.val = StackValue

    def doSet(self):
        limitPath = '/etc/security/limits.conf'
        errMsg = SharedFuncs.SetLimitsConf(["soft", "hard"], "stack", STACK,
                                           limitPath)
        if errMsg != "Success":
            self.result.val = "%s\n" % errMsg
        else:
            self.result.val = "Success to set openfile to %d\n" % STACK
