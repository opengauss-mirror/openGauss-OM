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
import subprocess
from gspylib.inspection.common.CheckItem import BaseItem
from gspylib.inspection.common.CheckResult import ResultStatus
from os_platform.UserPlatform import g_Platform
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.file_util import FileUtil
from base_utils.os.cmd_util import CmdUtil

rmDir = []


class CheckDirLeft(BaseItem):
    def __init__(self):
        super(CheckDirLeft, self).__init__(self.__class__.__name__)
        self.directoryList = None

    def preCheck(self):
        # check current node contains cn instances if not raise  exception
        super(CheckDirLeft, self).preCheck()
        # check the threshold was set correctly
        if (not self.threshold.__contains__('directoryList')):
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53013"]
                            % "threshold directoryList")
        self.directoryList = self.threshold['directoryList'].split(',')

    def doCheck(self):
        global rmDir
        parRes = ""
        flag = 0
        mountDir = []
        mountList = FileUtil.readFile(g_Platform.getMtablFile())
        for line in mountList:
            mountInfo = line.strip()
            if (not mountInfo.startswith('#') and len(mountInfo.split()) > 5):
                mountDir.append(mountInfo.split()[1])
        for dirName in self.directoryList:
            if (os.path.exists(dirName)):
                flagNumber = True
                for mdir in mountDir:
                    if (len(mdir) >= len(dirName)):
                        if (mdir[0:len(dirName)] == dirName):
                            flagNumber = False
                            break
                if (not flagNumber):
                    continue

                parRes += "\nThe directory of %s exists." % dirName
                rmDir.append(dirName)
                flag = 1

        if (flag == 1):
            self.result.rst = ResultStatus.NG
        else:
            self.result.rst = ResultStatus.OK
        self.result.val = parRes
        self.result.raw = "mount directory: %s" % mountDir

    def doSet(self):
        errMsg = ""
        for path in rmDir:
            if (os.path.exists(path)):
                cmd_list = ['rm', '-rf', path]
                (output, error, status) = CmdUtil.execCmdList(cmd_list)
                if (status != 0):
                    errMsg += "Failed to delete %s.Error: %s\n" % \
                              (path, output)
                    errMsg += "The cmd is %s " % ' '.join(cmd_list)
        if (errMsg):
            self.result.val = errMsg
        else:
            self.result.val = "Successfully clean up file residues.\n"
