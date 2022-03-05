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
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from gspylib.inspection.common import SharedFuncs
from gspylib.inspection.common.CheckItem import BaseItem
from gspylib.inspection.common.CheckResult import ResultStatus
from base_utils.os.disk_util import DiskUtil
from os_platform.UserPlatform import g_Platform

expectedReadAhead = "16384"
g_needRepair = []


class blockdev:
    def __init__(self):
        """
        function : Init class blockdev
        input  : NA
        output : NA
        """
        self.ra = dict()  # key is device name value is getra value
        self.errormsg = ''


class CheckBlockdev(BaseItem):
    def __init__(self):
        super(CheckBlockdev, self).__init__(self.__class__.__name__)

    def getDevices(self):
        """
        """
        cmd = "fdisk -l 2>/dev/null | grep \"Disk /dev/\"" \
              " | grep -v \"/dev/mapper/\" | awk '{ print $2 }' " \
              "| awk -F'/' '{ print $NF }' | sed s/:$//g"
        output = SharedFuncs.runShellCmd(cmd)
        devList = output.split('\n')
        return devList


    def getDeviceIoctls(self, devName):
        """
        function : Get device ioctls
        input  : devName   device name
        output : blockSize
        """
        blockSize = 0
        cmd = g_Platform.getBlockdevCmd(devName)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50408"] % cmd +
                            " Error: \n%s" % str(output))
        if str(output.strip()) != "" and output.isdigit():
            blockSize = int(output)
        return blockSize


    def collectBlockdev(self):
        """
        function : Collector blockdev
        input  : NA
        output : Instantion
        """
        data = blockdev()
        devices = list()
        try:
            diskName = ''
            # If the directory of '/' is a disk array,
            # all disk prereads will be set
            devlist = self.getDevices()
            allDiskList = DiskUtil.getMountInfo()
            for diskInfo in allDiskList:
                if (diskInfo.mountpoint == '/'):
                    diskName = diskInfo.device.replace('/dev/', '')
            for dev in devlist:
                if (dev.strip() == diskName.strip()):
                    continue
                devices.append("/dev/%s" % dev)
        except Exception as e:
            data.errormsg = e.__str__()
        for d in devices:
            data.ra[d] = self.getDeviceIoctls(d)

        return data

    def doCheck(self):
        global g_needRepair
        data = self.collectBlockdev()
        flag = True
        abnormalMsg = ""
        resultStr = ""
        for dev in data.ra.keys():
            ra = data.ra[dev]
            if int(ra) < int(expectedReadAhead):
                g_needRepair.append(dev)
                abnormalMsg += "On device (%s) 'blockdev readahead'" \
                               " RealValue '%s' ExpectedValue '%s'\n" % (
                                   dev, ra, expectedReadAhead)
                flag = False
            else:
                resultStr += "On device (%s) 'blockdev readahead': '%s' \n" % (
                    dev, ra)
        if flag:
            self.result.rst = ResultStatus.OK
        else:
            self.result.rst = ResultStatus.NG
        self.result.val = abnormalMsg
        self.result.raw = abnormalMsg + resultStr

    def doSet(self):
        for dev in g_needRepair:
            self.SetBlockdev(dev)

    def SetBlockdev(self, devname):
        (THPFile, initFile) = SharedFuncs.getTHPandOSInitFile()
        cmd = "/sbin/blockdev --setra %s %s " % (expectedReadAhead, devname)
        cmd += " && echo \"/sbin/blockdev --setra %s %s\" >> %s" % (
            expectedReadAhead, devname, initFile)
        SharedFuncs.runShellCmd(cmd)
