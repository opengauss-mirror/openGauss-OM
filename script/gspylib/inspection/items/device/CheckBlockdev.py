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
        cmd = "lsblk -d -n -o NAME,TYPE 2>/dev/null | " \
              "awk '$2==\"disk\"{print $1}'"
        output = SharedFuncs.runShellCmd(cmd)
        devList = output.split('\n')
        return devList


    def getDeviceIoctls(self, dev_name):
        """
        function : Get device ioctls
        input  : dev_name   device name
        output : block_size
        """
        block_size = 0
        cmd = g_Platform.getBlockdevCmd(dev_name)
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            result = p.communicate(timeout=3)
            output = result[0].decode().strip()
            if p.returncode != 0:
                raise Exception(ErrorCode.GAUSS_504["GAUSS_50408"] % cmd +
                                " Error: \n%s" % result[1].decode().strip())
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise Exception("Timeout getting readahead for '%s',"
                            " device may be faulty." % dev_name)
        if str(output.strip()) != "" and output.isdigit():
            block_size = int(output)
        return block_size


    def collectBlockdev(self):
        """
        function : Collector blockdev
        input  : NA
        output : Instantion
        """
        data = blockdev()
        devices = list()
        try:
            disk_name = ''
            # If the directory of '/' is a disk array,
            # all disk prereads will be set
            devlist = self.getDevices()
            all_disk_list = DiskUtil.getMountInfo()
            for diskInfo in all_disk_list:
                if (diskInfo.mountpoint == '/'):
                    disk_name = diskInfo.device.replace('/dev/', '')
            for dev in devlist:
                if (dev.strip() == disk_name.strip()):
                    continue
                devices.append("/dev/%s" % dev)
        except Exception as e:
            data.errormsg = e.__str__()
        for d in devices:
            try:
                data.ra[d] = self.getDeviceIoctls(d)
            except Exception as e:
                data.errormsg += "Failed to get readahead for '%s': %s\n" \
                                 % (d, str(e))

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
