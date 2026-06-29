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
from gspylib.inspection.common import SharedFuncs
from gspylib.inspection.common.CheckItem import BaseItem
from gspylib.inspection.common.CheckResult import ResultStatus
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from script.base_utils.os.disk_util import DiskUtil

deviceNeedRepair = []


class CheckIOConfigure(BaseItem):
    def __init__(self):
        super(CheckIOConfigure, self).__init__(self.__class__.__name__)

    def obtainDataDir(self, nodeInfo):
        dataDirList = []
        for inst in nodeInfo.datanodes:
            dataDirList.append(inst.datadir)
        for inst in nodeInfo.cmservers:
            dataDirList.append(inst.datadir)
        for inst in nodeInfo.coordinators:
            dataDirList.append(inst.datadir)
        for inst in nodeInfo.gtms:
            dataDirList.append(inst.datadir)
        if (hasattr(nodeInfo, 'etcds')):
            for inst in nodeInfo.etcds:
                dataDirList.append(inst.datadir)

        dataDirList.append(EnvUtil.getEnv("PGHOST"))
        dataDirList.append(EnvUtil.getEnv("GPHOME"))
        dataDirList.append(EnvUtil.getEnv("GAUSSHOME"))
        dataDirList.append(EnvUtil.getEnv("GAUSSLOG"))
        dataDirList.append("/tmp")
        return dataDirList

    def obtainDiskDir(self):
        cmd = "df -h -P /data* | grep -v 'Mounted' | awk '{print $6}'"
        output = SharedFuncs.runShellCmd(cmd)
        if output.lower().find("no such") >= 0:
            allDiskPath = ["/"]
        else:
            allDiskPath = output.split('\n')
        return allDiskPath

    def getDevices(self):
        path_list = []
        devices = []
        disk_name = ""
        disk_dict = {}
        disk_dict = self.getDisk()  
        if (self.cluster):
            path_list = self.obtainDataDir(self.cluster.getDbNodeByName(self.host))
        else:
            path_list = self.obtainDiskDir()
        for path in path_list:
            if path.find('No such file or directory') >= 0 or path.find(
                    'no file systems processed') >= 0:
                self.result.rst = ResultStatus.ERROR
                self.result.val += \
                    "There are no cluster and no /data* directory."
                return
            cmd = "df -P -i %s" % path
            output = SharedFuncs.runShellCmd(cmd)
            # Filesystem      Inodes  IUsed   IFree IUse% Mounted on
            # /dev/xvda2     2363904 233962 2129942   10% /
            disk_name = output.split('\n')[-1].split()[0]
            for disk in disk_dict.keys():
                if disk_name in disk_dict[disk] and disk not in devices:
                    devices.append(disk)
        return devices

    def getDisk(self):
        """
        function: get disk name by partition
        input: partition list
        return: disk dict
        """
        return DiskUtil.obtain_disk()

    def collectIOschedulers(self):
        devices = set()
        data_dict = dict()
        files = self.getDevices()
        for f in files:
            fname = "/sys/block/%s/queue/scheduler" % f
            words = fname.split("/")
            if len(words) != 6:
                continue
            devices.add(words[3].strip())

        for d in devices:
            if (not d):
                continue
            device = {}
            scheduler = FileUtil.readFile("/sys/block/%s/queue/scheduler" % d)[0]
            words = scheduler.split("[")
            if len(words) != 2:
                continue
            words = words[1].split("]")
            if len(words) != 2:
                continue
            device["request"] = words[0].strip()
            for dead in scheduler.split():
                if dead.find("deadline") >= 0:
                    device["deadvalue"] = dead.split("[")[-1].split("]")[0]
                else:
                    continue
            data[d] = device
        return data

    def doCheck(self):
        global deviceNeedRepair
        deviceNeedRepair = []
        expectedScheduler = "deadline"
        data = self.collectIOschedulers()
        flag = True
        resultStr = ""
        for i in data.keys():
            result = ()
            expectedScheduler = data[i]["deadvalue"]
            request = data[i]["request"]
            if (request != expectedScheduler):
                result = (i, expectedScheduler)
                deviceNeedRepair.append(result)
                resultStr += \
                    "On device (%s) 'IO Request' RealValue '%s' " \
                    "ExpectedValue '%s'" % (
                        i, request.strip(), expectedScheduler)
                flag = False
        self.result.val = resultStr
        if flag:
            self.result.rst = ResultStatus.OK
            self.result.val = "All disk IO Request is deadline."
        else:
            self.result.rst = ResultStatus.NG

    def doSet(self):
        for dev, expectedScheduler in deviceNeedRepair:
            self.SetIOSchedulers(dev, expectedScheduler)

    def SetIOSchedulers(self, devname, expectedScheduler):
        """
        function : Set IO Schedulers
        input  : String
        output : NA
        """
        (THPFile, initFile) = SharedFuncs.getTHPandOSInitFile()
        cmd = " echo %s >> /sys/block/%s/queue/scheduler" % (
            expectedScheduler, devname)
        cmd += " && echo \"echo %s >> /sys/block/%s/queue/scheduler\" >> %s" \
               % (
                   expectedScheduler, devname, initFile)
        SharedFuncs.runShellCmd(cmd)
