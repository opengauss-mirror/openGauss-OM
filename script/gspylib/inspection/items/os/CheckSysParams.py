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
from gspylib.common.ErrorCode import ErrorCode
from domain_utils.cluster_file.config_param import ConfigParam
from base_utils.os.file_util import FileUtil
from os_platform.linux_distro import LinuxDistro
from base_utils.os.cmd_util import CmdUtil

setParameterList = {}


class CheckSysParams(BaseItem):
    def __init__(self):
        super(CheckSysParams, self).__init__(self.__class__.__name__)
        self.version = None

    def preCheck(self):
        # check the threshold was set correctly
        if (not self.threshold.__contains__('version')):
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53013"] % "version")
        self.version = self.threshold['version']

    def SetSysctlForList(self, key, value):
        """
        function: Set sysctl parameter
        input : key, value
        output: NA
        """
        kernelParameterFile = "/etc/sysctl.conf"
        cmd = """sed -i '/^\\s*%s *=.*$/d' %s &&
               echo %s = %s  >> %s 2>/dev/null""" % (
            key, kernelParameterFile, key, value, kernelParameterFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(output + " The cmd is %s " % cmd)


    def doCheck(self):
        global setParameterList
        patchlevel = ""
        resultList = []
        informationlist = []
        dirName = os.path.dirname(os.path.realpath(__file__))

        configFile = "%s/../../config/check_list_%s.conf" % (
            dirName, self.version)
        suggestParameterList = ConfigParam.getConfigFilePara(
            configFile,
            'SUGGEST:/etc/sysctl.conf')
        kernelParameter = ConfigParam.getConfigFilePara(configFile,
                                                 '/etc/sysctl.conf')
        kernelParameter.update(suggestParameterList)
        distname, version, idnum = LinuxDistro.linux_distribution()
        if (distname == "SuSE" and version == "11"):
            patInfo = FileUtil.readFile("/etc/SuSE-release", 'PATCHLEVEL')[0]
            if (patInfo.find('=') > 0):
                output = patInfo.split('=')[1].strip()
                if (output != ""):
                    patchlevel = output
        for key in kernelParameter:
            if (patchlevel == "1" and key == "vm.extfrag_threshold"):
                continue

            sysFile = "/proc/sys/%s" % key.replace('.', '/')
            # High version of linux no longer supports tcp_tw_recycle
            if (not os.path.exists(
                    sysFile) and key == "net.ipv4.tcp_tw_recycle"):
                continue
            output = FileUtil.readFile(sysFile)[0].strip()
            if (len(output.split()) > 1):
                output = ' '.join(output.split())

            if (output != kernelParameter[key].strip() and key not in list(
                    suggestParameterList.keys())):
                resultList.append(1)
                informationlist.append(
                    "Abnormal reason: variable '%s' "
                    "RealValue '%s' ExpectedValue '%s'." % (
                        key, output, kernelParameter[key]))
                setParameterList[key] = kernelParameter[key]
            elif output != kernelParameter[key].strip():
                if (key == "vm.overcommit_ratio"):
                    output = FileUtil.readFile("/proc/sys/vm/overcommit_memory")[
                        0].strip()
                    if (output == "0"):
                        continue
                resultList.append(2)
                informationlist.append(
                    "Warning reason: variable '%s' RealValue '%s' "
                    "ExpectedValue '%s'." % (
                        key, output, kernelParameter[key]))
        if (1 in resultList):
            self.result.rst = ResultStatus.NG
        elif (2 in resultList):
            self.result.rst = ResultStatus.WARNING
        else:
            self.result.rst = ResultStatus.OK
        self.result.val = ""
        for info in informationlist:
            self.result.val = self.result.val + '%s\n' % info

    def delSysctlForList(self, key, value):
        """
        """
        kernelParameterFile = "/etc/sysctl.conf"
        cmd = """sed -i '/^\\s*%s *=.*$/d' %s """ % (key, kernelParameterFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53019"] % (key, value))

    def doSet(self):
        for checkResult in self.result.val.split('\n'):
            if (checkResult.startswith("Abnormal reason")):
                checkResultList = checkResult.split('\'')
                setParameterList[checkResultList[1]] = checkResultList[5]
        self.result.val = ""

        if (len(setParameterList) != 0):
            for key in setParameterList:
                self.SetSysctlForList(key, setParameterList[key])
                self.result.val += "Set variable '%s' to '%s'\n" % (
                    key, setParameterList[key])
            cmd_list = ['sysctl', '-p']
            (output, error, status) = CmdUtil.execCmdList(cmd_list)
            if (status != 0):
                cmderrorinfo = "sysctl -p | grep 'No such file or directory'"
                (status, outputresult) = subprocess.getstatusoutput(
                    cmderrorinfo)
                if (status != 0 and outputresult == ""):
                    raise Exception(output)
                for key in setParameterList:
                    tmp = "/proc/sys/%s" % key.replace('.', '/')
                    if (tmp in outputresult or key in outputresult):
                        # delete the record about key from the /etc/sysctl.conf
                        self.delSysctlForList(key, setParameterList[key])
