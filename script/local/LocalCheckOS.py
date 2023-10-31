#!/usr/bin/env python3
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
# Description : LocalCheckOS.py is a utility to check OS info on local node.
#############################################################################
import os
import sys
import subprocess
import glob
import getopt
import subprocess
import platform
import time
import re
from datetime import datetime

localDirPath = os.path.dirname(os.path.realpath(__file__))

sys.path.append(sys.path[0] + "/../")
from gspylib.common.ParameterParsecheck import Parameter
from os_platform.UserPlatform import g_Platform
from gspylib.common.GaussLog import GaussLog
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.config_param import ConfigParam
from base_utils.os.disk_util import DiskUtil
from domain_utils.cluster_file.version_info import VersionInfo
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from os_platform.linux_distro import LinuxDistro
from os_platform.common import SUPPORT_RHEL6X_VERSION_LIST, \
    SUPPORT_RHEL7X_VERSION_LIST, SUPPORT_SUSE12X_VERSION_LIST, \
    SUPPORT_SUSE11X_VERSION_LIST, SUPPORT_RHEL8X_VERSION_LIST, \
    SUPPORT_RHEL_LEAST_VERSION

sys.path.insert(0, localDirPath + "/../../lib")
import psutil

ACTION_CHECK_OS_VERSION = "Check_OS_Version"
ACTION_CHECK_KERNEL_VERSION = "Check_Kernel_Version"
ACTION_CHECK_UNICODE = "Check_Unicode"
ACTION_CHECK_TIMEZONE = "Check_TimeZone"
ACTION_CHECK_DISK_CONFIGURE = "Check_Disk_Configure"
ACTION_CHECK_BLOCKDEV_CONFIGURE = "Check_BlockDev_Configure"
ACTION_CHECK_IO_CONFIGURE = "Check_IO_Configure"
ACTION_CHECK_LOGICAL_BLOCK = "Check_Logical_Block"
ACTION_CHECK_IO_REQUEST = "Check_IO_Request"
ACTION_CHECK_ASYNCHRONOUS_IO_REQUEST = "Check_Asynchronous_IO_Request"
ACTION_CHECK_NETWORK_CONFIGURE = "Check_Network_Configure"
ACTION_CHECK_NETWORK_BOND_MODE = "Check_Network_Bond_Mode"
ACTION_CHECK_SWAP_MEMORY_CONFIGURE = "Check_Swap_Memory_Configure"
ACTION_CHECK_TIME_CONSISTENCY = "Check_Time_Consistency"
ACTION_CHECK_FIREWALL_SERVICE = "Check_Firewall_Service"
ACTION_CHECK_THP_SERVICE = "Check_THP_Service"

ACTION_SET_BLOCKDEV_CONFIGURE = "Set_BlockDev_Configure"
ACTION_SET_IO_CONFIGURE = "Set_IO_Configure"
ACTION_SET_REMOVEIPC_VALUE = "Set_RemoveIPC_Value"
ACTION_SET_SESSION_PROCESS = "Set_Session_Process"
ACTION_SET_NETWORK_CONFIGURE = "Set_Network_Configure"
ACTION_SET_THP_SERVICE = "Set_THP_Service"
ACTION_SET_LOGICAL_BLOCK = "Set_Logical_Block"
ACTION_SET_IO_REQUEST = "Set_IO_REQUEST"
ACTION_SET_ASYNCHRONOUS_IO_REQUEST = "Set_Asynchronous_IO_Request"

#############################################################################
# Global variables
#############################################################################
netWorkLevel = 10000
expectMTUValue = 8192
expectRXValue = 4096
expectTXValue = 4096
MASTER_INSTANCE = 0
STANDBY_INSTANCE = 1

g_logger = None
g_opts = None
g_clusterInfo = None
netWorkBondInfo = None
g_readlist = None


###########################################################################
# mounts
###########################################################################
class mounts:
    """
    Class: mounts
    """

    def __init__(self):
        """
        function : Init class mounts
        input  : NA
        output : NA
        """
        self.entries = dict()  # dictionary key=partition value=mount object
        self.errormsg = None


class GSMount:
    """
    Class: GSMount
    """

    def __init__(self):
        """
        function : Init class GSMount
        input  : NA
        output : NA
        """
        self.partition = None
        self.dir = None
        self.type = None
        self.options = set()  # mount options

    def __str__(self):
        """
        function : Convert to a string
        input  : NA
        output : string
        """
        optionstring = ''
        first = True
        for k in self.options:
            if not first:
                optionstring = "%s," % optionstring
            thisoption = k
            optionstring = "%s%s" % (optionstring, thisoption)
            first = False
        return "%s on %s type %s (%s)" % (self.partition, self.dir,
                                          self.type, optionstring)


def collectMounts():
    """
    function : Collector mounts
    input  : NA
    output : Instantion
    """
    data = mounts()
    p = subprocess.Popen(["mount"], shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    result = p.communicate()
    data.errormsg = result[1].decode().strip()
    if p.returncode:
        return data

    for line in result[0].decode().splitlines():
        mdata = GSMount()
        words = line.strip().split()
        mdata.partition = words[0]
        mdata.dir = words[2]
        mdata.type = words[4]
        # get the options string
        tmpa = words[5]
        tmpb = tmpa.strip().strip("()")
        tmpc = tmpb.split(",")
        for op in tmpc:
            mdata.options.add(op)
        data.entries[mdata.partition] = mdata
    return data


###########################################################################
# blockdev:
###########################################################################
class blockdev:
    """
    Class: blockdev
    """

    def __init__(self):
        """
        function : Init class blockdev
        input  : NA
        output : NA
        """
        self.ra = dict()  # key is device name value is getra value
        self.errormsg = ''


def collectBlockdev():
    """
    function : Collector blockdev
    input  : NA
    output : Instantion
    """
    data = blockdev()
    devices = list()
    try:
        # If the directory of '/' is disk array, all disk prereads will be set
        devlist = DiskUtil.getDevices()
        cmd = "mount | awk '{if( $3==\"/\" ) print $1}' |" \
              " sed 's/\/dev\///' | sed 's/[0-9]//'"
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                             + " Error: \n%s" % output)
        for dev in devlist:
            if (dev.strip() == output.strip()):
                continue
            devices.append("/dev/%s" % dev)
    except Exception as e:
        data.errormsg = e.__str__()

    for d in devices:
        p = subprocess.Popen(["/sbin/blockdev", "--getra", "%s" % d],
                             shell=False, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()
        data.errormsg += result[1].decode().strip()
        if p.returncode:
            continue
        data.ra[d] = result[0].decode().strip()

    return data


###########################################################################
# platform: uname
###########################################################################
class uname:
    """
    Class: uname
    """

    def __init__(self):
        """
        function : Init class uname
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectUname():
    """
    function : Collector uname
    input  : NA
    output : Instantion
    """
    data = uname()
    p = subprocess.Popen(["uname", "-r"], shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    result = p.communicate()
    data.errormsg = result[1].decode().strip()
    if p.returncode:
        return data
    data.output = result[0].decode().strip()
    return data


###########################################################################
# unicode
###########################################################################
class codename:
    """
    Class: codename
    """

    def __init__(self):
        """
        function : Init class codename
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectUnicode():
    """
    function : Collector unicode
    input  : NA
    output : Instantion
    """
    data = codename()
    cmd = "locale | grep '^LANG='"
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception((ErrorCode.GAUSS_505["GAUSS_50502"] % "Unicode") +
                        ("The cmd is : %s" % cmd))
    data.output = output
    return data


###########################################################################
# timezone
###########################################################################

class timezone:
    """
    Class: timezone
    """

    def __init__(self):
        """
        function : Init class timezone
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectTimeZone():
    """
    function : Collector timezone
    input  : NA
    output : Instantion
    """
    data = timezone()
    cmd = "date -R | awk -F ' ' '{print $NF}'"
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception((ErrorCode.GAUSS_505["GAUSS_50502"] % "TimeZone") +
                        ("The cmd is : %s" % cmd))
    data.output = output
    return data


###########################################################################
# platform: version
###########################################################################
class platformInfo:
    """
    Class: platformInfo
    """

    def __init__(self):
        """
        function : Init class platforminfo
        input  : NA
        output : NA
        """
        self.distname = ""
        self.version = ""
        self.id = ""
        self.bits = ""
        self.linkage = ""
        self.patchlevel = ""


def collectplatformInfo():
    """
    function : Collector platforminfo
    input  : NA
    output : Instantion
    """
    data = platformInfo()
    distname, version, idnum = LinuxDistro.linux_distribution()
    bits, linkage = platform.architecture()

    data.distname = distname
    data.version = version
    data.id = idnum
    data.bits = bits
    data.linkage = linkage

    # os-release is added since SLE 12;
    # SuSE-release will be removed in a future service pack or release
    if (distname == "SuSE" and version in ("11", "12")):
        if os.path.exists('/etc/SuSE-release'):
            cmd = "grep -i 'PATCHLEVEL' /etc/SuSE-release  |" \
                  " awk -F '=' '{print $2}'"
        else:
            cmd = "grep -i 'VERSION_ID' /etc/os-release  |" \
                  " awk -F '.' '{print $2}' | sed 's/\"//'"
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status == 0 and output != ""):
            data.patchlevel = output.strip()
        else:
            g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                             + " Error: \n%s " % output)

    return data


###########################################################################
# I/O schedulers
###########################################################################
class ioschedulers:
    """
    Class: ioschedulers
    """

    def __init__(self):
        """
        function : Init class ioschedulers
        input  : NA
        output : NA
        """
        # key is device name, value is scheduler name
        self.devices = dict()
        self.errormsg = ''
        # key is device name, value is optional configuration list
        self.all_item = {}


def collectIOschedulers():
    """
    function : Collector IOschedulers
    input  : NA
    output : Instantion
    """
    data = ioschedulers()
    devices = set()
    try:
        files = DiskUtil.getDevices()
        for f in files:
            fname = "/sys/block/%s/queue/scheduler" % f
            words = fname.split("/")
            if len(words) != 6:
                continue
            devices.add(words[3].strip())
    except Exception as e:
        data.errormsg = e.__str__()

    for d in devices:
        try:
            with open("/sys/block/%s/queue/scheduler" % d, 'r') as fd:
                scheduler = fd.read()
            words = scheduler.split("[")
            if len(words) != 2:
                continue
            words = words[1].split("]")
            if len(words) != 2:
                continue
            data.devices[d] = words[0].strip()
            data.all_item[d] = scheduler.replace("[", "").replace("]",
                                                                 "").split()
        except Exception as e:
            data.errormsg += e.__str__()

    return data


###########################################################################
# I/O REQUEST   #device_name
###########################################################################
class ioRequest():
    """
    Class: ioRequest
    """

    def __init__(self):
        """
        function : Init class ioRequest
        input  : NA
        output : NA
        """
        self.devices = dict()
        self.errormsg = ''


def collectIORequest():
    """
    function : Collector ioRequest
    input  : NA
    output : Dict
    """
    data = ioRequest()
    devices = []

    try:
        files = glob.glob("/sys/block/*/queue/nr_requests")
        for f in files:
            words = f.split("/")
            if len(words) != 6:
                continue
            devices.append(words[3].strip())
    except Exception as e:
        data.errormsg = e.__str__()

    result = {}
    for d in devices:
        try:
            with open("/sys/block/%s/queue/nr_requests" % d, 'r') as fd:
                request = fd.read()
            result[d] = request
        except Exception as e:
            data.errormsg += e.__str__()

    return result


###########################################################################
# Asynchronous I/O REQUEST   #device_name
###########################################################################
class AsynchronousIoRequest():
    """
    Class: AsynchronousIoRequest
    """

    def __init__(self):
        """
        function : Init class AsynchronousIoRequest
        input  : NA
        output : NA
        """
        self.devices = dict()
        self.errormsg = ''


def collectAsynchronousIORequest():
    """
    function : Collector AsynchronousIORequest
    input  : NA
    output : List
    """
    data = AsynchronousIoRequest()
    result = []
    try:
        with open("/proc/sys/fs/aio-max-nr", 'r') as fd:
            request = fd.read()
            result.append(request)
    except Exception as e:
        data.errormsg += e.__str__()

    return result


###########################################################################
# LogicalBlock
###########################################################################
class LogicalBlock():
    """
    class: LogicalBlock
    """

    def __init__(self):
        """
        function : Init class LogicalBlock
        input  : NA
        output : NA
        """
        self.devices = dict()
        self.errormsg = ''


def collectLogicalBlock():
    """
    function : Collector LogicalBlock
    input  : NA
    output : Dict
    """
    data = LogicalBlock()
    devices = set()

    try:
        files = glob.glob("/sys/block/*/queue/logical_block_size")
        for f in files:
            words = f.split("/")
            if len(words) != 6:
                continue
            devices.add(words[3].strip())
    except Exception as e:
        data.errormsg = e.__str__()

    result = {}
    for d in devices:
        try:
            with open("/sys/block/%s/queue/logical_block_size" % d, 'r') as fd:
                request = fd.read()
            result[d] = request
        except Exception as e:
            data.errormsg += e.__str__()

    return result


###########################################################################
# getTHPandOSInitFile:
###########################################################################
def getTHPandOSInitFile():
    """
    function : We know that the centos have same init file and THP file
     as RedHat.
    input  : NA
    output : String, String
    """
    THPFile = "/sys/kernel/mm/transparent_hugepage/enabled"
    initFile = DefaultValue.getOSInitFile()
    if (initFile == ""):
        raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                        % "startup file of current OS" +
                        " The startup file for SUSE OS is"
                        " /etc/init.d/boot.local.The startup file for Redhat"
                        " OS is /etc/rc.d/rc.local.")
    return (THPFile, initFile)


###########################################################################
# THP Server:
###########################################################################
class THPServer:
    """
    Class: THPServer
    """

    def __init__(self):
        """
        function : Init class THPServer
        input  : NA
        output : NA
        """
        self.status = ""


def collectTHPServer():
    """
    function : collect THPServer
    input  : NA
    output : instantion
    """
    data = THPServer()
    THPFile = getTHPandOSInitFile()[0]
    if (os.path.exists(THPFile)):
        cmd = "grep '\[never\]' %s | wc -l" % THPFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.debug("Failed to obtain THP service status. Commands for"
                           " obtaining THP server status: %s." % cmd)
            g_logger.logExit(ErrorCode.GAUSS_510["GAUSS_51001"]
                             + " Error: \n%s" % output)
        if (output.strip().isdigit()):
            num = int(output.strip())
        else:
            num = 1
        if (num > 0):
            data.status = "disabled"
        else:
            data.status = "enabled"
    else:
        data.status = "disabled"
    return data


def disRemoveIPC():
    """
    function : close RemoveIPC
    input  : NA
    output : NA
    """
    g_logger.debug("disbale RemoveIPC.")
    distName = g_Platform.getCurrentPlatForm()[0]
    if distName.upper() in ("OPENEULER", "FUSIONOS", "KYLIN"):
        cmd = "setenforce 0"
        subprocess.getstatusoutput(cmd)
        initFile = "/usr/lib/systemd/system/systemd-logind.service"
        if os.path.exists(initFile):
            close_cmd = "if [ `systemctl show systemd-logind | " \
                        "grep RemoveIPC` != \"RemoveIPC=no\" ]; " \
                        "then echo 'RemoveIPC=no' >> " \
                        "/usr/lib/systemd/system/systemd-logind.service; " \
                        "sed -i '/RemoveIPC=yes/'d " \
                        "/usr/lib/systemd/system/systemd-logind.service; fi;"
            disableRemoveIPCLog(close_cmd)
        initFile = "/etc/systemd/logind.conf"
        if os.path.exists(initFile):
            close_cmd = "if [ `loginctl show-session | " \
                        "grep RemoveIPC` != \"RemoveIPC=no\" ]; " \
                        "then echo 'RemoveIPC=no' >> " \
                        "/etc/systemd/logind.conf; " \
                        "sed -i '/RemoveIPC=yes/'d " \
                        "/etc/systemd/logind.conf; fi;"
            disableRemoveIPCLog(close_cmd)
        cmd = "systemctl daemon-reload"
        disableRemoveIPCLog(cmd)

        cmd = "systemctl restart systemd-logind"
        disableRemoveIPCLog(cmd)

        cmd = "systemctl show systemd-logind | grep RemoveIPC && " \
              "loginctl show-session | grep RemoveIPC"
        output = disableRemoveIPCLog(cmd)
        ipc_check_num = 0
        for result in output.split("\n"):
            if result == "RemoveIPC=no":
                ipc_check_num = ipc_check_num + 1
        if ipc_check_num < 1:
            g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                             + " Error: \n cmd:\"systemctl show systemd-logind"
                               " | grep RemoveIPC and  loginctl show-session "
                               "| grep RemoveIPC\" The result"
                               " cannot be all no")
    g_logger.debug("Successfully change RemoveIPC to no.")

def disableRemoveIPCLog(cmd):
    """
    function : disable remove IPCLog
    input  : cmd
    output : NA
    """
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Failed to disbale RemoveIPC. Commands"
                       " for disbale RemoveIPC: %s." % cmd)
        g_logger.logExit(ErrorCode.GAUSS_510["GAUSS_51002"]
                         + " Error: \n%s" % output)
    return output



def CheckSessionProcess():
    """
    function : Set User Session Process Control
    input  : NA
    output : NA
    """
    g_logger.debug("Setting User Session Process Control.")
    etcFile = "/etc/pam.d/sshd"
    if os.path.exists(etcFile):
        set_cmd = "sed -i '/.*session\+.*pam_limits\.so/d' /etc/pam.d/sshd;" \
                  "echo 'session    required     pam_limits.so' >> " \
                  "/etc/pam.d/sshd;  "
        setSeesionProcess(set_cmd)
    g_logger.debug("Successfully Set Session Process.")

def setSeesionProcess(cmd):
    """
    function : Set User Session Process Control
    input  : cmd
    output : NA
    """
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Failed to set session process. Commands"
                       " for set session process: %s." % cmd)
        g_logger.logExit(ErrorCode.GAUSS_510["GAUSS_51003"]
                         + " Error: \n%s" % output)
    return output



def disTHPServer():
    """
    function : close THP Server
    input  : NA
    output : NA
    """
    g_logger.debug("Closing the THP service.")
    (THPFile, initFile) = getTHPandOSInitFile()
    if (os.path.exists(initFile)):
        # 1.close thp
        close_cmd = "(if test -f '%s'; then echo never > %s;fi)" \
                    % (THPFile, THPFile)
        (status, output) = subprocess.getstatusoutput(close_cmd)
        if (status != 0):
            g_logger.debug("Failed to close THP service. Commands"
                           " for closing THP server: %s." % close_cmd)
            g_logger.logExit(ErrorCode.GAUSS_510["GAUSS_51002"]
                             + " Error: \n%s" % output)
        # 2.add close cmd to init file
        cmd = "sed -i '/^.*transparent_hugepage.*enabled.*echo" \
              " never.*$/d' %s &&" % initFile
        cmd += "echo \"%s\" >> %s" % (close_cmd, initFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                             + " Error: \n%s" % output)
    g_logger.debug("Successfully closed the THP service.")


###########################################################################
# network card parameter:
###########################################################################
class netWork:
    """
    Class: netWork
    """

    def __init__(self):
        """
        function : Init class netWork
        input  : NA
        output : NA
        """
        self.netLevel = ""
        self.netNum = ""
        self.variables = dict()
        self.modeType = False
        self.nums = 0


def CheckNetWorkBonding(serviceIP, bondMode=False):
    """
    function : Check NetWork ConfFile
    input  : String, bool
    output : List
    """
    networkCardNum = NetUtil.getNICNum(serviceIP)
    NetWorkConfFile = DefaultValue.getNetWorkConfFile(networkCardNum)
    if (NetWorkConfFile.find("No such file or directory") >= 0
            and DefaultValue.checkDockerEnv()):
        return
    networkCardNumList = []
    networkCardNumList.append(networkCardNum)
    bondingConfFile = "/proc/net/bonding/%s" % networkCardNum
    teamConfFile = "/etc/sysconfig/network-scripts/ifcfg-%s" % networkCardNum
    if os.path.exists(NetWorkConfFile):
        cmd = "grep -i 'BONDING_OPTS\|BONDING_MODULE_OPTS' %s" \
              % NetWorkConfFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if ((status == 0) and (output.strip() != "")):
            if ((output.find("mode") > 0)
                    and os.path.exists(bondingConfFile)):
                networkCardNumList = networkCardNumList + \
                                     checkBondMode(bondingConfFile, bondMode)
            elif os.path.exists(teamConfFile):
                networkCardNumList = networkCardNumList + checkTeamMode(teamConfFile, bondMode)
            else:
                g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"] +
                                 "The cmd is " + cmd)
        else:
            g_logger.log("BondMode Null")
    else:
        flag = NetUtil.getNetWorkBondFlag(networkCardNum)[0]
        if flag:
            if os.path.exists(bondingConfFile):
                networkCardNumList = networkCardNumList + \
                                     checkBondMode(bondingConfFile, bondMode)
            elif os.path.exists(teamConfFile):
                networkCardNumList = networkCardNumList + checkTeamMode(teamConfFile, bondMode)
            else:
                g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"]
                                 + "Without NetWorkConfFile mode.")
        else:
            g_logger.log("BondMode Null")
    if (len(networkCardNumList) != 1):
        del networkCardNumList[0]
    return networkCardNumList


def checkBondMode(bondingConfFile, isCheck):
    """
    function : Check Bond mode
    input  : String, bool
    output : List
    """
    netNameList = []

    cmd = "grep -w 'Bonding Mode' %s | awk  -F ':' '{print $NF}'" \
          % bondingConfFile
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0 or output.strip() == ""):
        g_logger.debug("Failed to obtain network card bonding information."
                       " Commands for getting: %s." % cmd)
        g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"]
                         + " Error: \n%s" % output)

    if ("active-backup" in output):
        netWorkBondInfo.modeType = 1
        netWorkBondInfo.nums = 0
    if isCheck:
        g_logger.log("BondMode %s" % output.strip())
    else:
        cmd = "grep -w 'Slave Interface' %s | awk  -F ':' '{print $NF}'" \
              % bondingConfFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.debug("Failed to obtain network card bonding "
                           "information. Commands for getting: %s." % cmd)
            g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"]
                             + " Error: \n%s" % output)
        for networkname in output.split('\n'):
            netNameList.append(networkname.strip())
            netWorkBondInfo.nums = netWorkBondInfo.nums + 1
    return netNameList

def checkTeamMode(teamConfFile, isCheck):
    """
    function : Check Team mode
    input  : String, bool
    output : List
    """
    teamModeList = []
    networkCardNum = NetUtil.getNICNum(serviceIP)

    cmd = "grep -w 'DEVICE' %s | awk  -F ':' '{print $NF}'" \
          % teamConfFile
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0 or output.strip() == ""):
        g_logger.debug("Failed to obtain network card teaming information."
                       " Commands for getting: %s." % cmd)
        g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"]
                         + " Error: \n%s" % output)

    teamMode = output.strip()

    if isCheck:
        g_logger.log("Teaming Mode: %s" % teamMode)
    else:
        cmd = "teamdctl %s state" % networkCardNum
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.debug("Failed to obtain network card teaming "
                           "information. Commands for getting: %s." % cmd)
            g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50611"]
                             + " Error: \n%s" % output)
            
        match = re.search(r"active port: (\w+)", output)
        if match:
            active_port = match.group(1)
            teamModeList.append(active_port)
    return teamModeList


def getNetWorkTXRXValue(networkCardNum, valueType):
    """
    function : Check Bond mode
    input  : int, String
    output : int
    """
    cmd = "/sbin/ethtool -g %s | grep '%s:' | tail -n 2" % (networkCardNum,
                                                            valueType)
    (status, output) = subprocess.getstatusoutput(cmd)
    if (output.find("Operation not supported") >= 0
            and DefaultValue.checkDockerEnv()):
        g_logger.log("        Warning reason: Failed to obtain the"
                     " network card TXRX value in docker container. Commands "
                     "for obtain the network card TXRX: %s. Error: \n%s"
                     % (cmd, output))
        return (0, 0)
    if (status != 0 or len(output.splitlines()) != 2):
        g_logger.debug("Failed to obtain network card %s value. Commands"
                       " for getting information: %s." % (valueType, cmd))
        g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50612"]
                         % valueType + " Error: \n%s" % output)

    # redhat2.0 here means EulerOS, because we get the os version 2.0
    valueMax = output.splitlines()[0].split(':')[1].split(' ')[0].strip()
    valueStr = output.splitlines()[1].split(':')[1].split(' ')[0].strip()
    if (not str(valueStr).isdigit() or not str(valueMax).isdigit()):
        g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50612"] % valueType
                         + " Error: \ncmd:%s\noutput:%s" % (cmd, output))
    if (int(valueMax) < int(valueStr)):
        valueTmp = valueMax
        valueMax = valueStr
        valueStr = valueTmp
    return (int(valueStr), int(valueMax))


def GetNetWorkCardInfo(networkCardNum):
    """
    function : Get NetWorkCard Info
    input  : int
    output : instantion
    """
    # set network card mtu and queue length
    g_logger.debug("Obtaining the value about mtu and queue length"
                   " from network card configuration.")
    data = netWork()
    data.netNum = networkCardNum
    # check the network card format. 
    #   if Speed >= 10000Mb/s, do the setting; else, nothing
    cmdGetSpeedStr = "/sbin/ethtool %s | grep 'Speed:'" % networkCardNum
    (status, output) = subprocess.getstatusoutput(cmdGetSpeedStr)
    if (status == 0 and output.find("Speed:") >= 0
            and output.find("Mb/s") >= 0):
        data.netLevel = int(output.split(':')[1].strip()[:-4])
        # get default mtu value
        valueMTU = psutil.net_if_stats()[networkCardNum].mtu
        data.variables["mtu"] = valueMTU
        if (data.netLevel >= int(netWorkLevel)):
            # get default rx value
            (valueRX, valueRXMax) = getNetWorkTXRXValue(networkCardNum, "RX")
            data.variables["rx"] = valueRX
            data.variables["rx_max"] = valueRXMax
            # get default tx value
            (valueTX, valueTXMax) = getNetWorkTXRXValue(networkCardNum, "TX")
            data.variables["tx"] = valueTX
            data.variables["tx_max"] = valueTXMax
        else:
            g_logger.debug("Warning: The speed of current card \"%s\""
                           " is less than %s Mb/s." % (networkCardNum,
                                                       netWorkLevel))
    elif (netWorkBondInfo.modeType == 1):
        data.netLevel = int(0)
        netWorkBondInfo.nums = netWorkBondInfo.nums - 1
        if (output.find("Speed:") >= 0):
            g_logger.log("        Warning reason: Obtain the network card "
                         "speed value is failed. Maybe the network card "
                         "\"%s\" is not working." % networkCardNum)
        else:
            g_logger.log("        Warning reason: Obtain the network card "
                         "speed value is failed. Commands for obtain the "
                         "network card speed: %s. Error: \n%s"
                         % (cmdGetSpeedStr, output))

        if (netWorkBondInfo.nums == 0):
            g_logger.log("        Warning reason: Failed to obtain speed rate"
                         " value for all bound networks card.")
    else:
        data.netLevel = int(0)
        if (output.find("Speed:") >= 0):
            g_logger.log("        Warning reason: Failed to obtain the "
                         "network card speed value. Maybe the network card"
                         " \"%s\" is not working." % networkCardNum)
        else:
            g_logger.log("        Warning reason: Failed to obtain the"
                         " network card speed value. Commands for obtain"
                         " the network card speed: %s. Error: \n%s"
                         % (cmdGetSpeedStr, output))
    g_logger.debug("Successfully obtained the mtu and queue length value"
                   " from network card.")
    return data


def setNetWorkMTUOrTXRXValue(networkCardNum, valueType,
                             expectValue, initFileName):
    """
    function : Set NetWork MTU Or TXRX Value
    input  : int, String, String, String
    output : NA
    """
    if (valueType == "tx" or valueType == "rx"):
        cmd = "/sbin/ethtool -G %s %s %s" % (networkCardNum,
                                             valueType, expectValue)

    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        if (valueType == 'tx' or valueType == 'rx'):
            if (output.find("no ring parameters changed, aborting") < 0):
                isPrint = True
            else:
                isPrint = False
        else:
            isPrint = True
        if isPrint:
            g_logger.debug("Failed to set network card %s value."
                           " Commands for setting: %s." % (valueType, cmd))
            g_logger.logExit(ErrorCode.GAUSS_506["GAUSS_50613"]
                             % valueType + " Error: \n%s" % output)

    # write setting cmds into init file
    if (valueType == "tx" or valueType == "rx"):
        cmd_write = "sed -i \"/^.*\\/sbin\\/ethtool -G %s %s %s$/d\" %s" \
                   % (networkCardNum, valueType, expectValue, initFileName)

    cmdInit = """%s && echo "%s">>%s""" % (cmdWrite, cmd, initFileName)
    (status, output) = subprocess.getstatusoutput(cmdInit)
    if (status != 0):
        g_logger.debug("Faile to write %s setting commands into init file."
                       " Commands for setting: %s." % (valueType, cmdInit))
        g_logger.logExit(ErrorCode.GAUSS_502["GAUSS_50205"]
                         % initFileName + " Error: \n%s" % output)


def SetNetWorkCardInfo(networkCardNum, data):
    """
    function : Set NetWorkCard Info
    input  : int, instantion, Bool
    output : NA
    """
    g_logger.debug("Setting the network card configuration value.")

    if (int(data.netLevel) >= int(netWorkLevel)):
        initFile = getTHPandOSInitFile()[1]
        for k in list(data.variables.keys()):
            if ((k == "rx") and int(data.variables[k].__str__()) < expectRXValue):
                targetValue = min(expectRXValue, int(data.variables["rx_max"].__str__()))
                setNetWorkMTUOrTXRXValue(
                    data.netNum, k,
                    targetValue,
                    initFile)
                g_logger.debug(
                    "Set the \"%s\" '%s' value from \"%s\" to \"%s\"."
                    % (networkCardNum, k, int(data.variables[k].__str__()), targetValue))
            if ((k == "tx") and int(data.variables[k].__str__()) < expectTXValue):
                targetValue = min(expectTXValue, int(data.variables["tx_max"].__str__()))
                setNetWorkMTUOrTXRXValue(
                    data.netNum, k,
                    targetValue,
                    initFile)
                g_logger.debug(
                    "Set the \"%s\" '%s' value from \"%s\" to \"%s\"."
                    % (networkCardNum, k, int(data.variables[k].__str__()), targetValue))
        # after doing setting the value, please wait a moment,
        # then we can get the real netwrok card information.
        time.sleep(2)

    g_logger.debug("Successfully setted the network card value.")


def CheckNetWorkCardInfo(data):
    """
    function : Check NetWorkCard Info
    input  : Instantion
    output : NA
    """
    g_logger.debug("Checking the network card configuration value.")
    for k in list(data.variables.keys()):
        value = int(data.variables[k].__str__())
        if (k == "mtu"):
            if g_opts.mtuValue != "" and int(value) != int(g_opts.mtuValue):
                g_logger.log("        Abnormal:"
                             " network '%s' '%s' value[%s:%s]"
                             " is different from the other node [%s:%s]"
                             % (data.netNum, k,
                                NetUtil.GetHostIpOrName(),
                                value, g_opts.hostname, g_opts.mtuValue))
            elif (int(value) != int(expectMTUValue)):
                g_logger.log("        Warning reason: network '%s' '%s'"
                             " RealValue '%s' ExpectedValue '%s'"
                             % (data.netNum, k, value, expectMTUValue))

        elif ((k == "rx") and
              int(value) < int(data.variables["rx_max"].__str__())):
            if (int(data.netLevel) >= int(netWorkLevel)):
                g_logger.log("        Warning reason: network '%s' '%s'"
                             " RealValue '%s' ExpectValue '%s'."
                             % (data.netNum, k, value,
                                data.variables["rx_max"].__str__()))
        elif ((k == "tx") and
              int(value) < int(data.variables["tx_max"].__str__())):
            if (int(data.netLevel) >= int(netWorkLevel)):
                g_logger.log("        Warning reason: network '%s' '%s' "
                             "RealValue '%s' ExpectValue '%s'."
                             % (data.netNum, k, value,
                                data.variables["tx_max"].__str__()))
            else:
                g_logger.log("        network '%s' '%s' RealValue '%s'"
                             " ExpectValue '%s'. [Normal]"
                             % (data.netNum, k, value,
                                data.variables["tx_max"].__str__()))

    g_logger.debug("Successfully checked the network card value.")


def GetInterruptCountNum(cardname):
    """
    function : We can makesure that all dev names is startwith 'ethX-'
     and endwith '-X'
    input  : String
    output : Int
    """
    cmd = "cat /proc/interrupts | grep '%s-' | wc -l" % cardname
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        g_logger.debug("Failed to obtain network card interrupt"
                       " count numbers. Commands for getting interrupt"
                       " count numbers: %s." % cmd)
        g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                         + " Error: \n%s" % output)

    if (not str(output.strip()).isdigit()):
        return 0
    return int(output.strip())


def CheckNetWorkCardInterrupt(data, isSetting=False):
    """
    function : Check NetWorkCard Interrupt
    input  : Instantion, Bool
    output : NA
    """
    g_logger.debug("Setting the network card interrupt value.")
    if (int(data.netLevel) >= int(netWorkLevel)):
        cmd = "for i in `cat /proc/interrupts | grep '%s-' |" \
              " awk -F ' ' '{print $1}' | awk -F ':' '{print $1}'`;" \
              " do cat /proc/irq/$i/smp_affinity ; done" % data.netNum
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            g_logger.debug("Failed to obtain network card interrupt value."
                           " Commands for getting interrupt value: %s." % cmd)
            g_logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                             + " Error: \n%s" % output)

        # cpu core number followed by 1 2 4 8,every 4 left shift one
        Mapping = {0: "1", 1: "2", 2: "4", 3: "8"}
        flag = "Normal"
        for index, eachLine in enumerate(output.split()):
            # Remove the ','
            eachLine = eachLine.replace(",", "")
            # Replace 0000,00001000 to 1,Remove invalid content
            validValue = eachLine.replace("0", "")
            # Convert the row index to the expected value
            expandNum = Mapping[index % 4]
            # Convert line index to expected position
            expandBit = index // 4 * -1 - 1
            # value and position is correct
            if (len(eachLine) * -1) > expandBit:
                g_logger.debug("Network card [%s] multi-queue support is"
                               " not enabled.\n" % data.netNum)
                flag = "Error"
                break
            if (eachLine[expandBit] == expandNum and validValue == expandNum):
                continue
            else:
                g_logger.debug("Network card [%s] multi-queue support is not"
                               " enabled.\n" % data.netNum)
                flag = "Error"
                break
        if (flag == "Normal"):
            pass
        else:
            if (isSetting):
                g_logger.debug("The network card '%s' interrupt is not"
                               " be setted." % data.netNum)
                cmd = "ps ax | grep -v grep | grep -q irqbalance; echo $?"
                (status, output) = subprocess.getstatusoutput(cmd)
                if (output.strip() == "0"):
                    g_logger.log("        Warning: irqbalance is running and"
                                 " will likely override this script's"
                                 " affinitization. Please stop the irqbalance"
                                 " service and/or execute 'killall"
                                 " irqbalance'.")
                    killcmd = "%s irqbalance" % CmdUtil.findCmdInPath("killall")
                    (status, output) = subprocess.getstatusoutput(killcmd)
                    if status != 0:
                        g_logger.log("Failed to execute killall irqbalance")
                count = int(GetInterruptCountNum(data.netNum))
                i = 0
                while (i < count):
                    # the dev name type like this: eth1-1,
                    # eth1-rx-1, eth1-tx-1, eth1-TxRx-1
                    cmd_IRQ = "cat /proc/interrupts | grep '%s.*-' | " \
                              "awk -F ' ' '{print $1}' | awk -F ':' " \
                              "'{print $1}'| awk 'NR==%s'" \
                              % (data.netNum, str(i + 1))
                    (status, output) = subprocess.getstatusoutput(cmd_IRQ)
                    if status != 0 or output.strip() == "":
                        g_logger.debug(
                            "Failed to obtain network card interrupt value. "
                            "Commands for getting interrupt value: %s."
                            % cmd_IRQ)
                    else:
                        IRQ = output.strip()
                        g_logger.log("The network '%s' interrupt "
                                     "configuration path:"
                                     " /proc/irq/%s/smp_affinity."
                                     % (data.netNum, IRQ))
                        num = 2 ** i
                        # Under SuSE platform, when the length is
                        # greater than 8, the ',' must be used.
                        value = str(hex(num))[2:]
                        if (len(value) > 16 and value[-1] == 'L'):
                            value = value[:-1]
                        result_value = ''
                        while (len(value) > 8):
                            result_value = ",%s%s" \
                                           % (value[-8:], result_value)
                            value = value[:-8]
                        result_value = "%s%s" % (value, result_value)
                        cmd_set = "echo '%s'> /proc/irq/%s/smp_affinity" \
                                  % (result_value, IRQ)
                        (status, output) = subprocess.getstatusoutput(cmd_set)
                        if (status != 0):
                            g_logger.log(
                                "Failed to set network '%s' IRQ. Commands for"
                                " setting: %s." % (data.netNum, cmd_set))
                        else:
                            g_logger.log(
                                "Set network card '%s' IRQ to \"%s\"."
                                % (data.netNum, result_value))
                    i = i + 1

    g_logger.debug("Successfully setted the network card interrupt value.")


def CheckNetWorkCardPara(serviceIP, isSetting=False):
    """
    function : Check NetWorkCard Para
    input  : String, Bool
    output : NA
    """

    global expectMTUValue

    # get the network parameter values from the configuration file
    dirName = os.path.dirname(os.path.realpath(__file__))
    configFile = "%s/../gspylib/etc/conf/check_list.conf" % dirName
    checkList = ['mtu', 'rx', 'tx']
    netParameterList = ConfigParam.getConfigFilePara(configFile,
                                                     '/sbin/ifconfig',
                                                     checkList)
    if (('mtu' in list(netParameterList.keys())) and
            (netParameterList['mtu'].strip() != '')):
        expectMTUValue = netParameterList['mtu'].strip()

    # set network card mtu and queue length
    networkCardNumList = DefaultValue.CheckNetWorkBonding(serviceIP)

    # if len=1, it means that there is no bonding
    if (len(networkCardNumList) == 1):
        data = GetNetWorkCardInfo(networkCardNumList[0].strip())
        if not isSetting:
            CheckNetWorkCardInfo(data)
            CheckNetWorkCardInterrupt(data)
        else:
            SetNetWorkCardInfo(networkCardNumList[0].strip(), data)
            CheckNetWorkCardInterrupt(data, True)
    else:
        for networkCardNum in networkCardNumList:
            data = GetNetWorkCardInfo(networkCardNum)
            if not isSetting:
                CheckNetWorkCardInfo(data)
                CheckNetWorkCardInterrupt(data)
            else:
                SetNetWorkCardInfo(networkCardNum, data)
                CheckNetWorkCardInterrupt(data, True)


###########################################################################
# meminfo:  
###########################################################################
class meminfo:
    """
    Class: meminfo
    """

    def __init__(self):
        """
        function : Init class meminfo
        input  : NA
        output : NA
        """
        self.memvalue = 0
        self.errormsg = None


class swapinfo:
    """
    class: swapinfo
    """

    def __init__(self):
        """
        function : Init class swapinfo
        input  : NA
        output : NA
        """
        self.swapvalue = 0
        self.errormsg = None


def collectSwapInfo():
    """
    function : Collect Swap Info
    input  : NA
    output : Instantion
    """
    data = swapinfo()
    cmd = "cat /proc/meminfo | grep SwapTotal"
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception((ErrorCode.GAUSS_505["GAUSS_50502"] % "SwapTotal") +
                        ("The cmd is:%s" % cmd))
    try:
        listname = output.strip().split(' ')
        val = int(listname[len(listname) - 2])
        factor = listname[len(listname) - 1]
        if factor == 'kB':
            data.swapvalue = val * 1024
        elif factor == '':
            data.swapvalue = val

    except Exception as e:
        raise Exception(ErrorCode.GAUSS_505["GAUSS_50502"] % "SwapTotal"
                        + " Error: \n%s" % str(e))
    return data


def collectMemInfo():
    """
    function : Collect Memory information
    input  : NA
    output : Instantion
    """
    data = meminfo()
    cmd = "cat /proc/meminfo | grep MemTotal"
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception((ErrorCode.GAUSS_505["GAUSS_50502"] % "MemTotal") +
                        ("The cmd is %s " % cmd))
    try:
        listname = output.strip().split(' ')
        val = int(listname[len(listname) - 2])
        factor = listname[len(listname) - 1]
        if factor == 'kB':
            data.memvalue = val * 1024
        elif factor == '':
            data.memvalue = val

    except Exception as e:
        raise Exception(ErrorCode.GAUSS_505["GAUSS_50502"] % "MemTotal"
                        + " Error: \n%s" % str(e))
    return data


###########################################################################
# firewall:
###########################################################################
class firewall:
    """
    class: firewall
    """

    def __init__(self):
        """
        function : Init class firewall
        input  : NA
        output : NA
        """
        self.status = ""
        self.distname = ""
        self.errormsg = ""


def collectfirewall():
    """
    function : Collect firewall
    input  : NA
    output : Instantion
    """
    data = firewall()
    distname = LinuxDistro.linux_distribution()[0]
    if distname in ("redhat", "centos", "euleros", "openEuler", "FusionOS", "kylin"):
        data.distname = distname.upper()
        if g_Platform.isPlatFormEulerOSOrRHEL7X():
            cmd = "systemctl status firewalld.service"
        else:
            cmd = "service iptables status"
    else:
        data.distname = "SUSE"
        cmd = "SuSEfirewall2 status"

    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        data.errormsg = output
        return data

    if distname in ("redhat", "centos", "euleros", "openEuler", "FusionOS", "kylin"):
        if g_Platform.isPlatFormEulerOSOrRHEL7X():
            if (output.strip()).find("Active: "
                                     "active (running)") > 0:
                data.status = "enabled"
            else:
                data.status = "disabled"
        else:
            if (output.strip()).find("Firewall is not"
                                     " running") > 0:
                data.status = "disabled"
            else:
                data.status = "enabled"
    else:
        if (output.strip()).find("SuSEfirewall2 not"
                                 " active") > 0:
            data.status = "disabled"
        else:
            data.status = "enabled"

    return data


###########################################################################
# ntp:  time consistence
###########################################################################
class ntp:
    """
    class: ntp
    """

    def __init__(self):
        """
        function : Init class ntp
        input  : NA
        output : NA
        """
        self.running = False
        self.hosts = set()
        self.currenttime = ""
        self.errormsg = None


def collectNtpd():
    """
    function : Collect Ntpd
    input  : NA
    output : Instantion
    """
    data = ntp()
    p = subprocess.Popen(["pgrep", "ntpd"], shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    result = p.communicate()

    if data.errormsg:
        data.errormsg = "%s\n%s" % (data.errormsg, result[1].strip())
    else:
        data.errormsg = result[1].strip()

    if not p.returncode:
        for line in result[0].splitlines():
            if line.strip().isdigit():
                data.running = True

    data.currenttime = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return data


#############################################################################
# CheckLinuxMounts:
#############################################################################
def CheckLinuxMounts():
    """
    function : Check Linux Mounts
    input  : NA
    output : NA
    """
    xfs_mounts = list()
    expectedOption = "inode64"
    data = collectMounts()
    for k in list(data.entries.keys()):
        entry = data.entries[k]
        if entry.type == "xfs":
            xfs_mounts.append(entry)

    for mnt in xfs_mounts:
        if mnt.type != "xfs":
            g_logger.log("The device '%s' is not XFS filesystem and"
                         " is expected to be so." % mnt.partition)
            continue

        is_find = "failed"
        for opt in mnt.options:
            if (opt == expectedOption):
                is_find = "success"
                break
        if (is_find == "failed"):
            g_logger.log("XFS filesystem on device %s is missing the "
                         "recommended mount option '%s'." % (mnt.partition,
                                                             expectedOption))


#############################################################################
def IterateClass(obj):
    """
    function : Check item in class
    input  : obj
    output : list
    """
    if not hasattr(obj, '__dict__'):
        return

    for attr_name in obj.__dict__:
        attr_value = getattr(obj, attr_name)
        if isinstance(attr_value, list):
            for item in attr_value:
                if hasattr(item, '__dict__'):
                    IterateClass(item)
                else:
                    g_readlist.append(item)
        elif isinstance(attr_value, dict):
            for key, value in attr_value.items():
                if hasattr(value, '__dict__'):
                    IterateClass(value)
                else:
                    g_readlist.append(value)
        elif hasattr(attr_value, '__dict__'):
            IterateClass(attr_value)
        else:
            g_readlist.append(attr_value)

def IsLinuxPath(input_str):
    """
    function : Check whether a character string is a file path
    input  : String
    output : Bool
    """
    linux_path_pattern = r'^/([A-Za-z0-9_\-]+/)*[A-Za-z0-9_\-]+\/*$'
    return re.match(linux_path_pattern, input_str) is not None

def GetMountInfo(file_path):
    """
    function : Determine the mount disk of the path
    input  : String
    output : Bool
    """
    try:
        dev = os.stat(file_path).st_dev
    except FileNotFoundError:
        return None

    for partition in psutil.disk_partitions(all=True):
        if os.stat(partition.mountpoint).st_dev == dev:
            return partition.device
    return None

def CheckBlockdev(isSetting=False):
    """
    function : Check Block dev
    input  : Bool
    output : NA
    """
    expectedReadAhead = "16384"
    my_mount = []
    IterateClass(g_clusterInfo)

    for path in g_readlist:
        mount_info = GetMountInfo(str(path))
        if mount_info is not None:
            my_mount.append(mount_info)
        else:
            continue
    unique_elements = list(set(my_mount))

    data = collectBlockdev()
    for dev in list(data.ra.keys()):
        for s in unique_elements:
            if dev not in s:
                continue
            ra = data.ra[dev]
            if int(ra) < int(expectedReadAhead):
                if not isSetting:
                    g_logger.log("On device (%s) 'blockdev readahead' RealValue"
                                " '%s' ExpectedValue '%s'."
                                % (dev, ra, expectedReadAhead))
                else:
                    SetBlockdev(expectedReadAhead, dev)
                    g_logger.log("On device (%s) set 'blockdev readahead' from"
                                " '%s' to '%s'." % (dev, ra, expectedReadAhead))
                
    

def SetBlockdev(expectedReadAhead, devname):
    """
    function : Set Block dev
    input  : String, String
    output : NA
    """
    g_logger.debug("Setting block dev value.")
    initFile = getTHPandOSInitFile()[1]
    cmd = "/sbin/blockdev --setra %s %s " % (expectedReadAhead, devname)
    cmd += " && echo \"/sbin/blockdev --setra %s %s\" >> %s" \
           % (expectedReadAhead, devname, initFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.log("Failed to set block dev '%s'. Error:\n%s"
                     % (devname, output))


#############################################################################
def CheckIOSchedulers(isSetting=False):
    """
    function : Check IO Schedulers
    input  : Bool
    output : NA
    """
    # The IO Schedulers in ubuntu system is default value,
    # so that it cannot be modified
    distname, version = LinuxDistro.linux_distribution()[0:2]
    if distname == "debian" and version == "buster/sid":
        return
    data = collectIOschedulers()
    for dev in list(data.devices.keys()):
        expectedScheduler = "deadline"
        # Vda disk only supports mq-deadline
        if (expectedScheduler not in data.all_item[dev]
                and "mq-deadline" in data.all_item[dev]):
            expectedScheduler = "mq-deadline"
        scheduler = data.devices[dev]
        if scheduler != expectedScheduler:
            if not isSetting:
                g_logger.log("On device (%s) 'IO scheduler' RealValue '%s' "
                             "ExpectedValue '%s'." % (dev, scheduler,
                                                      expectedScheduler))
            else:
                SetIOSchedulers(dev, expectedScheduler)
                g_logger.log("On device (%s) set 'IO scheduler' from"
                             " '%s' to '%s'." % (dev, scheduler,
                                                 expectedScheduler))


def SetIOSchedulers(devname, expectedScheduler):
    """
    function : Set IO Schedulers
    input  : String
    output : NA
    """
    g_logger.debug("Set IO Schedulers value.")
    initFile = getTHPandOSInitFile()[1]
    cmd = " echo %s >> /sys/block/%s/queue/scheduler" \
          % (expectedScheduler, devname)
    cmd += " && echo \"echo %s >> /sys/block/%s/queue/scheduler\" >> %s" \
           % (expectedScheduler, devname, initFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        g_logger.log("Failed to set dev '%s' IO Schedulers. Error:\n%s"
                     % (devname, output))


def CheckIORequest(isSetting=False):
    """
    function : Check IO Request
    input  : Bool
    output : NA
    """
    expectedScheduler = "32768"
    data = collectIORequest()
    if len(data) == 0:
        g_logger.log("        WARNING:Not find IO Request file.")
    for i in list(data.keys()):
        reuqest = data[i]
        if int(reuqest) != int(expectedScheduler):
            g_logger.log("        WARNING:On device (%s) 'IO Request' "
                         "RealValue '%s' ExpectedValue '%s'"
                         % (i, reuqest.strip(), expectedScheduler))
            if isSetting:
                SetIORequest(expectedScheduler, i)


def SetIORequest(expectedScheduler, dev):
    """
    function : Set IO Request
    input  : String, String
    output : NA
    """
    g_logger.debug("Set IO Request value!")
    initFile = getTHPandOSInitFile()[1]
    cmd = " echo %s >> /sys/block/%s/queue/nr_requests" \
          % (expectedScheduler, dev)
    cmd += " && echo \"echo %s >> /sys/block/%s/queue/nr_requests\" >> %s" \
           % (expectedScheduler, dev, initFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        g_logger.log("        WARNING:Failed to set dev '%s' IO Request."
                     " Error:\n%s" % (dev, output))


#############################################################################
def CheckAsyIOrequests(isSetting=False):
    """
    function : Check Asy IO requests
    input  : Bool
    output : NA
    """
    expectedScheduler = "104857600"

    cnnum = 0
    dnnum = 0
    instancenum = 0

    hostname = NetUtil.GetHostIpOrName()
    dbnode = g_clusterInfo.getDbNodeByName(hostname)
    for i in dbnode.coordinators:
        if i.datadir != "":
            cnnum += 1

    for i in dbnode.datanodes:
        if (i.instanceType == MASTER_INSTANCE):
            dnnum += 1
        if (i.instanceType == STANDBY_INSTANCE):
            dnnum += 1

    instancenum = (dnnum + cnnum) * 1048576
    data = collectAsynchronousIORequest()
    if len(data) == 0:
        g_logger.log("        WARNING:Not find AsynchronousIORequest file.")
        if int(instancenum) > int(expectedScheduler):
            SetAsyIOrequests(instancenum)
        else:
            SetAsyIOrequests(expectedScheduler)
    else:
        for i in iter(data):
            request = i
            if (int(request) < int(instancenum) and
                    int(expectedScheduler) < int(instancenum)):
                if isSetting:
                    SetAsyIOrequests(instancenum)
            elif (int(request) < int(expectedScheduler) and
                  int(instancenum) < int(expectedScheduler)):
                if isSetting:
                    SetAsyIOrequests(expectedScheduler)
            elif (int(expectedScheduler) < int(request) and
                  int(instancenum) < int(request)):
                if isSetting:
                    SetAsyIOrequests(request)


def SetAsyIOrequests(expectedScheduler):
    """
    function : Set Asy IO requests
    input  : String
    output : NA
    """
    g_logger.debug("Set Asynchronous IO Maximum requests value!")
    initFile = getTHPandOSInitFile()[1]
    cmd = " echo %s >> /proc/sys/fs/aio-max-nr" % expectedScheduler
    cmd += " && echo \"echo %s >> /proc/sys/fs/aio-max-nr\" >> %s" \
           % (expectedScheduler, initFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        g_logger.log("Failed to set Asynchronous IO Maximum Request."
                     " Error:\n%s" % (output))


#############################################################################
def CheckClogicalBlock(isSetting=True):
    """
    function : Check Clogical Block
    input  : Bool
    output : NA
    """
    expectedScheduler = "512"
    data = collectLogicalBlock()
    if len(data) == 0:
        g_logger.log("        Warning:Not find clogical block file,"
                     "please check it.")
    for i in list(data.keys()):
        reuqest = data[i]
        if int(reuqest) < int(expectedScheduler):
            g_logger.log("        Warning:On device (%s) ' ClogicalBlock"
                         " Request' RealValue '%d' ExpectedValue '%d'"
                         % (i, int(reuqest), int(expectedScheduler)))
            if isSetting:
                SetClogicalBlock(expectedScheduler, i)


def SetClogicalBlock(expectedScheduler, dev):
    """
    function : Set Clogical Block
    input  : String, String
    output : NA
    """
    g_logger.debug("Set logicalBlock value!")
    initFile = getTHPandOSInitFile()[1]
    cmd = " echo %s >> /sys/block/%s/queue/logical_block_size" \
          % (expectedScheduler, dev)
    cmd += " && echo \"echo %s >> /sys/block/%s/queue/logical_block_size\"" \
           " >> %s" % (expectedScheduler, dev, initFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        g_logger.error("Failed to set dev '%s' logicalBlock by excuting"
                       " command:\n%s\nOutput:\n%s" % (dev, cmd, str(output)))


#############################################################################
def CheckPlatformInfo():
    """
    function : Check Platform Info
    input  : NA
    output : NA
    """
    data = collectplatformInfo()
    if (data.distname == "SuSE"):
        if (data.version == "11" and data.patchlevel == "1"):
            mixed_type = "%s%sSP%s" % (data.distname, data.version,
                                      data.patchlevel)
            platform_str = "%s_%s_SP%s_%s" % (data.distname, data.version,
                                             data.patchlevel, data.bits)
        elif data.version == "11" and data.patchlevel \
            in SUPPORT_SUSE11X_VERSION_LIST:
            mixed_type = "%s%s" % (data.distname, data.version)
            platform_str = "%s_%s_SP%s_%s" % (data.distname, data.version,
                                             data.patchlevel, data.bits)
        elif data.version == "12" and \
            data.patchlevel in SUPPORT_SUSE12X_VERSION_LIST:
            mixed_type = "%s%s" % (data.distname, data.version)
            platform_str = "%s_%s_SP%s_%s" % (data.distname, data.version,
                                             data.patchlevel, data.bits)
        else:
            platform_str = "%s_%s_SP%s_%s" % (data.distname, data.version,
                                             data.patchlevel, data.bits)
            g_logger.log("False %s %s" % (data.distname, platform_str))
            return
    elif data.distname in ("redhat", "centos", "asianux"):
        if data.version in SUPPORT_RHEL6X_VERSION_LIST:
            mixed_type = "%s6" % data.distname
            platform_str = "%s_%s_%s" % (data.distname,
                                        data.version, data.bits)
        elif data.version[0:3] in SUPPORT_RHEL7X_VERSION_LIST:
            mixed_type = "%s7" % data.distname
            platform_str = "%s_%s_%s" % (data.distname, data.version,
                                        data.bits)
        elif data.version[0:3] in SUPPORT_RHEL8X_VERSION_LIST:
            mixed_type = "%s8" % data.distname
            platform_str = "%s_%s_%s" % (data.distname, data.version,
                                        data.bits)
        elif int(data.version[0:3]) >= int(SUPPORT_RHEL_LEAST_VERSION[0]):
            mixed_type = "%s" % data.distname
            platform_str = "%s_%s_%s" % (data.distname, data.version,
                                        data.bits)
        else:
            platform_str = "%s_%s_%s" % (data.distname, data.version,
                                        data.bits)
            g_logger.log("False %s %s" % (data.distname, platform_str))
            return
    elif (data.distname == "euleros" or data.distname == "openEuler" or data.distname == "FusionOS" or data.distname == "kylin" or data.distname == "UnionTech"):
        mixed_type = "%s" % data.distname
        platform_str = "%s_%s_%s" % (data.distname, data.version, data.bits)
    elif (data.distname == "debian" or data.version == "buster/sid"):
        mixed_type = "%s" % data.distname
        platform_str = "%s_%s_%s" % (data.distname, data.version, data.bits)
    else:
        g_logger.log("Warning reason: %s version is not the official version"
                        "supported by OM, but you can still deploy and install it" % 
                        platform_str)
        if ask_to_continue():
            mixed_type = "%s" % data.distname
            platform_str = "%s_%s_%s" % (data.distname, data.version, data.bits)
            g_logger.log("True %s %s" % (mixed_type, platform_str))
        else:
            g_logger.log("False unknown %s" % platform_str)
        return

    g_logger.log("True %s %s" % (mixed_type, platform_str))
    return


#############################################################################
def ask_to_continue():
    """
    function : Check proceed with the installation
    input  : NA
    output : NA
    """
    while True:
        response = input("Do you wish to proceed with the installation?"
                    "(yes/no): ").strip().lower()
        if response == 'yes':
            print("Executing the operation.")
            return True
        elif response == 'no':
            print("Operation canceled.")
            return False
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")
            


#############################################################################
def CheckUname():
    """
    function : Check Uname
    input  : NA
    output : NA
    """
    data = collectUname()
    g_logger.log("KernelVersion %s" % data.output)


#############################################################################
def CheckUnicode():
    """"
    function : Check Unicode
    input  : NA
    output : NA
    """
    data = collectUnicode()
    g_logger.log("Unicode %s" % data.output)


#############################################################################
def CheckTimeZone():
    """
    function : Check Time Zone
    input  : NA
    output : NA
    """
    data = collectTimeZone()
    g_logger.log("TimeZone %s" % data.output)


#############################################################################
def CheckNtp():
    """
    function : Check Ntp
    input  : NA
    output : NA
    """
    data = collectNtpd()
    if not data.running:
        g_logger.log("False, %s" % data.currenttime)
    else:
        g_logger.log("True, %s" % data.currenttime)


#############################################################################


def CheckTHPServer():
    """
    function : Check THP Server
    input  : NA
    output : NA
    """
    expectedValues = "disabled"
    data = collectTHPServer()
    if data.status != expectedValues:
        g_logger.log("The THP service status RealValue '%s'"
                     " ExpectedValue '%s'." % (data.status, expectedValues))


#############################################################################
def CheckFirewallServer():
    """
    function : Check Firewall Server
    input  : NA
    output : NA
    """
    expectedValues = "disabled"
    data = collectfirewall()
    if data.status == "":
        return
    elif (data.status != expectedValues):
        g_logger.log("The firewall service status RealVaue '%s'"
                     " ExpectedValue '%s'" % (data.status, expectedValues))


#############################################################################
def CheckMemInfo():
    """
    function : Check Mem Info
    input  : NA
    output : NA
    """
    try:
        memdata = collectMemInfo()
        swapdata = collectSwapInfo()
    except SystemExit as e:
        raise Exception(ErrorCode.GAUSS_505["GAUSS_50503"] % e)
    if (swapdata.swapvalue > memdata.memvalue):
        g_logger.log("SwapMemory %s TotalMemory %s" % (swapdata.swapvalue,
                                                       memdata.memvalue))


#############################################################################
class CmdOptions():
    """
    Class: CmdOptions
    """

    def __init__(self):
        """
        function : Init class CmdOptions
        input  : NA
        output : NA
        """
        self.action = ""
        self.user = ""
        self.extrachecklist = []
        self.logFile = ""
        self.confFile = ""
        self.mtuValue = ""
        self.hostname = ""
        self.mppdbfile = ""


#########################################################
# Init global log
#########################################################
def initGlobals():
    """
    function : init Globals
    input  : NA
    output : NA
    """
    global g_logger
    global g_clusterInfo
    global g_readlist
    g_readlist = []

    g_logger = GaussLog(g_opts.logFile, "LocalCheckOS")

    g_clusterInfo = dbClusterInfo()
    if (g_opts.confFile != "" and g_opts.confFile is not None):
        g_clusterInfo.initFromXml(g_opts.confFile)


def usage():
    """
Usage:
 python3 --help | -?
 python3 LocalCheckOS -t action [-l logfile] [-X xmlfile] [-V]
Common options:
 -t                                The type of action.
 -s                                the path of MPPDB file
 -l --log-file=logfile             The path of log file.
 -? --help                         Show this help screen.
 -X --xmlfile = xmlfile            Cluster config file
    --ntp-server                   NTP server node's IP.
 -V --version
    """
    print(usage.__doc__)


def parseCommandLine():
    """
    function : Parse command line and save to global variables
    input  : NA
    output : NA
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:s:l:X:V?",
                                   ["help", "log-file=", "xmlfile=",
                                    "MTUvalue=", "hostname=",
                                    "ntp-server=", "version"])
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(e))

    if (len(args) > 0):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    for (key, value) in opts:
        if (key == "-?" or key == "--help"):
            usage()
            sys.exit(0)
        elif (key == "-V" or key == "--version"):
            print("%s %s" % (sys.argv[0].split("/")[-1],
                             VersionInfo.COMMON_VERSION))
            sys.exit(0)
        elif (key == "-t"):
            g_opts.action = value
        elif (key == "-s"):
            g_opts.mppdbfile = value
        elif (key == "-X" or key == "--xmlfile"):
            g_opts.confFile = value
        elif (key == "-l" or key == "--log-file"):
            g_opts.logFile = os.path.realpath(value)
        elif (key == "--MTUvalue"):
            g_opts.mtuValue = value
        elif (key == "--hostname"):
            g_opts.hostname = value
        Parameter.checkParaVaild(key, value)


def checkParameter():
    """
    function : check parameter
    input  : NA
    output : NA
    """
    if (g_opts.action == ""):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + '.')
    if (g_opts.action != ACTION_CHECK_OS_VERSION
            and g_opts.action != ACTION_CHECK_KERNEL_VERSION
            and g_opts.action != ACTION_CHECK_UNICODE
            and g_opts.action != ACTION_CHECK_TIMEZONE
            and g_opts.action != ACTION_CHECK_DISK_CONFIGURE
            and g_opts.action != ACTION_CHECK_BLOCKDEV_CONFIGURE
            and g_opts.action != ACTION_CHECK_IO_CONFIGURE
            and g_opts.action != ACTION_CHECK_IO_REQUEST
            and g_opts.action != ACTION_CHECK_ASYNCHRONOUS_IO_REQUEST
            and g_opts.action != ACTION_CHECK_LOGICAL_BLOCK
            and g_opts.action != ACTION_CHECK_NETWORK_CONFIGURE
            and g_opts.action != ACTION_CHECK_NETWORK_BOND_MODE
            and g_opts.action != ACTION_CHECK_SWAP_MEMORY_CONFIGURE
            and g_opts.action != ACTION_CHECK_TIME_CONSISTENCY
            and g_opts.action != ACTION_CHECK_FIREWALL_SERVICE
            and g_opts.action != ACTION_CHECK_THP_SERVICE
            and g_opts.action != ACTION_SET_BLOCKDEV_CONFIGURE
            and g_opts.action != ACTION_SET_NETWORK_CONFIGURE
            and g_opts.action != ACTION_SET_IO_CONFIGURE
            and g_opts.action != ACTION_SET_REMOVEIPC_VALUE
            and g_opts.action != ACTION_SET_SESSION_PROCESS
            and g_opts.action != ACTION_SET_THP_SERVICE
            and g_opts.action != ACTION_SET_LOGICAL_BLOCK
            and g_opts.action != ACTION_SET_IO_REQUEST
            and g_opts.action != ACTION_SET_ASYNCHRONOUS_IO_REQUEST):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "t")

    if (g_opts.logFile == ""):
        dirName = os.path.dirname(os.path.realpath(__file__))
        g_opts.logFile = os.path.join(dirName, ClusterConstants.LOCAL_LOG_FILE)


def getLocalIPAddr():
    """
    function: get local ip
    input : NA
    output: Ips
    """
    Ips = []

    if g_opts.confFile == "":
        Ips.append(DefaultValue.getIpByHostName())
        return Ips

    for node in g_clusterInfo.dbNodes:
        if (node.name == NetUtil.GetHostIpOrName()):
            Ips.append(node.backIps[0])

    return Ips


def doLocalCheck():
    """
    function: check OS item on local node
    input : NA
    output: NA
    """

    global netWorkBondInfo
    netWorkBondInfo = netWork()

    function_dict = {ACTION_CHECK_OS_VERSION: CheckPlatformInfo,
                     ACTION_CHECK_KERNEL_VERSION: CheckUname,
                     ACTION_CHECK_UNICODE: CheckUnicode,
                     ACTION_CHECK_TIMEZONE: CheckTimeZone,
                     ACTION_CHECK_DISK_CONFIGURE: CheckLinuxMounts,
                     ACTION_CHECK_SWAP_MEMORY_CONFIGURE: CheckMemInfo,
                     ACTION_CHECK_TIME_CONSISTENCY: CheckNtp,
                     ACTION_CHECK_FIREWALL_SERVICE: CheckFirewallServer,
                     ACTION_SET_REMOVEIPC_VALUE: disRemoveIPC,
                     ACTION_SET_SESSION_PROCESS: CheckSessionProcess,
                     ACTION_CHECK_THP_SERVICE: CheckTHPServer,
                     ACTION_SET_THP_SERVICE: disTHPServer}
    function_keys = list(function_dict.keys())

    function_dict_false = {ACTION_CHECK_BLOCKDEV_CONFIGURE: CheckBlockdev,
                           ACTION_CHECK_IO_CONFIGURE: CheckIOSchedulers,
                           ACTION_CHECK_IO_REQUEST: CheckIORequest,
                           ACTION_CHECK_LOGICAL_BLOCK: CheckClogicalBlock}
    function_keys_false = list(function_dict_false.keys())

    function_dict_true = {ACTION_SET_BLOCKDEV_CONFIGURE: CheckBlockdev,
                          ACTION_SET_IO_CONFIGURE: CheckIOSchedulers,
                          ACTION_SET_IO_REQUEST: CheckIORequest,
                          ACTION_SET_LOGICAL_BLOCK: CheckClogicalBlock}
    function_keys_true = list(function_dict_true.keys())

    if (g_opts.action in function_keys):
        function_dict[g_opts.action]()
    elif (g_opts.action in function_keys_false):
        function_dict_false[g_opts.action](False)
    elif (g_opts.action in function_keys_true):
        function_dict_true[g_opts.action](True)
    elif (g_opts.action == ACTION_CHECK_ASYNCHRONOUS_IO_REQUEST):
        if (g_opts.confFile != "" and g_opts.confFile is not None):
            CheckAsyIOrequests(False)
    elif (g_opts.action == ACTION_CHECK_NETWORK_CONFIGURE):
        for localAddres in nodeIps:
            CheckNetWorkCardPara(localAddres, False)
    elif (g_opts.action == ACTION_CHECK_NETWORK_BOND_MODE):
        CheckNetWorkBonding(DefaultValue.getIpByHostName(), True)
    elif (g_opts.action == ACTION_SET_NETWORK_CONFIGURE):
        for localAddres in nodeIps:
            CheckNetWorkCardPara(localAddres, True)
    elif (g_opts.action == ACTION_SET_ASYNCHRONOUS_IO_REQUEST):
        if (g_opts.confFile != "" and g_opts.confFile is not None):
            CheckAsyIOrequests(True)
    else:
        g_logger.logExit(ErrorCode.GAUSS_500["GAUSS_50004"] % 't' +
                         " Value: %s." % g_opts.action)


if __name__ == '__main__':
    """
    main function
    """
    try:
        parseCommandLine()
        checkParameter()
        initGlobals()
    except Exception as e:
        GaussLog.exitWithError(str(e))

    try:
        nodeIps = []
        nodeIps = getLocalIPAddr()
        doLocalCheck()
        g_logger.closeLog()
    except Exception as e:
        g_logger.logExit(str(e))

    sys.exit(0)
