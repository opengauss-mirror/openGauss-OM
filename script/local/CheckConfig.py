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
# Description  : CheckConfig.py is a local utility to
#               execute some functions about init instance
#############################################################################
import subprocess
import getopt
import sys
import os

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.Common import DefaultValue
from gspylib.common.LocalBaseOM import LocalBaseOM
from gspylib.common.ErrorCode import ErrorCode
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.cluster_file.cluster_log import ClusterLog
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.common.constantsbase import ConstantsBase
from domain_utils.cluster_os.cluster_user import ClusterUser

#############################################################################
# Global variables
#   TIME_OUT: set time out
#   self.logger: globle logger
#   g_clusterUser: global user information
#############################################################################
TIME_OUT = 2


class CheckNodeEnv(LocalBaseOM):
    """
    function: Init all instance on local node
    input : NA
    output: NA
    """

    def __init__(self, logFile, clusterUser, dataParams, instIds):
        """
        function: init function
        input : logFile, clusterUser, dataParams, instIds
        output: NA
        """
        LocalBaseOM.__init__(self, logFile, clusterUser)
        self.__dataGucParams = dataParams[:]
        self.__instanceIds = instIds[:]  # if is empty, check all instances
        self.clusterInfo = None
        self.dbNodeInfo = None
        self.__diskSizeInfo = {}
        self.__pgsqlFiles = []

    def run(self):
        """
        function: Init instance on local node:
                  1.Check GaussDB Log directory
                  2.Check pgsql directory
                  3.Check instances config on local node
                  4.Set manual start
                  5.Set linux cron
        input : NA
        output: NA
        """
        self.__checkParameters()
        self.readConfigInfo()
        self.logger.debug("Instance information on local node:\n%s."
                          % str(self.dbNodeInfo))
        self.initComponent()
        # Check GaussDB Log directory
        self.__checkGaussLogDir()
        # Check pgsql directory
        self.__checkPgsqlDir()
        # Check instances config on local node
        self.__checkNodeConfig()
        # Set manual start
        self.__set_manual_start()
        # Set linux cron
        self.__set_cron()
        self.logger.log("Checked the configuration file on node[%s]"
                        " successfully." % NetUtil.GetHostIpOrName())

    def __checkParameters(self):
        """
        function: Check parameters for instance config:
                  1.Check parameter for configuring CNs
                  2.Check parameter for configuring DNs
        input : NA
        output: NA
        """
        self.logger.log("Checking parameters for configuring DNs.")
        for param in self.__dataGucParams:
            if self.__checkconfigParams(param.strip()) != 0:
                self.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50000"]
                                    % param)

    def __checkconfigParams(self, param):
        """
        function: Check parameter for postgresql.conf,
                  port : this is calculated automatically
        input : param
        output: 0/1
        """
        configInvalidArgs = ["port"]

        argList = param.split("=")
        for arg in configInvalidArgs:
            if (arg in argList):
                return 1

        return 0

    def __checkGaussLogDir(self):
        """
        function: Check GaussDB Log directory:
                  1.check user base log directory
                  2.create instance log directory
                  3.change directory mode
        input : NA
        output: NA
        """
        # check user base log dir
        user_dir = ClusterDir.getUserLogDirWithUser(self.user)
        self.logger.log("Checking %s log directory[%s]."
                        % (VersionInfo.PRODUCT_NAME, user_dir))
        if (not os.path.exists(user_dir)):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % ('user base log directory [%s]' % user_dir))
        ##make gs_profile dir
        user_profile_dir = os.path.join(user_dir, "gs_profile")
        self.__makeDirForDBUser(user_profile_dir, "user_profile_dir")

        ##make pg_log dir and pg_audit dir
        user_pg_log_dir = os.path.join(user_dir, "pg_log")
        self.__makeDirForDBUser(user_pg_log_dir, "user_pg_log_dir")

        user_pg_audit_dir = os.path.join(user_dir, "pg_audit")
        self.__makeDirForDBUser(user_pg_audit_dir, "user_pg_audit_dir")

        ##make bin log dir
        user_bin_dir = os.path.join(user_dir, "bin")
        self.__makeDirForDBUser(user_bin_dir, "user_bin_dir")

        for inst in self.dbNodeInfo.datanodes:
            log_dir_name = "dn_%d" % (inst.instanceId)
            log_dir = os.path.join(user_pg_log_dir, log_dir_name)
            audit_dir = os.path.join(user_pg_audit_dir, log_dir_name)
            self.__makeDirForDBUser(log_dir, "user_pg_log_%s_dir"
                                    % log_dir_name)
            self.__makeDirForDBUser(audit_dir, "user_pg_audit_%s_dir"
                                    % log_dir_name)

        try:
            self.logger.debug("Command to find directory in directory[%s] "
                              % user_dir)
            # change directory mode
            FileUtil.getchangeDirModeCmd(user_dir)
            self.logger.debug("Command to find file in directory[%s] "
                              % user_dir)
            # change log file mode
            FileUtil.getchangeFileModeCmd(user_dir)
            self.logger.debug("Command to change the obs log setting.")
            # change the obs log setting file  distribute package
            self.changeObsLogSetting()
        except Exception as e:
            self.logger.logExit(str(e))

    def changeObsLogSetting(self):
        """
        function: change the obs log setting file  distribute package
        input : NA
        output: NA
        """
        obspathNum = self.clusterInfo.appPath.count("/")
        """
        obs path is the relative path between log path and app path.
        if app path is /test/app and log path is /test/log
        then the relative path from app to log is '..'+'/..'*(num-1)+logpath
        the relative path from obs to log is '../../..'+'/..'*(num-1)+logpath
        """
        username = EnvUtil.getEnv("LOGNAME")
        DefaultValue.checkPathVaild(username)
        obspath = "LogPath=../.." + "/.." * obspathNum + "%s/" \
                  % self.clusterInfo.logPath + "%s" % username + "/bin/gs_obs"
        cmd = "mkdir -p '%s/%s/bin/gs_obs' -m %s" \
              % (self.clusterInfo.logPath, username,
                 DefaultValue.KEY_DIRECTORY_MODE)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            self.logger.debug("The cmd is %s " % cmd)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50208"] % "obs log"
                            + " Error: \n%s " % output)
        obsinifile = "%s/lib/OBS.ini" % self.clusterInfo.appPath

        if not os.path.exists(obsinifile):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % obsinifile)
        try:
            with open(obsinifile, 'r') as fp:
                lines = fp.readlines()
            flen = len(lines) - 1
            for i in range(flen):
                if "sdkname=eSDK-OBS-API-Linux-C" in lines[i]:
                    lines[i] = lines[i].replace("sdkname=eSDK-OBS-API-Linux-C",
                                                "sdkname=gs_obs")
                if "LogPath=../logs" in lines[i]:
                    lines[i] = lines[i].replace("LogPath=../logs", obspath)
            with open(obsinifile, 'w') as fpw:
                fpw.writelines(lines)
        except Exception as e:
            self.logger.logExit(str(e))

    def __makeDirForDBUser(self, path, desc):
        """
        function: Create a dir for DBUser:
                  1.create a dir for DB user
                  2.Check if target directory is writeable for user
        input : path, desc
        output: NA
        """
        self.logger.debug("Making %s directory[%s] for database node user."
                          % (desc, path))
        FileUtil.createDirectory(path)
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, path)
        if not FileUtil.checkDirWriteable(path):
            self.logger.logExit(ErrorCode.GAUSS_501["GAUSS_50102"]
                                % (path, self.user))

    def __checkPgsqlDir(self):
        """
        function: 1.Check pgsql directory
                  2.change permission
                  3.Check if target directory is writeable for user
        input : NA
        output: NA
        """
        tmpDir = EnvUtil.getTmpDirFromEnv()
        self.logger.log("Checking directory [%s]." % tmpDir)
        if (not os.path.exists(tmpDir)):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % tmpDir + " Please create it first.")

        self.__pgsqlFiles = os.listdir(tmpDir)

        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, tmpDir)
        if not FileUtil.checkDirWriteable(tmpDir):
            self.logger.logExit(ErrorCode.GAUSS_501["GAUSS_50102"]
                                % (tmpDir, self.user))

    def check_cm_agent_config(self):
        """
        function: Check cm_agent configuration
        input : NA
        output: NA
        """
        for cmaInst in self.dbNodeInfo.cmagents:
            if len(self.__instanceIds) != 0 and cmaInst.instanceId not in self.__instanceIds:
                continue
            self.__checkDataDir(cmaInst.datadir)

    def check_cm_server_config(self):
        """
        function: Check cm_server configuration
        input : NA
        output: NA
        """
        for cmsInst in self.dbNodeInfo.cmservers:
            if len(self.__instanceIds) != 0 and cmsInst.instanceId not in self.__instanceIds:
                continue
            self.__checkDataDir(cmsInst.datadir)

    def checkDNConfig(self):
        """
        function: Check DN configuration
        input : NA
        output: NA
        """
        for dnInst in self.dbNodeInfo.datanodes:
            if (len(self.__instanceIds) != 0 and
                    dnInst.instanceId not in self.__instanceIds):
                continue
            self.__checkDataDir(dnInst.datadir)
            if (len(dnInst.ssdDir) != 0):
                self.__checkDataDir(dnInst.ssdDir)

    def __checkNodeConfig(self):
        """
        function: Check instances config on local node
        input : NA
        output: NA
        """
        self.logger.log("Checking CM data directory.")
        if self.dbNodeInfo.cmDataDir:
            self.__checkDataDir(self.dbNodeInfo.cmDataDir, False)
            self.logger.log("Checking CMAgent configuration file.")
            self.check_cm_agent_config()
            self.logger.log("Checking CMServer configuration file.")
            self.check_cm_server_config()
        self.logger.log("Checking database node configuration.")
        self.checkDNConfig()

    def __checkDataDir(self, datadir, checkEmpty=True, checkSize=True):
        """
        function: Check if directory exists and disk size lefted
        input : datadir, checkEmpty, checkSize
        output: NA
        """
        self.logger.log("Checking directory [%s]." % datadir)

        # Check and create directory
        ownerPath = datadir
        if (os.path.exists(datadir)):
            if (checkEmpty):
                fileList = os.listdir(datadir)
                # full_upgrade_bak is backup path for datapath and install path
                # we should skip it
                for intent in ["full_upgrade_bak", "pg_location", "cfg", "log"]:
                    if intent in fileList:
                        fileList.remove(intent)
                if (len(fileList) != 0):
                    self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50202"]
                                        % datadir)
        else:
            while True:
                (ownerPath, dirName) = os.path.split(ownerPath)
                if (os.path.exists(ownerPath) or dirName == ""):
                    ownerPath = os.path.join(ownerPath, dirName)
                    os.makedirs(datadir,
                                ConstantsBase.KEY_DIRECTORY_PERMISSION)
                    break

        # Check if data directory is writeable
        if not FileUtil.checkDirWriteable(datadir):
            self.logger.logExit(ErrorCode.GAUSS_501["GAUSS_50102"]
                                % (datadir, self.user))

        if (checkSize):
            self.__diskSizeInfo = DefaultValue.checkDirSize(
                datadir, DefaultValue.INSTANCE_DISK_SIZE, self.logger)

    def __set_manual_start(self):
        """
        function: Set manual start
        input : NA
        output: NA
        """
        self.logger.log("Setting manual start.")

        if len(self.__instanceIds) == 0:
            manual_start_file = "%s/bin/cluster_manual_start" % self.clusterInfo.appPath
            FileUtil.createFile(manual_start_file)
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, manual_start_file)
            host_name = NetUtil.GetHostIpOrName()
            db_node = self.clusterInfo.getDbNodeByName(host_name)
            if not db_node:
                self.logger.logExit(ErrorCode.GAUSS_512["GAUSS_51209"] % ("NODE", host_name))
        else:
            for instId in self.__instanceIds:
                if (instId in self.dbNodeInfo.coordinators) or \
                        (instId in self.dbNodeInfo.datanodes) or \
                        (instId in self.dbNodeInfo.gtms):
                    inst_start_file = "%s/bin/instance_manual_start_%d" % (
                        self.clusterInfo.appPath, instId)
                    FileUtil.createFile(inst_start_file)
                    FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, inst_start_file)

    def __set_cron(self):
        """
        function: Set linux cron
        input : NA
        output: NA
        """
        if self.cmCons and self.cmCons[0].instInfo.datadir == "/cm_agent" and \
                not os.path.exists(self.cmCons[0].instInfo.datadir):
            self.logger.debug("No CM instance configuration.No need to set crontab.")
            return
        self.cmCons[0].setMonitor(self.user)


def usage():
    """
Usage:
    python3 CheckConfig.py -h | --help
    python3 CheckConfig.py -U user
    [-i instId [...]]
    [-C "PARAMETER=VALUE" [...]]
    [-D "PARAMETER=VALUE" [...]]
    [-l logfile]
    """

    print(usage.__doc__)


def main():
    """
    function: main function
    input : NA
    output: NA
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "U:C:D:i:l:h", ["help"])
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(e))

    if (len(args) > 0):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(args[0]))

    logFile = ""
    dataParams = []
    instanceIds = []

    for (key, value) in opts:
        if (key == "-h" or key == "--help"):
            usage()
            sys.exit(0)
        elif (key == "-U"):
            clusterUser = value
        elif (key == "-D"):
            dataParams.append(value)
        elif (key == "-l"):
            logFile = os.path.realpath(value)
        elif (key == "-i"):
            if (value.isdigit()):
                instanceIds.append(int(value))
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "i")

        Parameter.checkParaVaild(key, value)

    # check if user exist and is the right user
    ClusterUser.checkUser(clusterUser)

    # check log dir
    if (logFile == ""):
        logFile = ClusterLog.getOMLogPath(ClusterConstants.LOCAL_LOG_FILE,
                                            clusterUser, "", "")

    try:
        checker = CheckNodeEnv(logFile, clusterUser,
                               dataParams, instanceIds)
        checker.run()

        sys.exit(0)
    except Exception as e:
        GaussLog.exitWithError(str(e))


if __name__ == '__main__':
    main()
