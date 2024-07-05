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
# Description : Uninstall.py is a utility to uninstall Gauss MPP Database.
#############################################################################

import getopt
import os
import sys
import re
import subprocess

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.LocalBaseOM import LocalBaseOM
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.cluster_file.cluster_log import ClusterLog
from base_utils.os.crontab_util import CrontabUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.profile_file import ProfileFile
from base_utils.os.process_util import ProcessUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from gspylib.component.DSS.dss_comp import Dss


class Uninstall(LocalBaseOM):
    """
    uninstall the cluster
    """

    def __init__(self):
        """
        Constructor
        """
        super(Uninstall, self).__init__()
        self.installPath = ""
        self.user = ""
        self.keepDir = False
        self.mpprcFile = ""
        self.logFile = ""
        self.logger = None
        self.installflag = False
        self.clusterInfo = None
        self.localNode = None
        self.keepData = True
        self.method = ""
        self.action = ""
        self.del_static_cfg_file = False

    ##########################################################################
    # Help context. U:R:oC:v: 
    ##########################################################################
    def usage(self):
        """
        function: usage
        """
        print("Uninstall.py is a utility to uninstall Gauss MPP Database.")
        print(" ")
        print("Usage:")
        print("  python3 Uninstall.py --help")
        print("  python3 Uninstall.py -U user -R installpath [-c] [-l log]")
        print(" ")
        print("Common options:")
        print("  -U         the database program and cluster owner")
        print("  -R         the database program install path")
        print("  -l         the log path")
        print("  --delete-static-file     delete static_config_file in uninstall step")
        print("  --help     show this help, then exit")
        print(" ")

    ##########################################################################
    # This is the main uninstall flow.  
    ##########################################################################
    def uninstall(self):
        """
        function: Remove install path content, which depend on $GAUSSHOME
        input : NA
        output: NA
        """
        try:
            self.logger.debug("OLAP's local uninstall.")
            self.__cleanMonitor()
            self.unregister()
            self.__cleanInstallProgram()
            self.__changeuserEnv()
            self.logger.closeLog()
        except Exception as e:
            raise Exception(str(e))

    def unregister(self):
        '''
        Deregistering a Disk in dss-mode
        '''
        gausshome = ClusterDir.getInstallDir(self.user)
        dsscmd = os.path.realpath(os.path.join(gausshome, 'bin', 'dsscmd'))
        perctrl = os.path.realpath(os.path.join(gausshome, 'bin', 'perctrl'))
        if os.path.isfile(dsscmd) and os.path.isfile(perctrl):
            if not FileUtil.get_caps(perctrl):
                self.logger.log("The perctrl does not have permissions.")
                return
            dss_home = EnvUtil.get_dss_home(self.user)
            cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')
            if os.path.isfile(cfg):
                self.logger.log("Start to unregist the lun.")
                Dss.unreg_disk(dss_home, logger=self.logger)
                self.logger.log("Successfully unregist the lun.")
            else:
                self.logger.log(f"The {cfg} not exist.")
        else:
            self.logger.log("Non-dss-mode or not find dsscmd.")

    def __changeuserEnv(self):
        """
        function: Change user GAUSS_ENV
        input : NA
        output: NA
        """
        # clean os user environment variable
        self.logger.log("Modifying user's environmental variable $GAUSS_ENV.")
        userProfile = self.mpprcFile
        ProfileFile.updateUserEnvVariable(userProfile, "GAUSS_ENV", "1")
        if "HOST_IP" in os.environ.keys():
            FileUtil.deleteLine(userProfile, "^\\s*export\\s*WHITELIST_ENV=.*$")
        self.logger.log("Successfully modified user's environmental"
                        " variable GAUSS_ENV.")

        self.logger.debug("Deleting symbolic link to $GAUSSHOME if exists.")
        gaussHome = ClusterDir.getInstallDir(self.user)
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
        if os.path.islink(gaussHome):
            self.installPath = os.path.realpath(gaussHome)
            os.remove(gaussHome)
        else:
            self.logger.debug("symbolic link does not exists.")
        self.logger.debug("Deleting bin file in installation path.")
        FileUtil.removeDirectory("%s/bin" % self.installPath)
        self.logger.debug("Successfully deleting bin file in"
                          " installation path.")

    def __cleanMonitor(self):
        """
        function: clean om_monitor process and delete cron
        input : NA
        output: NA
        """
        self.logger.log("Deleting monitor.")
        if not CrontabUtil.check_user_crontab_permission():
            self.logger.log("Warning: The user has no permission to delete crontab task.")
            self.query_om_monitor_service()
            self.clean_om_monitor_service()
        else:
            self.clean_om_monitor_crontab()
        # clean om_monitor,cm_agent,cm_server process
        for progname in ["om_monitor", "cm_agent", "cm_server"]:
            ProcessUtil.killallProcess(self.user, progname, '9')
        self.logger.log("Successfully deleted OM Monitor.")

    def clean_om_monitor_crontab(self):
        """
        function: clean om_monitor crontab
        input : NA
        output: NA
        """
        self.logger.log("Deleting om monitor crontab.")
        try:
            # get all content by crontab command
            (status, output) = CrontabUtil.getAllCrontab()
            # overwrit crontabFile, make it empty.
            crontabFile = "%s/gauss_crontab_file_%d" \
                          % (EnvUtil.getTmpDirFromEnv(), os.getpid())
            FileUtil.createFile(crontabFile, True)
            content_CronTabFile = [output]
            FileUtil.writeFile(crontabFile, content_CronTabFile)
        except Exception as e:
            raise Exception(str(e))
        self.logger.log("Successfully deleted om monitor.")

    def clean_om_monitor_service(self):
        """
        function: clean om_monitor systemd service
        input : NA
        output: NA
        """
        self.logger.log("Deleting om monitor service.")
        cmd = "systemctl --user stop om_monitor; systemctl --user disable om_monitor"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.log("Failed to stop om_monitor service.")
        clean_systemd_cmd = "ps ux|grep dbus-daemon |grep -v grep | awk '{print $2}'|xargs -r kill -9 \
            ps ux|grep /usr/lib/systemd/systemd |grep -v grep | awk '{print $2}'|xargs -r kill -9 "
        (status, output) = subprocess.getstatusoutput(clean_systemd_cmd)
        if status != 0:
            self.logger.log("Failed to clean systemd service.")
        self.logger.log("Deleting om monitor service.")

    def query_om_monitor_service(self):
        """
        function: query om_monitor systemd service
        input : NA
        output: True False
        """
        self.logger.log("Querying om monitor service.")
        cmd = "systemctl --user status om_monitro"
        (status, output) = subprocess.getstatusoutput(cmd)
        if output.find("om_monitor") == -1:
            self.logger.log("Warning: The om monitor service is not running.")
            return False
        self.logger.log("Querying om monitor service succefully.")
        return True
        

    def checkParameters(self):
        """
        function: Check input parameters
        input : NA
        output: NA
        """
        try:
            opts, args = getopt.getopt(sys.argv[1:], "t:U:R:l:X:M:T",
                                       ["help", "delete-data", "delete-static-file"])
        except getopt.GetoptError as e:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                   % str(e))

        if (len(args) > 0):
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                   % str(args[0]))

        for key, value in opts:
            if (key == "-U"):
                self.user = value
            elif (key == "-R"):
                self.installPath = value
            elif (key == "-l"):
                self.logFile = value
            elif (key == "--help"):
                self.usage()
                sys.exit(0)
            elif (key == "-T"):
                self.installflag = True
            elif key == "--delete-data":
                self.keepData = False
            elif key == "-M":
                self.method = value
            elif key == "-t":
                self.action = value
            elif key == "--delete-static-file":
                self.del_static_cfg_file = True
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                       % key)

            Parameter.checkParaVaild(key, value)

        if (self.user == ""):
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                   % 'U' + ".")

        if (self.installPath == ""):
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                   % 'R' + ".")

        self.mpprcFile = EnvUtil.getMpprcFile()
        if (self.logFile == ""):
            self.logFile = ClusterLog.getOMLogPath(
                ClusterConstants.LOCAL_LOG_FILE, self.user, self.installPath)

    def __initLogger(self):
        """
        function: Init logger
        input : NA
        output: NA
        """
        self.logger = GaussLog(self.logFile, "UninstallApp")

    def _check_and_remove(self):
        """
        Check app directory after clean app
        """
        file_list = os.listdir(self.installPath)
        if not file_list:
            return
        for base_name in file_list:
            special_file = os.path.join(self.installPath, base_name)
            if os.path.exists(special_file) and not os.path.isdir(special_file):
                os.remove(special_file)
                self.logger.log("Successfully cleaned {0} .".format(special_file))
        self.logger.log("Check and clean finish.")

    def __cleanInstallProgram(self):
        """
        function: Clean install program
        input : NA
        output: NA
        """
        if (not os.path.exists(self.installPath)):
            self.logger.log("The installation directory does not exist. ")
            return

        realLink = self.installPath
        if os.path.islink(self.installPath):
            realLink = os.readlink(self.installPath)

        # delete upgrade directory
        self.logger.debug("Starting delete other installation directory.")
        try:
            recordVersionFile = os.path.realpath(
                os.path.join(self.installPath, "record_app_directory"))
            if os.path.isfile(recordVersionFile):
                with open(recordVersionFile, 'r') as fp:
                    retLines = fp.readlines()
                if len(retLines) != 2:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"]
                                    % recordVersionFile)
                oldPath = retLines[0].strip()
                newPath = retLines[1].strip()
                if os.path.normcase(oldPath) == os.path.normcase(realLink):
                    FileUtil.removeDirectory(newPath)
                else:
                    FileUtil.removeDirectory(oldPath)
                self.logger.debug("Successfully deleted other installation"
                                  " path need to delete.")
            else:
                self.logger.debug("No other installation path need"
                                  " to delete.")
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50209"]
                            % "other installation"
                            + " Can not delete other installation"
                              " directory: %s." % str(e))

        self.logger.log("Removing the installation directory.")
        try:

            dss_app = os.path.realpath(
                os.path.join(
                    os.path.dirname(self.installPath),
                    f'dss_app_{os.path.realpath(self.installPath)[-8:]}'))
            if os.path.isdir(dss_app):
                for fn in os.listdir(dss_app):
                    fp = os.path.realpath(os.path.join(dss_app, fn))
                    if os.path.isfile(fp):
                        os.remove(fp)
                        self.logger.debug("Remove path:%s." % fp)

            fileList = os.listdir(self.installPath)
            for fileName in fileList:
                fileName = fileName.replace("/", "").replace("..", "")
                filePath = os.path.join(os.path.realpath(self.installPath),
                                        fileName)
                if os.path.isfile(filePath):
                    os.remove(filePath)
                elif os.path.isdir(filePath):
                    if (fileName == "bin"):
                        binFileList = os.listdir(filePath)
                        for binFile in binFileList:
                            fileInBinPath = os.path.join(filePath, binFile)
                            if os.path.isfile(fileInBinPath):
                                if binFile == "cluster_static_config" and not self.del_static_cfg_file:
                                    continue
                                os.remove(fileInBinPath)
                            elif os.path.islink(fileInBinPath):
                                os.remove(fileInBinPath)
                            elif os.path.isdir(fileInBinPath):
                                FileUtil.removeDirectory(fileInBinPath)
                    else:
                        FileUtil.removeDirectory(filePath)

                self.logger.debug("Remove path:%s." % filePath)
            self._check_and_remove()
            self.logger.debug("Successfully deleted bin file"
                              " in installation path.")

        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50209"]
                            % "installation"
                            + " Can not delete installation directory: %s."
                            % str(e))

        # regular match delete empty directory
        self.logger.debug("Starting delete empty installation directory.")
        try:
            removeflag = False
            namePrefix = os.path.basename(self.installPath)
            gaussPath = os.path.realpath(os.path.dirname(self.installPath))
            curInstallName = os.path.basename(realLink)
            fileList = os.listdir(gaussPath)
            for fileName in fileList:
                if fileName.strip() != curInstallName.strip():
                    filePath = os.path.join(os.path.realpath(gaussPath),
                                            fileName)
                    if os.path.isdir(filePath) \
                            and not os.listdir(filePath) and "_" in fileName:
                        fileNameElement = fileName.split("_", 1)
                        if namePrefix.strip() == fileNameElement[0].strip():
                            res = re.search(
                                '^(?![0-9]+$)(?![a-zA-Z]+$)[0-9A-Za-z]{8}$',
                                fileNameElement[1].strip())
                            if res:
                                removeflag = True
                                FileUtil.removeDirectory(filePath)
            if removeflag:
                self.logger.debug("Successfully deleted empty"
                                  " installation path.")
            else:
                self.logger.debug("No empty installation path need"
                                  " to delete.")
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50209"]
                            % "other installation"
                            + " Can not delete empty installation"
                              " directory: %s." % str(e))

        self.logger.log("Successfully deleted installation directory.")

    def init(self):
        """
        function: constuctor
        """
        self.__initLogger()


if __name__ == '__main__':
    """
    main function
    """
    try:
        uninstaller = Uninstall()
        uninstaller.checkParameters()
        uninstaller.init()
        uninstaller.uninstall()
    except Exception as e:
        GaussLog.exitWithError(str(e))

    sys.exit(0)
