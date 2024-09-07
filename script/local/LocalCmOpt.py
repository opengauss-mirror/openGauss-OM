#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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

from pickle import STOP
import subprocess
from re import sub
import sys
import getopt

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.LocalBaseOM import LocalBaseOM
from gspylib.common.ParameterParsecheck import Parameter
from domain_utils.cluster_file.cluster_log import ClusterLog
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.os.env_util import EnvUtil
from gspylib.component.DSS.dss_checker import DssConfig
from base_utils.os.crontab_util import CrontabUtil
from domain_utils.cluster_file.cluster_dir import ClusterDir
from gspylib.common.Common import DefaultValue

class CMOptConst:
    START = "start"
    STOP = "stop"
        

class LocalCmOpt(LocalBaseOM):
    """
    The class is used to do perform start
    """

    def __init__(self):
        """
        function: initialize the parameters
        input: NA
        output: NA
        """
        super(LocalCmOpt, self).__init__()
        self.user = ""
        self.dataDir = ""
        self.time_out = 300
        self.logFile = ""
        self.logger = None
        self.installPath = ""
        self.security_mode = ""
        self.cluster_number = None
        self.action = ""
        
    def usage(self):
        """
General options:
    -U USER                  the database program and cluster owner")
    -D DATADIR               data directory of instance
    -t SECS                  seconds to wait
    -l LOGFILE               log file
    -?, --help               show this help, then exit
    --action                 start or stop
        """
        print(self.usage.__doc__)

    def parseCommandLine(self):
        """
        function: Check input parameters
        input : NA
        output: NA
        """
        try:
            opts, args = getopt.getopt(sys.argv[1:], "U:D:R:l:h?",
                                       ["help", "action="])
        except getopt.GetoptError as e:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

        if (len(args) > 0):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

        for key, value in opts:
            if key == "-U":
                self.user = value
            elif key == "-D":
                self.dataDir = value
            elif key == "-t":
                self.time_out = int(value)
            elif key == "-l":
                self.logFile = value
            elif key == "-R":
                self.installPath = value
            elif key == "--action":
                self.action = value
            elif key == "--help" or key == "-h" or key == "-?":
                self.usage()
                sys.exit(0)
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                       % key)
            Parameter.checkParaVaild(key, value)

        if self.user == "":
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                   % 'U' + ".")
        if self.logFile == "":
            self.logFile = ClusterLog.getOMLogPath(
                ClusterConstants.LOCAL_LOG_FILE, self.user, self.installPath)

    def __initLogger(self):
        """
        function: Init logger
        input : NA
        output: NA
        """
        self.logger = GaussLog(self.logFile, "LocalCMOperation")

    def init(self):
        """
        function: constructor
        """
        self.__initLogger()
        self.readConfigInfo()
        
    def do_stop_components(self):
        cmd = ""
        if CrontabUtil.check_user_crontab_permission():
            crondesc = subprocess.getoutput("crontab -l | grep om_monitor")
            if not crondesc.startswith("#"):
                cmd += "crontab -l | sed '/om_monitor/s/^/#/' | crontab -;"
        cmd += f"pkill -9 om_monitor -U {self.user};"
        cmd += f"pkill -9 cm_agent -U {self.user};"
        cmd += f"pkill -9 cm_server -U {self.user};"
        
        self.logger.log(f"stop cm components: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        self.logger.log(status, output)
           
           
    def do_start_components(self):
        mpprc_file = EnvUtil.getEnv(DefaultValue.MPPRC_FILE_ENV)
        app_path = ClusterDir.getInstallDir(self.user)
        log_path = ClusterLog.getOMLogPath(DefaultValue.OM_MONITOR_DIR_FILE,
                                             self.user,
                                             app_path)
        cmd = ""
        if CrontabUtil.check_user_crontab_permission():
            crondesc = subprocess.getoutput("crontab -l | grep om_monitor")
            if crondesc.startswith("#"):
                cmd = "crontab -l | sed '/om_monitor/s/^#//' | crontab -;"
        if mpprc_file != "" and mpprc_file is not None:
            cmd += "source ~/.bashrc;source %s; nohup %s/bin/om_monitor -L %s " \
                  ">>/dev/null 2>&1 &" % (mpprc_file, app_path, log_path)
        else:
            cmd += "source ~/.bashrc; nohup %s/bin/om_monitor -L %s >>" \
                  "/dev/null 2>&1 &" % (app_path, log_path)
        
        self.logger.log(f"start cm components: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        self.logger.log(status, output)
        

    def do_operate(self):
        """
        function: do start database
        input  : NA
        output : NA
        """
        print(self.action)
        if self.action == CMOptConst.START:
            self.do_start_components()
        elif self.action == CMOptConst.STOP:
            self.do_stop_components()
        else:
            self.logger.warn(f"action [{self.action}] is unknown, Do nothing.")
            

def main():
    """
    main function
    """
    try:
        opt = LocalCmOpt()
        opt.parseCommandLine()
        opt.init()
    except Exception as e:
        GaussLog.exitWithError(ErrorCode.GAUSS_536["GAUSS_53608"] % str(e))
    try:
        opt.do_operate()
    except Exception as e:
        GaussLog.exitWithError(str(e))


if __name__ == "__main__":
    main()
