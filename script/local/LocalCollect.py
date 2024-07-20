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
# Description  : LoaclCollector.py is a local utility to
# collect file and parameter file
#############################################################################

import os
import sys
import subprocess
import getopt
import time
import re
import base64
import collections
import json
import datetime
import getpass
import heapq

sys.path.append(sys.path[0] + "/../")
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import ClusterCommand, DefaultValue
from multiprocessing.dummy import Pool as ThreadPool
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.cluster_log import ClusterLog
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from domain_utils.cluster_os.cluster_user import ClusterUser
from domain_utils.cluster_file.cluster_dir import ClusterDir
from gspylib.component.DSS.dss_comp import Dss, DssInst

###########################
# instance type. only for CN/DN
###########################
INSTANCE_TYPE_UNDEFINED = -1
# master
MASTER_INSTANCE = 0
# standby
STANDBY_INSTANCE = 1
# dummy standby
DUMMY_STANDBY_INSTANCE = 2

#######################################################################
# GLOBAL VARIABLES
#   g_opts: globle option
#   g_logger: globle logger
#   g_clusterInfo: global clueter information
#   g_resultdir: globle result dir
#   g_localnodeinfo: globle local nodes information
#######################################################################
HOSTNAME = NetUtil.GetHostIpOrName()
g_opts = None
g_logger = None
g_clusterInfo = None
g_resultdir = None
g_localnodeinfo = None
g_jobInfo = None
g_tmpdir = None
g_current_time = ""
g_need_gstack = 0
g_core_pattern = 'core-%e-%p-%t'


class CmdOptions():
    '''
    classdocs
    '''

    def __init__(self):
        """
        function: Constructor
        """
        # initialize variable
        self.action = ""
        self.outputDir = ""
        self.logFile = ""
        self.nodeName = ""
        self.appPath = ""
        self.user = ""
        self.begin = ""
        self.end = ""
        self.key = ""
        # Speed limit to copy/remote copy files, in KB/s
        # Here we use KB/s to avoid bandwidth is too small to calculate,
        # which may get a zero.
        self.speedLimitKBs = 0
        self.speedLimitFlag = 0
        self.config = ""
        self.content = []


class JobInfo():
    """
    class: JobInfo
    """

    def __init__(self):
        '''
        Constructor
        '''
        # initialize variable
        self.jobName = ""
        self.successTask = []
        self.failedTask = {}


def checkEmpty(path):
    """
    function: check the path is empty
    input  : path
    output : int
    """
    isEmpty = 1
    for root, dirs, files in os.walk(path, topdown=False):
        if files:
            isEmpty = 0
            break
    return isEmpty


def replaceInvalidStr(outputStr):
    """
    function: replace invalid str
    input  : outputStr
    output : str
    """
    return outputStr.replace("\'", "").replace("\"", "").replace("`",
                                                                 "").replace(
        "echo", "e c h o").replace("\n", " ")


def sendLogFiles():
    """
    function: package and send log files back to the command node.
    :return:
    """
    g_logger.debug("Begin to remote copy log files.")
    g_logger.debug(
        "Speed limit to copy log files is %d KB/s." % g_opts.speedLimitKBs)
    # Compress the copied log file and modify the permissions in the
    # temporary directory
    tarName = "%s.tar.gz" % HOSTNAME

    path = g_tmpdir + "/%s" % HOSTNAME
    if not os.path.exists(path):
        g_logger.logExit("Result Dir is not exists.")

    isEmpty = checkEmpty(path)
    if isEmpty == 1:
        # Delete the result temporary directory if the result temporary
        # directory exists
        cmd = "(if [ -d '%s' ];then rm -rf '%s';fi)" % (
        g_resultdir, g_resultdir)
        # Delete the archive if the archive is present in the temporary
        # directory
        cmd = "%s && (if [ -f '%s'/'%s' ];then rm -rf '%s'/'%s';fi)" % \
              (cmd, g_tmpdir, tarName, g_tmpdir, tarName)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            g_logger.logExit("Failed to delete %s." % "%s and %s" % (
            g_resultdir, tarName) + " Error:\n%s" % output)
        g_logger.logExit("All collection tasks failed")

    cmd = "cd '%s' && tar -zcf '%s' '%s' && chmod %s '%s'" % \
          (g_tmpdir, tarName, HOSTNAME, DefaultValue.FILE_MODE, tarName)
    (status, output) = CmdUtil.retryGetstatusoutput(cmd)
    if status != 0:
        g_logger.logExit("Failed to compress %s." % ("directory %s/%s" % \
                                                     (g_tmpdir,
                                                      HOSTNAME))
                         + " Error: \n%s" % output)

    if g_opts.nodeName != "":
        # send  backup file which is compressed  to the node that is
        # currently performing the backup
        if g_opts.nodeName == NetUtil.GetHostIpOrName():
            if int(g_opts.speedLimitFlag) == 1:
                cmd = "rsync --bwlimit=%d '%s'/'%s' '%s'/" % \
                      (g_opts.speedLimitKBs, g_tmpdir, tarName,
                       g_opts.outputDir)
            else:
                cmd = "cp '%s'/'%s' '%s'/" % (
                g_tmpdir, tarName, g_opts.outputDir)
        else:
            # scp's limit parameter is specified in Kbit/s. 1KB/s = 8Kbit/s
            cmd = "pscp -x '-l %d' -H %s '%s'/'%s' '%s'/" % \
                  (
                  g_opts.speedLimitKBs * 8, g_opts.nodeName, g_tmpdir, tarName,
                  g_opts.outputDir)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            g_logger.logExit(
                "Failed to copy %s." % tarName + " Error:\n%s" % output)

    # Delete the temporary directory if the temporary directory exists
    cmd = "(if [ -d '%s' ];then rm -rf '%s';fi)" % (g_resultdir, g_resultdir)
    # Delete the archive if the archive is present in the temporary directory
    cmd = "%s && (if [ -f '%s'/'%s' ];then rm -rf '%s'/'%s';fi)" % \
          (cmd, g_tmpdir, tarName, g_tmpdir, tarName)
    (status, output) = CmdUtil.retryGetstatusoutput(cmd)
    if status != 0:
        g_logger.logExit("Failed to delete %s. %s" % (
        "%s and %s" % (g_resultdir, tarName), " Error:\n%s" % output))


def checkParameterEmpty(parameter, parameterName):
    """
    function: check parameter whether is or not empty
    input  : parameter, parameterName
    output : NA
    """
    if parameter == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                               % parameterName)


def parseCommandLine():
    """
    function: do parse command line
    input : cmdCommand
    output: help/version information
    """
    global g_opts
    g_opts = CmdOptions()
    try:
        # Parse command
        opts, args = getopt.getopt(sys.argv[1:], "t:U:o:h:b:e:k:l:s:S:C:",
                                   [""])
    except getopt.GetoptError as e:
        # Error exit if an illegal parameter exists
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))
    if len(args) > 0:
        # Error exit if an illegal parameter exists
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] %
                               str(args[0]))
    # Save parameter
    parameter_map = {"-t": g_opts.action, "-U": g_opts.user,
                     "-o": g_opts.outputDir, "-h": g_opts.nodeName, \
                     "-l": g_opts.logFile, "-b": g_opts.begin,
                     "-e": g_opts.end, "-k": g_opts.key,
                     "-s": g_opts.speedLimitKBs, "-S": g_opts.speedLimitFlag,
                     "-C": g_opts.config}
    parameter_keys = parameter_map.keys()

    for key, value in opts:
        if key in parameter_keys:
            if key == "-C":
                value = value.replace("#", "\"")
            parameter_map[key] = value.strip()
        else:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % value)

        Parameter.checkParaVaild(key, value)
    g_opts.action = parameter_map["-t"]
    g_opts.user = parameter_map["-U"]
    g_opts.outputDir = parameter_map["-o"]
    g_opts.nodeName = parameter_map["-h"]
    g_opts.logFile = parameter_map["-l"]
    g_opts.begin = parameter_map["-b"]
    g_opts.end = parameter_map["-e"]
    g_opts.key = parameter_map["-k"]
    g_opts.speedLimitKBs = parameter_map["-s"]
    g_opts.speedLimitFlag = parameter_map["-S"]
    g_opts.config = parameter_map["-C"]
    # The -t parameter is required
    checkParameterEmpty(g_opts.action, "t")
    # check if user exist and is the right user
    checkParameterEmpty(g_opts.user, "U")
    ClusterUser.checkUser(g_opts.user, False)
    # check log file
    if g_opts.logFile == "":
        g_opts.logFile = ClusterLog.getOMLogPath(ClusterConstants.LOCAL_LOG_FILE,
                                                   g_opts.user, "", "")
    if not os.path.isabs(g_opts.logFile):
        GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50213"] % "log")
    if int(g_opts.speedLimitKBs) < 0:
        GaussLog.exitWithError(ErrorCode.GAUSS_526["GAUSS_53032"])

    g_opts.speedLimitKBs = int(g_opts.speedLimitKBs)

    # 1048576 KB/s = 1GB/s, which means unlimited.
    if g_opts.speedLimitKBs == 0:
        g_opts.speedLimitKBs = 1048576


def initGlobal():
    """
    function: Init logger g_clusterInfo g_sshTool g_nodes
    input : NA
    output: []
    """
    global g_logger
    global g_clusterInfo
    global g_resultdir
    global g_localnodeinfo
    global g_tmpdir
    global g_current_time
    global g_core_pattern

    try:
        # The -t parameter is required
        g_logger = GaussLog(g_opts.logFile, "LocalCollect")
        # Init the cluster information from static configuration file
        g_clusterInfo = dbClusterInfo()
        g_clusterInfo.initFromStaticConfig(g_opts.user)
        g_tmpdir = EnvUtil.getTmpDirFromEnv()

        # Obtain the cluster installation directory
        g_opts.appPath = g_clusterInfo.appPath
        # Gets the current node information
        g_localnodeinfo = g_clusterInfo.getDbNodeByName(HOSTNAME)
        # Gets a temporary directory
        g_resultdir = "%s/%s" % (g_tmpdir, HOSTNAME)

        g_current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f")
    except Exception as e:
        g_logger.logExit(str(e))


def check_command():
    """
    function: check command
    input  : NA
    output : NA
    """
    g_logger.debug("check Command for rsync")
    g_logger.debug(g_opts.speedLimitFlag)
    cmd = "command -v rsync"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.logExit(("The cmd is %s." % cmd) + output)


def create_temp_result_folder():
    """
    function: create_temp_result_folder
    output: Successfully create temp result folder
    """
    # Delete the temporary folder if a temporary folder with the same name
    # exists
    cmd = "(if [ -d '%s' ];then rm -rf '%s';fi)" % (g_resultdir, g_resultdir)
    # Create temporary folders and subfolders
    cmd = "%s && mkdir -p -m %s '%s'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/systemfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/catalogfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/xlogfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/gstackfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/coreDumpfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s/planSimulatorfiles'" % (
    cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    cmd = "%s && mkdir -p -m %s '%s'/logfiles && mkdir -p -m %s " \
          "'%s/configfiles'" % \
          (cmd, DefaultValue.KEY_DIRECTORY_MODE, g_resultdir,
           DefaultValue.KEY_DIRECTORY_MODE, g_resultdir)
    g_logger.debug("Command for creating output directory: %s" % cmd)
    (status, output) = CmdUtil.retryGetstatusoutput(cmd)
    if status != 0:
        g_logger.logExit("Failed to create the %s directory." % \
                         ("%s/logfiles and %s/configfiles" % (
                         g_resultdir, g_resultdir)) + " Error:\n%s" % output)


def itemTitleCommand(cmds, info, dataFileName):
    """
    function: item title command
    input  : cmds, info, dataFileName
    output : NA
    """
    itemTitle = "'###########################################################'"
    cmds.append("echo '\n%s' >> %s 2>&1" % (itemTitle, dataFileName))
    cmds.append("echo '#' >> %s 2>&1" % dataFileName)
    cmds.append("echo '#' %s >> %s 2>&1" % (info, dataFileName))
    cmds.append("echo '#' >> %s 2>&1" % dataFileName)
    cmds.append("echo %s >> %s 2>&1" % (itemTitle, dataFileName))


def basic_info_check():
    """
    function: collected basci information
    output: Successfully collected basic information
    """
    g_logger.debug("Starting collect basic info.")
    dataFileName = "%s/systemfiles/database_system_info_%s.txt" % (
    g_resultdir, datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f"))
    cmds = []
    itemTitleCommand(cmds, "C L U S T E R'    'I N F O", dataFileName)
    cmds.append("gs_om -t status --detail >> %s 2>&1" % dataFileName)

    itemTitleCommand(cmds, "V E R S I O N'    'I N F O", dataFileName)
    cmds.append("gaussdb --version >> %s 2>&1" % dataFileName)
    cmds.append("cm_agent --version >> %s 2>&1" % dataFileName)
    cmds.append("cm_server --version >> %s 2>&1" % dataFileName)
    cmds.append("gs_gtm --version >> %s 2>&1" % dataFileName)
    cmds.append("cat /proc/version >> %s 2>&1" % dataFileName)

    cmd = "cat /proc/sys/kernel/core_pattern"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug(
            "Failed to collect core dump files. Command: %s.\n Error:\n%s" % (
            cmd, output))
    core_config = str(output)
    core_pattern = core_config.split('/')[-1]
    itemTitleCommand(cmds, "C O R E'    'F I L E'    'I N F O", dataFileName)
    if core_pattern != g_core_pattern:
        cmds.append(
            "echo Failed to collect core dump files, core pattern "
            "is not core-e-p-t. >> %s 2>&1" % dataFileName)
    else:
        core_path = "/".join(core_config.split("/")[:-1])
        cmds.append("ls -lrt %s >> %s 2>&1" % (core_path, dataFileName))

    itemTitleCommand(cmds, "X L O G'    'F I L E'    'I N F O", dataFileName)
    for Inst in g_localnodeinfo.datanodes:
        cmds.append(
            "echo '\n********' dn_%d xlog file info '*******' >> %s 2>&1" % (
            Inst.instanceId, dataFileName))
        pg_xlog = Inst.datadir + "/pg_xlog"
        cmds.append("ls -lrt %s >> %s 2>&1" % (pg_xlog, dataFileName))

    for Inst in g_localnodeinfo.coordinators:
        cmds.append(
            "echo '\n********' cn_%d xlog file info '*******' >> %s 2>&1" % (
            Inst.instanceId, dataFileName))
        pg_xlog = Inst.datadir + "/pg_xlog"
        cmds.append("ls -lrt %s >> %s 2>&1" % (pg_xlog, dataFileName))

    cmd = "echo $GAUSSLOG"
    (status, output) = subprocess.getstatusoutput(cmd)
    gausslog = str(output)
    pg_log = "%s/pg_log" % gausslog

    itemTitleCommand(cmds, "P G_L O G'    'F I L E'    'I N F O", dataFileName)
    for root, dirs, files in os.walk(pg_log):
        for perDir in dirs:
            cmds.append(
                "echo '\n********' %s pg_log file info '*******' >> %s 2>&1"
                % (
                perDir, dataFileName))
            cmds.append(
                "ls -lrt %s/%s >> %s 2>&1" % (root, perDir, dataFileName))

    # Executes each query command and redirects the results to the specified
    # file
    for cmd in cmds:
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_logger.debug(
                ("Failed to collect basic information. Error:\n%s." % output) +
                ("The cmd is %s " % cmd))


def system_check():
    """
    function: collected OS information
    input : dataFileName
    output: Successfully collected OS information
    """
    g_logger.debug("Collecting OS information.")
    g_jobInfo.jobName = "Collecting OS information"
    dataFileName = "%s/systemfiles/OS_information_%s.txt" % (
    g_resultdir, datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f"))
    cmds = []
    # Add information to the document
    cmds.append(
        "echo '************************************\n* OS information"
        " for host' > %s 2>&1" % dataFileName)
    cmds.append("hostname >> %s 2>&1" % dataFileName)
    cmds.append("echo '************************************' >> %s 2>&1" %
                dataFileName)
    appendCommand(cmds, "cat /proc/cpuinfo", dataFileName)
    appendCommand(cmds, "cat /proc/meminfo", dataFileName)
    appendCommand(cmds, "df -h", dataFileName)
    appendCommand(cmds, "ps ux", dataFileName)
    appendCommand(cmds, "iostat -xm 2 3", dataFileName)
    appendCommand(cmds, "cat /proc/net/dev", dataFileName)
    appendCommand(cmds, "free -m", dataFileName)
    # Executes each query command and redirects the results to the specified
    # file
    for cmd in cmds:
        (status, output) = subprocess.getstatusoutput(cmd)
        if ">>" in cmd:
            cmd = cmd.split(">>")[0]
        cmd = cmd.replace("\n", " ")
        if "echo" in cmd:
            continue
        if status != 0:
            if "Permission denied" in output:
                output = "can not print info to file: Permission denied"
            elif 'iostat' in cmd and 'command not found' in str(
                    output).lower().strip():
                output = ErrorCode.GAUSS_514["GAUSS_51405"] % " iostat." + str(
                    output).lstrip().strip()
            g_jobInfo.failedTask[cmd] = replaceInvalidStr(output)
            g_logger.debug(
                "Failed to collect OS information. Error:\n%s" % output)
        else:
            g_jobInfo.successTask.append(cmd)
    basic_info_check()
    # Modify the file permissions
    os.chmod(dataFileName, DefaultValue.FILE_MODE_PERMISSION)
    g_logger.log(json.dumps(g_jobInfo.__dict__))
    g_logger.debug("Successfully collected OS information.")


def appendCommand(cmds, newCommand, dataFileName):
    """
    function: make up the commands into the array
    input : cmds, newCommand, dataFileName
    output: NA
    """
    # Execute the command and output to the specified file
    cmds.append("echo '\n************************************\n* " \
                "%s \n" \
                "************************************' >> %s 2>&1" % \
                (newCommand, dataFileName))
    if 'iostat' in newCommand:
        cmds.append("%s >> %s" % (newCommand, dataFileName))
    else:
        cmds.append("%s >> %s 2>&1" % (newCommand, dataFileName))


def database_check():
    """
    function: collected catalog informatics
    input : dbNode
    output: Successfully collected catalog statistics.
    """
    # Execute SQL for collect catalog statistics
    g_logger.debug("Collecting catalog statistics.")
    g_jobInfo.jobName = "Collecting catalog information"
    for dnInst in g_localnodeinfo.datanodes:
        if dnInst.instanceType == STANDBY_INSTANCE:
            continue
        sqls = []
        schema = ""
        for s in DefaultValue.DATABASE_CHECK_WHITE_LIST:
            schema += "\'%s\'," % s
        sql = "SELECT viewname FROM pg_views Where schemaname IN (%s) union " \
              "SELECT tablename FROM pg_tables Where schemaname IN (%s);" % (
        schema[:-1], schema[:-1])
        g_logger.debug(sql)
        (status, output) = ClusterCommand.execSQLCommand(sql, g_opts.user, "",
                                                         dnInst.port)
        if status != 0:
            g_logger.debug(
                "Failed to exec SQL command. please check db status. sql: "
                "%s.\n Error: %s.\n" % (
                sql, output))
            g_jobInfo.failedTask["find views"] = ErrorCode.GAUSS_535[
                "GAUSS_53502"]
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            raise Exception("")
        g_jobInfo.successTask.append("find views")
        V_list = output.split("\n")
        for view in g_opts.content:
            view = view.replace(" ", "")
            if len(view) > 0:
                schema = 'pg_catalog'
                if "." in view:
                    s_t = view.split(".")
                    if len(s_t) != 2:
                        g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                                                         "GAUSS_53515"] % view
                        continue
                    else:
                        schema = s_t[0]
                        name = s_t[1]
                        if schema.lower() not in \
                                DefaultValue.DATABASE_CHECK_WHITE_LIST:
                            g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                                                             "GAUSS_53513"] \
                                                         % schema
                            continue
                        if name.lower() not in V_list:
                            g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                                                             "GAUSS_53514"] % (
                                                         name, schema)
                            continue
                elif view.lower() not in V_list:
                    g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                                                     "GAUSS_53514"] % (
                                                 view, schema)
                    continue
                filepath = ("%s/catalogfiles/" % g_resultdir)
                if not os.path.exists(filepath):
                    os.makedirs(filepath)
                filename = ("%s/dn_%s_%s_%s.csv" % (
                    filepath, dnInst.instanceId, view.replace(".", "_"),
                    datetime.datetime.now().strftime("%Y%m%d_%H%M%S%f")))
                sql = "\copy (select * from %s) to %s with csv HEADER;" % (
                view, filename)
                (status, output) = ClusterCommand.execSQLCommand(sql,
                                                                 g_opts.user,
                                                                 "",
                                                                 dnInst.port)
                if status != 0:
                    g_logger.debug(
                        "Failed to exec SQL command. sql %s.\n Error: %s.\n"
                        % (
                        sql, output))
                    if "does not exist" in output:
                        g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                                                         "GAUSS_53500"] % view
                    elif "Connection refused" in output:
                        g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                            "GAUSS_53501"]
                    else:
                        g_jobInfo.failedTask[view] = ErrorCode.GAUSS_535[
                            "GAUSS_53502"]
                else:
                    g_jobInfo.successTask.append(view)
                    g_logger.debug(
                        "Successfully collected %s statistics. %s" % (
                        view, sql))
    g_logger.log(json.dumps(g_jobInfo.__dict__))
    g_logger.debug("Successfully collected catalog statistics.")

def log_check(logFileName):
    """
    function: log check
    input : logFileName
    output: filename includes keywords or not
    """
    for c in g_opts.content:
        c = c.replace(" ", "").lower()
        if len(c) > 0 and c in logFileName.lower():
            return 1
    return 0

def dss_cert_replacer(logger):
    '''
    Re-generate the ciphertext of the DSS.
    '''

    logger.debug("Start to replace the ciphertext of the DSS locally")
    user = getpass.getuser()
    gausshome = ClusterDir.getInstallDir(user)
    dsscmd = os.path.realpath(os.path.join(gausshome, 'bin', 'dsscmd'))
    if os.path.isfile(dsscmd):
        dss_home = EnvUtil.get_dss_home(user)
        cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')
        if os.path.isfile(cfg):
            Dss.write_dss_context_with_file()
            logger.debug("Successfully generate the ciphertext of the DSS.")
        else:
            logger.log(f"The {cfg} not exist.")
    else:
        logger.debug("Non-dss-mode or not find dsscmd.")

def parallel_dss_conf(inst):
    """
    parallel copy dss config files
    """
    cmd = "mkdir -p -m %s %s/dssconfigfiles && cp -r $DSS_HOME/cfg/* %s/dssconfigfiles/." % (
        DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_resultdir)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug(
            "Failed to collect dss config files. Command: %s.\n Error: %s\n" % (
                cmd, output))
        g_jobInfo.failedTask["collect dss config giles"] = replaceInvalidStr(
            output)
        raise Exception("")

def dss_conf_copy():
    """
    function: collected dss config files
    input:  NA
    output: NA
    """
    g_logger.debug("Starting collect dss config files.")
    g_jobInfo.jobName = "Collecting dss_config information."
    try:
        # Get all instances of the cluster.
        instances = [] 
        for inst in g_localnodeinfo.datanodes:
            if "dn" in ",".join(g_opts.content).lower():
                instances.append(inst)
        # parallel copy dss config files 
        if instances:
            pool = ThreadPool(DefaultValue.getCpuSet())
            pool.map(parallel_dss_conf, instances)
            pool.close()
            pool.join()
            g_jobInfo.successTask.append("collect dss config information")
            g_logger.log(json.dumps(g_jobInfo.__dict__))
    except Exception as e:
        g_logger.debug(str(e))
        g_logger.log(json.dumps(g_jobInfo.__dict__))
        raise Exception("")

    g_logger.debug(
        "Successfully collected dss config files."
    )

def disk_info_copy():
    """
    function: collected disk info on nodes
    input: NA
    output: NA
    """
    g_logger.debug("Starting collect disk info.")
    g_jobInfo.jobName = "Collecting disk info."
    cmds = []
    # copy dss disk vg info
    lsvg_cmd = "mkdir -p -m %s %s/dssdiskinfo && dsscmd lsvg > %s/dssdiskinfo/vg_info" % (
        DefaultValue.DIRECTORY_MODE, g_resultdir, g_resultdir)
    cmds.append(lsvg_cmd)
    # copy lun/reg inq info
    lun_cmd = "mkdir -p -m %s %s/dssdiskinfo/inq && dsscmd inq -t lun > %s/dssdiskinfo/inq/lun" % (
            DefaultValue.DIRECTORY_MODE, g_resultdir, g_resultdir)
    cmds.append(lun_cmd)
    reg_cmd = "mkdir -p -m %s %s/dssdiskinfo/inq && dsscmd inq -t reg > %s/dssdiskinfo/inq/reg" % (
              DefaultValue.DIRECTORY_MODE, g_resultdir, g_resultdir)
    cmds.append(reg_cmd)
    # copy disk info using dsscmd showdisk
    collect_disk = ('core_ctrl', 'vg_header', 'volume_ctrl', 'root_ft_block')
    for c in g_opts.content:
        if c == 'vgname':
            disk = EnvUtil.getEnv('VGNAME')
        else:
            dss_home = EnvUtil.getEnv('DSS_HOME')
            inst_id = DssInst.get_dss_id_from_key(dss_home)
            disk = DssInst.get_private_vgname_by_ini(dss_home, inst_id)
        disk_cmd = "mkdir -p -m %s %s/dssdiskinfo/disk/%s" % (
                   DefaultValue.DIRECTORY_MODE, g_resultdir, disk)
        cmds.append(disk_cmd)
        for col_disk in collect_disk:
            cmd = "dsscmd showdisk -g %s -s core_ctrl > %s/dssdiskinfo/disk/%s/%s" % (
                   disk, g_resultdir, disk, col_disk)
            cmds.append(cmd)

    for cmd in cmds:
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_jobInfo.failedTask["collect disk info"] = replaceInvalidStr(
                output)
            g_logger.debug(
                ("Failed to collect disk information. Error:\n%s." % output) +
                ("The cmd is %s " % cmd))

    g_logger.log(json.dumps(g_jobInfo.__dict__))
    g_logger.debug("Successfully collected disk files.")

def check_dss_env():
    """
    function: check if dss exists
    input: NA
    output: NA
    """
    dss_home = EnvUtil.getEnv('DSS_HOME')
    if dss_home:
        return True 
    return False 

def find_log():
    cmd = ""
    if g_opts.key is not None and g_opts.key != "":
        cmd = "cd $GAUSSLOG && if [ -d tmp_gs_collector ];" \
              "then rm -rf tmp_gs_collector; " \
              "fi && (find . -type f -iname '*.log' -print && " \
              "find . -type f -iname '*.log.gz' -print)" \
              " | xargs ls --time-style='+ %Y%m%d%H%M' -ll"
    else:
        cmd = "cd $GAUSSLOG && if [ -d tmp_gs_collector ];" \
              "then rm -rf tmp_gs_collector; " \
              "fi && (find . -type f -iname '*.log' -print && " \
              "find . -type f -iname '*.prf' -print && " \
              "find . -type f -iname '*.log.gz' -print)" \
              "| xargs ls --time-style='+ %Y%m%d%H%M' -ll"
    if check_dss_env():
        cmd = "%s && (find $GAUSSLOG/pg_log/DMS -type f -iname '*.*log' -print && " \
              "find $GAUSSLOG/pg_log/DMS -type f -iname '*.*log.gz' -print && "\
              "find $GAUSSLOG/pg_log/DSS -type f -iname '*.*log' -print && "\
              "find $GAUSSLOG/pg_log/DSS -type f -iname '*.*log.gz' -print && "\
              "find $DSS_HOME/log -type f -iname '*.*log' -print && " \
              "find $DSS_HOME/log -type f -iname '*.*log.gz' -print)" \
              "| xargs ls --time-style='+ %%Y%%m%%d%%H%%M' -ll" % cmd
    (status, output) = subprocess.getstatusoutput(cmd)
    logFiles = output.split("\n")
    logs = []
    find_files = 0
    # If there is a log file filtered by time
    if len(logFiles[0].split()) != 2:
        for logFile in logFiles:
            logFileName = logFile.split()[6]
            logStartTime = formatTime(logFileName)
            # If the log file name does not meet the format requirements,skip
            if not logStartTime.isdigit() or len(logStartTime) != 12:
                continue
            logStartTime = int(logStartTime)
            logEndTime = int(logFile.split()[5])
            # Filter out the log we need
            if (logEndTime > int(g_opts.begin) and logStartTime < int(
                    g_opts.end) and log_check(logFileName)):
                logs.append(logFileName)
                find_files = 1
        if find_files == 1:
            g_jobInfo.successTask.append("find log files")
        else:
            g_jobInfo.failedTask["find log files"] = ErrorCode.GAUSS_535["GAUSS_53504"] % 'log'
        g_logger.debug("Successfully find log files.")
    else:
        g_jobInfo.failedTask["find log files"] = ErrorCode.GAUSS_535[
            "GAUSS_53505"]
        g_logger.debug("There is no log files.")
    return logs

def make_log_dir(log_files, deleteCmd):
    cmd = "cd $GAUSSLOG && mkdir -p -m %s tmp_gs_collector" % \
           DefaultValue.DIRECTORY_MODE
    if check_dss_env():
        cmd = "%s && cd $GAUSSLOG && mkdir -p -m %s tmp_gs_collector/pg_log/DMS/run && " \
              "mkdir -p -m %s tmp_gs_collector/pg_log/DMS/debug && mkdir -p -m %s tmp_gs_collector/pg_log/DMS/oper" \
              " && mkdir -p -m %s tmp_gs_collector/pg_log/DMS/blackbox && " \
              "mkdir -p -m %s tmp_gs_collector/pg_log/DSS/run && mkdir -p -m %s tmp_gs_collector/pg_log/DSS/debug" \
              " && mkdir -p -m %s tmp_gs_collector/pg_log/DSS/oper && " \
              "mkdir -p -m %s tmp_gs_collector/pg_log/DSS/blackbox && mkdir -p -m %s tmp_gs_collector/DSSLog" % (
              cmd, DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE,
              DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE,
              DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE)
        cmd = "%s && mkdir -p -m %s tmp_gs_collector/DSSLog/run &&" \
              "mkdir -p -m %s tmp_gs_collector/DSSLog/debug && mkdir -p -m %s tmp_gs_collector/DSSLog/oper &&" \
              "mkdir -p -m %s tmp_gs_collector/DSSLog/blackbox" % (
              cmd, DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE,
              DefaultValue.DIRECTORY_MODE, DefaultValue.DIRECTORY_MODE)
    (status, output) = subprocess.getstatusoutput(cmd)
    directorys = []
    for log in log_files:
        if '.log' in log or '.prf' in log:
            directorys.append(os.path.dirname(log))
    for directory in directorys:
        cmd = "cd $GAUSSLOG && mkdir -p -m %s tmp_gs_collector/'%s'" % (
        DefaultValue.DIRECTORY_MODE, directory)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            (status1, output1) = subprocess.getstatusoutput(deleteCmd)
            g_jobInfo.failedTask["mkdir"] = ErrorCode.GAUSS_535["GAUSS_53506"]
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            g_logger.debug("Failed to mkdir. Error:\n%s." % output)
            raise Exception("")

def copy_log(log_files, deleteCmd):
    dss_home = EnvUtil.getEnv("DSS_HOME")
    dss_str = [('rlog', 'run'), ('dlog', 'debug'), ('olog', 'oper'), ('blog', 'blackbox')]
    dss_log = collections.defaultdict(str)
    for k, v in dss_str:
        dss_log[k] = v
    for log in log_files:
        log_str = log.split('.')[-1] if log.split('.')[-1] in dss_log else log.split('.')[-2]
        if int(g_opts.speedLimitFlag) == 1:
            if 'pg_log/DMS' in log:
                cmd = "cd $GAUSSLOG && rsync --bwlimit=%d '%s' " \
                      "tmp_gs_collector/pg_log/DMS/%s/." % (g_opts.speedLimitKBs, log, dss_log[log_str])
            elif 'pg_log/DSS' in log:
                cmd = "cd $GAUSSLOG && rsync --bwlimit=%d '%s' " \
                      "tmp_gs_collector/pg_log/DSS/%s/." % (g_opts.speedLimitKBs, log, dss_log[log_str])
            elif dss_home and dss_home in log:
                cmd = "cd $GAUSSLOG && rsync --bwlimit=%d '%s' " \
                      "tmp_gs_collector/DSSLog/%s/." % (g_opts.speedLimitKBs, log, dss_log[log_str])

            else:
                cmd = "cd $GAUSSLOG && rsync --bwlimit=%d '%s' " \
                      "tmp_gs_collector/'%s'" % (g_opts.speedLimitKBs, log, log)
        else:
            if 'pg_log/DMS' in log:
                cmd = "cd $GAUSSLOG && cp %s tmp_gs_collector/pg_log/DMS/%s/." % (log, dss_log[log_str])
            elif 'pg_log/DSS' in log:
                cmd = "cd $GAUSSLOG && cp %s tmp_gs_collector/pg_log/DSS/%s/." % (log, dss_log[log_str])
            elif dss_home and dss_home in log:
                cmd = "cd $GAUSSLOG && cp %s tmp_gs_collector/DSSLog/%s/." % (log, dss_log[log_str])
            else:
                cmd = "cd $GAUSSLOG && cp '%s' tmp_gs_collector/'%s'" % (log, log)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 and 'Permission denied' not in output:
            (status1, output1) = subprocess.getstatusoutput(deleteCmd)
            g_jobInfo.failedTask["copy log files"] = replaceInvalidStr(output)
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            g_logger.debug("Failed to copy logFiles. Error:\n%s." % output)
            raise Exception("")

    g_jobInfo.successTask.append("copy log files")
    g_logger.debug("Successful to copy logFiles.")

def find_zip_log():
    cmd = "cd $GAUSSLOG && find . -type f -iname '*.zip' -print" \
          " | xargs ls --time-style='+ %Y%m%d%H%M' -ll"
    (status, output) = subprocess.getstatusoutput(cmd)
    zipFiles = output.split("\n")
    # If there is a zip file filtered by time
    if len(zipFiles[0].split()) != 2:
        for zipFile in zipFiles:
            zipFileName = zipFile.split()[6]
            logStartTime = formatTime(zipFileName)
            # If the zip file name does not meet the format requirements,skip
            if not logStartTime.isdigit() or len(logStartTime) != 12:
                continue
            logStartTime = int(logStartTime)
            logEndTime = int(zipFile.split()[5])
            # Filter out the log we need
            if (logEndTime > int(g_opts.begin) and logStartTime < int(g_opts.end)):
                zipdir = os.path.dirname(zipFileName)
                g_jobInfo.successTask.append("find log zip files: %s" % zipFileName)
                cmd = "cd $GAUSSLOG && mkdir -p -m %s tmp_gs_collector/%s " \
                      "&& unzip -o %s -d tmp_gs_collector/%s " % \
                      (DefaultValue.DIRECTORY_MODE, zipdir,zipFileName, zipdir)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    g_jobInfo.failedTask[
                        "find log zip files"] = replaceInvalidStr(output)
                    g_logger.log(json.dumps(g_jobInfo.__dict__))
                    g_logger.debug(("Failed to filter zip files. Error:\n%s."
                                   % output) + ("The cmd is %s " % cmd))
                    raise Exception("")
        g_logger.debug("Successfully filter zip files.")
    else:
        g_logger.debug("There is no zip files.")

def log_keywords(log_files, keyword_result):
    if log_files:
        g_opts.key = g_opts.key.replace('$', '\$')
        g_opts.key = g_opts.key.replace('\"', '\\\"')
        cmd = "cd $GAUSSLOG/tmp_gs_collector && "
        cmd = "%s grep \"%s\" -r * > %s/logfiles/%s" % (
        cmd, g_opts.key, g_resultdir, keyword_result)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 and output != "":
            cmd = "rm -rf $GAUSSLOG/tmp_gs_collector"
            (status1, output1) = CmdUtil.retryGetstatusoutput(cmd)
            g_jobInfo.failedTask[
                "filter keyword"] = "keywords: %s, Error: %s" % (g_opts.key, output)
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            g_logger.debug("Failed to filter keyword. Error:\n%s." % output)
            raise Exception("")
        else:
            cmd = "rm -rf $GAUSSLOG/tmp_gs_collector"
            (status, output) = CmdUtil.retryGetstatusoutput(cmd)
            g_logger.debug("Successfully filter keyword.")
            g_jobInfo.successTask.append("filter keyword: %s" % g_opts.key)

    else:
        cmd = "touch %s/logfiles/%s && " % (g_resultdir, keyword_result)
        cmd = "%s rm -rf $GAUSSLOG/tmp_gs_collector" % cmd
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            g_jobInfo.failedTask["touch keyword file"] = replaceInvalidStr(output)
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            g_logger.debug("Failed to touch keyword file. Error:\n%s." % output)
            raise Exception("")
        g_logger.debug("Successfully filter keyword.")

def log_copy():
    """
    function: collected log files
    input : NA
    output: NA
    """
    g_logger.debug("Starting collect log.")
    g_jobInfo.jobName = "Collecting pg_log information"
    logfiletar = "log_%s.tar.gz" % datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S%f")
    keyword_result = "keyword_result.txt"
    deleteCmd = "cd $GAUSSLOG && if [ -d tmp_gs_collector ];" \
                "then rm -rf tmp_gs_collector; fi"

    if g_opts.key is not None and g_opts.key != "":
        g_logger.debug(
            "Keyword for collecting log in base64 encode [%s]." % g_opts.key)
        g_opts.key = base64.b64decode(g_opts.key)
        g_logger.debug(
            "Keyword for collecting log in plain text [%s]." % g_opts.key)

    g_logger.debug(
        "Speed limit to copy log files is %d KB/s." % g_opts.speedLimitKBs)

    # Filter the log files, if has keyword, do not collect prf file
    logs = find_log()

    # Make temporary directory and copy
    make_log_dir(logs, deleteCmd)

    copy_log(logs, deleteCmd)

    # Filter zip files
    find_zip_log()

    # Filter keywords
    if g_opts.key is not None and g_opts.key != "":
        log_keywords(logs, keyword_result)
    else:
        cmd = "cd $GAUSSLOG/tmp_gs_collector && tar -czf ../'%s' . && "\
              % logfiletar
        if int(g_opts.speedLimitFlag) == 1:
            cmd = "%s rsync --bwlimit=%d $GAUSSLOG/'%s' '%s'/logfiles/ && " % (
            cmd, g_opts.speedLimitKBs, logfiletar, g_resultdir,)
        else:
            cmd = "%s cp $GAUSSLOG/'%s' '%s'/logfiles/ && " % (cmd, logfiletar, g_resultdir)
        cmd = " %s rm -rf $GAUSSLOG/tmp_gs_collector " \
              "&& rm -rf $GAUSSLOG/'%s'" % (cmd, logfiletar)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_jobInfo.failedTask[
                "copy result file and delete tmp file"] = replaceInvalidStr(output)
            g_logger.log(json.dumps(g_jobInfo.__dict__))
            g_logger.debug("Failed to delete log files. Error:\n%s." % output)
            raise Exception("")

    subprocess.getstatusoutput("cd '%s'/logfiles/ && chmod %s *" % (
    g_resultdir, DefaultValue.FILE_MODE))
    g_logger.debug("Successfully collected log files.")
    g_logger.log(json.dumps(g_jobInfo.__dict__))

def formatTime(filename):
    """
    function: format time
    input  : filename
    output : str
    """
    try:
        timelist = re.findall(r"\d\d\d\d-\d\d-\d\d_\d\d\d\d\d\d", filename)
        if not timelist:
            with open(filename, 'r') as f:
                lines = f.readlines()
            timelist = re.findall(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d", lines[0])
            if 'blog' in filename:
                timelist = re.findall(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d", lines[2])
        time1 = re.findall(r"\d+", timelist[0])
        time2 = ""
        for i in time1:
            time2 += i
        return time2[:-2]
    except Exception:
        return "ERROR"

def xlog_copy():
    """
    function: collected xlog files
    input : NA
    output: NA
    """
    g_logger.debug("Starting collect xlog.")
    if int(g_opts.speedLimitFlag) == 1:
        g_logger.debug(
            "Speed limit to collect xlog files is %d KB/s."
            % g_opts.speedLimitKBs)
    g_jobInfo.jobName = "Collecting xlog information"
    Instances = []
    try:
        for inst in g_localnodeinfo.datanodes:
            if "dn" in ",".join(g_opts.content).lower():
                Instances.append(inst)
        for inst in g_localnodeinfo.coordinators:
            if "cn" in ",".join(g_opts.content).lower():
                Instances.append(inst)
            # parallel copy xlog files
        if Instances:
            pool = ThreadPool(DefaultValue.getCpuSet())
            pool.map(parallel_xlog, Instances)
            pool.close()
            pool.join()
            path = "%s/xlogfiles" % g_resultdir
            if checkEmpty(path) == 0:
                cmd = " cd %s/xlogfiles " \
                      "&& tar -czf xlogfile_%s.tar.gz  xlogfile_%s " \
                      "&& rm -rf xlogfile_%s" % \
                      (g_resultdir, g_current_time, g_current_time,
                       g_current_time)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    g_logger.debug(
                        "Failed to collect xlog. Command %s \n, Error %s \n",
                        (cmd, output))
                    g_jobInfo.failedTask["compress xlog files"] = \
                    ErrorCode.GAUSS_535["GAUSS_53507"] % 'tar'
                else:
                    g_jobInfo.successTask.append("compress xlog files")
    except Exception as e:
        g_logger.debug(str(e))
        g_logger.log(json.dumps(g_jobInfo.__dict__))
        raise Exception(str(e))
    g_logger.debug("Successfully collected xlog.")
    g_logger.log(json.dumps(g_jobInfo.__dict__))


def getTargetFile(dir_path, fileList):
    """
    function: get target file
    input : dir_path, filelist
    output: target file
    """
    if os.path.isfile(dir_path):
        create_time = time.strftime('%Y%m%d%H%M',
                                    time.localtime(os.stat(dir_path).st_ctime))
        if int(g_opts.begin) < int(create_time) < int(g_opts.end):
            fileList.append(dir_path)
    elif os.path.isdir(dir_path):
        for s in os.listdir(dir_path):
            if "archive" in s:
                continue
            newDir = os.path.join(dir_path, s)
            getTargetFile(newDir, fileList)
    return fileList

def get_dss_xlog_dir(pri_vgname):
    cmd = "dsscmd ls -p +%s" % pri_vgname
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Failed to collect xlog directorys.")
        raise Exception("")
    xlog_dirs = []
    out_list = output.split('\n')
    for out in out_list:
        data_line = out.split()
        for item in data_line:
            if re.findall(r"pg_xlog", item):
                xlog_dirs.append(item)
    
    return xlog_dirs

def get_dss_xlog_file(xlog_path):
    """
    function: get xlog file list when dss enabled
    input: xlog path
    output: xlog_lists
    """
    cmd = "dsscmd ls -p %s" % xlog_path
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Failed to collect disk xlog files")
        raise Exception("Failed to collect disk xlog files")
    out_lines = output.split('\n')
    xlog_lists = []
    for line in out_lines:
        data_line = line.split()
        for item in data_line:
            if re.findall(r"\d{24}", item):
                heapq.heappush(xlog_lists, xlog_path + '/' + item)
    pop_num = len(xlog_lists) - g_opts.file_number
    while pop_num > 0:
        heapq.heappop(xlog_lists)
        pop_num -= 1
    return xlog_lists

def getXlogCmd(Inst):
    """
    function: get xlog file
    input : Inst
    output: xlog file
    """
    if check_dss_env():
        if g_opts.file_number <= 0:
            g_logger.log("Failed to collect xlog files when enable dss, FileNumber must be greater than 0.")
            raise Exception("Failed to collect xlog files when enable dss, FileNumber must be greater than 0.")
        dss_home = EnvUtil.getEnv('DSS_HOME')
        inst_id = DssInst.get_dss_id_from_key(dss_home)
        pri_vgname = DssInst.get_private_vgname_by_ini(dss_home, inst_id)
        xlog_dirs = get_dss_xlog_dir(pri_vgname)
        xlogs = []
        for xdir in xlog_dirs:
            pg_xlog = '+' + pri_vgname + '/' + xdir
            tmp_xlogs = get_dss_xlog_file(pg_xlog)
            xlogs.extend(tmp_xlogs)
    else:
        pg_xlog = Inst.datadir + "/pg_xlog"
        xlogs = getTargetFile(pg_xlog, [])
    cmd = ""
    prefix = ""
    if Inst.instanceRole == DefaultValue.INSTANCE_ROLE_COODINATOR:
        prefix = 'cn'
    elif Inst.instanceRole == DefaultValue.INSTANCE_ROLE_DATANODE:
        prefix = 'dn'
    if len(xlogs) == 0:
        g_jobInfo.failedTask["find %s_%s xlog files" % (prefix, Inst.instanceId)] = \
        ErrorCode.GAUSS_535["GAUSS_53504"] % 'xlog'
    else:
        g_jobInfo.successTask.append(
            "find %s_%s xlog files" % (prefix, Inst.instanceId))
        cmd = "mkdir -p -m %s '%s/xlogfiles/xlogfile_%s/%s_%s'" % \
              (
              DefaultValue.DIRECTORY_MODE, g_resultdir, g_current_time,
              prefix, Inst.instanceId)
        if check_dss_env():
            for xdir in xlog_dirs:
                cmd = "%s && mkdir -p -m %s '%s/xlogfiles/xlogfile_%s/%s_%s/%s'" % \
                      (cmd, DefaultValue.DIRECTORY_MODE, g_resultdir, g_current_time, prefix, Inst.instanceId, xdir)
        for xlog in xlogs:
            if check_dss_env():
                cmd = "%s && dsscmd cp -s %s -d '%s/xlogfiles/xlogfile_%s/%s_%s/%s/%s'" % \
                    (cmd, xlog, g_resultdir, g_current_time, prefix, Inst.instanceId, (xlog.split('/'))[-2],
                    (xlog.split('/'))[-1])
            else:
                if int(g_opts.speedLimitFlag) == 1:
                    cmd = \
                        "%s && rsync --bwlimit=%d %s" \
                        " '%s/xlogfiles/xlogfile_%s/%s_%s'" % \
                          (cmd, g_opts.speedLimitKBs, xlog, g_resultdir,
                           g_current_time, prefix, Inst.instanceId)
                else:
                    cmd = "%s && cp -rf %s " \
                          "'%s/xlogfiles/xlogfile_%s/%s_%s'" % \
                          (cmd, xlog, g_resultdir, g_current_time,
                           prefix, Inst.instanceId)

    return cmd

def parallel_xlog(Inst):
    """
    parallel copy xlog files
    """
    cmd = getXlogCmd(Inst)
    if len(cmd) > 1:
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_logger.debug(
                "Failed to collect xlog files. Command: %s.\n Error: %s\n" % (
                cmd, output))
            g_jobInfo.failedTask["collect xlog files"] = replaceInvalidStr(
                output)
            raise Exception("")

def check_core_pattern():
    """
    function: check core pattern
    input: NA
    output: core_path
    """
    cmd = "cat /proc/sys/kernel/core_pattern"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug(
            "Failed to collect core dump files. Command: %s.\n Error:\n%s" % (
            cmd, output))
        g_jobInfo.failedTask["read core pattern"] = ErrorCode.GAUSS_535[
                                                        "GAUSS_53507"] % 'cat'
        g_logger.log(json.dumps(g_jobInfo.__dict__))
        raise Exception("Failed to collect core dump files")
    core_config = str(output)
    core_pattern = core_config.split('/')[-1]
    core_path = "/".join(core_config.split("/")[:-1])
    if core_pattern != g_core_pattern:
        g_logger.debug(
            "Failed to collect core dump files, core pattern is not '%s'."
            % g_core_pattern)
        g_jobInfo.failedTask["check core pattern"] = ErrorCode.GAUSS_535[
            "GAUSS_53508"]
        g_logger.log(json.dumps(g_jobInfo.__dict__))
        raise Exception("")

    g_jobInfo.successTask.append("check core pattern")
    return core_path

def check_gaussdb_version():
    """
    function: check gaussdb version
    input: NA
    output: NA
    """
    cmd = "mkdir -p -m %s '%s/coreDumpfiles/corefile_%s'" % \
          (DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time)
    cmd = "%s && gaussdb --version >>" \
          " %s/coreDumpfiles/corefile_%s/version.txt" % \
          (cmd, g_resultdir, g_current_time)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug(
            "Failed to collect gaussdb version info."
            " Command: %s.\n Error:\n%s" % (
            cmd, output))
        g_jobInfo.failedTask["check gaussdb version"] = replaceInvalidStr(
            output)
    g_jobInfo.successTask.append("check gaussdb version")

def copy_core_files(cores):
    """
    function: copy core files
    input: core files
    output: isEmpty
    """
    isEmpty = 1
    for core in cores:
        tempName = str(core.split("/")[-1])
        if not tempName.startswith("core-"):
            g_logger.debug(
                 "WARNING: core file %s is not match core-e-p-t." % (
                    str(core.split("/")[-1])))
            continue
        p = tempName.split("-")[1]
        if "".join(p).lower() in ",".join(g_opts.content).lower() or p[0] == '%':
            p_stack = "%s_stack" % p
            cmdList = []
            if p_stack in g_opts.content or p[0] == '%':
                cmd = "gdb -q --batch --ex" \
                        " \"set height 0\" -ex \"thread apply" \
                        " all bt full\" %s %s >> " \
                        "%s/coreDumpfiles/corefile_%s/%s-stack1.txt" % (
                p, core, g_resultdir, g_current_time, core.split("/")[-1])
                cmd += " && gdb -q --batch --ex \"set height 0\"" \
                        " -ex \"thread apply all bt\" %s %s >> " \
                        "%s/coreDumpfiles/corefile_%s/%s-stack2.txt" % (
                p, core, g_resultdir, g_current_time, core.split("/")[-1])
                cmdList.append(cmd)

            if p in g_opts.content:
                if int(g_opts.speedLimitFlag) == 1:
                    cmd = \
                        "rsync --bwlimit=%d %s" \
                        " '%s/coreDumpfiles/corefile_%s'" % (
                        g_opts.speedLimitKBs, core, g_resultdir,
                        g_current_time)
                else:
                    cmd = "cp -rf %s '%s/coreDumpfiles/corefile_%s'" % (
                          core, g_resultdir, g_current_time)
                    cmdList.append(cmd)
            for c in cmdList:
                (status, output) = subprocess.getstatusoutput(c)
                if status != 0:
                    g_logger.debug(
                        "Failed to copy core dump files. Command:"
                        " %s.\n Error:\n%s" % (
                        c, output))
                    g_jobInfo.failedTask[
                        "copy core file"] = replaceInvalidStr(output)
                else:
                    isEmpty = 0
    return isEmpty

def core_copy():
    """
    function: collected core files
    input : NA
    output: NA
    """
    g_logger.debug("Starting collect core dump.")
    if int(g_opts.speedLimitFlag) == 1:
        g_logger.debug(
            "Speed limit to collect core dump files is %d KB/s."
            % g_opts.speedLimitKBs)
    g_jobInfo.jobName = "Collecting Core information"
    Instances = []
    core_path = check_core_pattern()

    check_gaussdb_version()

    cores = getTargetFile(core_path, [])
    if len(cores) > 0:
        g_jobInfo.successTask.append("find core files")
        is_empty = copy_core_files(cores)

        if is_empty == 0:
            cmd = "cd %s/coreDumpfiles && tar -czf corefile_%s.tar.gz" \
                  "  corefile_%s && rm -rf corefile_%s" % \
                  (g_resultdir, g_current_time, g_current_time, g_current_time)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                g_logger.debug(
                    "Failed to collect core dump files."
                    " Command: %s.\n Error:\n%s" % (
                    cmd, output))
                g_jobInfo.failedTask[
                    "compress core files"] = replaceInvalidStr(output)
                g_logger.log(json.dumps(g_jobInfo.__dict__))
                raise Exception("")
            else:
                g_jobInfo.successTask.append("compress core files")
        else:
            g_jobInfo.failedTask["copy core file"] = ErrorCode.GAUSS_535[
                "GAUSS_53509"]
    else:
        g_jobInfo.failedTask["find core files"] = ErrorCode.GAUSS_535[
                                                      "GAUSS_53504"] % 'core'

    g_logger.debug("Successfully collected core dump. %s" % cores)
    g_logger.log(json.dumps(g_jobInfo.__dict__))


def conf_gstack(jobName):
    """
    function: collected configuration files and processed stack information
    output: Successfully collected configuration files
    and processed stack information.
    """
    g_logger.debug("Collecting %s information." % jobName)
    g_jobInfo.jobName = "Collecting %s information" % jobName
    try:
        # Gets all instances of the cluster
        Instances = []
        for Inst in g_localnodeinfo.datanodes:
            if "dn" in ",".join(g_opts.content).lower():
                Instances.append(Inst)
        # parallel copy configuration files, and get gstack
        if Instances:
            pool = ThreadPool(DefaultValue.getCpuSet())
            pool.map(parallel_conf_gstack, Instances)
            pool.close()
            pool.join()
            g_jobInfo.successTask.append("collect %s information" % jobName)
            g_logger.log(json.dumps(g_jobInfo.__dict__))
    except Exception as e:
        g_logger.debug(str(e))
        g_logger.log(json.dumps(g_jobInfo.__dict__))
        raise Exception("")

    g_logger.debug(
        "Successfully collected configuration files "
        "and processed stack information.")


def plan_simulator_check():
    """
    function: collect plan simulator files
    output: Successfully collected files.
    """
    g_logger.debug("Collecting plan simulator.")
    g_jobInfo.jobName = "Collecting plan simulator information"
    haveCnInst = 0
    for cnInst in g_localnodeinfo.datanodes:
        haveCnInst = 1
        if "*" in g_opts.content:
            sql = "SELECT datname FROM pg_database" \
                  " Where datname NOT IN ('template1', 'template0');"
            (status, output) = ClusterCommand.execSQLCommand(sql, g_opts.user,
                                                             "", cnInst.port)
            if status != 0:
                g_logger.debug(
                    "Failed to exec SQL command. please "
                    "check db status. sql: %s.\n Error: %s.\n" % (
                    sql, output))
                g_jobInfo.failedTask["find database"] = ErrorCode.GAUSS_535[
                    "GAUSS_53502"]
                g_logger.log(json.dumps(g_jobInfo.__dict__))
                raise Exception("")
            g_jobInfo.successTask.append("find database")
            dbList = output.split("\n")
        else:
            dbList = g_opts.content
        for db in dbList:
            cmd = "mkdir -p -m %s '%s/planSimulatorfiles/%s'" % \
                  (DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, db)
            cmd = "%s && gs_plan_simulator.sh -m dump -d %s " \
                  "-p %d -D %s/planSimulatorfiles/%s" % \
                  (cmd, db, cnInst.port, g_resultdir, db)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                g_logger.debug(
                    "Failed to Collect plan simulator. "
                    "Command %s.\n Error: %s.\n" % (
                    cmd, output))
                g_jobInfo.failedTask["dump %s plan info" % db] = \
                ErrorCode.GAUSS_535["GAUSS_53510"]
            else:
                g_jobInfo.successTask.append("dump %s plan info" % db)
    if haveCnInst == 0:
        g_jobInfo.failedTask["dump database plan info"] = ErrorCode.GAUSS_535[
            "GAUSS_53503"]
    g_logger.log(json.dumps(g_jobInfo.__dict__))


def getBakConfCmd(Inst):
    """
    function: get bak conf cmd
    input  : Inst
    output : NA
    """
    cmd = ""
    pidfile = ""
    if Inst.instanceRole == DefaultValue.INSTANCE_ROLE_GTM:
        if g_need_gstack == 0:
            cmd = "mkdir -p -m %s '%s/configfiles/config_%s/gtm_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            cmd = "%s && cp '%s'/gtm.conf '%s'/gtm.control " \
                  "'%s'/configfiles/config_%s/gtm_%s/" % \
                  (
                  cmd, Inst.datadir, Inst.datadir, g_resultdir, g_current_time,
                  Inst.instanceId)
            if Inst.instanceType == DefaultValue.MASTER_INSTANCE:
                cmd = "%s && cp '%s'/gtm.sequence" \
                      " '%s'/configfiles/config_%s/gtm_%s/" % \
                      (cmd, Inst.datadir, g_resultdir, g_current_time,
                       Inst.instanceId)
        else:
            cmd = "mkdir -p -m %s '%s/gstackfiles/gstack_%s/gtm_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            pidfile = Inst.datadir + "/gtm.pid"
            try:
                with open(pidfile, 'r') as f:
                    pid = int(f.readline())
                    if pid != 0:
                        cmd += " && gstack '%d' >" \
                               " '%s'/gtm.stack && mv " \
                               "'%s'/gtm.stack '%s'" \
                               "/gstackfiles/gstack_%s/gtm_%s/gtm_%s.stack" % \
                               (pid, Inst.datadir, Inst.datadir, g_resultdir,
                                g_current_time, Inst.instanceId,
                                Inst.instanceId)
            except Exception:
                g_jobInfo.failedTask[
                    "collect gtm_%s process stack info" % Inst.instanceId] = \
                ErrorCode.GAUSS_535["GAUSS_53511"] % 'GTM'

    elif Inst.instanceRole == DefaultValue.INSTANCE_ROLE_COODINATOR:
        if g_need_gstack == 0:
            cmd = "mkdir -p -m %s '%s/configfiles/config_%s/cn_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            cmd = "%s && cp -rf '%s'/postgresql.conf '%s'" \
                  "/pg_hba.conf '%s'/global/pg_control" \
                  " '%s'/gaussdb.state  %s/pg_replslot/ %s/pg_ident.conf" \
                  " '%s'/configfiles/config_%s/cn_%s/" % \
                  (cmd, Inst.datadir, Inst.datadir, Inst.datadir, Inst.datadir,
                   Inst.datadir, Inst.datadir,
                   g_resultdir, g_current_time, Inst.instanceId)
        else:
            cmd = "mkdir -p -m %s '%s/gstackfiles/gstack_%s/cn_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            pidfile = Inst.datadir + "/postmaster.pid"
            try:
                with open(pidfile, 'r') as f:
                    pid = int(f.readline())
                    if pid != 0:
                        cmd = "%s && gstack '%d' > '%s'" \
                              "/cn.stack && mv '%s'/cn.stack '%s'" \
                              "/gstackfiles/gstack_%s/cn_%s/cn_%s.stack" % \
                              (cmd, pid, Inst.datadir, Inst.datadir,
                               g_resultdir, g_current_time, Inst.instanceId,
                               Inst.instanceId)
            except Exception:
                g_jobInfo.failedTask[
                    "collect cn_%s process stack info" % Inst.instanceId] = \
                ErrorCode.GAUSS_535["GAUSS_53511"] % 'CN'

    elif Inst.instanceRole == DefaultValue.INSTANCE_ROLE_DATANODE:
        if g_need_gstack == 0:
            cmd = "mkdir -p -m %s '%s/configfiles/config_%s/dn_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            cmd = "%s && cp -rf '%s'/postgresql.conf '%s'/pg_hba." \
                  "conf {}" \
                  " '%s'/gaussdb.state  %s/pg_replslot/ %s/pg_ident.conf" \
                  " '%s'/configfiles/config_%s/dn_%s/" % \
                  (cmd, Inst.datadir, Inst.datadir, Inst.datadir,
                  Inst.datadir, Inst.datadir,
                  g_resultdir, g_current_time, Inst.instanceId)
            pg_conf_dir = os.path.realpath(
                os.path.join(Inst.datadir, 'global/pg_control'))
            cmd = cmd.format(pg_conf_dir if os.path.isdir(pg_conf_dir) else "")
        else:
            cmd = "mkdir -p -m %s '%s/gstackfiles/gstack_%s/dn_%s'" % \
                  (
                  DefaultValue.KEY_DIRECTORY_MODE, g_resultdir, g_current_time,
                  Inst.instanceId)
            pidfile = Inst.datadir + "/postmaster.pid"
            try:
                with open(pidfile, 'r') as f:
                    pid = int(f.readline())
                    if pid != 0:
                        cmd = "%s && gstack '%d' > '%s'/dn.stack && mv" \
                              " '%s'/dn.stack '%s'" \
                              "/gstackfiles/gstack_%s/dn_%s/dn_%s.stack" % \
                              (cmd, pid, Inst.datadir, Inst.datadir,
                               g_resultdir, g_current_time, Inst.instanceId,
                               Inst.instanceId)
            except Exception:
                g_jobInfo.failedTask[
                    "collect dn_%s process stack info" % Inst.instanceId] = \
                ErrorCode.GAUSS_535["GAUSS_53511"] % 'DN'
    return (cmd, pidfile)

def get_dss_replslot_dir(vgname):
    cmd = "dsscmd ls -p +%s/pg_replslot/" % vgname
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Failed to collect pg_replslot directorys."
                       " Command: %s \n Error: %s.\n" % (cmd, output))
        raise Exception("Failed to collect pg_replslot directorys.")
    file_dirs = []
    out_list = output.split('\n')
    for out in out_list:
        data = out.split()
        for item in data:
            if re.findall(r"slot", item):
                file_dirs.append(item)

    return file_dirs

def get_dss_repslot_files(vgname, slot_path):
    cmd = "dsscmd ls -p +%s/pg_replslot/%s/" % (vgname, slot_path)
    (status1, output1) = subprocess.getstatusoutput(cmd)
    if status1 != 0:
        g_logger.debug("Failed to collect pg_replslot directorys."
                       " Command: %s \n Error: %s.\n" % (cmd, output1))
        raise Exception("Failed to collect pg_replslot directorys.")
    slot_files = []
    out1_lines = output1.split('\n')
    for line in out1_lines:
        data_line = line.split()
        for item in data_line:
            if re.findall(r"state", item):
                slot_files.append(slot_path + '/' + item)
    return slot_files

def get_dss_bak_conf(Inst):
    vgname = EnvUtil.getEnv("VGNAME")
    cmd = "dsscmd cp -s +%s/pg_control -d '%s'/configfiles/config_%s/pg_control" % \
          (vgname, g_resultdir, g_current_time)
    create_path = '%s/configfiles/config_%s/pg_replslot' % (g_resultdir, g_current_time)
    cmd = "%s && mkdir -p %s" % (cmd, create_path)
    slot_dir = get_dss_replslot_dir(vgname)
    slots = []
    for sdir in slot_dir:
        cmd = "%s && mkdir -p %s/%s" % (cmd, create_path, sdir)
        slot_files = get_dss_repslot_files(vgname, sdir)
        slots.extend(slot_files)
    for slot in slots:
        cmd = "%s && dsscmd cp -s +%s/pg_replslot/%s -d %s/%s" % \
              (cmd, vgname, slot, create_path, slot)
    (status1, output1) = subprocess.getstatusoutput(cmd)
    if status1 != 0:
        g_jobInfo.failedTask[
            "collect configuration files"] = replaceInvalidStr(output1)
        g_logger.debug(
            "Failed to collect configuration files."
            " Command: %s \n Error: %s.\n" % (
            cmd, output1))
        raise Exception("Failed to collect configuration files.")

def parallel_conf_gstack(Inst):
    """
    parallel copy configuration files, and get gstack
    """
    (cmd, pidfile) = getBakConfCmd(Inst)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        if "command not found" in output:
            g_jobInfo.failedTask["collect process stack info"] = \
            ErrorCode.GAUSS_535["GAUSS_53512"]
            g_logger.debug(
                "Failed to collect gstack files. "
                "Command: %s \n Error: %s.\n" % (
                cmd, output))
            raise Exception("")
        elif "gstack" in output:
            g_jobInfo.failedTask[
                "collect process stack info"] = replaceInvalidStr(output)
            g_logger.debug(
                "Failed to collect gstack files."
                " Command: %s \n Error: %s.\n" % (
                cmd, output))
            raise Exception("")
        elif "Process" in output:
            g_jobInfo.failedTask[
                "collect process stack info"] = replaceInvalidStr(output)
            g_logger.debug(
                "Failed to collect gstack files. "
                "Command: %s \n Error: %s.\n" % (
                cmd, output))
            raise Exception("")
        else:
            if check_dss_env():
                get_dss_bak_conf(Inst)
                return
            g_jobInfo.failedTask[
                        "collect configuration files"] = replaceInvalidStr(output)
            g_logger.debug(
                "Failed to collect configuration files."
                " Command: %s \n Error: %s.\n" % (
                cmd, output))
            raise Exception("")


def parseConfig():
    """
    function: parse Config parameter
    input : NA
    output: NA
    """
    if g_opts.config != "":
        d = json.loads(g_opts.config)
        g_opts.content = list(filter(None, d['Content'].split(",")))
        g_opts.file_number = int(d.get('FileNumber', 0))

def main():
    """
    main function
    """
    try:
        parseCommandLine()
        initGlobal()
        parseConfig()
        global g_jobInfo
        g_jobInfo = JobInfo()
        if g_opts.action == "check_command":
            check_command()
        elif g_opts.action == "create_dir":
            create_temp_result_folder()
        # Get system information
        elif g_opts.action == "system_check":
            system_check()
        # Gets the database information
        elif g_opts.action == "database_check":
            database_check()
        # Make a copy of the log file
        elif g_opts.action == "log_copy":
            log_copy()
        elif g_opts.action == "dss_cert_replacer":
            dss_cert_replacer(g_logger)
        # Copy configuration files, and get g stack
        elif g_opts.action == "Config":
            conf_gstack("Config")
        elif g_opts.action == "Gstack":
            global g_need_gstack
            g_need_gstack = 1
            conf_gstack("Gstack")
            g_need_gstack = 0
        # Copy dss config files
        elif g_opts.action == "dss_conf_copy":
            dss_conf_copy() 
        # Copy dss info
        elif g_opts.action == "disk_info_copy":
            disk_info_copy()
        # Send all log files we collected to the command node.
        elif g_opts.action == "copy_file":
            sendLogFiles()
        elif g_opts.action == "xlog_copy":
            xlog_copy()
        elif g_opts.action == "plan_simulator_check":
            plan_simulator_check()
        elif g_opts.action == "core_copy":
            core_copy()
        else:
            g_logger.logExit("Unrecognized parameter: %s." % g_opts.action)
    except Exception as e:
        GaussLog.exitWithError(str(e))


if __name__ == '__main__':
    main()
    sys.exit(0)
