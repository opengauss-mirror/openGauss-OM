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
# Description :
# UpgradeUtility.py is a utility to execute upgrade on each local node
#############################################################################

import getopt
import sys
import os
import subprocess
import pwd
import re
import time
import traceback
import json
import platform
import shutil
import copy
import csv
from multiprocessing.dummy import Pool as ThreadPool

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue, ClusterCommand, \
    ClusterInstanceConfig
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.os.gsfile import g_file
import impl.upgrade.UpgradeConst as const

INSTANCE_TYPE_UNDEFINED = -1
MASTER_INSTANCE = 0
STANDBY_INSTANCE = 1
DUMMY_STANDBY_INSTANCE = 2
# init value
INSTANCE_ROLE_UNDEFINED = -1
# cn
INSTANCE_ROLE_COODINATOR = 3
# dn
INSTANCE_ROLE_DATANODE = 4

BINARY_UPGRADE_TMP = "binary_upgrade"
PG_LOCATION = "pg_location"
CFDUMPPREFIX = "cfdump"

# Global parameter
g_oldVersionModules = None
g_clusterInfo = None
g_oldClusterInfo = None
g_logger = None
g_dbNode = None
g_opts = None
g_DWS_mode = False
g_gausshome = None


class CmdOptions():
    """
    Class to define some cmd options
    """

    def __init__(self):
        """
        function: constructor
        """
        # action value
        self.action = ""
        # user value
        self.user = ""
        # app install path
        self.appPath = ""
        # env file
        self.mpprcFile = ""
        self.userProfile = ""
        # log file
        self.logFile = ""
        # backup path
        self.bakPath = ""
        # old cluster version
        self.oldVersion = ""
        # xml file
        self.xmlFile = ""
        # inplace upgrade bak path or grey upgrade path
        self.upgrade_bak_path = ""
        self.scriptType = ""
        self.rollback = False
        self.forceRollback = False
        self.oldClusterAppPath = ""
        self.newClusterAppPath = ""
        self.gucStr = ""
        self.oldclusternum = ""
        self.postgisSOFileList = \
            {"postgis-*.*.so": "lib/postgresql/",
             "libgeos_c.so.*": "lib/",
             "libproj.so.*": "lib/",
             "libjson-c.so.*": "lib/",
             "libgeos-*.*.*so": "lib/",
             "postgis--*.*.*.sql": "share/postgresql/extension/",
             "postgis.control": "share/postgresql/extension/",
             "pgsql2shp": "bin/",
             "shp2pgsql": "bin/",
             "libgcc_s.so.*": "lib/",
             "libstdc++.so.*": "lib/"}


class OldVersionModules():
    """
    Class for providing some functions to apply old version cluster
    """
    def __init__(self):
        """
        function: constructor
        """
        # old cluster information module
        self.oldDbClusterInfoModule = None
        # old cluster status module
        self.oldDbClusterStatusModule = None


def importOldVersionModules():
    """
    function: import some needed modules from the old cluster.
    currently needed are: DbClusterInfo
    input: NA
    output:NA
    """
    # get install directory by user name
    installDir = DefaultValue.getInstallDir(g_opts.user)
    if installDir == "":
        GaussLog.exitWithError(
            ErrorCode.GAUSS_503["GAUSS_50308"] + " User: %s." % g_opts.user)
    # import DbClusterInfo module
    global g_oldVersionModules
    g_oldVersionModules = OldVersionModules()
    sys.path.append("%s/bin/script/util" % installDir)
    g_oldVersionModules.oldDbClusterInfoModule = __import__('DbClusterInfo')


def initGlobals():
    """
    function: init global variables
    input: NA
    output: NA
    """
    global g_oldVersionModules
    global g_clusterInfo
    global g_oldClusterInfo
    global g_logger
    global g_dbNode
    # make sure which env file we use
    g_opts.userProfile = g_opts.mpprcFile

    # init g_logger
    g_logger = GaussLog(g_opts.logFile, g_opts.action)

    if g_opts.action in [const.ACTION_RESTORE_CONFIG,
                         const.ACTION_SWITCH_BIN,
                         const.ACTION_CLEAN_INSTALL_PATH]:
        g_logger.debug(
            "No need to init cluster information under action %s."
            % g_opts.action)
        return
    # init g_clusterInfo
    # not all action need init g_clusterInfo
    try:
        g_clusterInfo = dbClusterInfo()
        if g_opts.xmlFile == "" or not os.path.exists(g_opts.xmlFile):
            g_clusterInfo.initFromStaticConfig(g_opts.user)
        else:
            g_clusterInfo.initFromXml(g_opts.xmlFile)
    except Exception as e:
        g_logger.debug(traceback.format_exc())
        g_logger.error(str(e))
        # init cluster info from install path failed
        # try to do it from backup path again
        g_opts.bakPath = DefaultValue.getTmpDirFromEnv() + "/"
        staticConfigFile = "%s/cluster_static_config" % g_opts.bakPath

        if os.path.isfile(staticConfigFile):
            try:
                # import old module
                g_oldVersionModules = OldVersionModules()
                sys.path.append(os.path.dirname(g_opts.bakPath))
                g_oldVersionModules.oldDbClusterInfoModule = __import__(
                    'OldDbClusterInfo')
                # init old cluster config
                g_clusterInfo = \
                    g_oldVersionModules.oldDbClusterInfoModule.dbClusterInfo()
                g_clusterInfo.initFromStaticConfig(g_opts.user,
                                                   staticConfigFile)
            except Exception as e:
                g_logger.error(str(e))
                # maybe the old cluster is V1R5C00 TR5 version,
                # not support specify static config file
                # path for initFromStaticConfig function,
                # so use new cluster format try again
                try:
                    g_clusterInfo = dbClusterInfo()
                    g_clusterInfo.initFromStaticConfig(g_opts.user,
                                                       staticConfigFile)
                except Exception as e:
                    g_logger.error(str(e))
                    try:
                        # import old module
                        importOldVersionModules()
                        # init old cluster config
                        g_clusterInfo = \
                            g_oldVersionModules \
                                .oldDbClusterInfoModule.dbClusterInfo()
                        g_clusterInfo.initFromStaticConfig(g_opts.user)
                    except Exception as e:
                        raise Exception(str(e))
        elif g_opts.xmlFile and os.path.exists(g_opts.xmlFile):
            try:
                sys.path.append(sys.path[0] + "/../../gspylib/common")
                curDbClusterInfoModule = __import__('DbClusterInfo')
                g_clusterInfo = curDbClusterInfoModule.dbClusterInfo()
                g_clusterInfo.initFromXml(g_opts.xmlFile)
            except Exception as e:
                raise Exception(str(e))
        else:
            try:
                # import old module
                importOldVersionModules()
                # init old cluster config
                g_clusterInfo = \
                    g_oldVersionModules.oldDbClusterInfoModule.dbClusterInfo()
                g_clusterInfo.initFromStaticConfig(g_opts.user)
            except Exception as e:
                raise Exception(str(e))

    # init g_dbNode
    localHost = DefaultValue.GetHostIpOrName()
    g_dbNode = g_clusterInfo.getDbNodeByName(localHost)
    if g_dbNode is None:
        raise Exception(
            ErrorCode.GAUSS_512["GAUSS_51209"] % ("NODE", localHost))


def usage():
    """
Usage:
  python3 UpgradeUtility.py -t action [-U user] [-R path] [-l log]

Common options:
  -t                               the type of action
  -U                               the user of old cluster
  -R                               the install path of cluster
  -l                               the path of log file
  -V                               original Version
  -X                               the xml configure file
  --help                           show this help, then exit
  --upgrade_bak_path               always be the $PGHOST/binary_upgrade
  --scriptType                     upgrade script type
  --old_cluster_app_path           absolute path with old commit id
  --new_cluster_app_path           absolute path with new commit id
  --rollback                       is rollback
  --guc_string                     check the guc string has been successfully
  --oldcluster_num                 old cluster number
   wrote in the configure file, format is guc:value,
   can only check upgrade_from, upgrade_mode
    """
    print(usage.__doc__)


def parseCommandLine():
    """
    function: Parse command line and save to global variables
    input: NA
    output: NA
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:U:R:l:V:X:",
                                   ["help", "upgrade_bak_path=",
                                    "script_type=", "old_cluster_app_path=",
                                    "new_cluster_app_path=", "rollback",
                                    "force", "guc_string=", "oldcluster_num="])
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

    if len(args) > 0:
        GaussLog.exitWithError(
            ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

    for (key, value) in opts:
        if key == "--help":
            usage()
            sys.exit(0)
        elif key == "-t":
            g_opts.action = value
        elif key == "-U":
            g_opts.user = value
        elif key == "-R":
            g_opts.appPath = value
        elif key == "-l":
            g_opts.logFile = os.path.realpath(value)
        elif key == "-V":
            g_opts.oldVersion = value
        elif key == "-X":
            g_opts.xmlFile = os.path.realpath(value)
        elif key == "--upgrade_bak_path":
            g_opts.upgrade_bak_path = os.path.normpath(value)
        elif key == "--script_type":
            g_opts.scriptType = os.path.normpath(value)
        elif key == "--old_cluster_app_path":
            g_opts.oldClusterAppPath = os.path.normpath(value)
        elif key == "--new_cluster_app_path":
            g_opts.newClusterAppPath = os.path.normpath(value)
        elif key == "--rollback":
            g_opts.rollback = True
        elif key == "--force":
            g_opts.forceRollback = True
        elif key == "--guc_string":
            g_opts.gucStr = value
        elif key == "--oldcluster_num":
            g_opts.oldclusternum = value
        else:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % key)

        Parameter.checkParaVaild(key, value)


def checkParameter():
    """
    function: check parameter for different action
    input: NA
    output: NA
    """
    # check mpprc file path
    g_opts.mpprcFile = DefaultValue.getMpprcFile()
    # the value of "-t" can not be ""
    if g_opts.action == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % "t" + ".")

    # check the value of "-t"
    if g_opts.action in [const.ACTION_SWITCH_PROCESS,
                         const.ACTION_COPY_CERTS] and \
            (not g_opts.newClusterAppPath or not g_opts.oldClusterAppPath):
        GaussLog.exitWithError(
            ErrorCode.GAUSS_500["GAUSS_50001"]
            % "-new_cluster_app_path and --old_cluster_app_path")
    elif g_opts.action in \
            [const.ACTION_SYNC_CONFIG,
             const.ACTION_RESTORE_CONFIG] and not g_opts.newClusterAppPath:
        GaussLog.exitWithError(
            ErrorCode.GAUSS_500["GAUSS_50001"] % "-new_cluster_app_path")
    elif g_opts.action in \
            [const.ACTION_SWITCH_BIN,
             const.ACTION_CLEAN_INSTALL_PATH] and not g_opts.appPath:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % "R")
    elif g_opts.action in [const.ACTION_UPGRADE_SQL_FOLDER] and not \
            g_opts.upgrade_bak_path:
        GaussLog.exitWithError(
            ErrorCode.GAUSS_500["GAUSS_50001"] % "-upgrade_bak_path")
    # Check the incoming parameter -U
    if g_opts.user == "":
        g_opts.user = pwd.getpwuid(os.getuid()).pw_name
    # Check the incoming parameter -l
    if g_opts.logFile == "":
        g_opts.logFile = DefaultValue.getOMLogPath(DefaultValue.LOCAL_LOG_FILE,
                                                   g_opts.user, "")

    global g_gausshome
    g_gausshome = DefaultValue.getInstallDir(g_opts.user)
    if g_gausshome == "":
        GaussLog.exitWithError(
            ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
    g_gausshome = os.path.normpath(g_gausshome)


def switchBin():
    """
    function: switch link bin from old to new
    input  : NA
    output : NA
    """
    if g_opts.forceRollback:
        if not os.path.exists(g_opts.appPath):
            g_file.createDirectory(g_opts.appPath, True,
                                   DefaultValue.KEY_DIRECTORY_MODE)
    g_logger.log("Switch to %s." % g_opts.appPath)
    if g_opts.appPath == g_gausshome:
        raise Exception(ErrorCode.GAUSS_502["GAUSS_50233"] % (
            "install path", "$GAUSSHOME"))
    if os.path.exists(g_gausshome):
        if os.path.samefile(g_opts.appPath, g_gausshome):
            g_logger.log(
                "$GAUSSHOME points to %s. No need to switch." % g_opts.appPath)
    cmd = "ln -snf %s %s" % (g_opts.appPath, g_gausshome)
    g_logger.log("Command for switching binary directory: '%s'." % cmd)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception(
            ErrorCode.GAUSS_508["GAUSS_50803"] + " Error: \n%s" % str(output))


def readPostgresqlConfig(filePath):
    """
    function: read postgres sql config
    input filepath
    output gucParamDict
    """
    GUC_PARAM_PATTERN = "^\\s*.*=.*$"
    pattern = re.compile(GUC_PARAM_PATTERN)
    gucParamDict = {}
    try:
        with open(filePath, 'r') as fp:
            resList = fp.readlines()
        for oneLine in resList:
            # skip blank line
            if oneLine.strip() == "":
                continue
            # skip comment line
            if (oneLine.strip()).startswith('#'):
                continue
            # search valid line
            result = pattern.match(oneLine)
            if result is not None:
                paramAndValue = oneLine
                # remove comment if eixst
                pos = oneLine.find(' #')
                if pos >= 0:
                    paramAndValue = oneLine[:pos]
                # should use tab here
                pos = oneLine.find('\t#')
                if pos >= 0:
                    paramAndValue = oneLine[:pos]
                # if the value contain "$" ,
                # we should using "\\\\\\$" to instead of it
                resList = paramAndValue.split('=')
                if len(resList) == 2:
                    param = resList[0]
                    value = resList[1].replace("$", "\\\\\\$")
                    gucParamDict[param.strip()] = value.strip()
                elif len(resList) > 2:
                    # invalid line, skip it
                    # only support replconninfo1, replconninfo2
                    if not resList[0].strip().startswith("replconninfo"):
                        continue
                    pos = paramAndValue.find('=')
                    param = paramAndValue[:pos]
                    value = paramAndValue[pos + 1:].replace("$", "\\\\\\$")
                    gucParamDict[param.strip()] = value.strip()
                else:
                    continue
    except Exception as e:
        g_logger.debug(str(e))
        raise Exception(
            ErrorCode.GAUSS_502["GAUSS_50204"] % "postgressql.conf file")

    return gucParamDict


def syncPostgresqlconf(dbInstance):
    """
    function: syncPostgresqlconf during inplace upgrade
    input: dbInstance
    output: NA
    """
    # get config info of current node
    try:
        # get guc param info from old cluster
        gucCmd = "source %s" % g_opts.userProfile
        oldPostgresConf = "%s/postgresql.conf" % dbInstance.datadir
        gucParamDict = readPostgresqlConfig(oldPostgresConf)

        synchronousStandbyNames = ""
        # synchronous_standby_names only can be set by write file
        if "synchronous_standby_names" in gucParamDict.keys():
            synchronousStandbyNames = gucParamDict["synchronous_standby_names"]
            del gucParamDict["synchronous_standby_names"]

        # internal parameters are not supported. So skip them when do gs_guc
        internalGucList = ['block_size', 'current_logic_cluster',
                           'integer_datetimes', 'lc_collate',
                           'lc_ctype', 'max_function_args',
                           'max_identifier_length', 'max_index_keys',
                           'node_group_mode', 'segment_size',
                           'server_encoding', 'server_version',
                           'server_version_num', 'sql_compatibility',
                           'wal_block_size', 'wal_segment_size', 'enable_beta_nestloop_fusion',
                           'enable_upsert_to_merge', 'force_parallel_mode',
                           'max_background_workers', 'max_parallel_workers_per_gather',
                           'min_parallel_table_scan_size', 'pagewriter_threshold',
                           'parallel_leader_participation', 'parallel_setup_cost',
                           'parallel_tuple_cost', 'parctl_min_cost', 'tcp_recv_timeout',
                           'wal_compression', 'enable_parallel_hash', 'enable_parallel_append',
                           'max_parallel_maintenance_workers', 'min_parallel_index_scan_size',
                           'sync_config_strategy', 'wal_file_init_num', 'wal_writer_cpu',
                           'xlog_flush_uplimit', 'xlog_idle_flushes_before_sleep']
        for gucName in internalGucList:
            if gucName in gucParamDict.keys():
                del gucParamDict[gucName]

        if dbInstance.instanceRole == DefaultValue.INSTANCE_ROLE_DATANODE:
            # rebuild replconninfo
            connInfo1 = None
            dummyStandbyInst = None
            peerInsts = g_clusterInfo.getPeerInstance(dbInstance)
            if len(peerInsts) > 0:
                (connInfo1, _) = ClusterInstanceConfig.\
                    setReplConninfoForSinglePrimaryMultiStandbyCluster(
                    dbInstance, peerInsts, g_clusterInfo)
                for i in range(len(connInfo1)):
                    connInfo = "replconninfo" + "%d" % (i + 1)
                    gucParamDict[connInfo] = "'%s'" % connInfo1[i]

        if len(gucParamDict) > 0:
            gucStr = ""
            for key, value in gucParamDict.items():
                gucStr += " -c \\\"%s=%s\\\" " % (key, value)
            gucCmd += "&& gs_guc set -D %s %s" % (dbInstance.datadir, gucStr)

        # set guc parameters about DummpyStandbyConfig at DN
        if dbInstance.instanceType == DUMMY_STANDBY_INSTANCE:
            gucstr = ""
            for entry in DefaultValue.getPrivateGucParamList().items():
                gucstr += " -c \"%s=%s\"" % (entry[0], entry[1])
            gucCmd += "&& gs_guc set -D %s %s " % (dbInstance.datadir, gucstr)

        g_logger.debug("Command for setting [%s] guc parameter:%s" % (
            dbInstance.datadir, gucCmd))

        # save guc parameter to temp file
        gucTempFile = "%s/setGucParam_%s.sh" % (
            g_opts.upgrade_bak_path, dbInstance.instanceId)
        # Do not modify the write file operation.
        # Escape processing of special characters in the content
        cmd = "echo \"%s\" > %s" % (gucCmd, gucTempFile)
        (status, output) = DefaultValue.retryGetstatusoutput(cmd)
        if status != 0:
            g_logger.debug("Command: %s. Error: \n%s" % (cmd, output))
            g_logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50205"] % gucTempFile
                + " Error: \n%s" % str(
                    output))
        g_file.changeOwner(g_opts.user, gucTempFile)
        g_file.changeMode(DefaultValue.KEY_FILE_MODE, gucTempFile)

        # replace old guc file with sample file
        newPostgresConf = "%s/share/postgresql/postgresql.conf.sample" \
                          % g_opts.newClusterAppPath
        if os.path.exists(newPostgresConf):
            g_file.cpFile(newPostgresConf, oldPostgresConf)
            g_file.changeMode(DefaultValue.KEY_FILE_MODE, oldPostgresConf)

        # set guc param
        cmd = "sh %s" % gucTempFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_logger.debug("Command: %s. Error: \n%s" % (cmd, output))
            g_logger.logExit(
                ErrorCode.GAUSS_514["GAUSS_51401"] % gucTempFile[:-3]
                + " Error: \n%s" % str(output))

        if synchronousStandbyNames != "":
            g_logger.debug(
                "Set the GUC value %s to synchronous_standby_names for %s" % (
                    synchronousStandbyNames, oldPostgresConf))
            g_file.deleteLine(oldPostgresConf,
                              "^\\s*synchronous_standby_names\\s*=.*$")
            g_file.writeFile(
                oldPostgresConf,
                ["synchronous_standby_names "
                 "= %s # standby servers that provide sync rep"
                 % synchronousStandbyNames])

        # clean temp file
        if os.path.isfile(gucTempFile):
            os.remove(gucTempFile)

    except Exception as e:
        g_logger.logExit(str(e))


def syncClusterConfig():
    """
    function: sync newly added guc during upgrade,
    for now we only sync CN/DN, gtm, cm_agent and cm_server
    input: NA
    output: NA
    """
    DnInstances = g_dbNode.datanodes
    if len(DnInstances) > 0:
        try:
            # sync postgresql.conf in parallel
            pool = ThreadPool(DefaultValue.getCpuSet())
            pool.map(syncPostgresqlconf, DnInstances)
            pool.close()
            pool.join()
        except Exception as e:
            g_logger.logExit(str(e))


def syncInstanceConfig(oldCmFile, newCmFile):
    """
    function: sync instance config
    input: NA
    output:NA
    """
    oldCmConfig = {}
    newCmConfig = {}
    newConfigItem = {}
    try:
        if not os.path.exists(oldCmFile):
            g_logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"] % oldCmFile)
        if not os.path.exists(newCmFile):
            g_logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"] % newCmFile)
        # Read and save old config file
        with open(oldCmFile, 'r') as fp:
            oldConfig = fp
            for eachLine in oldConfig:
                ParameterConfig = eachLine.strip()
                index = ParameterConfig.find("=")
                if index > 0 and ParameterConfig[0] != "#":
                    key = ParameterConfig[:index].strip()
                    value = ParameterConfig[index + 1:].strip()
                    oldCmConfig[key] = value
        # Read and save new config file
        with open(newCmFile, 'r') as fp:
            newConfig = fp
            for eachLine in newConfig:
                ParameterConfig = eachLine.strip()
                index = ParameterConfig.find("=")
                if index > 0 and ParameterConfig[0] != "#":
                    key = ParameterConfig[:index].strip()
                    value = ParameterConfig[index + 1:].strip()
                    newCmConfig[key] = value

        # Filter new configuration parameters
        for newConfig in newCmConfig.keys():
            keyExist = False
            for oldConfig in oldCmConfig.keys():
                if oldConfig == newConfig:
                    keyExist = True
                    break
            if not keyExist:
                newConfigItem[newConfig] = newCmConfig[newConfig]
        # Write new config item to old config file
        if len(newConfigItem) > 0:
            with open(oldCmFile, "a") as fp:
                for ConfigItem in newConfigItem.keys():
                    fp.write("\n%s = %s" % (ConfigItem,
                                            newConfigItem[ConfigItem]))
                fp.write("\n")
                fp.flush()

    except Exception as e:
        g_logger.logExit(str(e))


def touchInstanceInitFile():
    """
    function: touch upgrade init file for every primary and standby instance
    input: NA
    output: NA
    """
    g_logger.log("Touch init file.")
    try:
        InstanceList = []
        # find all DB instances need to touch
        if len(g_dbNode.datanodes) != 0:
            for eachInstance in g_dbNode.datanodes:
                if (eachInstance.instanceType == MASTER_INSTANCE
                        or eachInstance.instanceType == STANDBY_INSTANCE):
                    InstanceList.append(eachInstance)

        # touch each instance parallelly
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(touchOneInstanceInitFile, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug(
                "No instance found on this node, nothing need to do.")
            return

        g_logger.log(
            "Successfully created all instances init file on this node.")
    except Exception as e:
        g_logger.logExit(str(e))


def initDbInfo():
    """
    function: create a init dbInfo dict
    input: NA
    output: NA
    """
    tmpDbInfo = {}
    tmpDbInfo['dbname'] = ""
    tmpDbInfo['dboid'] = -1
    tmpDbInfo['spclocation'] = ""
    tmpDbInfo['CatalogList'] = []
    tmpDbInfo['CatalogNum'] = 0
    return tmpDbInfo


def initCatalogInfo():
    """
    function: create a init catalog dict
    input: NA
    output: NA
    """
    tmpCatalogInfo = {}
    tmpCatalogInfo['relname'] = ""
    tmpCatalogInfo['oid'] = -1
    tmpCatalogInfo['relfilenode'] = -1

    return tmpCatalogInfo


def cpDirectory(srcDir, destDir):
    """
    function: copy directory
    input  : NA
    output : NA
    """
    cmd = "rm -rf '%s' && cp -r -p '%s' '%s'" % (destDir, srcDir, destDir)
    g_logger.debug("Backup commad:[%s]." % cmd)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception(
            ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "\nOutput:%s" % output)


def touchOneInstanceInitFile(instance):
    """
    function: touch upgrade init file for this instance
    input: NA
    output: NA
    """
    g_logger.debug(
        "Touch instance init file. Instance data dir: %s" % instance.datadir)
    dbInfoDict = {}
    dbInfoDict["dblist"] = []
    dbInfoDict["dbnum"] = 0
    try:
        # we touch init file by executing a simple query for every database
        get_db_list_sql = """
        SELECT d.datname, d.oid, pg_catalog.pg_tablespace_location(t.oid) 
        AS spclocation 
        FROM pg_catalog.pg_database d 
        LEFT OUTER JOIN pg_catalog.pg_tablespace t 
        ON d.dattablespace = t.oid  
        ORDER BY 2;"""
        g_logger.debug("Get database info command: \n%s" % get_db_list_sql)
        (status, output) = ClusterCommand.execSQLCommand(get_db_list_sql,
                                                         g_opts.user, "",
                                                         instance.port,
                                                         "postgres", False,
                                                         "-m",
                                                         IsInplaceUpgrade=True)
        if status != 0:
            raise Exception(
                ErrorCode.GAUSS_513["GAUSS_51300"] % get_db_list_sql
                + " Error:\n%s" % output)
        if output == "":
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52938"]
                            % "any database!!")
        g_logger.debug("Get database info result: \n%s." % output)
        resList = output.split('\n')
        for each_line in resList:
            tmpDbInfo = initDbInfo()
            (datname, oid, spclocation) = each_line.split('|')
            tmpDbInfo['dbname'] = datname.strip()
            tmpDbInfo['dboid'] = oid.strip()
            tmpDbInfo['spclocation'] = spclocation.strip()
            dbInfoDict["dblist"].append(tmpDbInfo)
            dbInfoDict["dbnum"] += 1

        # connect each database, run a simple query
        touch_sql = "SELECT 1;"
        for each_db in dbInfoDict["dblist"]:
            (status, output) = ClusterCommand.execSQLCommand(
                touch_sql,
                g_opts.user, "",
                instance.port,
                each_db["dbname"],
                False, "-m",
                IsInplaceUpgrade=True)
            if status != 0 or not output.isdigit():
                raise Exception(
                    ErrorCode.GAUSS_513["GAUSS_51300"] % touch_sql
                    + " Error:\n%s" % output)

    except Exception as e:
        raise Exception(str(e))

    g_logger.debug(
        "Successfully created instance init file. Instance data dir: %s"
        % instance.datadir)


def getInstanceName(instance):
    """
    get master instance name
    """
    instance_name = ""
    if instance.instanceRole == INSTANCE_ROLE_COODINATOR:
        instance_name = "cn_%s" % instance.instanceId
    elif instance.instanceRole == INSTANCE_ROLE_DATANODE:
        if g_clusterInfo.isSingleInstCluster():
            # the instance type must be master or standby dn
            peerInsts = g_clusterInfo.getPeerInstance(instance)
            (instance_name, masterInst, _) = \
                ClusterInstanceConfig.\
                    getInstanceInfoForSinglePrimaryMultiStandbyCluster(
                    instance, peerInsts)
        else:
            # if dn, it should be master or standby dn
            if instance.instanceType == DUMMY_STANDBY_INSTANCE:
                raise Exception(
                    "Invalid instance type:%s" % instance.instanceType)
            peerInsts = g_clusterInfo.getPeerInstance(instance)
            if len(peerInsts) != 2 and len(peerInsts) != 1:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51620"] % "peer")
            for i in range(len(peerInsts)):
                if peerInsts[i].instanceType == MASTER_INSTANCE:
                    masterInst = peerInsts[i]
                    standbyInst = instance
                    instance_name = "dn_%d_%d" % (masterInst.instanceId,
                                                  standbyInst.instanceId)
                elif peerInsts[i].instanceType == STANDBY_INSTANCE:
                    standbyInst = peerInsts[i]
                    masterInst = instance
                    instance_name = "dn_%d_%d" % (masterInst.instanceId,
                                                  standbyInst.instanceId)
                else:
                    # we are searching master or standby dn instance,
                    # if dummy dn, just continue
                    continue
        if instance_name == "":
            raise Exception("Can not get instance name!")
    else:
        raise Exception("Invalid node type:%s" % instance.instanceRole)

    return instance_name.strip()


def getStandbyInstance(instance):
    """
    function: get standby instance of input master instance
    input: NA
    output: NA
    """
    if instance.instanceType != MASTER_INSTANCE:
        raise Exception(ErrorCode.GAUSS_529["GAUSS_52940"]
                        % instance.instanceType)

    if instance.instanceRole != INSTANCE_ROLE_DATANODE:
        raise Exception(ErrorCode.GAUSS_529["GAUSS_52941"] %
                        instance.instanceRole)

    peerInsts = g_clusterInfo.getPeerInstance(instance)
    if len(peerInsts) == 0:
        return
    standbyInst = None
    for i in iter(peerInsts):
        if i.instanceType == STANDBY_INSTANCE:
            standbyInst = i
    if not standbyInst:
        raise Exception(
            "Can not find standby instance of instance [%s]!"
            % instance.datadir)

    return standbyInst


def getJsonFile(instance, backup_path):
    """
    function: get json file
    input  : instance, backup_path
    output : db_and_catalog_info_file_name: str
    """
    try:
        instance_name = getInstanceName(instance)
        # load db and catalog info from json file
        if instance.instanceRole == INSTANCE_ROLE_COODINATOR:
            db_and_catalog_info_file_name = \
                "%s/cn_db_and_catalog_info_%s.json" % (
                    backup_path, instance_name)
        elif instance.instanceRole == INSTANCE_ROLE_DATANODE:
            if instance.instanceType == MASTER_INSTANCE or\
                    instance.instanceType == STANDBY_INSTANCE:
                db_and_catalog_info_file_name = \
                    "%s/dn_db_and_catalog_info_%s.json" % (
                        backup_path, instance_name)
            else:
                raise Exception(
                    "Invalid instance type:%s" % instance.instanceType)
        else:
            raise Exception("Invalid instance role:%s" % instance.instanceRole)
        return db_and_catalog_info_file_name
    except Exception as e:
        raise Exception(str(e))


def __backup_base_folder(instance):
    """
    """
    g_logger.debug("Backup instance catalog physical files. "
                   "Instance data dir: %s" % instance.datadir)

    backup_path = "%s/oldClusterDBAndRel/" % g_opts.upgrade_bak_path
    db_and_catalog_info_file_name = getJsonFile(instance, backup_path)

    fp = open(db_and_catalog_info_file_name, 'r')
    dbInfoStr = fp.read()
    fp.close()
    dbInfoDict = json.loads(dbInfoStr)

    # get instance name
    instance_name = getInstanceName(instance)

    # backup base folder
    for each_db in dbInfoDict["dblist"]:
        if each_db["spclocation"] != "":
            if each_db["spclocation"].startswith('/'):
                tbsBaseDir = each_db["spclocation"]
            else:
                tbsBaseDir = "%s/pg_location/%s" % (instance.datadir,
                                                    each_db["spclocation"])
            pg_catalog_base_dir = "%s/%s_%s/%d" % (
                tbsBaseDir, DefaultValue.TABLESPACE_VERSION_DIRECTORY,
                instance_name, int(each_db["dboid"]))
        else:
            pg_catalog_base_dir = "%s/base/%d" % (instance.datadir,
                                                  int(each_db["dboid"]))
        # for base folder, template0 need handle specially
        if each_db["dbname"] == 'template0':
            pg_catalog_base_back_dir = "%s_bak" % pg_catalog_base_dir
            cpDirectory(pg_catalog_base_dir, pg_catalog_base_back_dir)
            g_logger.debug(
                "Template0 has been backed up from {0} to {1}".format(
                    pg_catalog_base_dir, pg_catalog_base_back_dir))
            continue

        # handle other db's base folder
        if len(each_db["CatalogList"]) <= 0:
            raise Exception(
                "Can not find any catalog in database %s" % each_db["dbname"])
        for each_catalog in each_db["CatalogList"]:
            # main/vm/fsm  -- main.1 ..
            main_file = "%s/%d" % (
                pg_catalog_base_dir, int(each_catalog['relfilenode']))
            if not os.path.isfile(main_file):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % main_file)
            cmd = "cp -f -p '%s' '%s_bak'" % (main_file, main_file)
            g_logger.debug(
                "{0} needs to be backed up to {0}_bak".format(main_file))
            seg_idx = 1
            while 1:
                seg_file = "%s/%d.%d" % (pg_catalog_base_dir,
                                         int(each_catalog['relfilenode']),
                                         seg_idx)
                if os.path.isfile(seg_file):
                    cmd += "&& cp -f -p '%s' '%s_bak'" % (seg_file, seg_file)
                    seg_idx += 1
                else:
                    break
            g_logger.debug("seg_file needs to be backed up")
            vm_file = "%s/%d_vm" % (pg_catalog_base_dir,
                                    int(each_catalog['relfilenode']))
            if os.path.isfile(vm_file):
                cmd += "&& cp -f -p '%s' '%s_bak'" % (vm_file, vm_file)
            g_logger.debug(
                "{0} needs to be backed up to {0}_bak".format(vm_file))
            fsm_file = "%s/%d_fsm" % (pg_catalog_base_dir,
                                      int(each_catalog['relfilenode']))
            if os.path.isfile(fsm_file):
                cmd += "&& cp -f -p '%s' '%s_bak'" % (fsm_file, fsm_file)
            g_logger.debug(
                "{0} needs to be backed up to {0}_bak".format(fsm_file))
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "\nOutput:%s" % output)

        # special files pg_filenode.map pg_internal.init
        cmd = ""
        pg_filenode_map_file = "%s/pg_filenode.map" % pg_catalog_base_dir
        if os.path.isfile(pg_filenode_map_file):
            if cmd == "":
                cmd = "cp -f -p '%s' '%s_bak'" % (
                    pg_filenode_map_file, pg_filenode_map_file)
            else:
                cmd += "&& cp -f -p '%s' '%s_bak'" % (
                    pg_filenode_map_file, pg_filenode_map_file)
            g_logger.debug("{0} needs to be backed up to {0}_bak".format(
                pg_filenode_map_file))
        pg_internal_init_file = "%s/pg_internal.init" % pg_catalog_base_dir
        if os.path.isfile(pg_internal_init_file):
            if cmd == "":
                cmd = "cp -f -p '%s' '%s_bak'" % (
                    pg_internal_init_file, pg_internal_init_file)
            else:
                cmd += "&& cp -f -p '%s' '%s_bak'" % (
                    pg_internal_init_file, pg_internal_init_file)
            g_logger.debug("{0} needs to be backed up to {0}_bak".format(
                pg_internal_init_file))
        if cmd != 0:
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "\nOutput:%s" % output)

    g_logger.debug("Successfully backuped instance catalog physical files."
                   " Instance data dir: %s" % instance.datadir)


def __restore_base_folder(instance):
    """
    """
    g_logger.debug("Restore instance base folders. "
                   "Instance data dir: {0}".format(instance.datadir))
    backup_path = "%s/oldClusterDBAndRel/" % g_opts.upgrade_bak_path
    # get instance name
    instance_name = getInstanceName(instance)

    # load db and catalog info from json file
    if instance.instanceRole == INSTANCE_ROLE_COODINATOR:
        db_and_catalog_info_file_name = \
            "%s/cn_db_and_catalog_info_%s.json" % (backup_path, instance_name)
    elif instance.instanceRole == INSTANCE_ROLE_DATANODE:
        if instance.instanceType == MASTER_INSTANCE or \
                instance.instanceType == STANDBY_INSTANCE:
            db_and_catalog_info_file_name = \
                "%s/dn_db_and_catalog_info_%s.json" % (
                    backup_path, instance_name)
        else:
            raise Exception("Invalid instance type:%s" % instance.instanceType)
    else:
        raise Exception("Invalid instance role:%s" % instance.instanceRole)
    fp = open(db_and_catalog_info_file_name, 'r')
    dbInfoStr = fp.read()
    fp.close()
    dbInfoDict = json.loads(dbInfoStr)

    # restore base folder
    for each_db in dbInfoDict["dblist"]:
        if each_db["spclocation"] != "":
            if each_db["spclocation"].startswith('/'):
                tbsBaseDir = each_db["spclocation"]
            else:
                tbsBaseDir = "%s/pg_location/%s" % (
                    instance.datadir, each_db["spclocation"])
            pg_catalog_base_dir = "%s/%s_%s/%d" % (
                tbsBaseDir, DefaultValue.TABLESPACE_VERSION_DIRECTORY,
                instance_name, int(each_db["dboid"]))
        else:
            pg_catalog_base_dir = "%s/base/%d" % (
                instance.datadir, int(each_db["dboid"]))
        # for base folder, template0 need handle specially
        if each_db["dbname"] == 'template0':
            pg_catalog_base_back_dir = "%s_bak" % pg_catalog_base_dir
            cpDirectory(pg_catalog_base_back_dir, pg_catalog_base_dir)
            g_logger.debug(
                "Template0 has been restored from {0} to {1}".format(
                    pg_catalog_base_back_dir, pg_catalog_base_dir))
            continue

        # handle other db's base folder
        if len(each_db["CatalogList"]) <= 0:
            raise Exception("Can not find any catalog in database %s" %
                            each_db["dbname"])

        for each_catalog in each_db["CatalogList"]:
            # main/vm/fsm  -- main.1 ..
            main_file = "%s/%d" % (pg_catalog_base_dir,
                                   int(each_catalog['relfilenode']))
            if not os.path.isfile(main_file):
                g_logger.debug("Instance data dir: %s, database: %s, "
                               "relnodefile: %s does not exists." \
                               % (instance.datadir, each_db["dbname"],
                                  main_file))

            cmd = "cp -f -p '%s_bak' '%s'" % (main_file, main_file)
            g_logger.debug(
                "{0} needs to be restored from {0}_bak".format(main_file))
            seg_idx = 1
            while 1:
                seg_file = "%s/%d.%d" % (pg_catalog_base_dir,
                                         int(each_catalog['relfilenode']),
                                         seg_idx)
                seg_file_bak = "%s_bak" % seg_file
                if os.path.isfile(seg_file):
                    if os.path.isfile(seg_file_bak):
                        cmd += "&& cp -f -p '%s' '%s'" % (seg_file_bak,
                                                          seg_file)
                    else:
                        cmd += "&& rm -f '%s'" % seg_file
                    seg_idx += 1
                else:
                    break
            g_logger.debug("seg_file needs to be restored")

            vm_file = "%s/%d_vm" % (pg_catalog_base_dir,
                                    int(each_catalog['relfilenode']))
            vm_file_bak = "%s_bak" % vm_file
            if os.path.isfile(vm_file):
                if os.path.isfile(vm_file_bak):
                    cmd += "&& cp -f -p '%s' '%s'" % (vm_file_bak, vm_file)
                else:
                    cmd += "&& rm -f '%s'" % vm_file
            g_logger.debug(
                "{0} needs to be restored from {0}_bak".format(vm_file))
            fsm_file = "%s/%d_fsm" % (pg_catalog_base_dir,
                                      int(each_catalog['relfilenode']))
            fsm_file_bak = "%s_bak" % fsm_file
            if os.path.isfile(fsm_file):
                if os.path.isfile(fsm_file_bak):
                    cmd += "&& cp -f -p '%s' '%s'" % (fsm_file_bak, fsm_file)
                else:
                    cmd += "&& rm -f '%s'" % fsm_file
            g_logger.debug("{0} needs to be restored from {0}_bak".format(
                fsm_file))
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "\nOutput:%s" % output)

        # special files pg_filenode.map pg_internal.init
        cmd = ""
        pg_filenode_map_file = "%s/pg_filenode.map" % pg_catalog_base_dir
        if os.path.isfile(pg_filenode_map_file):
            if cmd == "":
                cmd = "cp -f -p '%s_bak' '%s'" % (pg_filenode_map_file,
                                                  pg_filenode_map_file)
            else:
                cmd += "&& cp -f -p '%s_bak' '%s'" % (pg_filenode_map_file,
                                                      pg_filenode_map_file)
            g_logger.debug("{0} needs to be restored from {0}_bak".format(
                pg_filenode_map_file))

        pg_internal_init_file = "%s/pg_internal.init" % pg_catalog_base_dir
        if os.path.isfile(pg_internal_init_file):
            if cmd == "":
                cmd = "cp -f -p '%s_bak' '%s'" % (pg_internal_init_file,
                                                  pg_internal_init_file)
            else:
                cmd += "&& cp -f -p '%s_bak' '%s'" % (pg_internal_init_file,
                                                      pg_internal_init_file)
            g_logger.debug("{0} needs to be restored from {0}_bak".format(
                pg_internal_init_file))

        if cmd != 0:
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "\nOutput:%s" % output)
    g_logger.debug("Successfully restore instance base folders. Instance data "
                   "dir: {0}".format(instance.datadir))


def cleanBackUpDir(backupDir):
    """
    function: clean backup dir
    input  : backupDir
    output : NA
    """
    # clean backupDir folder. First, we kill any pending backup process
    bakDir = "%s_bak" % backupDir
    backcmd = "cp -r -p %s %s" % (backupDir, bakDir)
    killCmd = DefaultValue.killInstProcessCmd(backcmd, False, 9, False)
    DefaultValue.execCommandLocally(killCmd)
    # Then do clean
    if os.path.isdir(bakDir):
        g_file.removeDirectory(bakDir)


def checkExistsVersion(instanceNames, cooInst, curCommitid):
    """
    function: check exits version
    input  : instanceNames, cooInst, curCommitid
    output : needKill False/True
    """
    needKill = False
    sql = ""
    for name in instanceNames:
        sql += "execute direct on (%s) 'select version()';" % name
    (status, output) = ClusterCommand.remoteSQLCommand(
        sql, g_opts.user,
        cooInst.hostname,
        cooInst.port, False,
        DefaultValue.DEFAULT_DB_NAME,
        IsInplaceUpgrade=True)
    g_logger.debug("Command to check version: %s" % sql)
    if status != 0 or ClusterCommand.findErrorInSql(output):
        raise Exception(
            ErrorCode.GAUSS_513["GAUSS_51300"] % sql + " Error: \n%s" % str(
                output))
    if not output:
        raise Exception(ErrorCode.GAUSS_516["GAUSS_51654"])
    resList = output.split('\n')
    pattern = re.compile(r'[(](.*?)[)]')
    for record in resList:
        versionInBrackets = re.findall(pattern, record)
        commitid = versionInBrackets[0].split(" ")[-1]
        if commitid != curCommitid:
            needKill = True
            break
    return needKill


def getTimeFormat(seconds):
    """
    format secends to h-m-s
    input:int
    output:int
    """
    seconds = int(seconds)
    if seconds == 0:
        return 0
    # Converts the seconds to standard time
    hour = seconds / 3600
    minute = (seconds - hour * 3600) / 60
    s = seconds % 60
    resultstr = ""
    if hour != 0:
        resultstr += "%dh" % hour
    if minute != 0:
        resultstr += "%dm" % minute
    return "%s%ds" % (resultstr, s)


def backupConfig():
    """
    function: backup config
    output: none
    """
    try:
        bakPath = g_opts.upgrade_bak_path
        clusterAppPath = g_clusterInfo.appPath

        # Backup cluster_static_config and cluster_dynamic_config,
        # logic_cluster_name.txt
        # cluster_static_config* at least one
        cmd = "cp -f -p '%s'/bin/*cluster_static_config* '%s'" % (
            clusterAppPath, bakPath)
        dynamic_config = "%s/bin/cluster_dynamic_config" % clusterAppPath
        logicalNameFile = "%s/bin/logic_cluster_name.txt" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            dynamic_config, dynamic_config, bakPath)
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            logicalNameFile, logicalNameFile, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # Backup libcgroup config
        MAX_PARA_NUMBER = 20
        cgroup_file_list = []
        gs_cgroup_path = "%s/etc" % clusterAppPath
        file_name_list = os.listdir(gs_cgroup_path)
        for file_name in file_name_list:
            if file_name.endswith('.cfg'):
                gs_cgroup_config_file = "%s/%s" % (gs_cgroup_path, file_name)
                cgroup_file_list.append(gs_cgroup_config_file)

        # build cmd string list
        # Every 20 records merged into one
        i = 0
        cmdCgroup = ""
        cmdList = []
        for gs_cgroup_config_file in cgroup_file_list:
            i += 1
            cmdCgroup += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
                gs_cgroup_config_file, gs_cgroup_config_file, bakPath)
            if i % MAX_PARA_NUMBER == 0:
                cmdList.append(cmdCgroup)
                i = 0
                cmdCgroup = ""
        if cmdCgroup != "":
            cmdList.append(cmdCgroup)
        for exeCmd in cmdList:
            g_logger.debug("Backup command: %s" % cmd)
            DefaultValue.execCommandLocally(exeCmd[3:])

        # Backup libsimsearch etc files and libs files
        searchConfigFile = "%s/etc/searchletConfig.yaml" % clusterAppPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            searchConfigFile, searchConfigFile, bakPath)
        searchIniFile = "%s/etc/searchServer.ini" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            searchIniFile, searchIniFile, bakPath)
        cmd += " && (if [ -d '%s/lib/libsimsearch' ];" \
               "then cp -r '%s/lib/libsimsearch' '%s';fi)" % (
                   clusterAppPath, clusterAppPath, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # Backup library file and database size file
        cmd = "cp -r '%s'/lib/postgresql/pg_plugin '%s'" % (
            clusterAppPath, bakPath)
        backup_dbsize = "%s/bin/%s" % (
            clusterAppPath, DefaultValue.DB_SIZE_FILE)
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            backup_dbsize, backup_dbsize, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # sync kerberos conf files
        krbConfigFile = "%s/kerberos" % clusterAppPath
        cmd = "(if [ -d '%s' ];then cp -r '%s' '%s';fi)" % (
            krbConfigFile, krbConfigFile, bakPath)
        cmd += "&& (if [ -d '%s/var/krb5kdc' ];then mkdir %s/var;" \
               " cp -r '%s/var/krb5kdc' '%s/var/';fi)" % (
                   clusterAppPath, bakPath, clusterAppPath, bakPath)
        g_logger.debug("Grey upgrade sync command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup obsserver.key.cipher/obsserver.key.rand and server.key.
        # cipher/server.key.rand and datasource.key.cipher/datasource.key.rand
        OBS_cipher_key_bak_file = \
            "%s/bin/obsserver.key.cipher" % clusterAppPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            OBS_cipher_key_bak_file, OBS_cipher_key_bak_file, bakPath)
        OBS_rand_key_bak_file = "%s/bin/obsserver.key.rand" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            OBS_rand_key_bak_file, OBS_rand_key_bak_file, bakPath)
        trans_encrypt_cipher_key_bak_file = \
            "%s/bin/trans_encrypt.key.cipher" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            trans_encrypt_cipher_key_bak_file,
            trans_encrypt_cipher_key_bak_file,
            bakPath)
        trans_encrypt_rand_key_bak_file = \
            "%s/bin/trans_encrypt.key.rand" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            trans_encrypt_rand_key_bak_file, trans_encrypt_rand_key_bak_file,
            bakPath)
        trans_encrypt_cipher_ak_sk_key_bak_file = \
            "%s/bin/trans_encrypt_ak_sk.key" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            trans_encrypt_cipher_ak_sk_key_bak_file,
            trans_encrypt_cipher_ak_sk_key_bak_file, bakPath)
        server_cipher_key_bak_file = \
            "%s/bin/server.key.cipher" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            server_cipher_key_bak_file, server_cipher_key_bak_file, bakPath)
        server_rand_key_bak_file = "%s/bin/server.key.rand" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            server_rand_key_bak_file, server_rand_key_bak_file, bakPath)
        datasource_cipher = "%s/bin/datasource.key.cipher" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            datasource_cipher, datasource_cipher, bakPath)
        datasource_rand = "%s/bin/datasource.key.rand" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            datasource_rand, datasource_rand, bakPath)
        tde_key_cipher = "%s/bin/gs_tde_keys.cipher" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            tde_key_cipher, tde_key_cipher, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup utilslib
        utilslib = "%s/utilslib" % clusterAppPath
        cmd = "if [ -d '%s' ];then cp -r '%s' '%s';fi" % (
            utilslib, utilslib, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup ca.key,etcdca.crt, client.key and client.crt
        CA_key_file = "%s/share/sslcert/etcd/ca.key" % clusterAppPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            CA_key_file, CA_key_file, bakPath)
        CA_cert_file = "%s/share/sslcert/etcd/etcdca.crt" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            CA_cert_file, CA_cert_file, bakPath)
        client_key_file = "%s/share/sslcert/etcd/client.key" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            client_key_file, client_key_file, bakPath)
        client_cert_file = "%s/share/sslcert/etcd/client.crt" % clusterAppPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            client_cert_file, client_cert_file, bakPath)
        if int(g_opts.oldVersion) >= 92019:
            client_key_cipher_file = \
                "%s/share/sslcert/etcd/client.key.cipher" % clusterAppPath
            cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
                client_key_cipher_file, client_key_cipher_file, bakPath)
            client_key_rand_file = \
                "%s/share/sslcert/etcd/client.key.rand" % clusterAppPath
            cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
                client_key_rand_file, client_key_rand_file, bakPath)
            etcd_key_cipher_file = \
                "%s/share/sslcert/etcd/etcd.key.cipher" % clusterAppPath
            cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
                etcd_key_cipher_file, etcd_key_cipher_file, bakPath)
            etcd_key_rand_file = \
                "%s/share/sslcert/etcd/etcd.key.rand" % clusterAppPath
            cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
                etcd_key_rand_file, etcd_key_rand_file, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup java UDF
        javadir = "'%s'/lib/postgresql/java" % clusterAppPath
        cmd = "if [ -d '%s' ];then cp -r '%s' '%s';fi" % (
            javadir, javadir, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup postGIS
        cmdPostGis = ""
        for sofile in g_opts.postgisSOFileList.keys():
            absPath = os.path.join(clusterAppPath,
                                   g_opts.postgisSOFileList[sofile])
            srcFile = "'%s'/%s" % (absPath, sofile)
            cmdPostGis += " && (if [ -f %s ];then cp -f -p %s '%s';fi)" % (
                srcFile, srcFile, bakPath)
        # skip " &&"
        cmd = cmdPostGis[3:]
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup extension library and config files
        hadoop_odbc_connector = \
            "%s/lib/postgresql/hadoop_odbc_connector.so" % clusterAppPath
        extension_config01 = \
            "%s/share/postgresql/extension/hadoop_odbc_connector--1.0.sql" \
            % clusterAppPath
        extension_config02 = \
            "%s/share/postgresql/extension/hadoop_odbc_connector.control" \
            % clusterAppPath
        extension_config03 = \
            "%s/share/postgresql/extension/" \
            "hadoop_odbc_connector--unpackaged--1.0.sql" % clusterAppPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            hadoop_odbc_connector, hadoop_odbc_connector, bakPath)
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            extension_config01, extension_config01, bakPath)
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            extension_config02, extension_config02, bakPath)
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s';fi)" % (
            extension_config03, extension_config03, bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup dict file and grpc files
        dictFileDir = "'%s'/share/postgresql/tsearch_data" % clusterAppPath
        grpcFileDir = "'%s'/share/sslcert/grpc" % clusterAppPath
        cmd = "if [ -d '%s' ];then cp -r '%s' '%s';fi && " % (dictFileDir,
                                                              dictFileDir,
                                                              bakPath)
        cmd += "if [ -d '%s' ];then cp -r '%s' '%s';fi" % (grpcFileDir,
                                                           grpcFileDir,
                                                           bakPath)
        g_logger.debug("Backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup gtm.control and gtm.sequence
        if len(g_dbNode.gtms) > 0:
            gtm_control = "%s/gtm.control" % g_dbNode.gtms[0].datadir
            gtm_sequence = "%s/gtm.sequence" % g_dbNode.gtms[0].datadir
            cmd = "(if [ -f '%s' ];" \
                  "then cp -f -p '%s' '%s/gtm.control.bak';fi)" % \
                  (gtm_control, gtm_control, bakPath)
            cmd += " && (if [ -f '%s' ];" \
                   "then cp -f -p '%s' '%s/gtm.sequence.bak';fi)" % \
                   (gtm_sequence, gtm_sequence, bakPath)
            g_logger.debug("Backup command: %s" % cmd)
            DefaultValue.execCommandLocally(cmd)
    except Exception as e:
        raise Exception(str(e))


def restoreConfig():
    """
    function: restore config
    output: none
    """
    try:
        bakPath = g_opts.upgrade_bak_path
        clusterAppPath = g_opts.newClusterAppPath
        # init old cluster config
        oldStaticConfigFile = os.path.join(
            g_opts.oldClusterAppPath, "bin/cluster_static_config")
        oldStaticClusterInfo = dbClusterInfo()
        oldStaticClusterInfo.initFromStaticConfig(g_opts.user,
                                                  oldStaticConfigFile)
        # flush new static configuration
        newStaticConfig = os.path.join(
            clusterAppPath, "bin/cluster_static_config")
        if not os.path.isfile(newStaticConfig):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            os.path.realpath(newStaticConfig))
        g_file.removeFile(newStaticConfig)
        newStaticClusterInfo = dbClusterInfo()
        newStaticClusterInfo.saveToStaticConfig(
            newStaticConfig, oldStaticClusterInfo.localNodeId,
            oldStaticClusterInfo.dbNodes, upgrade=True)
        # restore dynamic configuration
        dynamic_config = "%s/cluster_dynamic_config" % bakPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            dynamic_config, dynamic_config, clusterAppPath)
        # no need to restore alarm.conf at here,
        # because it has been done on upgradeNodeApp
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore libsimsearch etc files and libsimsearch libs files
        searchConfigFile = "%s/searchletConfig.yaml" % bakPath
        cmd = "(if [ -f '%s' ];" \
              "then cp -f -p '%s' '%s/etc/searchletConfig.yaml'; fi)" % (
                  searchConfigFile, searchConfigFile, clusterAppPath)
        searchIniFile = "%s/searchServer.ini" % bakPath
        cmd += " && (if [ -f '%s' ];" \
               "then cp -f -p '%s' '%s/etc/searchServer.ini'; fi)" % (
                   searchIniFile, searchIniFile, clusterAppPath)
        cmd += " && (if [ -d '%s/libsimsearch' ];" \
               "then cp -r '%s/libsimsearch' '%s/lib/';fi)" % (
                   bakPath, bakPath, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore library file,
        # database size file and initialized configuration parameters files
        cmd = "cp -r '%s/pg_plugin' '%s'/lib/postgresql" % (
            bakPath, clusterAppPath)
        backup_dbsize = os.path.join(bakPath, DefaultValue.DB_SIZE_FILE)
        cmd += " && (if [ -f '%s' ];then cp '%s' '%s/bin';fi)" % (
            backup_dbsize, backup_dbsize, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # sync kerberos conf files
        cmd = "(if [ -d '%s/kerberos' ];then cp -r '%s/kerberos' '%s/';fi)" % (
            bakPath, bakPath, clusterAppPath)
        cmd += "&& (if [ -d '%s/var/krb5kdc' ];" \
               "then mkdir %s/var; cp -r '%s/var/krb5kdc' '%s/var/';fi)" % (
                   bakPath, clusterAppPath, bakPath, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore obsserver.key.cipher/obsserver.key.rand
        # and server.key.cipher/server.key.rand
        # and datasource.key.cipher/datasource.key.rand
        OBS_cipher_key_bak_file = "%s/obsserver.key.cipher" % bakPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            OBS_cipher_key_bak_file, OBS_cipher_key_bak_file, clusterAppPath)
        OBS_rand_key_bak_file = "%s/obsserver.key.rand" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            OBS_rand_key_bak_file, OBS_rand_key_bak_file, clusterAppPath)
        trans_encrypt_cipher_key_bak_file = \
            "%s/trans_encrypt.key.cipher" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            trans_encrypt_cipher_key_bak_file,
            trans_encrypt_cipher_key_bak_file,
            clusterAppPath)
        trans_encrypt_rand_key_bak_file = "%s/trans_encrypt.key.rand" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            trans_encrypt_rand_key_bak_file, trans_encrypt_rand_key_bak_file,
            clusterAppPath)
        trans_encrypt_cipher_ak_sk_key_bak_file = \
            "%s/trans_encrypt_ak_sk.key" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            trans_encrypt_cipher_ak_sk_key_bak_file,
            trans_encrypt_cipher_ak_sk_key_bak_file, clusterAppPath)
        server_cipher_key_bak_file = "%s/server.key.cipher" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            server_cipher_key_bak_file, server_cipher_key_bak_file,
            clusterAppPath)
        server_rand_key_bak_file = "%s/server.key.rand" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            server_rand_key_bak_file, server_rand_key_bak_file, clusterAppPath)
        datasource_cipher = "%s/datasource.key.cipher" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            datasource_cipher, datasource_cipher, clusterAppPath)
        datasource_rand = "%s/datasource.key.rand" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            datasource_rand, datasource_rand, clusterAppPath)
        tde_key_cipher = "%s/gs_tde_keys.cipher" % bakPath
        cmd += " && (if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
            tde_key_cipher, tde_key_cipher, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore utilslib
        utilslib = "%s/utilslib" % bakPath
        cmd = "if [ -d '%s' ];then cp -r '%s' '%s'/;" % (
            utilslib, utilslib, clusterAppPath)
        # create new $GAUSSHOME/utilslib if not exist.
        # no need to do chown, it will be done at all restore finished
        cmd += " else mkdir -p '%s'/utilslib -m %s; fi " % (
            clusterAppPath, DefaultValue.DIRECTORY_MODE)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore ca.key,etcdca.crt, client.key and client.crt
        CA_key_file = "%s/ca.key" % bakPath
        cmd = "(if [ -f '%s' ];" \
              "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                  CA_key_file, CA_key_file, clusterAppPath)
        CA_cert_file = "%s/etcdca.crt" % bakPath
        cmd += " && (if [ -f '%s' ];" \
               "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                   CA_cert_file, CA_cert_file, clusterAppPath)
        client_key_file = "%s/client.key" % bakPath
        cmd += " && (if [ -f '%s' ];" \
               "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                   client_key_file, client_key_file, clusterAppPath)
        client_cert_file = "%s/client.crt" % bakPath
        cmd += " && (if [ -f '%s' ];" \
               "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                   client_cert_file, client_cert_file, clusterAppPath)
        if int(g_opts.oldVersion) >= 92019:
            client_key_cipher_file = "%s/client.key.cipher" % bakPath
            cmd += " && (if [ -f '%s' ];" \
                   "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                       client_key_cipher_file, client_key_cipher_file,
                       clusterAppPath)
            client_key_rand_file = "%s/client.key.rand" % bakPath
            cmd += " && (if [ -f '%s' ];" \
                   "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                       client_key_rand_file, client_key_rand_file,
                       clusterAppPath)
            etcd_key_cipher_file = "%s/etcd.key.cipher" % bakPath
            cmd += " && (if [ -f '%s' ];" \
                   "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                       etcd_key_cipher_file, etcd_key_cipher_file,
                       clusterAppPath)
            etcd_key_rand_file = "%s/etcd.key.rand" % bakPath
            cmd += " && (if [ -f '%s' ];" \
                   "then cp -f -p '%s' '%s/share/sslcert/etcd/';fi)" % (
                       etcd_key_rand_file, etcd_key_rand_file, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore javaUDF
        # lib/postgresql/java/pljava.jar use new package, no need to restore.
        javadir = "%s/java" % bakPath
        desPath = "%s/lib/postgresql/" % clusterAppPath
        cmd = "if [ -d '%s' ];" \
              "then rm -f '%s/pljava.jar'&&cp -r '%s' '%s' ;fi" % (
                  javadir, javadir, javadir, desPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore postGIS
        cmdPostGis = ""
        machineType = platform.machine()
        for sofile in g_opts.postgisSOFileList.keys():
            # To solve the dependency problem on the ARM platform,
            # the dependency library libbgcc_s.so* and libstdc++.
            # so.* is contained in the ARM package.
            # The libgcc_s.so.*
            # on the ARM platform is the database built-in library.
            # Therefore, no restoration is required.
            if machineType == "aarch64" and sofile.find('libgcc_s.so') >= 0:
                continue
            desPath = os.path.join(clusterAppPath,
                                   g_opts.postgisSOFileList[sofile])
            srcFile = "'%s'/%s" % (bakPath, sofile)
            cmdPostGis += " && (if [ -f %s ];then cp -f -p %s '%s';fi)" % (
                srcFile, srcFile, desPath)
        # skip " &&"
        cmd = cmdPostGis[3:]
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore extension library and config files
        hadoop_odbc_connector = \
            "%s/lib/postgresql/hadoop_odbc_connector.so" % bakPath
        extension_config01 = \
            "%s/share/postgresql/extension/hadoop_odbc_connector--1.0.sql" \
            % bakPath
        extension_config02 = \
            "%s/share/postgresql/extension/hadoop_odbc_connector.control" \
            % bakPath
        extension_config03 = \
            "%s/share/postgresql/extension/" \
            "hadoop_odbc_connector--unpackaged--1.0.sql" % bakPath
        cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/lib/postgresql/';fi)" % (
            hadoop_odbc_connector, hadoop_odbc_connector, clusterAppPath)
        cmd += \
            " && (if [ -f '%s' ];then cp -f " \
            "-p '%s/share/postgresql/extension/' '%s';fi)" % (
                extension_config01, extension_config01, clusterAppPath)
        cmd += \
            " && (if [ -f '%s' ];then cp " \
            "-f -p '%s/share/postgresql/extension/' '%s';fi)" % (
                extension_config02, extension_config02, clusterAppPath)
        cmd += \
            " && (if [ -f '%s' ];then cp -f " \
            "-p '%s/share/postgresql/extension/' '%s';fi)" % (
                extension_config03, extension_config03, clusterAppPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # restore dict file and grpc file
        dictFileDir = "'%s'/tsearch_data" % bakPath
        dictDesPath = "'%s'/share/postgresql" % clusterAppPath
        grpcFileDir = "'%s'/grpc" % bakPath
        grpcDesPath = "'%s'/share/sslcert" % clusterAppPath
        cmd = "if [ -d '%s' ];then cp -r '%s' '%s/' ;fi &&" % (
            dictFileDir, dictFileDir, dictDesPath)
        cmd += "if [ -d '%s' ];then cp -r '%s' '%s/' ;fi" % (
            grpcFileDir, grpcFileDir, grpcDesPath)
        g_logger.debug("Restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)
    except Exception as e:
        raise Exception(str(e))


def restoreDynamicConfigFile():
    """
    function: restore dynamic config file
    output: None
    :return:
    """
    bakPath = g_opts.upgrade_bak_path
    newClusterAppPath = g_opts.newClusterAppPath
    oldClusterAppPath = g_opts.oldClusterAppPath
    # cp new dynamic config file to new app path
    newDynamicConfigFile = "%s/bin/cluster_dynamic_config" % oldClusterAppPath
    g_file.removeFile("%s/bin/cluster_dynamic_config" % newClusterAppPath)
    cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
        newDynamicConfigFile, newDynamicConfigFile, newClusterAppPath)
    g_logger.debug("Restore command: %s" % cmd)
    DefaultValue.execCommandLocally(cmd)
    # cp old dynamic config file to old app path
    dynamic_config = "%s/cluster_dynamic_config" % bakPath
    g_file.removeFile(newDynamicConfigFile)
    cmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/bin/';fi)" % (
        dynamic_config, dynamic_config, oldClusterAppPath)
    g_logger.debug("Restore command: %s" % cmd)
    DefaultValue.execCommandLocally(cmd)


def inplaceBackup():
    """
    function: backup config
    output: none
    """
    try:
        # backup gds files
        bakPath = g_opts.upgrade_bak_path
        gdspath = "%s/share/sslcert/gds" % g_clusterInfo.appPath
        cmd = "(if [ -d '%s' ];" \
              "then chmod 600 -R '%s'/*; cp -r '%s' '%s';fi)" % (
                  gdspath, gdspath, gdspath, bakPath)
        g_logger.debug("Inplace backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)

        # backup gsql files
        bakPath = g_opts.upgrade_bak_path
        gsqlpath = "%s/share/sslcert/gsql" % g_clusterInfo.appPath
        cmd = "(if [ -d '%s' ];then chmod 600 -R '%s'/*; cp -r '%s' '%s';fi)" %\
              (gsqlpath, gsqlpath, gsqlpath, bakPath)
        g_logger.debug("Inplace backup command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)
    except Exception as e:
        raise Exception(str(e))


def inplaceRestore():
    """
    function: restore config
    output: none
    """
    try:
        # restore gds files
        gdspath = "%s/share/sslcert/" % g_clusterInfo.appPath
        gdsbackup = "%s/gds" % g_opts.upgrade_bak_path
        cmd = "(if [ -d '%s' ];then cp -r '%s' '%s';fi)" % (
            gdsbackup, gdsbackup, gdspath)
        g_logger.debug("Inplace restore command: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)
    except Exception as e:
        raise Exception(str(e))


def checkGucValue():
    """
    function: check guc value
    input  : NA
    output : NA
    """
    key = g_opts.gucStr.split(':')[0].strip()
    value = g_opts.gucStr.split(':')[1].strip()
    if key == "upgrade_from":
        instances = g_dbNode.cmagents
        fileName = "cm_agent.conf"
    elif key == "upgrade_mode":
        #instances = g_dbNode.coordinators
        #instances.extend(g_dbNode.datanodes)
        instances = g_dbNode.datanodes
        fileName = "postgresql.conf"
    else:
        raise Exception(ErrorCode.GAUSS_529["GAUSS_52942"])
    for inst in instances:
        configFile = "%s/%s" % (inst.datadir, fileName)
        cmd = "sed 's/\t/ /g' %s " \
              "| grep '^[ ]*\<%s\>[ ]*=' " \
              "| awk -F '=' '{print $2}'" % (configFile, key)
        g_logger.debug("Command for checking guc:%s" % cmd)
        retryTimes = 100
        for i in range(retryTimes):
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                time.sleep(3)
                g_logger.debug(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                    + " Output: \n%s" % output)
                continue
            if output == "":
                time.sleep(3)
                g_logger.debug(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                    + " There is no %s in %s" % (key, configFile))
                continue
            realValue = output.split('\n')[0].strip()
            if '#' in realValue:
                realValue = realValue.split('#')[0].strip()
            g_logger.debug("[key:%s]: Realvalue %s, ExpectValue %s" % (
                key, str(realValue), str(value)))
            if str(value) != str(realValue):
                raise Exception(
                    ErrorCode.GAUSS_521["GAUSS_52102"] % key
                    + " Real value %s, expect value %s"
                    % (str(realValue), str(value)))
            break


def backupInstanceHotpatchConfig(instanceDataDir):
    """
    function: backup
    input  : instanceDataDir
    output : NA
    """
    hotpatch_info_file = "%s/hotpatch/patch.info" % instanceDataDir
    hotpatch_info_file_bak = "%s/hotpatch/patch.info.bak" % instanceDataDir
    cmd = "(if [ -f '%s' ];then mv -f '%s' '%s';fi)" % (
        hotpatch_info_file, hotpatch_info_file, hotpatch_info_file_bak)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception(
            ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "\nOutput:%s" % output)


def backupHotpatch():
    """
    function: if the upgrade process failed in check cluster status,
        user can reenter upgrade process
    """
    if os.path.samefile(g_gausshome, g_opts.newClusterAppPath):
        g_logger.debug("Has switched to new version, no need to backup again.")
        return

    for dbInstance in g_dbNode.cmservers:
        backupInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.coordinators:
        backupInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.datanodes:
        backupInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.gtms:
        backupInstanceHotpatchConfig(dbInstance.datadir)


def rollbackInstanceHotpatchConfig(instanceDataDir):
    """
    function: rollback
    input  : instanceDataDir
    output : NA
    """
    hotpatch_info_file = "%s/hotpatch/patch.info" % instanceDataDir
    hotpatch_info_file_bak = "%s/hotpatch/patch.info.bak" % instanceDataDir
    cmd = "(if [ -f '%s' ];then mv -f '%s' '%s';fi)" % (
        hotpatch_info_file_bak, hotpatch_info_file_bak, hotpatch_info_file)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception(
            ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "\nOutput:%s" % output)


def rollbackHotpatch():
    """
    function: rollback
    input  : NA
    output : NA
    """
    for dbInstance in g_dbNode.cmservers:
        rollbackInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.coordinators:
        rollbackInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.datanodes:
        rollbackInstanceHotpatchConfig(dbInstance.datadir)

    for dbInstance in g_dbNode.gtms:
        rollbackInstanceHotpatchConfig(dbInstance.datadir)


def readDeleteGuc():
    """
     function: get the delete guc from file,
     input:  NA
     output: return the dict gucContent[instanceName]: guc_name
        :return:the key instancename is gtm, coordinator,
        datanode, cmserver, cmagent
    """
    deleteGucFile = os.path.join(g_opts.upgrade_bak_path,
                                 "upgrade_sql/set_guc/delete_guc")
    if not os.path.isfile(deleteGucFile):
        raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % deleteGucFile)
    g_logger.debug("Get the delete GUC from file %s." % deleteGucFile)
    gucContent = {}
    with open(deleteGucFile, 'r') as fp:
        resList = fp.readlines()
    for oneLine in resList:
        oneLine = oneLine.strip()
        # skip blank line and comment line
        if not oneLine or oneLine.startswith('#'):
            continue
        result = oneLine.split()
        if len(result) != 2:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] % deleteGucFile)
        gucName = result[0]
        instanceName = result[1]
        gucContent.setdefault(instanceName, []).append(gucName)
    g_logger.debug("Successfully get the delete GUC from file.")
    return gucContent


def  cleanInstallPath():
    """
    function: clean install path
    input  : NA
    output : NA
    """
    installPath = g_opts.appPath
    if not os.path.exists(installPath):
        g_logger.debug(ErrorCode.GAUSS_502[
                           "GAUSS_50201"] % installPath + " No need to clean.")
        return
    if not os.listdir(installPath):
        g_logger.debug("The path %s is empty." % installPath)
        cmd = "(if [ -d '%s' ]; then rm -rf '%s'; fi)" % (
            installPath, installPath)
        g_logger.log("Command for cleaning install path: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)
        return
    if g_opts.forceRollback and not os.path.islink(g_gausshome):
        g_logger.log(
            "Under force rollback mode, "
            "$GAUSSHOME is not symbolic link. No need to clean.")
        return
    elif os.path.samefile(installPath, g_gausshome):
        g_logger.log("The install path is $GAUSSHOME, cannot clean.")
        return
    tmpDir = DefaultValue.getTmpDirFromEnv(g_opts.user)
    if tmpDir == "":
        raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
    # under upgrade, we will change the mode to read and execute
    # in order to not change the dir, so we need to restore
    # the permission to original mode after we switch to new version,
    # and then we will have the permission to clean
    # appPath under commit-upgrade
    # under rollback, we also need to restore the permission
    pluginPath = "%s/lib/postgresql/pg_plugin" % installPath
    cmd = "(if [ -d '%s' ]; then chmod -R %d '%s'; fi)" % (
        pluginPath, DefaultValue.KEY_DIRECTORY_MODE, pluginPath)
    appBakPath = "%s/to_be_delete" % tmpDir
    cmd += " && (if [ ! -d '%s' ]; then mkdir -p '%s'; fi)" % (
        appBakPath, appBakPath)
    cmd += " && (if [ -d '%s' ]; then cp -r '%s/' '%s/to_be_delete/'; fi)" % (
        installPath, installPath, tmpDir)
    g_logger.debug(
        "Command for change permission and backup install path: %s" % cmd)
    DefaultValue.execCommandLocally(cmd)

    cmd = "(if [ -d '%s/bin' ]; then rm -rf '%s/bin'; fi) &&" % \
          (installPath, installPath)
    cmd += "(if [ -d '%s/etc' ]; then rm -rf '%s/etc'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/include' ]; then rm -rf '%s/include'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/lib' ]; then rm -rf '%s/lib'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/share' ]; then rm -rf '%s/share'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/logs' ]; then rm -rf '%s/logs'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/utilslib' ]; then rm -rf '%s/utilslib'; fi) && " % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/jdk' ]; then rm -rf '%s/jdk'; fi) && " % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/kerberos' ]; then rm -rf '%s/kerberos'; fi) &&" % \
           (installPath, installPath)
    cmd += "(if [ -d '%s/var/krb5kdc' ]; then rm -rf '%s/var/krb5kdc'; fi) &&" \
           % (installPath, installPath)
    cmd += "(if [ -e '%s/version.cfg' ]; then rm -rf '%s/version.cfg'; fi)"\
           % (installPath, installPath)
    DefaultValue.execCommandLocally(cmd)
    if os.listdir(installPath):
        g_logger.log(
            "The path %s has personal file ot directory, please remove it."
            % installPath)
    else:
        cmd = "(if [ -d '%s' ]; then rm -rf '%s'; fi)" % (
            installPath, installPath)
        g_logger.log("Command for cleaning install path: %s" % cmd)
        DefaultValue.execCommandLocally(cmd)


def copyCerts():
    """
    function: copy certs
    input  : NA
    output : NA
    """
    g_logger.debug("Starting copy Certs")
    oldBinPath = os.path.join(g_opts.oldClusterAppPath, "bin")
    newBinPath = os.path.join(g_opts.newClusterAppPath, "bin")
    oldOmSslCerts = os.path.join(g_opts.oldClusterAppPath, "share/sslcert/om")
    newOmSslCerts = os.path.join(g_opts.newClusterAppPath, "share/sslcert/om")

    g_file.cpFile("%s/server.key.cipher" % oldBinPath, "%s/" % newBinPath)
    g_file.cpFile("%s/server.key.rand" % oldBinPath, "%s/" % newBinPath)
    for certFile in DefaultValue.SERVER_CERT_LIST:
        g_file.cpFile("%s/%s" % (oldOmSslCerts, certFile), "%s/" %
                      newOmSslCerts)

    g_file.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.key.cipher" %
                      newBinPath)
    g_file.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.key.rand" %
                      newBinPath)
    g_file.changeMode(DefaultValue.KEY_FILE_MODE, "%s/*" %
                      newOmSslCerts)


def prepareUpgradeSqlFolder():
    """
    function: verify upgrade_sql.tar.gz and extract it to binary backup path,
              if execute gs_upgradectl again, we will decompress the sql folder
               again to avoid the file in backup path destroyed
    input : NA
    output: NA
    """
    g_logger.debug("Preparing upgrade sql folder.")
    # verify upgrade_sql.tar.gz
    dirName = os.path.dirname(os.path.realpath(__file__))
    packageDir = os.path.join(dirName, "./../../")
    packageDir = os.path.normpath(packageDir)
    upgrade_sql_gz_file = "%s/%s" % (packageDir, const.UPGRADE_SQL_FILE)
    upgrade_sql_sha256_file = "%s/%s" % (packageDir, const.UPGRADE_SQL_SHA)
    if not os.path.isfile(upgrade_sql_gz_file):
        raise Exception(
            ErrorCode.GAUSS_502["GAUSS_50201"] % upgrade_sql_gz_file)
    if not os.path.isfile(upgrade_sql_sha256_file):
        raise Exception(
            ErrorCode.GAUSS_502["GAUSS_50201"] % upgrade_sql_sha256_file)
    g_logger.debug(
        "The SQL file is %s, the sha256 file is %s." % (
            upgrade_sql_gz_file, upgrade_sql_sha256_file))

    g_logger.debug("Checking the SHA256 value of upgrade sql folder.")
    sha256Actual = g_file.getFileSHA256(upgrade_sql_gz_file)
    sha256Record = g_file.readFile(upgrade_sql_sha256_file)
    if sha256Actual.strip() != sha256Record[0].strip():
        raise Exception(ErrorCode.GAUSS_516["GAUSS_51635"] + \
                        " The SHA256 value is different: \nTar file: "
                        "%s \nSHA256 file: %s " % \
                        (upgrade_sql_gz_file, upgrade_sql_sha256_file))

    # extract it to binary backup path
    # self.context.upgradeBackupPath just recreated at last step,
    # it should not has upgrade_sql folder, so no need do clean
    g_logger.debug("Extracting upgrade sql folder.")
    g_file.decompressFiles(upgrade_sql_gz_file, g_opts.upgrade_bak_path)
    g_logger.debug("Successfully prepared upgrade sql folder.")


def backupOldClusterDBAndRel():
    """
    backup old cluster db and rel info
    get database list
    connect to each cn and master dn
    connect to each database, and get rel info
    """
    g_logger.log("Backing up old cluster database and catalog.")
    try:
        InstanceList = []
        # find all instances need to do backup
        if len(g_dbNode.coordinators) != 0:
            InstanceList.append(g_dbNode.coordinators[0])
        primaryDnIntance = getLocalPrimaryDNInstance()
        if primaryDnIntance:
            InstanceList.extend(primaryDnIntance)

        # do backup parallelly
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(backupOneInstanceOldClusterDBAndRel, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug("No master instance found on this node, "
                           "nothing need to do.")
            return

        g_logger.log("Successfully backed up old cluster database and catalog.")
    except Exception as e:
        g_logger.logExit(str(e))


def getLocalPrimaryDNInstance():
    """
    function: Get local primary DN instance
    input: NA
    output: NA
    """
    g_logger.log("We will find all primary dn instance in the local node.")
    tmpFile = os.path.join(DefaultValue.getTmpDirFromEnv(
        g_opts.user), const.TMP_DYNAMIC_DN_INFO)
    primaryDNList = []
    try:
        # Match query results and cluster configuration
        clusterStatus = DbClusterStatus()
        clusterStatus.initFromFile(tmpFile)
        # Find the master DN instance
        for dbNode in clusterStatus.dbNodes:
            for instance in dbNode.datanodes:
                if instance.status == 'Primary' and \
                        instance.nodeId == g_dbNode.id:
                    for eachInstance in g_dbNode.datanodes:
                        if eachInstance.instanceId == instance.instanceId:
                            primaryDNList.append(eachInstance)
                    g_logger.log(
                        "Success get the primary dn instance:{0}.".format(
                            instance.__dict__))
        return primaryDNList
    except Exception as er:
        raise Exception(str(er))


def backupOneInstanceOldClusterDBAndRel(instance):
    """
        backup db and catalog info for one old cluster instance
        do checkpoint
        get database info list
        remove template0
        connect each database, get catalog info
        save to file
        """
    tmpDir = DefaultValue.getTmpDirFromEnv(g_opts.user)
    if tmpDir == "":
        raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
    g_logger.debug(
        "Obtaining instance catalog information. Instance data dir: %s" %
        instance.datadir)
    dbInfoDict = {}
    dbInfoDict["dblist"] = []
    dbInfoDict["dbnum"] = 0
    backup_path = "%s/oldClusterDBAndRel/" % g_opts.upgrade_bak_path
    try:
        # get database info
        get_db_list_sql = """SELECT d.datname, d.oid, 
        pg_catalog.pg_tablespace_location(t.oid) AS spclocation 
        FROM pg_catalog.pg_database d LEFT OUTER JOIN 
        pg_catalog.pg_tablespace t ON d.dattablespace = t.oid ORDER BY 2;"""
        g_logger.debug("Get database info command: \n%s" % get_db_list_sql)
        (status, output) = ClusterCommand.execSQLCommand(get_db_list_sql,
                                                         g_opts.user, "",
                                                         instance.port,
                                                         "postgres",
                                                         False, "-m",
                                                         IsInplaceUpgrade=True)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_513[
                                "GAUSS_51300"] % get_db_list_sql +
                            " Error:\n%s" % output)
        if output == "":
            raise Exception("can not find any database!!")
        g_logger.debug("Get database info result: \n%s." % output)
        resList = output.split('\n')
        for each_line in resList:
            tmpDbInfo = initDbInfo()
            (datname, oid, spclocation) = each_line.split('|')
            tmpDbInfo['dbname'] = datname.strip()
            tmpDbInfo['dboid'] = oid.strip()
            tmpDbInfo['spclocation'] = spclocation.strip()
            dbInfoDict["dblist"].append(tmpDbInfo)
            dbInfoDict["dbnum"] += 1

        # connect each database, get catalog info
        get_catalog_list_sql =\
            """SELECT p.oid, n.nspname, p.relname, 
            pg_catalog.pg_relation_filenode(p.oid) AS relfilenode, 
            p.reltablespace, pg_catalog.pg_tablespace_location(t.oid) AS 
            spclocation FROM pg_catalog.pg_class p INNER JOIN 
            pg_catalog.pg_namespace n ON (p.relnamespace = n.oid) LEFT OUTER 
            JOIN pg_catalog.pg_tablespace t ON (p.reltablespace = t.oid) WHERE 
            p.oid < 16384 AND p.relkind IN ('r', 'i', 't') AND
             p.relisshared= false AND p.relpersistence != 'u' ORDER BY 1;"""
        g_logger.debug("Get catalog info command: \n%s" % get_catalog_list_sql)
        for each_db in dbInfoDict["dblist"]:
            # template0 need handle specially, skip it here
            if each_db["dbname"] == 'template0':
                continue
            (status, output) = ClusterCommand.execSQLCommand(
                get_catalog_list_sql, g_opts.user, "", instance.port,
                each_db["dbname"], False, "-m", IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513[
                                    "GAUSS_51300"] % get_catalog_list_sql +
                                " Error:\n%s" % output)
            if output == "":
                raise Exception("can not find any catalog!!")
            g_logger.debug("Get catalog info result of %s: \n%s." % (
            each_db["dbname"], output))
            resList = output.split('\n')
            for each_line in resList:
                tmpCatalogInfo = initCatalogInfo()
                (oid, nspname, relname, relfilenode, reltablespace,
                 spclocation) = each_line.split('|')
                tmpCatalogInfo['oid'] = oid.strip()
                tmpCatalogInfo['relname'] = relname.strip()
                tmpCatalogInfo['relfilenode'] = relfilenode.strip()
                each_db["CatalogList"].append(tmpCatalogInfo)
                each_db["CatalogNum"] += 1

        # save db and catlog info into file
        instance_name = getInstanceName(instance)
        if instance.instanceRole == INSTANCE_ROLE_COODINATOR:
            # handle cn instance
            cn_db_and_catalog_info_file_name = \
                "%s/cn_db_and_catalog_info_%s.json" % (
                    backup_path, instance_name)
            DbInfoStr = json.dumps(dbInfoDict, indent=2)
            fp = open(cn_db_and_catalog_info_file_name, 'w')
            fp.write(DbInfoStr)
            fp.flush()
            fp.close()
        else:
            # handle master dn instance
            dn_db_and_catalog_info_file_name = \
                "%s/dn_db_and_catalog_info_%s.json" % (
                    backup_path, instance_name)
            DbInfoStr = json.dumps(dbInfoDict, indent=2)
            fp = open(dn_db_and_catalog_info_file_name, 'w')
            fp.write(DbInfoStr)
            fp.flush()
            fp.close()

            standbyInstLst = []
            peerInsts = g_clusterInfo.getPeerInstance(instance)
            for i in range(len(peerInsts)):
                if peerInsts[i].instanceType == DefaultValue.MASTER_INSTANCE\
                        or peerInsts[i].instanceType == \
                        DefaultValue.STANDBY_INSTANCE:
                    standbyInstLst.append(peerInsts[i])
            for standbyInstance in standbyInstLst:
                cmd = "pscp -H %s %s %s" % (
                standbyInstance.hostname, dn_db_and_catalog_info_file_name,
                dn_db_and_catalog_info_file_name)
                g_logger.debug("exec cmd is: %s" % cmd)
                (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514[
                                        "GAUSS_51400"] % cmd +
                                    "\nOutput:%s" % output)

    except Exception as e:
        raise Exception(str(e))

    g_logger.debug(
        "Successfully obtained instance catalog information. "
        "Instance data dir: %s" % instance.datadir)


def updateCatalog():
    """
    connect database and update catalog one by one
    1.get database list
    2.connect each database, and exec update sql/check sql
    """
    g_logger.log("Updating catalog.")
    try:
        update_catalog_maindb_sql = "{0}/{1}_catalog_maindb_tmp.sql".format(
            g_opts.upgrade_bak_path, g_opts.scriptType)
        update_catalog_otherdb_sql = "{0}/{1}_catalog_otherdb_tmp.sql".format(
            g_opts.upgrade_bak_path,
            g_opts.scriptType)
        check_upgrade_sql = ""
        if "upgrade" == g_opts.scriptType:
            check_upgrade_sql = "{0}/check_upgrade_tmp.sql".format(
                g_opts.upgrade_bak_path)
            if not os.path.isfile(check_upgrade_sql):
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50210"] % check_upgrade_sql)
        if not os.path.isfile(update_catalog_maindb_sql):
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50210"] % update_catalog_maindb_sql)
        if not os.path.isfile(update_catalog_otherdb_sql):
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50210"] % update_catalog_otherdb_sql)

        # get database list
        clusterNodes = g_clusterInfo.dbNodes
        for dbNode in clusterNodes:
            if len(dbNode.datanodes) == 0:
                continue
            dnInst = dbNode.datanodes[0]
            primaryDnNode, _ = DefaultValue.getPrimaryNode(g_opts.userProfile)
            if dnInst.hostname not in primaryDnNode:
                continue
            break
        reslines = get_database_list(dnInst)

        # connect each database, and exec update sql/check sql
        maindb = "postgres"
        otherdbs = reslines
        otherdbs.remove("postgres")
        # 1.handle maindb first
        upgrade_one_database([maindb, dnInst.port,
                              update_catalog_maindb_sql, check_upgrade_sql])

        # 2.handle otherdbs
        upgrade_info = []
        for eachdb in otherdbs:
            g_logger.debug("Updating catalog for database %s." % eachdb)
            upgrade_info.append([eachdb, dnInst.port,
                                 update_catalog_otherdb_sql, check_upgrade_sql])
        if len(upgrade_info) != 0:
            pool = ThreadPool(1)
            pool.map(upgrade_one_database, upgrade_info)
            pool.close()
            pool.join()

        g_logger.log("Successfully updated catalog.")
    except Exception as e:
        g_logger.logExit(str(e))


def get_database_list(dnInst):
    """
    get database list
    :return:
    """
    # get database list
    sqlSelect = "select datname from pg_database;"
    g_logger.debug("Command for getting database list: %s" % sqlSelect)
    (status, output) = ClusterCommand.execSQLCommand(
        sqlSelect, g_opts.user, "", dnInst.port, IsInplaceUpgrade=True)
    g_logger.debug("The result of database list: %s." % output)
    if 0 != status:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] %
                        sqlSelect + " Error:\n%s" % output)
    if "" == output:
        raise Exception(
            "No database objects were found in the cluster!")

    reslines = (output.strip()).split('\n')
    if (len(reslines) < 3
            or "template1" not in reslines
            or "template0" not in reslines
            or "postgres" not in reslines):
        raise Exception(
            "The database list is invalid:%s." % str(reslines))
    return reslines


def upgrade_one_database(upgrade_info):
    """
    upgrade catalog for one database
    """
    try:
        db_name = upgrade_info[0]
        port = upgrade_info[1]
        update_catalog_file = upgrade_info[2]
        check_upgrade_file = upgrade_info[3]

        g_logger.debug("Updating catalog for database %s" % db_name)
        execSQLFile(db_name, update_catalog_file, port)
        if "" != check_upgrade_file:
            execSQLFile(db_name, check_upgrade_file, port)
    except Exception as e:
        raise Exception(str(e))


def execSQLFile(dbname, sqlFile, cn_port):
    """
    exec sql file
    """
    gsql_cmd = ClusterCommand.getSQLCommandForInplaceUpgradeBackup(
        cn_port, dbname.replace('$', '\$'))
    cmd = "%s -X --echo-queries --set ON_ERROR_STOP=on -f %s" % (
        gsql_cmd, sqlFile)
    (status, output) = subprocess.getstatusoutput(cmd)
    g_logger.debug("Catalog modification log for database %s:\n%s." % (
        dbname, output))
    if status != 0 or ClusterCommand.findErrorInSqlFile(sqlFile, output):
        g_logger.debug(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
        raise Exception("Failed to update catalog. Error: %s" % str(output))


def backupOldClusterCatalogPhysicalFiles():
    """
    backup old cluster catalog physical files
    get database list
    connect to each cn and dn,
    connect to each database, and do backup
    """
    g_logger.log("Backing up old cluster catalog physical files.")
    try:
        InstanceList = []
        # find all instances need to do backup
        if len(g_dbNode.coordinators) != 0:
            InstanceList.append(g_dbNode.coordinators[0])
        if len(g_dbNode.datanodes) != 0:
            for eachInstance in g_dbNode.datanodes:
                InstanceList.append(eachInstance)

        # do backup parallelly
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(
                backupOneInstanceOldClusterCatalogPhysicalFiles, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug("No master instance found on this node,"
                           " nothing need to do.")
            return

        g_logger.log(
            "Successfully backed up old cluster catalog physical files.")
    except Exception as e:
        g_logger.logExit(str(e))


def backupOneInstanceOldClusterCatalogPhysicalFiles(instance):
    """
    backup catalog physical files for one old cluster instance
    read database and catalog info from file
    connect each database, do backup
    """
    g_logger.debug("Backup instance catalog physical files and xlog. "
                   "Instance data dir: %s" % instance.datadir)
    try:
        # backup list folder
        __backup_global_dir(instance)

        if instance.instanceRole == INSTANCE_ROLE_DATANODE and \
                instance.instanceType == DUMMY_STANDBY_INSTANCE:
            g_logger.debug("There is no need to backup catalog. "
                           "Instance data dir: %s" % instance.datadir)
            return
        __backup_xlog_file(instance)
        __backup_cbm_file(instance)
        __backup_base_folder(instance)
    except Exception as e:
        raise Exception(str(e))

    g_logger.debug(
        "Successfully backuped instance catalog physical files and xlog. "
        "Instance data dir: %s" % instance.datadir)


def __backup_global_dir(instance):
    """
    """
    g_logger.debug("Start to back up global_dir")
    try:
        backup_dir_list = const.BACKUP_DIR_LIST_BASE
        if float(g_opts.oldclusternum) < float(const.UPGRADE_VERSION_64bit_xid):
            backup_dir_list.extend(const.BACKUP_DIR_LIST_64BIT_XID)
        for name in backup_dir_list:
            srcDir = "%s/%s" % (instance.datadir, name)
            destDir = "%s_bak" % srcDir
            if os.path.isdir(srcDir):
                cpDirectory(srcDir, destDir)
        g_logger.debug("Successfully backed up global_dir")
    except Exception as e:
        raise Exception(str(e))


def __backup_xlog_file(instance):
    """
    """
    try:
        g_logger.debug("Backup instance xlog files. "
                       "Instance data dir: %s" % instance.datadir)

        # get Latest checkpoint location
        pg_xlog_info = __get_latest_checkpoint_location(instance)
        xlog_back_file = os.path.join(
            instance.datadir, "pg_xlog", pg_xlog_info.get(
                'latest_checkpoint_redo_xlog_file'))
        if not os.path.exists(xlog_back_file):
            raise Exception("There is no xlog to backup for %d."
                            % instance.instanceId)

        xlog_dir = os.path.join(instance.datadir, "pg_xlog")
        xlog_file_list = os.listdir(xlog_dir)
        xlog_file_list.sort()

        backup_xlog_list = []
        for one_file in xlog_file_list:
            if not os.path.isfile(os.path.join(xlog_dir, one_file)):
                continue
            if len(one_file) != 24:
                continue
            if one_file >= pg_xlog_info.get('latest_checkpoint_redo_xlog_file'):
                backup_xlog_list.append(one_file)

        if len(backup_xlog_list) == 0:
            raise Exception("There is no xlog to backup for %d." %
                            instance.instanceId)

        for one_file in backup_xlog_list:
            src_file = os.path.join(xlog_dir, one_file)
            dst_file = os.path.join(xlog_dir, one_file + "_upgrade_backup")
            shutil.copy2(src_file, dst_file)
            g_logger.debug("file {0} has been backed up to {1}".format(
                src_file, dst_file))

        xlog_backup_info = copy.deepcopy(pg_xlog_info)
        xlog_backup_info['backup_xlog_list'] = backup_xlog_list
        xlog_backup_info_target_file = os.path.join(xlog_dir,
                                                    const.XLOG_BACKUP_INFO)
        g_file.createFileInSafeMode(xlog_backup_info_target_file)
        with open(xlog_backup_info_target_file, "w") as fp:
            json.dump(xlog_backup_info, fp)

        g_logger.debug("XLOG backup info:%s." % xlog_backup_info)
        g_logger.debug("Successfully backuped instance xlog files. "
                       "Instance data dir: %s" % instance.datadir)
    except Exception as e:
        raise Exception(str(e))


def __get_latest_checkpoint_location(instance):
    try:
        result = dict()
        cmd = "pg_controldata '%s'" % instance.datadir
        if g_opts.mpprcFile != "" and g_opts.mpprcFile is not None:
            cmd = "source %s; %s" % (g_opts.mpprcFile, cmd)
        (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
        g_logger.debug("Command for get control data:%s.Output:\n%s." % (
            cmd, output))
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "\nOutput:%s" % output)
        time_line_id = ""
        latest_checkpoint_redo_location = ""
        for one_line in output.split('\n'):
            one_line = one_line.strip()
            if len(one_line.split(':')) == 2:
                if one_line.split(':')[0].strip() == \
                        "Latest checkpoint's TimeLineID":
                    time_line_id = one_line.split(':')[1].strip()
                elif one_line.split(':')[0].strip() == \
                        "Latest checkpoint's REDO location":
                    latest_checkpoint_redo_location = \
                        one_line.split(':')[1].strip()
            if time_line_id != "" and latest_checkpoint_redo_location != "":
                break
        if time_line_id == "":
            raise Exception(
                "Failed to get Latest checkpoint's TimeLineID for %d." %
                instance.instanceId)
        if latest_checkpoint_redo_location == "":
            raise Exception("Failed to get Latest checkpoint' "
                            "REDO location for %d." % instance.instanceId)
        redo_log_id = latest_checkpoint_redo_location.split('/')[0]
        redo_tmp_log_seg = latest_checkpoint_redo_location.split('/')[1]
        if len(redo_tmp_log_seg) > 6:
            redo_log_seg = redo_tmp_log_seg[0:-6]
        else:
            redo_log_seg = 0
        latest_checkpoint_redo_xlog_file = \
            "%08d%s%s" % (int(time_line_id, 16),
                          str(redo_log_id).zfill(8), str(redo_log_seg).zfill(8))
        result['latest_checkpoint_redo_location'] = \
            latest_checkpoint_redo_location
        result['time_line_id'] = time_line_id
        result['latest_checkpoint_redo_xlog_file'] = \
            latest_checkpoint_redo_xlog_file
        g_logger.debug("%d(pg_xlog_info):%s." % (instance.instanceId, result))
        return result
    except Exception as e:
        raise Exception(str(e))


def __backup_cbm_file(instance):
    """
    """
    try:
        g_logger.debug("Backup instance cbm files. "
                       "Instance data dir: %s" % instance.datadir)
        cbm_back_dir = os.path.join(instance.datadir, "pg_cbm_back")
        cmd = "rm -rf '%s' " % cbm_back_dir
        (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "\nOutput:%s" % output)

        cbm_dir = os.path.join(instance.datadir, "pg_cbm")
        if not os.path.exists(cbm_dir):
            g_logger.debug("There is no cbm dir to backup for %d."
                           % instance.instanceId)
            return

        cpDirectory(cbm_dir, cbm_back_dir)
        g_logger.debug("Successfully backuped instance cbm files. "
                       "Instance data dir: %s" % instance.datadir)
    except Exception as e:
        raise Exception(str(e))


def restoreOldClusterCatalogPhysicalFiles():
    """
    restore old cluster catalog physical files
    get database list
    connect to each cn and dn,
    connect to each database, and do backup
    """
    g_logger.log("Restoring old cluster catalog physical files.")
    try:
        InstanceList = []
        # find all instances need to do restore
        if len(g_dbNode.datanodes) != 0:
            for eachInstance in g_dbNode.datanodes:
                InstanceList.append(eachInstance)

        # do restore parallelly
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(
                restoreOneInstanceOldClusterCatalogPhysicalFiles, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug("No master instance found on this node, "
                           "nothing need to do.")
            return

        g_logger.log(
            "Successfully restored old cluster catalog physical files.")
    except Exception as e:
        g_logger.logExit(str(e))


def restoreOneInstanceOldClusterCatalogPhysicalFiles(instance):
    """
    restore catalog physical files for one old cluster instance
    read database and catalog info from file
    connect each database, do restore
    """
    g_logger.debug("Restore instance catalog physical files. "
                   "Instance data dir: %s" % instance.datadir)
    try:
        # handle dummy standby dn instance first
        if instance.instanceRole == INSTANCE_ROLE_DATANODE and \
                instance.instanceType == DUMMY_STANDBY_INSTANCE:
            # clean pg_xlog folder of dummy standby dn instance and return
            pg_xlog_dir = "%s/pg_xlog" % instance.datadir
            cmd = "find '%s' -type f | xargs -r -n 100 rm -f" % pg_xlog_dir
            DefaultValue.execCommandLocally(cmd)

            # restore list folder
            __restore_global_dir(instance)
            return

        __restore_global_dir(instance)
        __restore_xlog_file(instance)
        __restore_cbm_file(instance)
        __restore_base_folder(instance)
    except Exception as e:
        raise Exception(str(e))

    g_logger.debug("Successfully restored instance catalog physical files. "
                   "Instance data dir: %s" % instance.datadir)


def __restore_global_dir(instance):
    """
    """
    try:
        g_logger.debug("Start to restore global_dir")
        backup_dir_list = const.BACKUP_DIR_LIST_BASE + const.BACKUP_DIR_LIST_64BIT_XID
        for name in backup_dir_list:
            srcDir = "%s/%s" % (instance.datadir, name)
            destDir = "%s/%s_bak" % (instance.datadir, name)
            if os.path.isdir(destDir):
                cpDirectory(destDir, srcDir)
        g_logger.debug("Successfully restored global_dir")
    except Exception as e:
        raise Exception(str(e))


def __restore_xlog_file(instance):
    """
    """
    try:
        g_logger.debug("Restore instance xlog files. "
                       "Instance data dir: %s" % instance.datadir)

        # read xlog_backup_info
        xlog_backup_info_file = os.path.join(instance.datadir,
                                             "pg_xlog", const.XLOG_BACKUP_INFO)
        if not os.path.exists(xlog_backup_info_file):
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50201"] % xlog_backup_info_file)

        with open(xlog_backup_info_file, "r") as fp:
            xlog_backup_info_str = fp.read()
        xlog_backup_info = json.loads(xlog_backup_info_str)

        # clean new xlog after latest_checkpoint_xlog_file
        xlog_dir = os.path.join(instance.datadir, "pg_xlog")
        xlog_list = os.listdir(xlog_dir)
        xlog_list.sort()

        for one_file in xlog_list:
            xlog_path = os.path.join(xlog_dir, one_file)
            if len(one_file) == 24 and one_file >= xlog_backup_info[
                'latest_checkpoint_redo_xlog_file'] and \
                    os.path.isfile(xlog_path):
                g_logger.debug("%s:Removing %s." % (
                    instance.instanceId, xlog_path))
                os.remove(xlog_path)

        # restore old xlog file
        for one_file in xlog_backup_info['backup_xlog_list']:
            src_file = os.path.join(xlog_dir, one_file + "_upgrade_backup")
            dst_file = os.path.join(xlog_dir, one_file)
            if os.path.exists(src_file):
                g_logger.debug("%s:Restoring %s." % (
                    instance.instanceId, dst_file))
                shutil.copy2(src_file, dst_file)
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % src_file)

        g_logger.debug("Successfully restore instance xlog files. "
                       "Instance data dir: {0}".format(instance.datadir))
    except Exception as e:
        raise Exception(str(e))


def __restore_cbm_file(instance):
    """
     """
    try:
        g_logger.debug("restore instance cbm files. "
                       "Instance data dir: %s" % instance.datadir)
        cbm_dir = os.path.join(instance.datadir, "pg_cbm")
        cmd = "rm -rf '%s' " % cbm_dir
        (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "\nOutput:%s" % output)

        cbm_back_dir = os.path.join(instance.datadir, "pg_cbm_back")
        if not os.path.exists(cbm_back_dir):
            g_logger.debug("There is no cbm dir to restore for %d." %
                           instance.instanceId)
            return
        cpDirectory(cbm_back_dir, cbm_dir)
        g_logger.debug("Successfully restored instance cbm files. "
                       "Instance data dir: %s" % instance.datadir)
    except Exception as e:
        raise Exception(str(e))


def cleanOldClusterCatalogPhysicalFiles():
    """
    clean old cluster catalog physical files
    get database list
    connect to each cn and dn,
    connect to each database, and do backup
    """
    g_logger.log("Cleaning old cluster catalog physical files.")
    try:
        # kill any pending processes that are
        # copying backup catalog physical files
        killCmd = DefaultValue.killInstProcessCmd(
            "backup_old_cluster_catalog_physical_files")
        (status, output) = subprocess.getstatusoutput(killCmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % killCmd +
                            "\nOutput:%s" % output)

        InstanceList = []
        # find all instances need to do clean
        if len(g_dbNode.datanodes) != 0:
            for eachInstance in g_dbNode.datanodes:
                InstanceList.append(eachInstance)

        # do clean parallelly
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(
                cleanOneInstanceOldClusterCatalogPhysicalFiles, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug("No master instance found on this node, "
                           "nothing need to do.")
            return

        g_logger.log("Successfully cleaned old cluster catalog physical files.")
    except Exception as e:
        g_logger.logExit(str(e))


def cleanOneInstanceOldClusterCatalogPhysicalFiles(instance):
    """
    clean catalog physical files for one old cluster instance
    read database and catalog info from file
    connect each database, do restore
    """
    g_logger.debug("clean up instance catalog backup. "
                   "Instance data dir: %s" % instance.datadir)
    try:
        __clean_global_dir(instance)

        if g_opts.rollback:
            pg_csnlog_dir = os.path.join(instance.datadir, "pg_csnlog")
            # when do rollback, if old cluster num less than
            # UPGRADE_VERSION_64bit_xid, remove the pg_csnlog directory
            if float(g_opts.oldclusternum) < float(
                    const.UPGRADE_VERSION_64bit_xid) and \
                    os.path.isdir(pg_csnlog_dir):
                g_file.removeDirectory(pg_csnlog_dir)
        else:
            pg_subtrans_dir = os.path.join(instance.datadir, "pg_subtrans")
            # when do commit, remove the pg_subtrans directory
            if os.path.isdir(pg_subtrans_dir):
                g_file.removeDirectory(pg_subtrans_dir)

        if instance.instanceRole == INSTANCE_ROLE_DATANODE and \
                instance.instanceType == DUMMY_STANDBY_INSTANCE:
            g_logger.debug("There is no need to clean catalog. "
                           "Instance data dir: %s" % instance.datadir)
            return

        __clean_xlog_file(instance)
        __clean_cbm_file(instance)
        __clean_base_folder(instance)
    except Exception as e:
        raise Exception(str(e))

    g_logger.debug("Successfully cleaned up instance catalog backup. "
                   "Instance data dir: %s" % instance.datadir)


def __clean_global_dir(instance):
    """
    """
    # clean pg_internal.init*
    g_logger.debug("Start to clean global_dir")
    cmd = "rm -f %s/global/pg_internal.init*" % instance.datadir
    DefaultValue.execCommandLocally(cmd)

    backup_dir_list = const.BACKUP_DIR_LIST_BASE + const.BACKUP_DIR_LIST_64BIT_XID
    for name in backup_dir_list:
        backup_dir = "%s/%s" % (instance.datadir, name)
        cleanBackUpDir(backup_dir)
    g_logger.debug("Successfully cleaned global_dir")


def __clean_xlog_file(instance):
    """
    """
    # clean *.upgrade_backup files
    cmd = "rm -f '%s'/pg_xlog/*_upgrade_backup && rm -f '%s'/pg_xlog/%s" % \
          (instance.datadir, instance.datadir, const.XLOG_BACKUP_INFO)
    DefaultValue.execCommandLocally(cmd)
    g_logger.debug("Successfully clean instance xlog files. "
                   "Instance data dir: {0}".format(instance.datadir))


def __clean_cbm_file(instance):
    """
    """
    # clean pg_cbm_back files
    cbm_back_dir = os.path.join(instance.datadir, "pg_cbm_back")
    cmd = "rm -rf '%s' " % cbm_back_dir
    (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
    if status != 0:
        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                        "\nOutput:%s" % output)
    g_logger.debug("Successfully clean instance cbm files. "
                   "Instance data dir: {0}".format(instance.datadir))


def __clean_base_folder(instance):
    """
    """
    g_logger.debug("Clean instance base folders. "
                   "Instance data dir: {0}".format(instance.datadir))
    backup_path = os.path.join(g_opts.upgrade_bak_path, "oldClusterDBAndRel")
    # get instance name
    instance_name = getInstanceName(instance)
    # load db and catalog info from json file
    if instance.instanceRole == INSTANCE_ROLE_COODINATOR:
        db_and_catalog_info_file_name = \
            "%s/cn_db_and_catalog_info_%s.json" % (backup_path, instance_name)
    elif instance.instanceRole == INSTANCE_ROLE_DATANODE:
        if instance.instanceType == MASTER_INSTANCE or \
                instance.instanceType == STANDBY_INSTANCE:
            db_and_catalog_info_file_name = \
                "%s/dn_db_and_catalog_info_%s.json" % (
                    backup_path, instance_name)
        else:
            raise Exception("Invalid instance type:%s" % instance.instanceType)
    else:
        raise Exception("Invalid instance role:%s" % instance.instanceRole)
    with open(db_and_catalog_info_file_name, 'r') as fp:
        dbInfoStr = fp.read()
    try:
        dbInfoDict = json.loads(dbInfoStr)
    except Exception as ee:
        raise Exception(str(ee))

    # clean base folder
    for each_db in dbInfoDict["dblist"]:
        if each_db["spclocation"] != "":
            if each_db["spclocation"].startswith('/'):
                tbsBaseDir = each_db["spclocation"]
            else:
                tbsBaseDir = "%s/pg_location/%s" % (
                    instance.datadir, each_db["spclocation"])
            pg_catalog_base_dir = "%s/%s_%s/%d" % (
                tbsBaseDir,
                DefaultValue.TABLESPACE_VERSION_DIRECTORY,
                instance_name,
                int(each_db["dboid"]))
        else:
            pg_catalog_base_dir = "%s/base/%d" % (
                instance.datadir, int(each_db["dboid"]))

        # for base folder, template0 need handle specially
        if each_db["dbname"] == 'template0':
            cmd = "rm -rf '%s_bak' && rm -f %s/pg_internal.init*" % \
                  (pg_catalog_base_dir, pg_catalog_base_dir)
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "\nOutput:%s" % output)
            g_logger.debug("{0} has been cleaned".format(pg_catalog_base_dir))
            continue

        # main/vm/fsm  -- main.1 ..
        # can not add '' for this cmd
        cmd = "rm -f %s/*_bak && rm -f %s/pg_internal.init*" % (
            pg_catalog_base_dir, pg_catalog_base_dir)
        g_logger.debug("{0} needs to be cleaned".format(pg_catalog_base_dir))
        (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "\nOutput:%s" % output)
    g_logger.debug("Successfully clean instance base folders. "
                   "Instance data dir: {0}".format(instance.datadir))


def replacePgprocFile():
    """
    function: replace pg_proc data file by pg_proc_temp data file
    input: NA
    output: NA
    """
    g_logger.log("Replace pg_proc file.")
    try:
        InstanceList = []
        # find all DB instances need to replace pg_proc
        if len(g_dbNode.datanodes) != 0:
            for eachInstance in g_dbNode.datanodes:
                if (eachInstance.instanceType == MASTER_INSTANCE
                        or eachInstance.instanceType == STANDBY_INSTANCE):
                    InstanceList.append(eachInstance)

        # replace each instance pg_proc
        if len(InstanceList) != 0:
            pool = ThreadPool(len(InstanceList))
            pool.map(replaceOneInstancePgprocFile, InstanceList)
            pool.close()
            pool.join()
        else:
            g_logger.debug(
                "No instance found on this node, nothing need to do.")
            return

        g_logger.log(
            "Successfully replaced all instances pg_proc file on this node.")
    except Exception as e:
        g_logger.logExit(str(e))


def replaceOneInstancePgprocFile(instance):
    """
    function: touch upgrade init file for this instance
    input: NA
    output: NA
    """
    g_logger.debug("Replace instance pg_proc file. "
                   "Instance data dir: %s" % instance.datadir)
    pg_proc_mapping_file = os.path.join(g_opts.appPath,
                                        'pg_proc_mapping.txt')
    with open(pg_proc_mapping_file, 'r') as fp:
        pg_proc_dict_str = fp.read()
    proc_dict = eval(pg_proc_dict_str)
    try:
        # replace pg_proc data file with pg_proc_temp data file
        for proc_file_path, pg_proc_temp_file_path in proc_dict.items():
            pg_proc_data_file = \
                os.path.join(instance.datadir, proc_file_path)
            if not os.path.exists(pg_proc_data_file):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                pg_proc_data_file)
            pg_proc_temp_data_file = os.path.join(
                instance.datadir, pg_proc_temp_file_path)
            if not os.path.exists(pg_proc_temp_data_file):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                    pg_proc_temp_data_file)
            g_file.removeFile(pg_proc_data_file)
            g_file.cpFile(pg_proc_temp_data_file, pg_proc_data_file)

    except Exception as e:
        raise Exception(str(e))

    g_logger.debug(
        "Successfully replaced instance pg_proc file. Instance data dir: %s"
        % instance.datadir)


def createPgprocPathMappingFile():
    """
    create pg_proc and pg_proc_temp_oids data file path mapping
    :return:
    """
    g_logger.log("Create file to save mapping between pg_proc file path and"
                 " pg_proc_temp_oids file path.")
    clusterNodes = g_clusterInfo.dbNodes
    dnInst = None
    for dbNode in clusterNodes:
        if len(dbNode.datanodes) == 0:
            continue
        dnInst = dbNode.datanodes[0]
        primaryDnNode, _ = DefaultValue.getPrimaryNode(g_opts.userProfile)
        if dnInst.hostname not in primaryDnNode:
            continue
        break
    database_list = get_database_list(dnInst)
    pg_proc_list = ['pg_proc', 'pg_proc_oid_index',
                    'pg_proc_proname_args_nsp_index']
    pg_proc_temp_list = ['pg_proc_temp_oids', 'pg_proc_oid_index_temp',
                         'pg_proc_proname_args_nsp_index_temp']
    proc_file_path_list = []
    pg_proc_temp_file_path_list = []
    for eachdb in database_list:
        for info in pg_proc_list:
            pg_proc_file_path = getTableFilePath(info, dnInst, eachdb)
            proc_file_path_list.append(pg_proc_file_path)
        for temp_info in pg_proc_temp_list:
            pg_proc_temp_file_path = getTableFilePath(temp_info, dnInst, eachdb)
            pg_proc_temp_file_path_list.append(pg_proc_temp_file_path)
    proc_dict = dict((proc_file_path, pg_proc_temp_file_path) for
                     proc_file_path, pg_proc_temp_file_path in
                     zip(proc_file_path_list, pg_proc_temp_file_path_list))
    pg_proc_mapping_file = os.path.join(g_opts.appPath, 'pg_proc_mapping.txt')
    with open(pg_proc_mapping_file, 'w') as fp:
        fp.write(str(proc_dict))
    g_logger.log(
        "Successfully created file to save mapping between pg_proc file path"
        " and pg_proc_temp_oids file path.")


def getTableFilePath(tablename, dnInst, db_name):
    """
     get table file path by oid
    :return:
    """
    sql = "select oid from pg_class where relname='%s';" % tablename
    (status, output) = ClusterCommand.remoteSQLCommand(
        sql, g_opts.user,
        dnInst.hostname,
        dnInst.port, False,
        db_name,
        IsInplaceUpgrade=True)
    if status != 0:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                        " Error: \n%s" % str(output))
    table_oid = output.strip('\n')
    g_logger.debug("pg_proc oid is %s" % table_oid)
    sql = "select pg_relation_filepath(%s);" % table_oid
    (status, output) = ClusterCommand.remoteSQLCommand(
        sql, g_opts.user,
        dnInst.hostname,
        dnInst.port, False,
        db_name,
        IsInplaceUpgrade=True)
    if status != 0:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                        " Error: \n%s" % str(output))
    table_file_path = output.strip('\n')
    g_logger.debug("pg_proc file path is %s" % table_file_path)
    return table_file_path


def createNewCsvFile():
    """
    1. copy pg_proc info to csv file
    2. modify csv file
    3. create new table and get info by csv file
    :return:
    """
    g_logger.log("Create new csv file.")
    clusterNodes = g_clusterInfo.dbNodes
    dnInst = None
    for dbNode in clusterNodes:
        if len(dbNode.datanodes) == 0:
            continue
        dnInst = dbNode.datanodes[0]
        primaryDnNode, _ = DefaultValue.getPrimaryNode(g_opts.userProfile)
        if dnInst.hostname not in primaryDnNode:
            continue
        break
    dndir = dnInst.datadir
    pg_proc_csv_path = '%s/pg_copydir/tbl_pg_proc_oids.csv' % dndir
    new_pg_proc_csv_path = '%s/pg_copydir/new_tbl_pg_proc_oids.csv' % dndir
    sql = \
        """copy pg_proc( proname, pronamespace, proowner, prolang, 
        procost, prorows, provariadic, protransform, prosecdef, 
        proleakproof, proisstrict, proretset, provolatile, pronargs, 
        pronargdefaults, prorettype, proargtypes, proallargtypes, 
        proargmodes, proargnames, proargdefaults, prosrc, probin, 
        proconfig, proacl, prodefaultargpos, fencedmode, proshippable, 
        propackage,prokind) WITH OIDS to '%s' delimiter ',' 
        csv header;""" % pg_proc_csv_path
    (status, output) = ClusterCommand.remoteSQLCommand(
        sql, g_opts.user,
        dnInst.hostname, dnInst.port, False,
        DefaultValue.DEFAULT_DB_NAME, IsInplaceUpgrade=True)
    if status != 0:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                        " Error: \n%s" % str(output))
    pg_proc_csv_reader = csv.reader(open(pg_proc_csv_path, 'r'))
    pg_proc_csv_data = list(pg_proc_csv_reader)
    header = pg_proc_csv_data[0]
    header.insert(header.index('protransform') + 1, 'proisagg')
    header.insert(header.index('protransform') + 2, 'proiswindow')
    new_pg_proc_csv_data = []
    new_pg_proc_csv_data.append(header)
    pg_proc_data_info = pg_proc_csv_data[1:]
    for i in range(2):
        for info in pg_proc_data_info:
            info.insert(header.index('protransform') + 2, 'True')
    for info in pg_proc_data_info:
        new_pg_proc_csv_data.append(info)
    f = open(new_pg_proc_csv_path, 'w')
    new_pg_proc_csv_writer = csv.writer(f)
    for info in new_pg_proc_csv_data:
        new_pg_proc_csv_writer.writerow(info)
    f.close()
    # scp csv file to other nodes
    standbyInstLst = []
    peerInsts = g_clusterInfo.getPeerInstance(dnInst)
    for i in range(len(peerInsts)):
        if peerInsts[i].instanceType == DefaultValue.MASTER_INSTANCE \
                or peerInsts[i].instanceType == \
                DefaultValue.STANDBY_INSTANCE:
            standbyInstLst.append(peerInsts[i])
    for standbyInstance in standbyInstLst:
        standbyCsvFilePath = \
            '%s/pg_copydir/new_tbl_pg_proc_oids.csv' % standbyInstance.datadir
        cmd = "pscp -H %s %s %s" % (
            standbyInstance.hostname, new_pg_proc_csv_path,
            standbyCsvFilePath)
        g_logger.debug("exec cmd is: %s" % cmd)
        (status, output) = DefaultValue.retryGetstatusoutput(cmd, 2, 5)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514[
                                "GAUSS_51400"] % cmd +
                            "\nOutput:%s" % output)


def checkAction():
    """
    function: check action
    input  : NA
    output : NA
    """
    if g_opts.action not in \
            [const.ACTION_TOUCH_INIT_FILE,
             const.ACTION_UPDATE_CATALOG,
             const.ACTION_BACKUP_OLD_CLUSTER_DB_AND_REL,
             const.ACTION_SYNC_CONFIG,
             const.ACTION_BACKUP_CONFIG,
             const.ACTION_RESTORE_CONFIG,
             const.ACTION_INPLACE_BACKUP,
             const.ACTION_INPLACE_RESTORE,
             const.ACTION_CHECK_GUC,
             const.ACTION_BACKUP_HOTPATCH,
             const.ACTION_ROLLBACK_HOTPATCH,
             const.ACTION_SWITCH_PROCESS,
             const.ACTION_SWITCH_BIN,
             const.ACTION_CLEAN_INSTALL_PATH,
             const.ACTION_COPY_CERTS,
             const.ACTION_UPGRADE_SQL_FOLDER,
             const.ACTION_BACKUP_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
             const.ACTION_RESTORE_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
             const.ACTION_CLEAN_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
             const.ACTION_REPLACE_PG_PROC_FILES,
             const.ACTION_CREATE_PG_PROC_MAPPING_FILE,
             const.ACTION_CREATE_NEW_CSV_FILE]:
        GaussLog.exitWithError(
            ErrorCode.GAUSS_500["GAUSS_50004"] % 't'
            + " Value: %s" % g_opts.action)


def main():
    """
    function: main function
    """
    try:
        global g_opts
        g_opts = CmdOptions()
        parseCommandLine()
        checkParameter()
        initGlobals()
    except Exception as e:
        GaussLog.exitWithError(str(e) + traceback.format_exc())
    try:
        # select the object's function by type
        funcs = {
            const.ACTION_SWITCH_BIN: switchBin,
            const.ACTION_CLEAN_INSTALL_PATH: cleanInstallPath,
            const.ACTION_TOUCH_INIT_FILE: touchInstanceInitFile,
            const.ACTION_SYNC_CONFIG: syncClusterConfig,
            const.ACTION_BACKUP_CONFIG: backupConfig,
            const.ACTION_RESTORE_CONFIG: restoreConfig,
            const.ACTION_INPLACE_BACKUP: inplaceBackup,
            const.ACTION_INPLACE_RESTORE: inplaceRestore,
            const.ACTION_CHECK_GUC: checkGucValue,
            const.ACTION_BACKUP_HOTPATCH: backupHotpatch,
            const.ACTION_ROLLBACK_HOTPATCH: rollbackHotpatch,
            const.ACTION_COPY_CERTS: copyCerts,
            const.ACTION_UPGRADE_SQL_FOLDER: prepareUpgradeSqlFolder,
            const.ACTION_BACKUP_OLD_CLUSTER_DB_AND_REL:
                backupOldClusterDBAndRel,
            const.ACTION_UPDATE_CATALOG: updateCatalog,
            const.ACTION_BACKUP_OLD_CLUSTER_CATALOG_PHYSICAL_FILES:
                backupOldClusterCatalogPhysicalFiles,
            const.ACTION_RESTORE_OLD_CLUSTER_CATALOG_PHYSICAL_FILES:
                restoreOldClusterCatalogPhysicalFiles,
            const.ACTION_CLEAN_OLD_CLUSTER_CATALOG_PHYSICAL_FILES:
                cleanOldClusterCatalogPhysicalFiles,
            const.ACTION_REPLACE_PG_PROC_FILES: replacePgprocFile,
            const.ACTION_CREATE_PG_PROC_MAPPING_FILE:
                createPgprocPathMappingFile,
            const.ACTION_CREATE_NEW_CSV_FILE: createNewCsvFile,
            const.ACTION_RESTORE_DYNAMIC_CONFIG_FILE: restoreDynamicConfigFile}
        func = funcs[g_opts.action]
        func()
    except Exception as e:
        checkAction()
        g_logger.debug(traceback.format_exc())
        g_logger.logExit(str(e))

if __name__ == '__main__':
    main()
