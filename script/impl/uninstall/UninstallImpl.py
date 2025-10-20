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
import sys
import subprocess
import time
import os

sys.path.append(sys.path[0] + "/../")

from gspylib.common.Common import DefaultValue, ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.os.gsfile import g_file
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.cmd_util import CmdUtil
from gspylib.common.DbClusterInfo import dbNodeInfo, \
    dbClusterInfo, compareObject
from domain_utils.cluster_file.profile_file import ProfileFile


class UninstallImpl:
    """
    init the command options
    save command line parameter values
    """

    def __init__(self, unstallation):
        """
        function: constructor
        """
        self.logFile = unstallation.logFile
        self.cleanInstance = unstallation.cleanInstance
        self.clearDisk = unstallation.clearDisk

        self.localLog = unstallation.localLog
        self.user = unstallation.user
        self.group = unstallation.group
        self.mpprcFile = unstallation.mpprcFile
        self.localMode = unstallation.localMode
        self.logger = unstallation.logger
        self.sshTool = unstallation.sshTool
        self.isSingle = unstallation.isSingle
        self.tmpDir = EnvUtil.getTmpDirFromEnv(self.user)
        try:
            # Initialize the unstallation.clusterInfo variable
            unstallation.initClusterInfoFromStaticFile(self.user)
            self.clusterInfo = unstallation.clusterInfo
            nodeNames = self.clusterInfo.getClusterNodeNames()
            # Initialize the self.sshTool variable
            unstallation.initSshTool(nodeNames,
                                     DefaultValue.TIMEOUT_PSSH_UNINSTALL)
            self.sshTool = unstallation.sshTool
        except Exception as e:
            self.logger.logExit(str(e))

    def checkLogFilePath(self):
        """
        function: Check log file path
        input : NA
        output: NA
        """
        clusterPath = []
        try:
            # get tool path
            clusterPath.append(ClusterDir.getClusterToolPath(self.user))
            # get tmp path
            tmpDir = EnvUtil.getTmpDirFromEnv()
            clusterPath.append(tmpDir)
            # get cluster path
            hostName = NetUtil.GetHostIpOrName()
            dirs = self.clusterInfo.getClusterDirectorys(hostName, False)
            # loop all cluster path
            for checkdir in dirs.values():
                clusterPath.extend(checkdir)
            self.logger.debug("Cluster paths %s." % clusterPath)

            # check directory
            FileUtil.checkIsInDirectory(self.logFile, clusterPath)
        except Exception as e:
            self.logger.logExit(str(e))

    def checkUninstall(self):
        """
        function: Check uninstall
        input : NA
        output: NA
        """
        # Checking uninstallation
        self.logger.log("Checking uninstallation.", "addStep")
        # use check uninstall to check every nodes
        cmd = "%s -R '%s' -U %s -l %s" % (
            OMCommand.getLocalScript("Local_Check_Uninstall"),
            self.clusterInfo.appPath, self.user, self.localLog)
        # check if need to clean instance
        if (self.cleanInstance):
            cmd += " -d"
        self.logger.debug("Command for checking uninstallation: " + cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode or self.isSingle,
                                        self.mpprcFile)
        self.logger.log("Successfully checked uninstallation.", "constant")

    def cm_stop_cluster(self):
        """
        Stop cluster with CM
        """
        # get stop command, if node_id is not zero, then only stop local node
        node_id = 0
        cmd = ClusterCommand.getStopCmd(node_id, "i")
        if self.localMode:
            local_node_list = [node for node in self.clusterInfo.dbNodes
                               if node.name == NetUtil.GetHostIpOrName()]
            if not local_node_list:
                self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51610"] % "the cluster" +
                                    " Error:\nLocal node is not in the static file.")
            cmd = ClusterCommand.getStopCmd(local_node_list[0].id, "i")
        (status, output) = subprocess.getstatusoutput(cmd)
        # if do command fail, throw error
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51610"] % "the cluster" +
                                " Error:\n%s" % output)
        if self.localMode:
            self.logger.log("Successfully stopped local node.", "constant")
        else:
            self.logger.log("Successfully stopped the cluster.", "constant")

        # check and kill all processes about
        # clean cm_agent,cm_server,gs_gtm,gaussdb(CN/DN) and etcd.
        self.logger.debug("Checking and killing processes.", "addStep")
        # local mode, kill all process in local node
        if self.localMode:
            for prog_name in ["cm_agent", "cm_server", "gaussdb",
                              "CheckDataDiskUsage"]:
                DefaultValue.KillAllProcess(self.user, prog_name)
        # kill process in all nodes
        else:
            cm_agent_file = "%s/bin/cm_agent" % self.clusterInfo.appPath
            cm_server_file = "%s/bin/cm_server" % self.clusterInfo.appPath
            gaussdb_file = "%s/bin/gaussdb" % self.clusterInfo.appPath
            check_file = "CheckDataDiskUsage"
            for prog_name in [cm_agent_file, cm_server_file, gaussdb_file,
                              check_file]:
                self.CheckAndKillAliveProc(prog_name)
        self.logger.debug("Successfully checked and killed processes.", "constant")

    def StopCluster(self):
        """
        function: Stopping the cluster
        input : NA
        output: NA
        """
        self.logger.log("Stopping the cluster.", "addStep")
        # get the static config
        static_config = \
            "%s/bin/cluster_static_config" % self.clusterInfo.appPath
        static_config_bak = \
            "%s/bin/cluster_static_config_bak" % self.clusterInfo.appPath
        # if cluster_static_config_bak exists
        # and static_config does not exists, mv it to static_config
        if (not os.path.exists(static_config) and os.path.exists(
                static_config_bak)):
            cmd_list = ['mv', static_config_bak, static_config]
            (output, error, status) = CmdUtil.execCmdList(cmd_list)
            if (status != 0):
                self.logger.debug("The cmd is %s " % ' '.join())
                self.logger.error("rename cluster_static_config_bak failed")
                self.logger.debug("Error:\n%s" % output)
        # if path not exits, can not stop cluster
        if not os.path.exists(static_config):
            self.logger.debug("Failed to stop the cluster.", "constant")
            return
        if DefaultValue.get_cm_server_num_from_static(self.clusterInfo) == 0:
            # Stop cluster applications
            cmd = "source %s; %s -U %s -R %s -l %s" % (
                self.mpprcFile, OMCommand.getLocalScript("Local_StopInstance"),
                self.user, self.clusterInfo.appPath, self.localLog)
            self.logger.debug("Command for stop cluster: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd, self.sshTool,
                                            self.localMode or self.isSingle, self.mpprcFile)
            self.logger.log("Successfully stopped the cluster.")
        else:
            self.cm_stop_cluster()

    def CheckAndKillAliveProc(self, procFileName):
        """
        function: When uninstall gaussdb cluster. After it is stopped,
                  We must make sure that all process
                  about gaussdb cluster have been stopped. Not including
                  om_monitor.
        input : procFileName
        output: NA
        """
        try:
            failedNodes = []
            validNodeName = self.clusterInfo.getClusterNodeNames()
            # the command for killing all process
            cmd_check_kill = DefaultValue.killInstProcessCmd(procFileName,
                                                             True, 9, False)
            # use sshTool to kill process in all nodes
            (status, output) = self.sshTool.getSshStatusOutput(cmd_check_kill,
                                                               validNodeName)
            # get the node which not be killed
            for node in validNodeName:
                if (status[node] != DefaultValue.SUCCESS):
                    failedNodes.append(node)
            # kill process in nodes again
            if (len(failedNodes)):
                time.sleep(1)
                (status, output) = self.sshTool.getSshStatusOutput(
                    cmd_check_kill, failedNodes)
                for node in failedNodes:
                    # if still fail, throw error
                    if (status[node] != DefaultValue.SUCCESS):
                        raise Exception(output)

        except Exception as e:
            raise Exception(str(e))

    def CleanInstance(self):
        """
        function: clean instance
        input  : NA
        output : NA
        """
        self.logger.debug("Deleting instance.", "addStep")
        # check if need delete instance
        if (not self.cleanInstance):
            self.logger.debug("No need to delete data.", "constant")
            return

        # Clean instance data
        cmd = "%s -U %s -l %s" % (
            OMCommand.getLocalScript("Local_Clean_Instance"), self.user,
            self.localLog)
        self.logger.debug("Command for deleting instance: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode or self.isSingle,
                                        self.mpprcFile)

        # clean upgrade temp backup path
        upgrade_bak_dir = ClusterDir.getBackupDir("upgrade", self.user)
        cmd = g_file.SHELL_CMD_DICT["cleanDir"] % (
            upgrade_bak_dir, upgrade_bak_dir, upgrade_bak_dir)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode or self.isSingle,
                                        self.mpprcFile)

        self.logger.log("Successfully deleted instances.", "constant")

    def CleanTmpFiles(self):
        """
        function: clean temp files
        input : NA
        output: NA
        """
        self.logger.debug("Deleting temporary files.", "addStep")
        try:
            # copy record_app_directory file
            tmpDir = EnvUtil.getTmpDirFromEnv(self.user)
            if tmpDir == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
            upgradeBackupPath = os.path.join(tmpDir, "binary_upgrade")
            copyPath = os.path.join(upgradeBackupPath, "record_app_directory")
            appPath = ClusterDir.getInstallDir(self.user)
            if appPath == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
            if copyPath != "":
                copyCmd = "(if [ -f '%s' ];then cp -f -p '%s' '%s/';fi)" % (
                    copyPath, copyPath, appPath)
                CmdExecutor.execCommandWithMode(
                    copyCmd,
                    self.sshTool, self.localMode or self.isSingle,
                    self.mpprcFile)

            cmd = g_file.SHELL_CMD_DICT["cleanDir"] % (
                self.tmpDir, self.tmpDir, self.tmpDir)
            # clean dir of PGHOST
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode or self.isSingle,
                                            self.mpprcFile)
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Successfully deleted temporary files.", "constant")

    def UninstallApp(self):
        """
        function: Uninstall application
        input : NA
        output: NA
        """
        self.logger.log("Uninstalling application.", "addStep")
        cmd = "%s -R '%s' -U %s -l %s -T" % (
            OMCommand.getLocalScript("Local_Uninstall"),
            self.clusterInfo.appPath,
            self.user, self.localLog)
        self.logger.debug("Command for Uninstalling: %s" % cmd)
        # clean application
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode or self.isSingle,
                                        self.mpprcFile)
        self.logger.log("Successfully uninstalled application.", "constant")

    def CleanStaticConfFile(self):
        """
        function: clean static conf file
        input : NA
        output: NA
        """
        self.logger.debug("Deleting static configuration file.", "addStep")
        try:
            cmd = "rm -rf '%s'/bin " % self.clusterInfo.appPath
            # delete bin dir in GAUSSHOME
            CmdExecutor.execCommandWithMode(
                cmd,
                self.sshTool, self.localMode or self.isSingle,
                self.mpprcFile)
        except Exception as e:
            self.logger.exitWithError(str(e))
        self.logger.debug("Successfully deleted static configuration file.",
                          "constant")

    def CleanRackFile(self):
        """
        function: clean rack information file
        input : NA
        output: NA
        """
        gp_home = EnvUtil.getEnv("GPHOME")
        if os.path.exists(gp_home):
            gp_home = os.path.realpath(gp_home)
        rack_conf_file = os.path.realpath(
            os.path.join(gp_home, "script/gspylib/etc/conf/rack_info.conf"))
        if os.path.isfile(rack_conf_file):
            cmd = "rm -f %s" % rack_conf_file
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode or self.isSingle,
                                            mpprc_file=self.mpprcFile)
            self.logger.debug("Successfully deleted rack information file.")

    def clean_dss_home(self):
        """
        function: Clean default log
        input : NA
        output: NA
        """
        self.logger.debug("Deleting dss_home.", "addStep")
        # check if need delete instance
        if not self.cleanInstance:
            self.logger.debug("No need to delete data.", "constant")
            return

        try:
            # clean log
            dss_home = EnvUtil.getEnvironmentParameterValue("DSS_HOME", self.user)
            cmd = g_file.SHELL_CMD_DICT["cleanDir"] % (
                dss_home, dss_home, dss_home)
            # delete log dir
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode or self.isSingle,
                                            self.mpprcFile)
        except Exception as e:
            self.logger.exitWithError(str(e))
        self.logger.debug("Successfully deleted log.", "constant")


    def CleanLog(self):
        """
        function: Clean default log
        input : NA
        output: NA
        """
        self.logger.debug("Deleting log.", "addStep")
        # check if need delete instance
        if (not self.cleanInstance):
            self.logger.debug("No need to delete data.", "constant")
            return

        try:
            # clean log
            userLogDir = ClusterDir.getUserLogDirWithUser(self.user)
            cmd = g_file.SHELL_CMD_DICT["cleanDir"] % (
                userLogDir, userLogDir, userLogDir)
            # delete log dir
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode or self.isSingle,
                                            self.mpprcFile)
        except Exception as e:
            self.logger.exitWithError(str(e))
        self.logger.log("Successfully deleted log.", "constant")

    def checkEnv(self):
        """
        function: check if GAUSS_ENV is 2
        input : NA
        output: NA
        """
        pass

    def ReCleanEtcdPath(self):
        """
        function: make sure the etcd path is clean.
        input : NA
        output: NA
        """
        pass

    def ReKillEtcdProcess(self):
        """
        function: make sure the etcd process is clean.
        input : NA
        output: NA
        """
        if (self.localMode):
            DefaultValue.KillAllProcess(self.user, "etcd")
        # kill process in all nodes
        else:
            etcd_file = "%s/bin/etcd" % self.clusterInfo.appPath
            self.CheckAndKillAliveProc(etcd_file)

    def check_drop_node(self):
        """
        Check flag file of drop node
        """
        flag_file = os.path.realpath(os.path.join(self.clusterInfo.appPath,
                                                  "bin", "drop_node_flag"))
        if os.path.isfile(flag_file):
            self.logger.log("This is a node where the gs_dropnode command has been executed. "
                            "Uninstall a single node instead of the gs_dropnode command.")
            self.localMode = True

    def check_dss(self):
        """
        function: make sure the etcd process is clean.
        input : NA
        output: NA
        """
        enable_dssLine = 'export ENABLE_DSS=ON\n'
        is_enabledssset = EnvUtil.getEnv("ENABLE_DSS")
        is_dsshome = EnvUtil.getEnv("DSS_HOME")
        
        if self.mpprcFile and os.path.isfile(self.mpprcFile):
            source_file = self.mpprcFile
            
        if is_dsshome and not is_enabledssset:
            with open(source_file, 'a') as file:
                file.write(enable_dssLine)

    def clear_dss_disk(self):
        """
        function: clear dss disk if dss_mode enabled.
        input : NA
        output: NA
        """
        if not self.clearDisk:
            self.logger.log("No need to clear dss disk.")
            return

        try:
            enabled_dss = EnvUtil.getEnv("DSS_HOME")
            if enabled_dss:
                disks = []
                dss_vg_info = enabled_dss + os.sep + "cfg" + os.sep + "dss_vg_conf.ini"
                cm_vg_info = enabled_dss + os.sep + "cfg" + os.sep + "dss_cm_conf.ini"
                with open(dss_vg_info, 'r') as fr_dss:
                    for dss_info in fr_dss.readlines():
                        disks.append(dss_info.split(':')[1].strip())
                with open(cm_vg_info, 'r') as fr_cm:
                    for cm_info in fr_cm.readlines():
                        disks.append(cm_info.strip())
                for disk in list(map(os.path.realpath, disks)):
                    subprocess.getstatusoutput("dd if=/dev/zero of=" + disk)
                    self.logger.log("dd if=/dev/zero of=" + disk + "complete.")
        except Exception as e:
            self.logger.exitWithError(str(e))
        self.logger.log("Successfully clear dss disk.")

    def run(self):
        """
        function: Uninstall database cluster
        input : NA
        output: NA
        """
        try:
            self.checkEnv()
            self.checkLogFilePath()
            self.check_drop_node()
            # do uninstall
            self.checkUninstall()
            self.StopCluster()
            self.CleanInstance()
            self.CleanTmpFiles()
            self.UninstallApp()
            self.ReCleanEtcdPath()
            self.ReKillEtcdProcess()
            self.logger.closeLog()
            self.CleanStaticConfFile()
            self.CleanRackFile()
            self.clear_dss_disk()
            self.clean_dss_home()
            self.CleanLog()
            self.check_dss()     
            self.logger.log("Uninstallation succeeded.")
        except Exception as e:
            self.logger.logExit(str(e))