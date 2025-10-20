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
import sys
import subprocess
import grp
import pwd
import getpass

from base_utils.os.user_util import UserUtil

sys.path.append(sys.path[0] + "/../")
from gspylib.threads.parallelTool import parallelTool
from gspylib.common.Common import DefaultValue, ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
import impl.upgrade.UpgradeConst as Const
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.profile_file import ProfileFile
from domain_utils.cluster_file.version_info import VersionInfo
from base_utils.os.net_util import NetUtil
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from os_platform.linux_distro import LinuxDistro

sys.path.append(sys.path[0] + "/../../../lib/")
DefaultValue.doConfigForParamiko()
import paramiko

#############################################################################
# Global variables
#############################################################################
gphome = None
# system config file
PROFILE_FILE = '/etc/profile'
# pssh directory name
PSSHDIR = 'pssh-2.3.1'
# action name
ACTION_CLEAN_TOOL_ENV = "clean_tool_env"
ACTION_CHECK_UNPREINSTALL = "check_unpreinstall"
ACTION_CLEAN_GAUSS_ENV = "clean_gauss_env"
ACTION_DELETE_GROUP = "delete_group"
ACTION_CLEAN_SYSLOG_CONFIG = 'clean_syslog_config'
ACTION_CLEAN_DEPENDENCY = "clean_dependency"
ACTION_DELETE_CGROUP = "delete_cgroup"

SYSTEM_SSH_ENV = "export LD_LIBRARY_PATH=/usr/lib64"

class PostUninstallImpl:
    """
    init the command options
    input : NA
    output: NA
    """

    def __init__(self, GaussPost):
        """
        function: constructor
        """
        pass

    def checkLogFilePath(self):
        """
        function: Check log file path
        input : NA
        output: NA
        """
        clusterPath = []

        try:
            self.logger.log("Check log file path.", "addStep")
            # get tool path
            clusterPath.append(ClusterDir.getClusterToolPath(self.user))

            # get tmp path
            tmpDir = DefaultValue.getTmpDir(self.user, self.xmlFile)
            clusterPath.append(tmpDir)

            # get cluster  path
            hostName = NetUtil.GetHostIpOrName()
            dirs = self.clusterInfo.getClusterDirectorys(hostName, False)
            for checkdir in dirs.values():
                clusterPath.extend(checkdir)

            self.logger.debug("Cluster paths %s." % clusterPath)
            # check directory
            FileUtil.checkIsInDirectory(self.logFile, clusterPath)
            self.logger.log("Successfully checked log file path.", "constant")
        except Exception as e:
            self.logger.logExit(str(e))

    ##########################################################################
    # Uninstall functions
    ##########################################################################
    def doCleanEnvironment(self):
        """
        function: Clean Environment
        input : NA
        output: NA
        """
        self.logger.debug("Do clean Environment.", "addStep")
        try:
            # check uninstall
            self.checkUnPreInstall()
            # clean cgroup
            self.clean_cgroup()
            # clean app/log/data/temp dirs
            self.cleanDirectory()
            # clean other user
            self.cleanRemoteOsUser()
            # clean other nodes log
            self.cleanOtherNodesLog()
            # clean other nodes environment software and variable
            self.cleanOtherNodesEnvSoftware()
            # clean local node environment software and variable
            self.cleanLocalNodeEnvSoftware()
            # clean local user
            self.cleanLocalOsUser()
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Do clean Environment succeeded.", "constant")

    def setOrCleanGphomeEnv(self, setGphomeenv=True):
        osProfile = ClusterConstants.ETC_PROFILE
        if setGphomeenv:
            GphomePath = ClusterDir.getPreClusterToolPath(self.xmlFile)
            # set GPHOME
            FileUtil.writeFile(osProfile, ["export GPHOME=%s" % GphomePath])
        else:
            FileUtil.deleteLine(osProfile, "^\\s*export\\s*GPHOME=.*$")
            FileUtil.deleteLine(osProfile, "^\\s*export\\s*UNPACKPATH=.*$")
            self.logger.debug(
                "Deleting crash GPHOME in user environment variables.")

    def checkUnPreInstall(self):
        """
        function: check whether do uninstall before unpreinstall
        input : NA
        output: NA
        """
        self.logger.log("Checking unpreinstallation.")
        if not self.localMode:
            ProfileFile.checkAllNodesMpprcFile(
                self.clusterInfo.getClusterNodeNames(), self.mpprcFile)

        cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
            OMCommand.getLocalScript("Local_UnPreInstall"),
            ACTION_CHECK_UNPREINSTALL,
            self.user,
            self.localLog,
            self.xmlFile)
        self.logger.debug("Command for checking unpreinstall: %s" % cmd)
        # check if do postuninstall in all nodes
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)
        self.logger.log("Successfully checked unpreinstallation.")

    def clean_cgroup(self):
        """
        function: clean cgroup
        input : NA
        output: NA
        """
        self.logger.log("check and clean cgroup")
        cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
            OMCommand.getLocalScript("Local_UnPreInstall"),
            ACTION_DELETE_CGROUP,
            self.user,
            self.localLog,
            self.xmlFile)
        self.logger.debug("Command for clean cgroup: %s" % cmd)
        # check if do postuninstall in all nodes
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)
        self.logger.log("Successfully clean cgroup.")

    def cleanDirectory(self):
        """
        function: clean install/instance/temp dirs
        input : NA
        output: NA
        """
        # clean instance path
        hostName = NetUtil.GetHostIpOrName()
        dbNodeInfo = self.clusterInfo.getDbNodeByName(hostName)
        instanceDirs = []
        # get DB instance
        for dbInst in dbNodeInfo.datanodes:
            instanceDirs.append(dbInst.datadir)
            if (len(dbInst.ssdDir) != 0):
                instanceDirs.append(dbInst.ssdDir)
        # clean all instances
        if (len(instanceDirs) > 0):
            if (os.path.exists(instanceDirs[0]) and len(
                    os.listdir(instanceDirs[0])) == 0):
                self.CleanInstanceDir()
            else:
                self.logger.debug(
                    "Instance directory [%s] is not empty. "
                    "Skip to delete instance's directory." %
                    instanceDirs[0])
        else:
            self.logger.debug(
                "Instance's directory is not been found. "
                "Skip to delete instance's directory.")

        # clean install path
        if (os.path.exists(self.clusterInfo.appPath)):
            self.logger.log("Deleting the installation directory.")
            cmd = "rm -rf '%s'" % self.clusterInfo.appPath
            self.logger.debug(
                "Command for deleting the installation path: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode,
                                            self.mpprcFile)
            self.logger.log("Successfully deleted the installation directory.")

        # clean tmp dir
        self.logger.log("Deleting the temporary directory.")
        tmpDir = DefaultValue.getTmpDir(self.user, self.xmlFile)
        cmd = "rm -rf '%s'; rm -rf /tmp/gs_checkos; rm -rf /tmp/gs_virtualip" \
              % tmpDir
        self.logger.debug(
            "Command for deleting the temporary directory: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)
        self.logger.log("Successfully deleted the temporary directory.")

        path = '/etc/udev/rules.d/zz-dss_{}.rules'.format(self.user)
        if self.clusterInfo.enable_dss == 'on' or os.path.isfile(path):
            self.logger.log("Deleting the udev rule file.")
            cmd = "if [ -f '{0}' ]; then rm -rf '{0}'; fi;".format(path)
            self.logger.debug("Command for deleting the udev rule file: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd, self.sshTool, self.localMode,
                                            self.mpprcFile)
            self.logger.log("Successfully deleted the udev rule file.")

    def CleanInstanceDir(self):
        """
        function: Clean instance directory
        input : NA
        output: NA
        """
        self.logger.log("Deleting the instance's directory.")
        cmd = "%s -U %s -l '%s' -X '%s'" % (
            OMCommand.getLocalScript("Local_Clean_Instance"), self.user,
            self.localLog, self.xmlFile)
        self.logger.debug("Command for deleting the instance: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)

        # clean upgrade temp backup path
        cmd = "rm -rf '%s'" % ClusterDir.getBackupDir("upgrade", self.user)
        self.logger.debug(
            "Command for deleting the upgrade temp backup path: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)

        self.logger.log("Successfully deleted the instance's directory.")

    def cleanRemoteOsUser(self):
        """
        function: Clean remote os user
        input : NA
        output: NA
        """
        # check if local mode
        if (self.localMode):
            return

        if (not self.deleteUser):
            # clean static config file
            if os.stat(os.path.dirname(self.clusterInfo.appPath)).st_uid != 0:
                cmd = "rm -rf '%s'" % self.clusterInfo.appPath
                CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool, self.localMode,
                                            self.mpprcFile)
            return

        group = grp.getgrgid(pwd.getpwnam(self.user).pw_gid).gr_name

        # get other nodes
        hostName = NetUtil.GetHostIpOrName()
        otherNodes = self.clusterInfo.getClusterNodeNames()
        for otherNode in otherNodes:
            if (otherNode == hostName):
                otherNodes.remove(otherNode)

        # clean remote user
        self.logger.log("Deleting remote OS user.")
        cmd = "%s -U %s -l %s" % (
            OMCommand.getLocalScript("Local_Clean_OsUser"), self.user,
            self.localLog)
        self.logger.debug("Command for deleting remote OS user: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd, self.sshTool,
                                        self.localMode, self.mpprcFile,
                                        otherNodes)
        self.logger.log("Successfully deleted remote OS user.")

        if (self.deleteGroup):
            # clean remote group
            self.logger.debug("Deleting remote OS group.")
            cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
                OMCommand.getLocalScript("Local_UnPreInstall"),
                ACTION_DELETE_GROUP, group, self.localLog, self.xmlFile)
            self.logger.debug("Command for deleting remote OS group: %s" % cmd)
            status = self.sshTool.getSshStatusOutput(cmd, otherNodes,
                                                               self.mpprcFile)[0]
            outputMap = self.sshTool.parseSshOutput(otherNodes)
            for node in status.keys():
                if (status[node] != DefaultValue.SUCCESS):
                    self.logger.log((outputMap[node]).strip("\n"))
            self.logger.debug("Deleting remote group is completed.")

    def cleanOtherNodesEnvSoftware(self):
        """
        function: clean other nodes environment software and variable
        input : NA
        output: NA
        """
        # check if local mode
        if self.localMode:
            return
        self.logger.log(
            "Deleting software packages "
            "and environmental variables of other nodes.")
        try:
            # get other nodes
            hostName = NetUtil.GetHostIpOrName()
            otherNodes = self.clusterInfo.getClusterNodeNames()
            for otherNode in otherNodes:
                if (otherNode == hostName):
                    otherNodes.remove(otherNode)
            self.logger.debug(
                "Deleting environmental variables of nodes: %s." % otherNodes)

            # clean $GAUSS_ENV
            if (not self.deleteUser):
                cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
                    OMCommand.getLocalScript("Local_UnPreInstall"),
                    ACTION_CLEAN_GAUSS_ENV,
                    self.user,
                    self.localLog,
                    self.xmlFile)
                self.logger.debug("Command for deleting $GAUSS_ENV: %s" % cmd)
                CmdExecutor.execCommandWithMode(cmd,
                                                self.sshTool, self.localMode,
                                                self.mpprcFile, otherNodes)
            cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
                OMCommand.getLocalScript("Local_UnPreInstall"),
                ACTION_CLEAN_TOOL_ENV,
                self.user,
                self.localLog,
                self.xmlFile)
            self.logger.debug(
                "Command for deleting environmental variables: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool,
                                            self.localMode,
                                            self.mpprcFile,
                                            otherNodes.append(hostName))
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.log(
            "Successfully deleted software packages "
            "and environmental variables of other nodes.")

    def cleanOtherNodesLog(self):
        """
        function: clean other nodes log
        input : NA
        output: NA
        """
        # check if local mode
        if self.localMode:
            return
        self.logger.log("Deleting logs of other nodes.")
        try:
            # get other nodes
            hostName = NetUtil.GetHostIpOrName()
            otherNodes = self.clusterInfo.getClusterNodeNames()
            for otherNode in otherNodes:
                if (otherNode == hostName):
                    otherNodes.remove(otherNode)

            # clean log
            if os.stat(ClusterDir.getClusterToolPath(self.user)).st_uid != 0 or \
                    os.stat(self.clusterInfo.logPath).st_uid != 0:
                cmd = "rm -rf '%s/%s'; rm -rf /tmp/gauss_*;" % (self.clusterInfo.logPath, self.user)
                python_path = "%s/Python-2.7.9" % ClusterDir.getClusterToolPath(self.user)
                if DefaultValue.non_root_owner(python_path):
                    cmd += "rm -rf '%s/Python-2.7.9'" % ClusterDir.getClusterToolPath(self.user)
                self.logger.debug("Command for deleting logs of other nodes: %s" % cmd)
                CmdExecutor.execCommandWithMode(cmd,
                                                self.sshTool,
                                                self.localMode,
                                                self.mpprcFile,
                                                otherNodes)
                self.logger.debug(
                    "Successfully deleted logs of the nodes: %s." % otherNodes)
        except Exception as e:
            self.logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50207"] % "other nodes log"
                + " Error: \n%s." % str(e))
        self.logger.log("Successfully deleted logs of other nodes.")

    def cleanOthernodesBackupScript(self):
        """
        function: clean othernodes gauss_om script
        """
        # check if local mode
        if self.localMode:
            return
        self.logger.log("Deleting gauss_om of other nodes.")
        try:
            # get other nodes
            hostName = NetUtil.GetHostIpOrName()
            otherNodes = self.clusterInfo.getClusterNodeNames()
            for otherNode in otherNodes:
                if (otherNode == hostName):
                    continue
                cmd = f"ssh root@%s 'rm -rf %s'" % (otherNode, self.gauss_om_path)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    self.logger.logExit(
                        ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                        + " Error:\n%s" % output)
                self.logger.debug(
                    "Successfully deleted gauss_om of the nodes: %s." % otherNodes)
        except Exception as e:
            self.logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50207"] % "other nodes gauss_om"
                + " Error: \n%s." % str(e))
        self.logger.log("Successfully deleted gauss_om of other nodes.")

    def cleanLocalNodeEnvSoftware(self):
        """
        function: clean local node environment software and variable
        input : NA
        output: NA
        in this function, Gauss-MPPDB* & sctp_patch is came from R5 upgrade R7
        """
        self.logger.log(
            "Deleting software packages "
            "and environmental variables of the local node.")
        try:
            self.clusterToolPath = ClusterDir.getClusterToolPath(self.user)

            # clean local node environment software
            path = "%s/%s" % (self.clusterToolPath, PSSHDIR)
            FileUtil.removeDirectory(path)
            path = "%s/upgrade.sh" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/version.cfg" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/GaussDB.py" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/libcgroup" % self.clusterToolPath
            FileUtil.removeDirectory(path)
            path = "%s/unixodbc" % self.clusterToolPath
            FileUtil.removeDirectory(path)
            path = "%s/server.key.cipher" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/server.key.rand" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/%s*" % (self.clusterToolPath, VersionInfo.PRODUCT_NAME)
            FileUtil.removeDirectory(path)
            path = "%s/server.key.rand" % self.clusterToolPath
            FileUtil.removeFile(path)
            path = "%s/Gauss*" % (self.clusterToolPath)
            FileUtil.removeDirectory(path)
            path = "%s/sctp_patch" % (self.clusterToolPath)
            FileUtil.removeDirectory(path)
            path = "%s/%s" % (self.clusterToolPath, Const.UPGRADE_SQL_FILE)
            FileUtil.removeFile(path)
            path = "%s/%s" % (self.clusterToolPath, Const.UPGRADE_SQL_SHA)
            FileUtil.removeFile(path)
            self.logger.debug(
                "Deleting environmental software of local nodes.")

            hostName = NetUtil.GetHostIpOrName()
            node_info = self.clusterInfo.getDbNodeByName(hostName)
            datadir = node_info.datanodes[0].datadir
            datadir_escaped = datadir.replace("/", "\\/")
            basePort = node_info.datanodes[0].port
            userprofile = ProfileFile.get_user_bashrc(self.user)
            # clean local node environment variable
            cmd = "(if [ -s '%s' ]; then " % userprofile
            cmd += "sed -i -e '/^export PATH=\/home\/%s\/gauss_om\/" \
                   "script:\$PATH/d' %s " % (self.user, userprofile)
            cmd += "-e '/^export PATH=\$GPHOME\/script\/gspylib\/pssh\/bin:" \
                   "\$GPHOME\/script:\$PATH/d' %s " % PROFILE_FILE
            cmd += "-e '/^export LD_LIBRARY_PATH=\$GPHOME\/script\/gspylib\/clib:\/usr\/local\/ubs_mem\/lib:" \
                   "\$LD_LIBRARY_PATH$/d' %s " % userprofile
            cmd += "-e '/^export LD_LIBRARY_PATH=\$GPHOME\/lib:" \
                   "\$LD_LIBRARY_PATH$/d' %s " % userprofile
            cmd += "-e '/^export PGDATABASE=postgres/d' %s " % userprofile
            cmd += "-e '/^export PGPORT=%d/d' %s " % (basePort, userprofile)
            cmd += "-e '/^export UNPACKPATH=/d' %s " % userprofile
            cmd += "-e '/^export COREPATH=/d' %s " % userprofile
            cmd += "-e '/^export GPHOME=/d' %s " % userprofile
            cmd += "-e '/^export PGDATA=%s/d' %s " % (datadir_escaped, userprofile)
            cmd += "-e '/^export PYTHONPATH=\$GPHOME\/lib$/d' %s; fi) " % userprofile

            self.logger.debug(
                "Command for deleting environment variable: %s" % cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50207"] %
                                    "environment variables of the local node"
                                    + " Error: \n%s" % output)
            # check if user profile exist
            user_bashrc = ProfileFile.get_user_bashrc(self.user)
            if (self.mpprcFile is not None and self.mpprcFile != "" and os.path.exists(self.mpprcFile)):
                userProfile = self.mpprcFile
            else:
                userProfile = user_bashrc
            if (not os.path.exists(userProfile)):
                self.logger.debug(
                    "The %s does not exist. "
                    "Please skip to clean $GAUSS_ENV." % userProfile)
                return
            # clean user's environmental variable
            DefaultValue.cleanUserEnvVariable(userProfile,
                                              cleanGAUSS_WARNING_TYPE=True)
            if os.path.exists(user_bashrc):
                FileUtil.deleteLine(user_bashrc,
                                    "^\\s*export\\s*%s=.*$" % DefaultValue.MPPRC_FILE_ENV)

            # clean $GAUSS_ENV
            if (not self.deleteUser):
                envContent = "^\\s*export\\s*GAUSS_ENV=.*$"
                FileUtil.deleteLine(userProfile, envContent)
                self.logger.debug("Command for deleting $GAUSS_ENV: %s" % cmd,
                                  "constant")

        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.log(
            "Successfully deleted software packages "
            "and environmental variables of the local nodes.")

    def cleanLocalOsUser(self):
        """
        function: Clean local os user
        input : NA
        output: NA
        """
        if (not self.deleteUser):
            if (self.localMode):
                if os.stat(os.path.dirname(self.clusterInfo.appPath)).st_uid != 0:
                    cmd = "rm -rf '%s'" % self.clusterInfo.appPath
                    CmdExecutor.execCommandWithMode(cmd,
                                                    self.sshTool, self.localMode,
                                                    self.mpprcFile)
            return

        group = grp.getgrgid(pwd.getpwnam(self.user).pw_gid).gr_name

        # clean local user
        self.logger.log("Deleting local OS user.")
        cmd = "%s -U %s -l %s" % (
            OMCommand.getLocalScript("Local_Clean_OsUser"), self.user,
            self.localLog)
        self.logger.debug("Command for deleting local OS user: %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            self.logger.logExit(output)
        self.logger.log("Successfully deleted local OS user.")

        if (self.deleteGroup):
            # clean local user group
            self.logger.debug("Deleting local OS group.")
            cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
                OMCommand.getLocalScript("Local_UnPreInstall"),
                ACTION_DELETE_GROUP,
                group,
                self.localLog,
                self.xmlFile)
            self.logger.debug("Command for deleting local OS group: %s" % cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                self.logger.log(output.strip())
            self.logger.debug("Deleting local group is completed.")

    def cleanLocalLog(self):
        """
        function: Clean default log
        input : NA
        output: NA
        """
        self.logger.log("Deleting local node's logs.", "addStep")
        try:
            # clean log
            path = "%s/%s" % (self.clusterInfo.logPath, self.user)
            FileUtil.removeDirectory(path)
        except Exception as e:
            self.logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50207"]
                % "logs" + " Error: \n%s." % str(e))
        self.logger.log("Successfully deleted local node's logs.", "constant")

    def cleanMpprcFile(self):
        """
        function: clean mpprc file if we are using environment seperate
        version.
        input : NA
        output: NA
        """
        self.logger.debug("Clean mpprc file.", "addStep")
        # check if mpprcfile is null
        if (self.mpprcFile != ""):
            try:
                UserUtil.check_user_exist(self.user)
                baseCmd = 'su - %s -c "rm -rf %s"' % (self.user, self.mpprcFile)
            except Exception as exp:
                self.logger.debug("Check user [%s] not exist. Error: %s" % (self.user, str(exp)))
                baseCmd = "if [ -f %s ]; then rm -rf %s; fi" % (self.mpprcFile, self.mpprcFile)
            # check if local mode
            if os.stat(self.mpprcFile).st_uid != 0:
                if (self.localMode):
                    (status, output) = subprocess.getstatusoutput(baseCmd)
                    if (status != 0):
                        self.logger.logExit(
                            ErrorCode.GAUSS_502["GAUSS_50207"]
                            % "MPPRC file"
                            + " Command: %s. Error: \n%s" % (baseCmd, output))
                else:
                    dbNodeNames = self.clusterInfo.getClusterNodeNames()
                    for dbNodeName in dbNodeNames:
                        cmd = "pssh -s -H %s '%s'" % (dbNodeName, baseCmd)
                        (status, output) = subprocess.getstatusoutput(cmd)
                        if (status != 0):
                            message = output.strip()
                            err_message = ErrorCode.GAUSS_502["GAUSS_50207"] % "MPPRC file" + \
                                          " Command: %s. Error: \n%s" % (cmd, output)
                            if "Permission denied" in message:
                                self.logger.debug(err_message)
                            else:
                                self.logger.logExit(err_message)
        self.logger.debug("Successfully cleaned mpprc file.", "constant")

    def cleanScript(self):
        """
        clean script directory
        """
        self.logger.debug("Clean script path")
        cmd = "%s -t %s -u %s -Q %s" % (
            OMCommand.getLocalScript("Local_UnPreInstall"),
            ACTION_CLEAN_DEPENDENCY, self.user,
            self.clusterToolPath)
        if self.deleteUser:
            cmd += " -P %s" % self.userHome
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool, self.localMode,
                                        self.mpprcFile)
        self.logger.debug("Clean script path successfully.")

    def cleanSyslogConfig(self):
        """
        function: clean syslog config
        input : NA
        output: NA
        """
        try:
            # only suse11/suse12 can support it
            distname = LinuxDistro.linux_distribution()[0]
            if (distname.upper() != "SUSE"):
                return

            # clean syslog-ng/rsyslog config
            cmd = "%s -t %s -u %s -l '%s' -X '%s'" % (
                OMCommand.getLocalScript("Local_UnPreInstall"),
                ACTION_CLEAN_SYSLOG_CONFIG,
                self.user,
                self.localLog,
                self.xmlFile)
            self.logger.debug(
                "Command for clean syslog-ng/rsyslog config: %s" % cmd)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.sshTool,
                self.localMode,
                self.mpprcFile,
                self.clusterInfo.getClusterNodeNames())
        except Exception as e:
            self.logger.logExit(str(e))

    def ssh_exec_with_pwd(self, host, port=DefaultValue.DEFAULT_SSH_PORT):
        """
        function: execute command with root password
        input : host
        output: NA
        """
        cmd = "if [ $(stat -c \"%s\" %s) == 0 ];then echo 'OKOKOK';" \
              "else rm -rf %s/* && echo 'OKOKOK';fi" % ("%u", gphome, gphome)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, "root", self.sshpwd)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read()
        self.logger.debug("%s: %s" % (str(host), str(output)))
        if output.find('OKOKOK') < 0:
            raise Exception(
                ErrorCode.GAUSS_514["GAUSS_51400"]
                % cmd + "host: %s. Error:\n%s"
                % (host, output))

    def verifyCleanGphome(self, localMode=True):
        """
        function: verify clean gphome and get root password
        input : localMode
        output: str
        """
        sshpwd = ""
        flag = input(
            "Are you sure you want to clean gphome[%s] (yes/no)? " % gphome)
        while (True):
            if (
                    flag.upper() != "YES"
                    and flag.upper() != "NO"
                    and flag.upper() != "Y" and flag.upper() != "N"):
                flag = input("Please type 'yes' or 'no': ")
                continue
            break
        if (flag.upper() == "NO" or flag.upper() == "N"):
            sys.exit(0)
        if "HOST_IP" in os.environ.keys() and not localMode:
            sshpwd = getpass.getpass("Please enter password for root:")
            sshpwd_check = getpass.getpass("Please repeat password for root:")
            if sshpwd_check != sshpwd:
                sshpwd_check = ""
                sshpwd = ""
                raise Exception(ErrorCode.GAUSS_503["GAUSS_50306"] % "root")
            sshpwd_check = ""
        return sshpwd

    def checkAuthentication(self, hostname):
        """
        function: Ensure the proper password-less access to the remote host.
        input : hostname
        output: True/False, hostname
        """
        cmd = 'ssh -n %s %s true' % (DefaultValue.SSH_OPTION, hostname)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            self.logger.debug("The cmd is %s " % cmd)
            self.logger.debug(
                "Failed to check authentication. Hostname:%s. Error: \n%s" % (
                    hostname, output))
            return (False, hostname)
        return (True, hostname)

    def getItemValueFromXml(self, itemName):
        """
        function: Get item from xml tag CLUSTER.
        input : hostname
        output: True/False, hostname
        """
        (retStatus, retValue) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(self.xmlFile), itemName, "cluster")
        if (retStatus != 0):
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50204"]
                % itemName + " Error: \n%s" % retValue)
        return retValue

    def cleanGphomeScript(self):
        """
        function: clean gphome script
        input : NA
        output: NA
        """
        try:
            if not self.clean_gphome:
                return
            global gphome
            gphome = os.path.normpath(
                self.getItemValueFromXml("gaussdbToolPath"))
            cmd_list = ['rm', '-rf', ('%s/*') % gphome]
            if "HOST_IP" in os.environ.keys():
                # Agent Mode
                if self.localMode:
                    # clean gphome in local mode
                    self.verifyCleanGphome()
                    (output, error, status) = CmdUtil.execCmdList(cmd_list)
                    if status != 0:
                        raise Exception(
                            ErrorCode.GAUSS_514["GAUSS_51400"]
                            % ' '.join(cmd_list) + " Error:\n%s" % output)
                    self.logger.logExit("Successfully clean gphome locally.")
                else:
                    # clean gphome with specified node
                    self.sshpwd = self.verifyCleanGphome(self.localMode)
                    parallelTool.parallelExecute(self.ssh_exec_with_pwd,
                                                 self.clean_host)
                    self.logger.logExit(
                        "Successfully clean gphome on node %s."
                        % self.clean_host)

            else:
                # SSH Mode
                SSH_TRUST = True
                self.nodeList = self.getItemValueFromXml("nodeNames").split(
                    ",")
                if len(self.nodeList) == 0:
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50203"] % "nodeList")
                results = parallelTool.parallelExecute(
                    self.checkAuthentication, self.nodeList)
                for (key, value) in results:
                    if (not key):
                        self.logger.log("SSH trust has not been created. \
                        \nFor node : %s. Only clean local node." % value,
                                        "constant")
                        SSH_TRUST = False
                        break
                if SSH_TRUST and not self.localMode:
                    # SSH trust has been created
                    self.verifyCleanGphome()
                    parallelTool.parallelExecute(self.ssh_exec_with_pwd,
                                                 self.nodeList)
                if not SSH_TRUST or self.localMode:
                    # SSH trust has not been created
                    # which means clean gphome locally
                    self.verifyCleanGphome()
                    if os.stat(gphome).st_uid != 0:
                        (output, error, status) = CmdUtil.execCmdList(cmd_list)
                        if status != 0:
                            raise Exception(
                                ErrorCode.GAUSS_514["GAUSS_51400"]
                                % ' '.join(cmd_list) + " Error:\n%s" % output)
                self.logger.logExit("Successfully clean gphome.")

        except Exception as e:
            self.logger.logExit(str(e))

    def createTrustForRoot(self):
        """
        :return:
        """
        if self.localMode or self.isSingle:
            return
        try:
            # save the sshIps
            Ips = []
            # create trust for root
            # get the user name
            username = pwd.getpwuid(os.getuid()).pw_name
            # get the user sshIps
            sshIps = self.clusterInfo.getClusterSshIps()
            # save the sshIps to Ips
            for ips in sshIps:
                Ips.extend(ips)

            self.logger.log("Creating SSH trust for the root permission user.")
            # Ask to create trust for root
            flag = input("Are you sure you want to create trust for root (yes/no)?")
            while True:
                # If it is not yes or no, it has been imported
                # if it is yes or no, it has been break
                if flag.upper() not in ("YES", "NO", "Y", "N"):
                    flag = input("Please type 'yes' or 'no': ")
                    continue
                break

            # Receives the entered password
            if flag.upper() in ("NO", "N"):
                return

            self.logger.log("Please enter password for root.")
            retry_times = 0
            while True:
                try:
                    ssh_ports_map = self.clusterInfo.get_cluster_nodes_ssh_port_by_ips(Ips)
                    self.sshTool.createTrust(username, Ips, ssh_port=ssh_ports_map, action='gs_postuninstall')
                    break
                except Exception as err_msg:
                    if retry_times == 2:
                        raise Exception(str(err_msg))
                    if "Authentication failed" in str(err_msg):
                        self.logger.log("Password authentication failed, please try again.")
                        retry_times += 1
                    else:
                        raise Exception(str(err_msg))
            FileUtil.changeMode(DefaultValue.HOSTS_FILE, "/etc/hosts", False,
                              "shell", retry_flag=True)
            self.logger.log("Successfully created SSH trust for the root permission user.")
            self.root_ssh_agent_flag = True
        except Exception as e:
            raise Exception(str(e))

    def delet_root_mutual_trust(self, local_host):
        """
        :return:
        """
        if self.localMode or self.isSingle:
            return
        if not self.root_ssh_agent_flag:
            return
        self.logger.debug("Start Delete root mutual trust")

        username = pwd.getpwuid(os.getuid()).pw_name
        # get dir path
        homeDir = os.path.expanduser("~" + username)
        tmp_path = "%s/gaussdb_tmp" % homeDir

        # get cmd
        bashrc_file = ProfileFile.get_user_bashrc(self.user)
        kill_ssh_agent_cmd = "ps ux | grep 'ssh-agent' | grep -v grep | awk '{print $2}' | " \
                             "xargs kill -9"
        delete_line_cmd = ""
        if os.path.exists(bashrc_file):
            delete_line_cmd += " && sed -i '/^\\s*export\\s*SSH_AUTH_SOCK=.*$/d' %s" % bashrc_file
            delete_line_cmd += " && sed -i '/^\\s*export\\s*SSH_AGENT_PID=.*$/d' %s" % bashrc_file
        delete_line_cmd += " && sed -i '/#OM$/d' %s" % DefaultValue.SSH_AUTHORIZED_KEYS
        delete_line_cmd += " && sed -i '/#OM$/d' %s" % DefaultValue.SSH_KNOWN_HOSTS
        delete_shell_cmd = " && rm -rf %s" % tmp_path
        delete_shell_cmd += " && rm -rf %s" % DefaultValue.SSH_PRIVATE_KEY
        delete_shell_cmd += " && rm -rf %s" % DefaultValue.SSH_PUBLIC_KEY
        if os.path.exists(DefaultValue.SSH_CONFIG):
            delete_shell_cmd += " && rm -rf %s" % DefaultValue.SSH_CONFIG
        cmd = "%s" + delete_line_cmd + delete_shell_cmd

        # get remote node and local node
        host_list = self.clusterInfo.getClusterNodeNames()
        host_list.remove(local_host)

        # delete remote root mutual trust
        kill_remote_ssh_agent_cmd = DefaultValue.killInstProcessCmd("ssh-agent", True)

        for host in host_list:
            remote_cmd = "%s;/usr/bin/ssh root@%s \"rm -rf %s\"" % (SYSTEM_SSH_ENV, host, cmd % kill_remote_ssh_agent_cmd)
            (status, output) = subprocess.getstatusoutput(remote_cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % remote_cmd
                    + " Error:\n%s" % output)
        # delete local root mutual trust
        CmdExecutor.execCommandLocally(cmd % kill_ssh_agent_cmd)
        self.logger.debug("Delete root mutual trust successfully.")

    def cleanLocalBackupScript(self):
        """
        function: clean gauss_om script
        """
        # clean root script path
        if os.path.exists(self.gauss_om_path):
            FileUtil.removeDirectory(self.gauss_om_path)
            self.logger.log("Successfully cleaned local gauss_om.")
            self.logger.log("clean over.")
            return
        # if /root/gauss_om has no files, delete it.
        if not os.listdir(self.gauss_om_path):
            FileUtil.removeDirectory(self.gauss_om_path)
            self.logger.log("Successfully cleaned local gauss_om.")
            self.logger.log("clean over.")
            return
        self.logger.log("clean over.")

    def run(self):
        try:
            self.logger.debug(
                "gs_postuninstall execution takes %s steps in total"
                % ClusterCommand.countTotalSteps("gs_postuninstall"))
            local_host = NetUtil.GetHostIpOrName()
            if (self.mpprcFile is not None and self.mpprcFile != "" and os.path.exists(self.mpprcFile)):
                os_profile = self.mpprcFile
            else:
                os_profile = ClusterConstants.ETC_PROFILE
            
            self.createTrustForRoot()
            self.cleanGphomeScript()
            self.checkLogFilePath()
            self.cleanSyslogConfig()
            self.doCleanEnvironment()
            self.logger.closeLog()
            self.cleanLocalLog()
            self.cleanMpprcFile()
            self.cleanScript()
            self.setOrCleanGphomeEnv(setGphomeenv=False)
            self.logger.log("Successfully cleaned environment.")
            if os.path.exists(self.gauss_om_path):
                self.cleanOthernodesBackupScript()
                self.delet_root_mutual_trust(local_host)
                self.cleanLocalBackupScript()
            else:
                self.delet_root_mutual_trust(local_host)
                self.logger.log("clean over.")
        except Exception as e:
            self.logger.logExit(str(e))
        sys.exit(0)
