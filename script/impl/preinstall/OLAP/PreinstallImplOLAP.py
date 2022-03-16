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
import subprocess
import os
import sys
import time

sys.path.append(sys.path[0] + "/../../")

from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.OMCommand import OMCommand
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.os.compress_util import CompressUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.package_info import PackageInfo
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.os.net_util import NetUtil
from impl.preinstall.PreinstallImpl import PreinstallImpl


# action name
# set the user environment variable
ACTION_SET_USER_ENV = "set_user_env"
# set the tools environment variable
ACTION_SET_TOOL_ENV = "set_tool_env"
#set cgroup service
ACTION_SET_CGROUP = "set_cgroup"
# set virtual Ip
ACTION_SET_VIRTUALIP = "set_virtualIp"
# clean virtual Ip
ACTION_CLEAN_VIRTUALIP = "clean_virtualIp"
# set arm optimization
ACTION_SET_ARM_OPTIMIZATION = "set_arm_optimization"

ACTION_CHECK_DISK_SPACE = "check_disk_space"
ACTION_FIX_SERVER_PACKAGE_OWNER = "fix_server_package_owner"

#############################################################################
# Global variables
#############################################################################
toolTopPath = ""


class PreinstallImplOLAP(PreinstallImpl):
    """
    init the command options
    save command line parameter values
    """

    def __init__(self, preinstall):
        """
        function: constructor
        """
        super(PreinstallImplOLAP, self).__init__(preinstall)

    def installToolsPhase1(self):
        """
        function: install tools to local machine
        input: NA
        output: NA
        """
        self.context.logger.log("Installing the tools on the local node.",
                                "addStep")
        try:
            # Determine if the old version of the distribution package
            # is in the current directory
            oldPackName = "%s-Package-bak.tar.gz" \
                          % VersionInfo.PRODUCT_NAME_PACKAGE
            oldPackPath = os.path.join(self.context.clusterToolPath,
                                       oldPackName)
            if os.path.exists(self.context.clusterToolPath):
                versionFile = os.path.join(self.context.clusterToolPath,
                                           "version.cfg")
                if os.path.isfile(versionFile):
                    version, number, commitid = VersionInfo.get_version_info(
                        versionFile)
                    newPackName = "%s-Package-bak_%s.tar.gz" % (
                        VersionInfo.PRODUCT_NAME_PACKAGE, commitid)
                    newPackPath = os.path.join(self.context.clusterToolPath,
                                               newPackName)
                    if os.path.isfile(oldPackPath):
                        cmd = "(if [ -f '%s' ];then mv -f '%s' '%s';fi)" % (
                            oldPackPath, oldPackPath, newPackPath)
                        self.context.logger.debug(
                            "Command for rename bak-package: %s." % cmd)
                        CmdExecutor.execCommandWithMode(
                            cmd,
                            self.context.sshTool,
                            self.context.localMode or self.context.isSingle,
                            self.context.mpprcFile)

            if (self.context.mpprcFile != ""):
                # check mpprc file
                self.checkMpprcFile()
            # check the package is not matches the system
            PackageInfo.checkPackageOS()
            # get the package path
            dirName = os.path.dirname(os.path.realpath(__file__))
            packageDir = os.path.join(dirName, "./../../../../")
            packageDir = os.path.normpath(packageDir)

            # change logPath owner
            self.context.logger.debug("Modifying logPath owner")
            top_dir_file = ClusterConstants.TOP_DIR_FILE
            keylist = []
            if (self.context.localMode):
                if (os.path.exists(top_dir_file)):
                    keylist = FileUtil.readFile(top_dir_file)
                    if (keylist != []):
                        for key in keylist:
                            if (os.path.exists(key.strip())):
                                FileUtil.changeOwner(self.context.user,
                                                   key.strip(), True, "shell", link=True)
                            else:
                                self.context.logger.debug(
                                    "Warning: Can not find the "
                                    "path in topDirPath.dat.")

                    FileUtil.removeFile(top_dir_file)
            self.context.logger.debug("Successfully modified logPath owner")

            # Delete the old bak package in GPHOME before copy the new one.
            for bakPack in DefaultValue.PACKAGE_BACK_LIST:
                bakFile = os.path.join(self.context.clusterToolPath, bakPack)
                if (os.path.isfile(bakFile)):
                    self.context.logger.debug(
                        "Remove old bak-package: %s." % bakFile)
                    FileUtil.removeFile(bakFile)

            PackageInfo.makeCompressedToolPackage(packageDir)

            # check and create tool package dir
            global toolTopPath
            ownerPath = self.context.clusterToolPath
            FileUtil.checkLink(self.context.clusterToolPath)
            clusterToolPathExistAlready = True
            # if clusterToolPath exist,
            # set the clusterToolPathExistAlready False
            if (not os.path.exists(ownerPath)):
                clusterToolPathExistAlready = False
                ownerPath = FileUtil.getTopPathNotExist(ownerPath)
                toolTopPath = ownerPath
            # append clusterToolPath to self.context.needFixOwnerPaths
            # self.context.needFixOwnerPaths will be checked the ownet
            self.context.needFixOwnerPaths.append(ownerPath)

            # if clusterToolPath is not exist, then create it

            if not os.path.exists(self.context.clusterToolPath):
                FileUtil.createDirectory(self.context.clusterToolPath)
                FileUtil.changeMode(DefaultValue.MAX_DIRECTORY_MODE,
                                  self.context.clusterToolPath, True, "shell")

            # change the clusterToolPath permission
            if not clusterToolPathExistAlready:
                #check the localMode
                if self.context.localMode:
                    #local mode,change the owner
                    FileUtil.changeMode(DefaultValue.DIRECTORY_MODE, ownerPath,
                                      recursive=True, cmd_type="shell")
                    FileUtil.changeOwner(self.context.user, ownerPath,
                                       recursive=True, cmd_type="shell", link=True)
                #not localMode, only change the permission
                else:
                    FileUtil.changeMode(DefaultValue.MAX_DIRECTORY_MODE,
                                      ownerPath, recursive=True,
                                      cmd_type="shell")
            else:
                FileUtil.changeMode(DefaultValue.DIRECTORY_MODE, ownerPath,
                                  recursive=False, cmd_type="shell")

            # Send compressed package to local host
            if (packageDir != self.context.clusterToolPath):
                # copy the package to clusterToolPath
                FileUtil.cpFile(os.path.join(
                    packageDir,
                    PackageInfo.get_package_back_name()),
                    self.context.clusterToolPath)

            # Decompress package on local host
            CompressUtil.decompressFiles(os.path.join(
                self.context.clusterToolPath,
                PackageInfo.get_package_back_name()),
                self.context.clusterToolPath)

            # change mode of packages
            FileUtil.changeMode(DefaultValue.DIRECTORY_MODE,
                              self.context.clusterToolPath, recursive=True,
                              cmd_type="shell")

            # get the top path of mpprc file need to be created on local node
            # this is used to fix the newly created path owner later
            if self.context.mpprcFile != "":
                ownerPath = self.context.mpprcFile
                if (not os.path.exists(self.context.mpprcFile)):
                    while True:
                        # find the top path to be created
                        (ownerPath, dirName) = os.path.split(ownerPath)
                        if os.path.exists(ownerPath) or dirName == "":
                            ownerPath = os.path.join(ownerPath, dirName)
                            break
                self.context.needFixOwnerPaths.append(ownerPath)

            # check the current storage package path is legal
            Current_Path = os.path.dirname(os.path.realpath(__file__))
            DefaultValue.checkPathVaild(os.path.normpath(Current_Path))
            # set ENV
            cmd = "%s -t %s -u %s -l %s -X '%s' -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_TOOL_ENV,
                self.context.user,
                self.context.localLog,
                self.context.xmlFile,
                self.context.clusterToolPath)
            if self.context.mpprcFile != "":
                cmd += " -s '%s' " % self.context.mpprcFile
                #check the localmode,if mode is local then modify user group
                if self.context.localMode:
                    cmd += "-g %s" % self.context.group
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then exit
            if status != 0:
                self.context.logger.debug(
                    "Command for setting %s tool environment variables: %s" % (
                        VersionInfo.PRODUCT_NAME, cmd))
                raise Exception(output)

        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log(
            "Successfully installed the tools on the local node.", "constant")

    def checkDiskSpace(self):
        """
        function: delete step tmp file
        input : NA
        output: NA
        """
        try:
            cmd = "%s -t %s -u %s -l %s -R %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHECK_DISK_SPACE,
                self.context.user,
                self.context.localLog,
                self.context.clusterInfo.appPath)
            if self.context.mpprcFile != "":
                cmd += " -s '%s'" % self.context.mpprcFile
            self.context.sshTool.executeCommand(cmd)
        except Exception as e:
            raise Exception(str(e))

    def setEnvParameter(self):
        """
        function: setting DBA environmental variables
        input: NA
        output: NA
        """
        self.context.logger.log("Setting user environmental variables.",
                                "addStep")

        try:
            # Setting DBA environmental variables
            cmdParam = ""
            # get then envParams
            for param in self.context.envParams:
                cmdParam += " -e \\\"%s\\\"" % param

            # set the environmental variables on all nodes
            cmd = "%s -t %s -u %s %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_USER_ENV,
                self.context.user,
                cmdParam,
                self.context.localLog)
            # check the mpprcFile
            if (self.context.mpprcFile != ""):
                cmd += " -s '%s'" % self.context.mpprcFile
            self.context.logger.debug(
                "Command for setting user's environmental variables: %s" % cmd)

            # set user's environmental variables
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log(
            "Successfully set user environmental variables.", "constant")

    def setCorePath(self):
        """
        function: set file size and path with core file
        :return: NA
        """
        self.context.clusterInfo.corePath = \
            self.context.clusterInfo.readClustercorePath(self.context.xmlFile)
        if not self.context.clusterInfo.corePath:
            return
        self.context.logger.log("Setting Core file", "addStep")
        try:
            # this is used to fix the newly created path owner later
            ownerPath = self.context.clusterInfo.corePath
            if not os.path.exists(self.context.clusterInfo.corePath):
                ownerPath = FileUtil.getTopPathNotExist(ownerPath)
            cmd = "ulimit -c unlimited; ulimit -c unlimited -S"
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle)
            cmd = "echo 1 > /proc/sys/kernel/core_uses_pid && "
            cmd += "echo '%s" % self.context.clusterInfo.corePath
            cmd += "/core-%e-%p-%t' > /proc/sys/kernel/core_pattern "
            cmd += "&& if [ ! -d '%s' ]; then mkdir %s -p -m %d;fi" % (
                self.context.clusterInfo.corePath,
                self.context.clusterInfo.corePath,
                DefaultValue.DIRECTORY_MODE)
            cmd += " && chown %s:%s %s -R -h" % (
                self.context.user, self.context.group,
                ownerPath)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully set core path.", "constant")

    def setPssh(self):
        """
        function: set pssh
        input  : NA
        output : NA
        """
        if "HOST_IP" in os.environ.keys():
            return
        self.context.logger.log("Setting pssh path", "addStep")
        try:
            pssh_path = os.path.join(os.path.dirname(__file__),
                                     "../../../gspylib/pssh/bin/pssh")
            pscp_path = os.path.join(os.path.dirname(__file__),
                                     "../../../gspylib/pssh/bin/pscp")
            psshlib_path = os.path.join(
                os.path.dirname(__file__),
                "../../../gspylib/pssh/bin/TaskPool.py")
            dest_path = "/usr/bin/"
            secbox_path = "/var/chroot/usr/bin/"
            cmd = "cp %s %s %s %s" % (
                pssh_path, pscp_path, psshlib_path, dest_path)
            cmd += \
                " && chmod %s %s/pssh && chmod %s %s/pscp " \
                "&& chmod %s %s/TaskPool.py" % (
                    DefaultValue.MAX_DIRECTORY_MODE, dest_path,
                    DefaultValue.MAX_DIRECTORY_MODE, dest_path,
                    DefaultValue.MAX_DIRECTORY_MODE, dest_path)
            # Set pssh and pscp path to secbox environment in dwsMode
            if (os.path.exists('/var/chroot/') and os.path.exists(
                    '/rds/datastore/')):
                cmd += " && cp %s %s %s %s" % (
                    pssh_path, pscp_path, psshlib_path, secbox_path)
                cmd += " && chmod %s %s/pssh && chmod %s %s/pscp " \
                       "&& chmod %s %s/TaskPool.py" % (
                           DefaultValue.MAX_DIRECTORY_MODE, secbox_path,
                           DefaultValue.MAX_DIRECTORY_MODE, secbox_path,
                           DefaultValue.MAX_DIRECTORY_MODE, secbox_path)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully set pssh path.", "constant")

    def setHostIpEnv(self):
        """
        function: set host ip env
        input  : NA
        output : NA
        """
        self.context.logger.log("Setting host ip env", "addStep")
        try:
            # remove HOST_IP info with /etc/profile and environ
            cmd = "sed -i '/^export[ ]*HOST_IP=/d' /etc/profile"
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle)
            if "HOST_IP" in os.environ.keys():
                os.environ.pop("HOST_IP")
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully set host ip env.", "constant")

    def setCgroup(self):
        """
        function: setting Cgroup
        input: NA
        output: NA
        """
        self.context.logger.log("Setting Cgroup.", "addStep")
        try:
            # set the cgroup
            cmd = "%s -t %s -u %s -X '%s' -l '%s' -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_CGROUP,
                self.context.user,
                self.context.xmlFile,
                self.context.localLog,
                self.context.clusterToolPath)
            self.context.logger.debug("Command for setting Cgroup: %s." % cmd)
            # exec cmd fro set cgroup
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.localMode or self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            # failed set Cgroup
            self.context.logger.log("Error: Failed to set Cgroup.")
            self.context.logger.logExit(str(e))
        # Successfully set Cgroup
        self.context.logger.log("Successfully set Cgroup.", "constant")

    def setArmOptimization(self):
        """
        function: setting ARM Optimization
        input: NA
        output: NA
        """
        self.context.logger.log("Set ARM Optimization.", "addStep")
        cmd = "python3 -c 'import platform;print(platform.machine())'"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.context.logger.logExit("Command for set platform ARM:"
                                      "%s" % cmd + " Error: \n%s" % output)
        if str(output) == "aarch64":
            pass
        else:
            self.context.logger.log("No need to set ARM Optimization.",
                                    "constant")
            return
        try:
            # exec cmd for set platform ARM
            cmd = "%s -t %s -u %s -l %s -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_ARM_OPTIMIZATION,
                self.context.user,
                self.context.localLog,
                self.context.clusterToolPath)
            self.context.logger.debug("Command for set platform ARM: %s" % cmd)

            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        # Successfully set ARM Optimization
        self.context.logger.log("Successfully set ARM Optimization.",
                                "constant")

    # AP
    def setVirtualIp(self):
        """
        function: set the virtual IPs
        input: NA
        output: NA
        """
        # the flag for whether the virtual IP exists
        flag = 0
        # all virtual IPs list
        allVirtualIP = []
        # get the all virtual IPs
        for node in self.context.clusterInfo.dbNodes:
            if node.virtualIp != []:
                flag = 1
                allVirtualIP.extend(node.virtualIp)
        # if flag=0, then return
        if (flag == 0):
            return
        self.context.logger.log("Setting the virtual IP service.", "addStep")
        # get the timestamp
        currentTime = time.strftime("%Y-%m-%d_%H%M%S")
        # temporary files
        tmpFile = os.path.join("/tmp/", "gauss_set_virtualIP_%d_%s.dat" % (
            os.getpid(), currentTime))
        try:
            # Setting the virtual IP service
            setCmd = "%s -t %s -u %s -l '%s' -X '%s' -f '%s'" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_VIRTUALIP,
                self.context.user,
                self.context.localLog,
                self.context.xmlFile, tmpFile)
            self.context.logger.debug(
                "Command for setting virtual IP: %s." % setCmd)
            # exec cmd for set virtual IP
            CmdExecutor.execCommandWithMode(
                setCmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
            # if non-native mode
            if (not self.context.localMode and not self.context.isSingle):
                # check all virtual IP is OK
                noPassIPs = DefaultValue.checkIsPing(allVirtualIP)
                # virtual IP are not accessible after configuring
                if noPassIPs != []:
                    self.context.logger.error(
                        ErrorCode.GAUSS_516["GAUSS_51632"]
                        % "the configuration of virtual IP")
                    self.context.logger.log(
                        "These virtual IP(%s) are not accessible after "
                        "configuring.\nRollback to clean virtual IP "
                        "service." % ",".join(noPassIPs), "constant")
                    # Rollback to clean virtual IP service
                    cleanCmd = "%s -t %s -u %s -l '%s' -X '%s' -f '%s'" % (
                        OMCommand.getLocalScript("Local_UnPreInstall"),
                        ACTION_CLEAN_VIRTUALIP,
                        self.context.user,
                        self.context.localLog,
                        self.context.xmlFile,
                        tmpFile)
                    # exec the cmd for clean virtual IP service
                    CmdExecutor.execCommandWithMode(
                        cleanCmd,
                        self.context.sshTool,
                        self.context.localMode or self.context.isSingle,
                        self.context.mpprcFile)
                    # remove the temporary files
                    cmd = "rm -rf '%s'" % tmpFile
                    CmdExecutor.execCommandWithMode(
                        cmd,
                        self.context.sshTool,
                        self.context.localMode or self.context.isSingle,
                        self.context.mpprcFile)
                    # exit
                    raise Exception("Successfully rollback to delete "
                                    "virtual IP service.")
        except Exception as e:
            # failed set virtual IP service
            # remove the temporary files
            cmd = "rm -rf '%s'" % tmpFile
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
            # exit
            raise Exception(str(e))
        # Successfully set virtual IP service
        self.context.logger.log("Successfully set virtual IP service.",
                                "constant")

    def del_remote_pkgpath(self):
        """
        delete remote package path om scripts, lib and version.cfg
        :return:
        """
        if not self.context.is_new_root_path:
            current_path = self.get_package_path()
            script = os.path.join(current_path, "script")
            hostList = self.context.clusterInfo.getClusterNodeNames()
            hostList.remove(NetUtil.GetHostIpOrName())
            if not self.context.localMode and hostList:
                cmd = "rm -f %s/gs_*" % script
                self.context.sshTool.executeCommand(cmd,
                                                    DefaultValue.SUCCESS,
                                                    hostList,
                                                    self.context.mpprcFile)

    def fixServerPackageOwner(self):
        """
        function: fix server package. when distribute server package,
                  the os user has not been created,
                  so we should fix server package Owner here after user create.
        input: NA
        output: NA
        """
        self.context.logger.log("Fixing server package owner.", "addStep")
        try:
            # fix server package owner for oltp
            cmd = ("%s -t %s -u %s -g %s -X %s -Q %s -l %s"
                   % (OMCommand.getLocalScript("Local_PreInstall"),
                      ACTION_FIX_SERVER_PACKAGE_OWNER,
                      self.context.user,
                      self.context.group,
                      self.context.xmlFile,
                      self.context.clusterToolPath,
                      self.context.localLog))
            # check the env file
            if self.context.mpprcFile != "":
                cmd += " -s %s" % self.context.mpprcFile
            self.context.logger.debug("Fix server pkg cmd: %s" % cmd)
            # exec the cmd
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.localMode,
                                            self.context.mpprcFile)

            self.del_remote_pkgpath()
        except Exception as e:
            raise Exception(str(e))
