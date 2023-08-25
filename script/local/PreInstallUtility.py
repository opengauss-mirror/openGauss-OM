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
# Description : PreInstallUtility.py is a utility to
# install the cluster on local node.
#############################################################################

import getopt
import sys
import os
import shutil
import subprocess
import time
import pwd
import grp
import configparser
import re


sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.Common import DefaultValue
from gspylib.common.OMCommand import OMCommand
from gspylib.common.LocalBaseOM import LocalBaseOM
from gspylib.common.ErrorCode import ErrorCode
from gspylib.os.gsfile import g_file
from os_platform.gsservice import g_service
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.cluster_file.cluster_log import ClusterLog
from base_utils.os.file_util import FileUtil
from base_utils.os.disk_util import DiskUtil
from domain_utils.cluster_file.profile_file import ProfileFile
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.cluster_file.package_info import PackageInfo
from base_utils.os.sshd_config import SshdConfig
from base_utils.os.env_util import EnvUtil
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from os_platform.linux_distro import LinuxDistro
from domain_utils.cluster_os.cluster_user import ClusterUser
from gspylib.common.aes_cbc_util import AesCbcUtil
from base_utils.os.user_util import UserUtil
from gspylib.component.DSS.dss_comp import DssInitCfg, Dss, UdevContext
from gspylib.component.DSS.dss_checker import DssConfig

ACTION_PREPARE_PATH = "prepare_path"
ACTION_CHECK_OS_VERSION = "check_os_Version"
ACTION_CREATE_OS_USER = "create_os_user"
ACTION_CHECK_OS_USER = "check_os_user"
ACTION_CREATE_CLUSTER_PATHS = "create_cluster_paths"
ACTION_SET_FINISH_FLAG = "set_finish_flag"
ACTION_SET_USER_ENV = "set_user_env"
ACTION_SET_TOOL_ENV = "set_tool_env"
ACTION_PREPARE_USER_CRON_SERVICE = "prepare_user_cron_service"
ACTION_PREPARE_USER_SSHD_SERVICE = "prepare_user_sshd_service"
ACTION_SET_LIBRARY = "set_library"
ACTION_SET_VIRTUALIP = "set_virtualIp"
ACTION_CHECK_HOSTNAME_MAPPING = "check_hostname_mapping"
ACTION_INIT_GAUSSLOG = "init_gausslog"
ACTION_CHECK_ENVFILE = "check_envfile"
ACTION_SET_ARM_OPTIMIZATION = "set_arm_optimization"
ACTION_CHECK_DISK_SPACE = "check_disk_space"
ACTION_SET_WHITELIST = "set_white_list"
ACTION_CHECK_OS_SOFTWARE = "check_os_software"
ACTION_FIX_SERVER_PACKAGE_OWNER = "fix_server_package_owner"
ACTION_CHANGE_TOOL_ENV = "change_tool_env"
ACTION_SET_CGROUP = "set_cgroup"
ACTION_CHECK_CONFIG = "check_config"
ACTION_DSS_NIT = "dss_init"

g_nodeInfo = None
envConfig = {}
configuredIps = []
checkOSUser = False
instance_type_set = ()
software_list = ["bzip2"]

ARM_PLATE = False


def get_package_path():
    """
    get package path
    :return:
    :return:
    """
    dir_name = os.path.dirname(os.path.realpath(__file__))
    package_path = os.path.join(dir_name, "./../../")
    package_path = os.path.realpath(package_path)
    return package_path


class PreInstall(LocalBaseOM):
    """
    install the cluster on local node
    """

    def __init__(self):
        """
        function: constructor
        """
        self.action = ""
        self.userInfo = ""
        self.user = ""
        self.group = ""
        self.clusterConfig = ""
        self.preparePath = ""
        self.checkEmpty = False
        self.envParams = []
        self.logFile = ""
        self.mpprcFile = ""
        self.user_env_file = ""
        self.clusterToolPath = ""
        self.tmpFile = ""
        self.clusterAppPath = ""
        self.white_list = {}
        self.logger = None

    def initGlobals(self):
        """
        init global variables
        input : NA
        output: NA
        """
        global instance_type_set

        self.logger = GaussLog(self.logFile, self.action)
        if self.clusterConfig != "":
            self.readConfigInfoByXML()

    def initNodeInfo(self):
        """
        function:
          init node info
        precondition:
          self.clusterInfo has been initialized
        input : NA
        output: NA
        """
        global g_nodeInfo

        hostName = NetUtil.GetHostIpOrName()
        g_nodeInfo = self.clusterInfo.getDbNodeByName(hostName)
        if g_nodeInfo is None:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51620"]
                                % "local" + " It is not a host named %s."
                                % hostName)

    def usage(self):
        """
Usage:
    python3 PreInstallUtility.py -t action -u user -T warning_type
    [-g group] [-X xmlfile] [-P path] [-Q clusterToolPath] [-D mount_path]
    [-e "envpara=value" [...]] [-w warningserverip] [-h nodename]
    [-s mpprc_file] [--check_empty] [-l log]
Common options:
    -t                                The type of action.
    -u                                The OS user of cluster.
    -g                                The OS user's group of cluster.
    -X                                The XML file path.
    -P                                The path to be check.
    -Q                                The path of cluster tool.
    -e "envpara=value"                The OS user environment variable.
    --check_empty                     Check path empty.
    -s                                The path of MPP environment file.
    -l                                The path of log file.
    -R                                The path of cluster install path.
    --help                            Show this help, then exit.
        """
        print(self.usage.__doc__)

    def parseCommandLine(self):
        """
        function: Check parameter from command line
        input : NA
        output: NA
        """
        try:
            opts, args = getopt.getopt(sys.argv[1:], "t:u:g:X:P:Q:e:s:l:f:R:",
                                       ["check_empty", "help"])
        except Exception as e:
            self.usage()
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

        if len(args) > 0:
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

        parameter_map = {"-t": self.action, "-u": self.user, "-g": self.group,
                         "-X": self.clusterConfig,
                         "-P": self.preparePath, "-Q": self.clusterToolPath,
                         "-s": self.mpprcFile, "-f": self.tmpFile,
                         "-R": self.clusterAppPath}
        parameter_keys = parameter_map.keys()

        for (key, value) in opts:
            if key == "--help":
                self.usage()
                sys.exit(0)
            elif key in parameter_keys:
                parameter_map[key] = value
            elif key == "-e":
                self.envParams.append(value)
            elif key == "--check_empty":
                self.checkEmpty = True
            elif key == "-l":
                self.logFile = os.path.realpath(value)
                self.tmpFile = value

            Parameter.checkParaVaild(key, value)
        self.action = parameter_map["-t"]
        self.user = parameter_map["-u"]
        self.group = parameter_map["-g"]
        self.clusterConfig = parameter_map["-X"]
        self.preparePath = parameter_map["-P"]
        self.clusterToolPath = parameter_map["-Q"]
        self.mpprcFile = parameter_map["-s"]
        self.tmpFile = parameter_map["-f"]
        self.clusterAppPath = parameter_map["-R"]

    def checkParameter(self):
        """
        function: Check parameter from command line
        input : NA
        output: NA
        """
        if (self.user == "" and self.action not in [ACTION_SET_VIRTUALIP,
                                                    ACTION_SET_WHITELIST]):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'u' + ".")

        try:
            if (self.action == ACTION_PREPARE_PATH
                    or self.action == ACTION_CREATE_CLUSTER_PATHS
                    or self.action == ACTION_SET_FINISH_FLAG
                    or self.action == ACTION_SET_USER_ENV):
                ClusterUser.checkUser(self.user, False)
        except Exception as e:
            GaussLog.exitWithError(str(e))
        parameter_list = [ACTION_CHECK_OS_VERSION, ACTION_SET_FINISH_FLAG,
                          ACTION_SET_USER_ENV, ACTION_SET_LIBRARY, \
                          ACTION_PREPARE_USER_CRON_SERVICE,
                          ACTION_PREPARE_USER_SSHD_SERVICE, \
                          ACTION_SET_VIRTUALIP, ACTION_INIT_GAUSSLOG,
                          ACTION_CHECK_ENVFILE, ACTION_CHECK_OS_SOFTWARE, \
                          ACTION_SET_ARM_OPTIMIZATION,
                          ACTION_CHECK_DISK_SPACE, ACTION_SET_WHITELIST,
                          ACTION_FIX_SERVER_PACKAGE_OWNER, ACTION_DSS_NIT,
                          ACTION_CHANGE_TOOL_ENV, ACTION_CHECK_CONFIG]
        if self.action == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + ".")
        function_map = {ACTION_PREPARE_PATH: self.checkPreparePathParameter,
                        ACTION_CREATE_OS_USER: self.checkCreateOSUserParameter,
                        ACTION_CHECK_OS_USER: self.checkCreateOSUserParameter,
                        ACTION_CREATE_CLUSTER_PATHS: \
                            self.checkCreateClusterPathsParameter,
                        ACTION_SET_TOOL_ENV: self.checkSetToolEnvParameter,
                        ACTION_SET_CGROUP:self.checkSetCgroupParameter,
                        ACTION_CHECK_HOSTNAME_MAPPING: \
                            self.checkHostnameMappingParameter}
        function_map_keys = function_map.keys()
        if self.action in function_map_keys:
            function_map[self.action]()
        elif self.action in parameter_list:
            pass
        else:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "t")

        if self.mpprcFile != "":
            if not os.path.isabs(self.mpprcFile):
                GaussLog.exitWithError(
                    ErrorCode.GAUSS_502["GAUSS_50213"] % "mpprc file")
                # 1.set tool env is the first time we use this mpprc file,
                # so we can check and create it.
            # 2.in other scene, the mpprc file should have exist,
            # so we just check its exists
            if self.action == ACTION_SET_TOOL_ENV:
                self.prepareMpprcFile()
            elif self.action == ACTION_CHECK_ENVFILE:
                pass
            else:
                if not os.path.exists(self.mpprcFile):
                    GaussLog.exitWithError(
                        ErrorCode.GAUSS_502["GAUSS_50201"] % self.mpprcFile)

        if self.logFile == "":
            self.logFile = ClusterLog.getOMLogPath(
                ClusterConstants.LOCAL_LOG_FILE, self.user, "")

    def prepareMpprcFile(self):
        """
        function: prepare MPPRC file, include path and permission
        input : NA
        output: NA
        """
        mpprcFilePath, mpprcFileName = os.path.split(self.mpprcFile)
        ownerPath = self.mpprcFile
        if not os.path.exists(self.mpprcFile):
            while True:
                # find the top path to be created
                (ownerPath, dirName) = os.path.split(ownerPath)
                if os.path.exists(ownerPath) or dirName == "":
                    ownerPath = os.path.join(ownerPath, dirName)
                    break

        try:
            # for internal useage, we should set
            # mpprc file permission to 644 here, and change to 640 later.
            FileUtil.createDirectory(mpprcFilePath, True)
            if os.path.exists(self.mpprcFile):
                pass
            else:
                FileUtil.createFile(self.mpprcFile, False)
            FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, ownerPath, True,
                              "shell")
            FileUtil.changeMode(DefaultValue.HOSTS_FILE, self.mpprcFile, False,
                              "shell")

            # if given group info in cmdline,
            # we will change the mpprc file owner, otherwise,
            # will not change the mpprc file owner.
            if self.group != "":
                FileUtil.changeOwner(self.user, ownerPath, True, "shell", link=True)
        except Exception as e:
            raise Exception(str(e))

    def checkPreparePathParameter(self):
        """
        function: check whether PreparePath parameter is right
        input : NA
        output: NA
        """
        if self.preparePath == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'P' + ".")
        if not os.path.isabs(self.preparePath):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_502["GAUSS_50213"] % self.preparePath)
        if self.group == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'g' + ".")

    def checkCreateOSUserParameter(self):
        """
        function: check whether CreateOSUser parameter is right
        input : NA
        output: NA
        """
        if self.group == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'g' + ".")

    def checkCreateClusterPathsParameter(self):
        """
        function: check whether CreateClusterPaths parameter is right
        input : NA
        output: NA
        """
        if self.group == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'g' + ".")

        if self.clusterConfig == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'X' + ".")
        if not os.path.exists(self.clusterConfig):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_502["GAUSS_50201"] % self.clusterConfig)
        if not os.path.isabs(self.clusterConfig):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_502["GAUSS_50213"] % "configuration file")

    def checkSetToolEnvParameter(self):
        """
        function: check whether SetToolEnv parameter is right
        input : NA
        output: NA
        """
        if self.clusterToolPath == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'Q' + ".")

    def checkSetCgroupParameter(self):
        """
        function: check whether SetCgroup parameter is right
        input : NA
        output: NA
        """
        if self.clusterToolPath == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'Q' + ".")

    def checkHostnameMappingParameter(self):
        """
        function: check whether HostnameMapping parameter is right
        input : NA
        output: NA
        """
        if self.clusterConfig == "":
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50001"] % 'X' + ".")
        if not os.path.exists(self.clusterConfig):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_502["GAUSS_50201"] % self.clusterConfig)
        if not os.path.isabs(self.clusterConfig):
            GaussLog.exitWithError(
                ErrorCode.GAUSS_502["GAUSS_50213"] % "configuration file")

    def checkOSVersion(self):
        """
        function:
          check if OS version is supported
        input : NA
        output: NA
        """
        self.logger.log("Checking OS version.")
        try:
            if not DefaultValue.checkOsVersion():
                self.logger.logExit(ErrorCode.GAUSS_519["GAUSS_51900"])
        except Exception as e:
            self.logger.logExit(str(e))

        self.logger.log("Successfully checked OS version.")

    def prepareGivenPath(self, onePath, checkEmpty=True, checkSize=True):
        """
        function:
          make sure the path exist and user has private to access this path
        precondition:
          1.checkEmpty is True or False
          2.checkSize is True or False
          3.user and group has been initialized
          4.path list has been initialized
          5.path in path list is absolute path
        postcondition:
          1.
        input:
          1.path list
          2.checkEmpty
          3.checkSize
          4.path owner
        output:
          paths in os
        hiden info:na
        ppp:
        for each path in the path list
            save the path
            if path exist
                if need check empty
                    check empty
            else
                find the top path to be created
            create the path
            chown owner
            check permission
            check path size
        """
        self.logger.debug("Preparing path [%s]." % onePath)
        ownerPath = onePath
        if os.path.exists(onePath):
            if checkEmpty:
                fileList = os.listdir(onePath)
                if "pg_location" in fileList:
                    fileList.remove("pg_location")

                if len(fileList) != 0:
                    self.logger.logExit(
                        ErrorCode.GAUSS_502["GAUSS_50202"] % onePath)
            # check the owner of 'onepath' whether it is exist; if not,
            # change it's owner to the cluster user
            FileUtil.checkPathandChangeOwner(
                onePath, self.user,
                DefaultValue.KEY_DIRECTORY_MODE)
        else:
            while True:
                # find the top path to be created
                (ownerPath, dirName) = os.path.split(ownerPath)
                if os.path.exists(ownerPath) or dirName == "":
                    ownerPath = os.path.join(ownerPath, dirName)
                    break
            # create the given path
            self.logger.debug(
                "Path [%s] does not exist. Please create it." % onePath)
            self.makeDirsInRetryMode(onePath, DefaultValue.KEY_DIRECTORY_MODE)

        # if the path already exist, just change the top path mode,
        # else change mode with -R
        ##do not change the file mode in path if exist
        # found error: given path is /a/b/c, script path is /a/b/c/d,
        # then change mode with -R
        # will cause an error
        try:
            FileUtil.checkLink(ownerPath)
            if ownerPath != onePath:
                FileUtil.changeOwner(self.user, ownerPath, True, "shell", link=True)
                FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, ownerPath,
                                  True, "shell")
            else:
                FileUtil.changeOwner(self.user, ownerPath, False, "shell", link=True)
        except Exception as e:
            raise Exception(str(e))
        # check permission
        if self.action == ACTION_PREPARE_PATH:
            # for tool path, we only need check enter permission
            if not self.checkPermission(self.user, onePath, True):
                self.logger.logExit(
                    ErrorCode.GAUSS_501["GAUSS_50100"] % (onePath, self.user))
        else:
            if not self.checkPermission(self.user, onePath):
                self.logger.logExit(
                    ErrorCode.GAUSS_501["GAUSS_50102"] % (onePath, self.user))
        # check path size
        if checkSize:
            DefaultValue.checkDirSize(
                onePath,
                DefaultValue.INSTANCE_DISK_SIZE, self.logger)

        self.logger.debug("Successfully prepared path.")

    def makeDirsInRetryMode(self, onePath, dirMode, retryTimes=3):
        """
        function: command for creating path,
        if failed then retry.Retry for 3 times
        input : onePath,dirMode,retryTimes
        output: NA
        """
        retry = 1
        try_flag = False
        while True:
            try_flag = FileUtil.createDirectory(onePath, True, dirMode)
            if try_flag:
                break
            if retry >= retryTimes:
                self.logger.logExit(
                    ErrorCode.GAUSS_502["GAUSS_50206"] % onePath)
            retry += 1

    def checkPermission(self, username, originalPath, check_enter_only=False):
        """
        function:
          check if given user has operation permission for given path
        precondition:
          1.user should be exist
          2.originalPath should be an absolute path
          3.caller should has root privilege
        postcondition:
          1.return True or False
        input : username,originalPath,check_enter_only
        output: True/False
        """
        # action: check and modify the permission of path before do check
        # For the scene: After delete the user
        # when execute gs_postuninstall --delete-user,
        # the owner of GPHOME path becomes no owner;
        # when execute gs_preinstall secondly,
        # report permisson error about GPHOME
        FileUtil.checkPathandChangeOwner(originalPath, self.user,
                                             DefaultValue.KEY_DIRECTORY_MODE)
        cmd = "su - %s -c \"cd '%s'\"" % (username, originalPath)
        status = subprocess.getstatusoutput(cmd)[0]
        if status != 0:
            return False

        if check_enter_only:
            return True

        testFile = os.path.join(originalPath, "touch.tst")
        cmd = "su - %s -c 'touch %s && chmod %s %s' >/dev/null 2>&1" % (
            username, testFile, DefaultValue.KEY_FILE_MODE, testFile)
        status = subprocess.getstatusoutput(cmd)[0]
        if status != 0:
            return False

        cmd = "su - %s -c 'echo aaa > %s' >/dev/null 2>&1" \
              % (username, testFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            cmd = "rm -f '%s' >/dev/null 2>&1" % testFile
            subprocess.getstatusoutput(cmd)
            return False

        cmd = "rm -f '%s' >/dev/null 2>&1" % testFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            return False

        return True

    def checkMappingForHostName(self):
        """
        function: Checking hostname mapping
        input : NA
        output: NA
        """
        self.logger.debug("Checking hostname mapping.")
        try:
            self.logger.debug("Change file[/etc/hosts] mode.")
            FileUtil.changeMode(DefaultValue.HOSTS_FILE, "/etc/hosts")
            OMCommand.checkHostnameMapping(self.clusterInfo)
        except Exception as e:
            self.logger.logExit(str(e))

        self.logger.debug("Successfully checked hostname mapping.")

    def checkPasswdIsExpires(self):
        """
        function: Check if user password is expires
        input : NA
        output: False or True
        """
        cmd = g_file.SHELL_CMD_DICT["checkPassword"] % (
            self.user, "'^Password expires'")
        (timestatus, output) = subprocess.getstatusoutput(cmd)
        if timestatus != 0:
            self.logger.logExit(ErrorCode.GAUSS_514[
                                    "GAUSS_51400"] % cmd
                                + " Error:\n%s" % output)
        result = output.split(":")[1].strip()
        try:
            passwd_expiretime = time.strptime(result, "%b %d, %Y")
        except Exception:
            return False
        local_time_string = time.strftime("%b %d, %Y")
        local_time = time.strptime(local_time_string, "%b %d, %Y")
        expire_seconds = int(time.mktime(passwd_expiretime))
        lcoalTime_seconds = int(time.mktime(local_time))
        if expire_seconds < lcoalTime_seconds:
            return True
        else:
            return False

    def delTempFile(self, filename):
        """
        function: delete temp file
        input : filename
        output: NA
        """
        try:
            if os.path.isfile(filename):
                FileUtil.removeFile(filename, "shell")
        except Exception as e:
            raise Exception(str(e))

    def addAllowItemValue(self, allow_item, item_value):
        """
        function: Add "item_value" to allow_item in /etc/ssh/sshd_config if necessary.
        input:
            item_value: the item_value name in string.
        output:
            1: Successfully added.
            0: Already added, or allow_item is disabled, nothing to do.
        """
        # If "allow_item" in sshd is enabled, only specified users can be authenticated.
        # So we need to add the newly created group to white list.
        sshd_config = "/etc/ssh/sshd_config"
        allow_item_cmd = "cat " + sshd_config + " | grep '\\<%s\\>'" % allow_item
        (status, output) = subprocess.getstatusoutput(allow_item_cmd)

        # No results found. "grep" returns non-zero if nothing grepped.
        # AllowItem in sshd_config is disabled.
        if (status != 0) and (output is None or len(output) == 0):
            self.logger.debug("'%s' of sshd_config is disabled." % allow_item)
            return 0
        elif status != 0:
            # It really failed.
            self.logger.logExit(
                ErrorCode.GAUSS_503["GAUSS_50321"] % allow_item + " Command: %s. Error: \n%s"
                % (allow_item_cmd, output))
            return 0
        else:
            allow_item_res = str(output).lstrip().lstrip("\t")
            if allow_item_res.find('#') == 0:
                return 0
            elif allow_item_res.find('#') > 0:
                allow_item_res = allow_item_res[0: allow_item_res.find('#')]
            if item_value not in allow_item_res.split(' '):
                set_allow_item_cmd = "sed -i '/\\<%s\\>/d' %s" % (allow_item, sshd_config)
                (status, output) = subprocess.getstatusoutput(set_allow_item_cmd)
                if status != 0:
                    self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % set_allow_item_cmd +
                                        " Error:\n%s" % output)
                SshdConfig.setKeyValueInSshd(allow_item_res, item_value)
        # Attention: here we will not restart sshd service,
        # as it will be done in "prepareUserSshdService".
        self.logger.debug("item_value '%s' added to '%s' of %s successfully." %
                          (item_value, allow_item, sshd_config))
        return 1

    def createOSUser(self):
        """
        function: Create OS user and group
        input : NA
        output: NA
        """
        self.logger.debug("Creating OS user on local host.")

        tempFile = "/tmp/temp.%s" % self.user

        userstatus = 0
        # Check if user exists
        try:
            DefaultValue.getUserId(self.user)
            # check user passwd is Expires
            if self.checkPasswdIsExpires():
                self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50307"])
        except Exception:
            self.logger.debug("User[%s] not exists" % self.user)
            userstatus = 1

        # check if the user is correct in /home/user path
        needChgOwner = False
        if userstatus == 1:
            userHomePath = "/home/%s" % self.user
            if os.path.exists(userHomePath):
                try:
                    homePathUser = FileUtil.getfileUser(userHomePath)[0]
                    if homePathUser != self.user:
                        needChgOwner = True
                except Exception:
                    needChgOwner = True

        # Check if group exists
        cmd = "cat /etc/group | awk -F [:] '{print $1}' | grep '^%s$'" \
              % self.group
        (groupstatus, groupoutput) = subprocess.getstatusoutput(cmd)
        if groupstatus != 0:
            self.logger.debug(
                "Command for checking group exists: %s." % cmd
                + " Error:\n%s" % groupoutput)

        # user exists and input group not exists
        if userstatus == 0 and groupstatus != 0:
            self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50305"]
                                + " User:Group[%s:%s]" 
                                % (self.user, self.group))

        # user exists and group exists
        if userstatus == 0 and groupstatus == 0:
            # UID is 0
            if pwd.getpwnam(self.user).pw_uid == 0:
                self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50302"])

            # user's group != input group
            groupInfo = grp.getgrgid(pwd.getpwnam(self.user).pw_gid).gr_name
            if self.group != groupInfo:
                self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50305"])

            self.delTempFile(tempFile)

            return

        if checkOSUser:
            self.logger.debug("checkOSUser is[%s] and abnormal exit!" %checkOSUser)
            sys.exit(1)

        # user does not exist and group does not exist
        if userstatus != 0 and groupstatus != 0:
            self.logger.debug(
                "Creating OS user [%s:%s]." % (self.user, self.group))
            cmd = "groupadd %s && useradd -m -g %s %s" % (
                self.group, self.group, self.user)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(
                    ErrorCode.GAUSS_502["GAUSS_50206"] % 'OS user'
                    + " Command: %s. Error: \n%s" % (cmd, output))

        # user does not exist and group exists
        if userstatus != 0 and groupstatus == 0:
            self.logger.debug(
                "Creating OS user [%s:%s]." % (self.user, self.group))
            cmd = "useradd -m -g %s %s" % (self.group, self.user)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(
                    ErrorCode.GAUSS_502["GAUSS_50206"] % 'OS user'
                    + " Command: %s. Error: \n%s" % (cmd, output))
        if needChgOwner:
            userProfile = ClusterConstants.HOME_USER_BASHRC % self.user
            if not os.path.exists(userProfile):
                cmd = g_file.SHELL_CMD_DICT["copyFile"] % \
                      ("/etc/skel/.bash*", "/home/%s/" % self.user)
                status, output = subprocess.getstatusoutput(cmd)
                if status != 0:
                    self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50214"]
                                        % userProfile + " Error: " + output)
            FileUtil.changeOwner(self.user, "/home/%s/" % self.user, True)

        self.logger.debug("Changing user password.")
        try:
            # check if the file is a link
            tmp_path = "/tmp/os_user_pwd"
            password = AesCbcUtil.aes_cbc_decrypt_with_multi(*AesCbcUtil.format_path(tmp_path))
            cmd = "rm -rf %s" % tmp_path
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_511["GAUSS_51103"] % cmd)
        except Exception as e:
            self.delTempFile(tempFile)
            self.logger.debug("Changing user password failed. %s" % str(e))
            self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50311"] % "user")

        cmd = "echo '%s:%s' | chpasswd" % (self.user, password)
        (status, output) = CmdUtil.getstatusoutput_by_fast_popen(cmd)
        if status != 0:
            self.logger.logExit(
                ErrorCode.GAUSS_503["GAUSS_50311"] % self.user
                + " Error: \n%s" % output)

    def createClusterPaths(self):
        """
        function:
          create all paths for cluster
            install path
            tmp path
            data path
            log path
        precondition:
          1.self.clusterInfo has been initialized
        postcondition:
          1.all path exist and have proper authority
        input:NA
        output:na
        hiden info:
          current info of each path
        """
        self.logger.debug("Creating paths for cluster.")
        if self.checkFinishFlag():
            needCheckEmpty = False
        else:
            needCheckEmpty = True

        self.initNodeInfo()
        self.prepareGaussLogPath()
        self.prepareInstallPath(needCheckEmpty)
        self.prepareTmpPath(needCheckEmpty)
        self.prepareDataPath(needCheckEmpty)
        if self.clusterInfo.enable_dss == 'on':
            idx = DssConfig.get_current_dss_id_by_dn(self.clusterInfo.dbNodes,
                                                     self.dbNodeInfo)
            if idx != -1 and not EnvUtil.is_fuzzy_upgrade(
                    self.user, self.logger, self.mpprcFile):
                self.prepare_dss_home_path(idx)
            else:
                self.logger.debug('In dss-mode, the dn does not ' \
                     'exist on the current node or in upgrade.')

        self.logger.debug("Successfully created paths for cluster.")


    def prepare_dss_inst_ini(self, dss_home, dss_id):
        '''
        Preparing the DSS Configuration File
        '''

        dss_inst_ini = os.path.realpath(
            os.path.join(dss_home, 'cfg', 'dss_inst.ini'))
        context = list(
            DssInitCfg(dss_id,
                       dss_home,
                       self.clusterInfo.dss_config,
                       dss_ssl=False))
        FileUtil.write_custom_context(
            dss_inst_ini, context, authority=DefaultValue.KEY_FILE_MODE_IN_OS)

    def prepare_dss_vg_ini(self, dss_home):
        '''
        Preparing the VG Configuration File
        '''

        dss_dict = {}
        dss_vg_ini = os.path.realpath(
            os.path.join(dss_home, 'cfg', 'dss_vg_conf.ini'))
        
        lun_map = self.clusterInfo.dss_vg_info
        lun_dss_vgname = self.clusterInfo.dss_vgname
        
        # dss_vg_info checker
        infos = list(filter(None, re.split(r':|,', lun_map)))

        # The volume name must correspond to the disk.
        if (lun_map.count(':') != lun_map.count(',') + 1) or (
                not infos) or (infos and len(infos) % 2 != 0):
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50414"] %
                            "The volume name must correspond to the disk.")

        # The shared volume must be in vg_config.
        if lun_dss_vgname not in infos[::2]:
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50419"] %
                            (lun_dss_vgname, lun_map))
        
        for i in range(0, len(lun_map), 2):
            key = lun_map[i]
            value = lun_map[i + 1]
            dss_dict[key] = value

        context = [':'.join([k, v]) for k, v in dss_dict.items()]
        FileUtil.write_custom_context(
            dss_vg_ini, context, authority=DefaultValue.KEY_FILE_MODE_IN_OS)


    def prepare_dss_home_path(self, dss_id):
        '''
        Preparing the DSS Home Directory
        '''

        dss_home = self.clusterInfo.dss_home
        dss_cfg = os.path.join(dss_home, 'cfg')
        dss_log = os.path.join(dss_home, 'log')
        self.prepareGivenPath(dss_cfg, False)
        self.prepareGivenPath(dss_log, False)
        self.prepare_dss_inst_ini(dss_home, dss_id)
        # this function does not need to be detected under multipath
        # self.prepare_dss_soft_link()
        self.prepare_dss_vg_ini(dss_home)


    def prepare_dss_soft_link(self):
        '''
        Creating a disk soft link
        '''

        self.logger.debug("Creating dss disk link.")
        context = list(
            UdevContext((self.user, self.group), self.clusterInfo,
                        DiskUtil.get_disk_dev_id, DiskUtil.get_disk_dev_name))

        self.logger.debug("Checking dss udev directory.")
        if os.path.isdir(UdevContext.DSS_UDEV_DIR):
            rule_file = os.path.join(UdevContext.DSS_UDEV_DIR,
                                     UdevContext.DSS_UDEV_NAME) % self.user

            for disk in UdevContext.get_all_phy_disk(self.clusterInfo):
                cmd = "cd %s; grep -iro '%s' | grep -v grep | grep -v '%s'" % (
                    UdevContext.DSS_UDEV_DIR, DiskUtil.get_disk_dev_id(disk),
                    UdevContext.DSS_UDEV_NAME % self.user)
                sts, out = subprocess.getstatusoutput(cmd)
                if sts == 1:
                    continue
                if sts != 0 :
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                    "Error: \n%s" % out)
                if out.strip():
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51406"] %
                                    (disk, UdevContext.DSS_UDEV_DIR) +
                                    " Error information: \n%s." % out)
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            UdevContext.DSS_UDEV_DIR)

        if os.path.isfile(rule_file):
            os.remove(rule_file)
        FileUtil.write_custom_context(rule_file,
                                      context,
                                      authority=DefaultValue.KEY_HOSTS_FILE)
        FileUtil.changeMode(DefaultValue.SQL_FILE_MODE, rule_file)
        FileUtil.changeOwner('root', rule_file)

        retry = 30
        for times in range(retry):
            DiskUtil.active_udev()
            flags = all([
                os.path.islink(link) for link in UdevContext.get_all_disk_alias(
                    self.user, self.group, self.clusterInfo)
            ])
            if not flags and times == retry - 1:
                raise Exception(ErrorCode.GAUSS_516['GAUSS_51656'])
            elif not flags:
                time.sleep(1)
            elif flags:
                break
        self.logger.debug("Successfully created dss disk link.")

    def prepareGaussLogPath(self):
        """
        function: Prepare Gausslog Path
        input : NA
        output: NA
        """
        self.logger.debug("Creating log path.")
        gaussdb_dir = self.clusterInfo.logPath

        self.logger.debug("Checking %s directory [%s]." % (
            VersionInfo.PRODUCT_NAME, gaussdb_dir))
        if not os.path.exists(gaussdb_dir):
            self.makeDirsInRetryMode(gaussdb_dir,
                                     DefaultValue.KEY_DIRECTORY_MODE)

        try:
            # change gaussdb dir mode
            FileUtil.checkLink(gaussdb_dir)
            FileUtil.changeMode(DefaultValue.DIRECTORY_MODE, gaussdb_dir, False,
                              "shell")
            FileUtil.changeOwner(self.user, gaussdb_dir, False, "shell", link=True)
        except Exception as e:
            raise Exception(str(e))

        # make user log dir
        user_dir = "%s/%s" % (self.clusterInfo.logPath, self.user)
        self.prepareGivenPath(user_dir, False)

        # change the directory permission. Remove hidden folders
        cmdDir = "find '%s' -type d ! -name '.*' -exec chmod '%s' {} \;" % (
            user_dir, DefaultValue.DIRECTORY_MODE)
        (status, diroutput) = subprocess.getstatusoutput(cmdDir)
        self.logger.debug(
            "Command to chmod the directory in directory[%s] " % user_dir)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502[
                                    "GAUSS_50201"] % user_dir
                                + " Error:\n%s" % diroutput)
        # change the file permission
        FileUtil.getchangeFileModeCmd(user_dir)

        # change user log dir owner
        try:
            FileUtil.changeOwner(self.user, user_dir, True, "shell",
                               retry_flag=True, retry_time=15, waite_time=1, link=True)
        except Exception as e:
            raise Exception(str(e))
        self.logger.debug("Successfully created log path.")

    def prepareTmpPath(self, needCheckEmpty):
        """
        function: Prepare temporary path
        input : needCheckEmpty
        output: NA
        """
        self.logger.debug("Creating temporary path.")
        tmpDir = DefaultValue.getTmpDir(self.user, self.clusterConfig)
        self.prepareGivenPath(tmpDir, needCheckEmpty)
        self.logger.debug("Successfully created temporary path.")

    def prepareDataPath(self, needCheckEmpty):
        """
        function: Prepare data path
        input : needCheckEmpty
        output: NA
        """
        self.logger.debug("Creating data path.")

        self.logger.debug("Checking CM datadir.")
        if g_nodeInfo.cmDataDir:
            self.prepareGivenPath(g_nodeInfo.cmDataDir, False)

            self.logger.debug("Checking CMAgent configuration.")
            for cmaInst in g_nodeInfo.cmagents:
                self.prepareGivenPath(cmaInst.datadir, needCheckEmpty)

            self.logger.debug("Checking CMServer configuration")
            for cmsInst in g_nodeInfo.cmservers:
                self.prepareGivenPath(cmsInst.datadir, needCheckEmpty)

        self.logger.debug("Checking database node configuration.")
        for dnInst in g_nodeInfo.datanodes:
            self.prepareGivenPath(dnInst.datadir, needCheckEmpty)
            if len(dnInst.ssdDir) != 0:
                self.prepareGivenPath(dnInst.ssdDir, needCheckEmpty)

        self.logger.debug("Checking database node XLOG PATH configuration.")
        for dnInst in g_nodeInfo.datanodes:
            if dnInst.xlogdir != '':
                self.prepareGivenPath(dnInst.xlogdir, needCheckEmpty)

        self.logger.debug("Successfully created data path.")

    def prepareInstallPath(self, needCheckEmpty):
        """
        function: Prepare installation path
        input : needCheckEmpty
        output: NA
        """
        self.logger.debug("Creating installation path.")

        installPath = self.clusterInfo.appPath
        if os.path.exists(installPath) and not os.path.islink(installPath):
            self.logger.logExit(ErrorCode.GAUSS_502[
                                    "GAUSS_50200"] % installPath
                                + " Please remove it."
                                  " It should be a symbolic link to "
                                  "$GAUSSHOME if it exists")
        versionFile = VersionInfo.get_version_file()
        commitid = VersionInfo.get_version_info(versionFile)[2]
        installPath = installPath + "_" + commitid
        if not needCheckEmpty:
            # check the upgrade app directory, if we set up a new
            # directory for upgrade, we must check empty
            gaussHome = ClusterDir.getInstallDir(self.user)
            if os.path.islink(gaussHome):
                actualPath = os.path.realpath(gaussHome)
                oldCommitId = actualPath[-8:]
                if oldCommitId != commitid and os.path.isdir(installPath):
                    fileList = os.listdir(installPath)
                    # mat have upgrade some node, so the dir should
                    # have the binary info
                    # if use other version to preinstall when upgrade
                    # is not finished, then we need to preinstall
                    # current upgrade version
                    if "bin" in fileList and "etc" in fileList and \
                            "include" in fileList:
                        pass
                    else:
                        needCheckEmpty = True

        self.logger.debug("Install path %s." % installPath)
        self.prepareGivenPath(installPath, needCheckEmpty)
        self.checkUpperPath(needCheckEmpty, installPath)

        if self.clusterInfo.enable_dss:
            dss_app = os.path.realpath(
                os.path.join(os.path.dirname(installPath),
                             f'dss_app_{commitid}'))
            self.logger.debug("Dss app path %s." % dss_app)
            self.prepareGivenPath(dss_app, False)

        self.logger.debug("Successfully created installation path.")

    def checkUpperPath(self, needCheckEmpty, installPath):
        """
        if first prepare the path, we should have the permission to
         write file with self.user, so we can create
        symbolic link in install process
        :param needCheckEmpty: get GAUSS_ENV is 2, we have successfully
        install the cluster, so needCheckEmpty is False
        :param installPath: is same with $GAUSSHOME
        :return: NA
        """
        if not needCheckEmpty:
            return
        upperDir = os.path.dirname(installPath)
        cmd = "su - %s -c \"if [ -w %s ];then echo 1; else echo 0;fi\"" % (
                  self.user, upperDir)
        self.logger.debug(
            "Command to check if we have write permission for upper path:"
            " %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(
                ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "Error: \n%s" % str(
                    output))
        if output:
            output = output.splitlines()[-1]
        if output == "1":
            return
        fileList = os.listdir(upperDir)
        if installPath in fileList:
            fileList.remove(installPath)
        if len(fileList) != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50202"] % upperDir +
                                " Or user [%s] has write"
                                " permission to directory %s."
                                " Because it will create "
                                "symbolic link [%s] to install path [%s] "
                                "in gs_install process with this user."
                                % (self.user, upperDir,
                                   self.clusterInfo.appPath, installPath))
        self.logger.log("The path [%s] is empty, change the owner to %s." % (
            upperDir, self.user))
        FileUtil.changeOwner(self.user, upperDir, False, "shell", link=True)
        self.logger.log("Successfully change the owner.")

    def prepareUserCronService(self):
        """
        function:
        1.set cron bin permission
        2.check and make sure user have pemission to use cron
        3.restart cron service
        input : NA
        output: NA
        """
        self.logger.debug("Preparing user cron service.")
        ##1.set crontab file permission
        crontabFile = "/usr/bin/crontab"
        if not os.path.exists(crontabFile):
            self.logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50201"] % crontabFile)
        if not os.path.isfile(crontabFile):
            self.logger.logExit(
                ErrorCode.GAUSS_502["GAUSS_50210"] % crontabFile)

        # attention:crontab file permission should be 755
        FileUtil.changeOwner("root", crontabFile)
        FileUtil.changeMode(DefaultValue.MAX_DIRECTORY_MODE, crontabFile)
        cmd = "chmod u+s '%s'" % crontabFile
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_501[
                                    "GAUSS_50107"] % crontabFile
                                + " Command:%s. Error:\n%s" % (
                                    cmd, output))

        ##2.make sure user have permission to use cron
        cron_allow_file = "/etc/cron.allow"
        if not os.path.isfile(cron_allow_file):
            FileUtil.createFile(cron_allow_file)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, cron_allow_file)
        FileUtil.changeOwner("root", cron_allow_file)

        FileUtil.deleteLine(cron_allow_file, "^\\s*%s\\s*$" % self.user)
        FileUtil.writeFile(cron_allow_file, [self.user])

        ##3.restart cron service
        self.logger.debug("Restarting CRON service.")
        retryTimes = 0
        while True:
            (status, output) = g_service.manageOSService("crond", "restart")
            if status == 0:
                break
            if retryTimes > 1:
                self.logger.logExit(ErrorCode.GAUSS_508[
                                        "GAUSS_50802"]
                                    % "restart crond" + " Error:\n%s" % output)
            else:
                self.logger.debug(
                    "Failed to restart CRON service."
                    " Retrying.\nOutput: \n%s." % str(
                        output))
            retryTimes = retryTimes + 1
            time.sleep(1)

        self.logger.debug("Successfully prepared user CRON service.")

    def prepareUserSshdService(self):
        """
        function: set MaxStartups to 1000.
        input : NA
        output: NA
        """
        self.logger.debug("Preparing user SSHD service.")
        sshd_config_file = "/etc/ssh/sshd_config"
        paramName = "MaxStartups"
        sshdNeedReload = False

        # 1.change the MaxStartups
        cmd = "grep -E '^[ ]*MaxStartups[ ]*1000$' %s" % sshd_config_file
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            cmd = "sed -i '/^.*%s.*$/d' %s" % (paramName, sshd_config_file)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514[
                                        "GAUSS_51400"] % cmd
                                    + " Error:\n%s" % output)
            SshdConfig.setKeyValueInSshd('MaxStartups', '1000')
            self.logger.debug("Write MaxStartups value.")
            sshdNeedReload = True

        # Check if is DWS mode.
        OsVersionFlag = False
        rdsFlag = False
        chrootFlag = False
        distname = LinuxDistro.linux_distribution()[0]
        if distname in "euleros":
            OsVersionFlag = True
        if os.path.exists("/rds/"):
            rdsFlag = True
        if os.path.exists("/var/chroot/"):
            chrootFlag = True
        if OsVersionFlag and rdsFlag and chrootFlag:
            # DWS mode has its own value of ClientAliveInterval,
            # which is 43200.
            self.logger.debug("In DWS mode, skip set ClientAliveInterval.")
            self.logger.debug("Successfully prepared user SSHD service.")
            return

        # 2.change the ClientAliveInterval
        cmd = "grep -E '^[ ]*ClientAliveInterval[ ]*0$' %s" % sshd_config_file
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            cmd = "sed -i '/^.*ClientAliveInterval.*$/d' %s" % sshd_config_file
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514[
                                        "GAUSS_51400"] % cmd
                                    + " Error:\n%s" % output)
            SshdConfig.setKeyValueInSshd('ClientAliveInterval', '0')
            self.logger.debug("Write ClientAliveInterval value.")
            sshdNeedReload = True

        # 3. add cluster owner to 'AllowUsers' or 'AllowGroups' to
        # /etc/ssh/sshd_config if necessary.
        if self.addAllowItemValue(allow_item="AllowUsers", item_value=self.user) > 0:
            sshdNeedReload = True

        if self.addAllowItemValue(allow_item="AllowGroups", item_value=self.group) > 0:
            sshdNeedReload = True

        if sshdNeedReload:
            self.logger.debug("Reload sshd service.")
            (status, output) = g_service.manageOSService("sshd", "reload")
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_508[
                                        "GAUSS_50802"] % "reload sshd"
                                    + " Error:\n%s" % output)

        self.logger.debug("Successfully prepared user SSHD service.")

    def setFinishFlag(self):
        """
        function:
          set env show that do pre install succeed
        precondition:
          1.user has been created
        postcondition:
          1.the value of GAUSS_ENV is 1
        input:NA
        output:user's env GAUSS_ENV
        hiden:
          the evn name and value to be set
        ppp:
        if user bashrc file does not exist
            create it
        clean GAUSS_ENV in user bashrc file
        set GAUSS_ENV in user bashrc file
        After set env, set daily alarm.
        """
        # get and check the userProfile
        self.user_env_file = ProfileFile.get_user_bashrc(self.user)
        if self.mpprcFile != "" and self.mpprcFile is not None:
            userProfile = self.mpprcFile
        else:
            # check if user profile exist
            userProfile = self.user_env_file
            if not os.path.exists(userProfile):
                self.logger.logExit(ErrorCode.GAUSS_502[
                                        "GAUSS_50201"] % 'user profile'
                                    + " Please create %s." % userProfile)

        # clean user's environmental variable
        self.logger.debug("Deleting user's environmental variable.")
        DefaultValue.cleanUserEnvVariable(userProfile,
                                          cleanGS_CLUSTER_NAME=False, cleanLD_LIBRARY=False)
        self.logger.debug("Successfully delete user's environmental variable.")
        if self.mpprcFile:
            # import environment variable separation scene to bashrc
            FileUtil.deleteLine(self.user_env_file,
                                "^\\s*export\\s*%s=.*$" % DefaultValue.MPPRC_FILE_ENV)
            context = "export %s=%s" % (DefaultValue.MPPRC_FILE_ENV, self.mpprcFile)
            FileUtil.writeFile(self.user_env_file, [context])
            self.logger.debug("Successfully flush 'export MPPRC' in bashrc")

        # user's environmental variable
        self.logger.debug("Seting user's environmental variable.")
        installPath = self.clusterInfo.appPath
        tmpPath = ClusterConfigFile.readClusterTmpMppdbPath(self.user,
                                                           self.clusterConfig)
        logPath = "%s/%s" % (
            ClusterConfigFile.readClusterLogPath(self.clusterConfig), self.user)
        agentPath = self.clusterInfo.agentPath
        agentLogPath = self.clusterInfo.agentLogPath
        FileUtil.checkLink(userProfile)
        DefaultValue.setUserEnvVariable(userProfile, installPath, tmpPath,
                                        logPath, agentPath, agentLogPath)

        if (os.path.exists('/var/chroot/') and os.path.exists(
                '/rds/datastore/')):
            clusterName = self.clusterInfo.name
            ProfileFile.updateUserEnvVariable(userProfile, "GS_CLUSTER_NAME",
                                               clusterName)

        self.logger.debug("Successfully set user's environmental variable.")

        # Set daily alarm.
        self.logger.debug("Set daily alarm.")
        # Check if is DWS mode.
        OsVersionFlag = False
        rdsFlag = False
        chrootFlag = False
        distname, version, idnum = LinuxDistro.linux_distribution()
        # check if OS version is Euler
        if distname in "euleros":
            OsVersionFlag = True
        if os.path.exists("/rds/"):
            rdsFlag = True
        if os.path.exists("/var/chroot/"):
            chrootFlag = True
        # Change the owner of Gausslog
        self.logger.debug("Changing the owner of Gausslog.")
        user_dir = "%s/%s" % (self.clusterInfo.logPath, self.user)
        self.logger.debug("Changing the owner of GPHOME: %s." % user_dir)
        FileUtil.changeOwner(self.user, user_dir, True, "shell", retry_flag=True,
                           retry_time=15, waite_time=1, link=True)
        omLogPath = os.path.dirname(self.logFile)
        self.logger.debug(
            "Changing the owner of preinstall log path: %s." % omLogPath)
        if os.path.exists(omLogPath):
            FileUtil.changeOwner(self.user, omLogPath, True, "shell",
                               retry_flag=True, retry_time=15, waite_time=1, link=True)
        self.logger.debug("Checking the permission of GPHOME: %s." % user_dir)
        cmd = g_file.SHELL_CMD_DICT["checkUserPermission"] % (
            self.user, user_dir)
        self.logger.debug("The command of check permission is: %s." % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_514[
                                    "GAUSS_51400"] % cmd
                                + " Error:\n%s" % output)
        self.logger.debug("Successfully change the owner of Gausslog.")

        # get the value of GAUSS_ENV
        self.logger.debug("Setting finish flag.")
        cmd = "su - %s -c 'source %s;echo $GAUSS_ENV' 2>/dev/null" % (
            self.user, userProfile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514[
                                "GAUSS_51400"] % cmd + " Error:\n%s" % output)
        ENVNUM = output.split("\n")[0]
        # set finish flag
        if str(ENVNUM) != "2":
            ProfileFile.updateUserEnvVariable(userProfile, "GAUSS_ENV", "1")

        self.logger.debug("Successfully set finish flag.")

    def checkFinishFlag(self):
        """
        function:
        return True means have execed preinstall script
        return False means have not execed preinstall script
        input : NA
        output: True/False
        """
        if self.mpprcFile != "":
            cmd = "su - root -c 'source %s;echo $GAUSS_ENV' 2>/dev/null" \
                  % self.mpprcFile
        else:
            cmd = "su - %s -c 'source ~/.bashrc;echo $GAUSS_ENV' 2>/dev/null" \
                  % self.user
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.debug(
                "Failed to obtain the environment variable "
                "$GAUSS_ENV. Error:\n%s" % output)
            return False

        if output.strip() == str(1) or output.strip() == str(2):
            self.logger.debug("Successfully checked GAUSS_ENV.")
            return True
        else:
            self.logger.debug(
                "The environmental variable [GAUSS_ENV]'s value "
                "is invalid. The value is:%s" % (
                    output.strip()))
            return False

    def setUserProfile(self, userEnvConfig):
        """
        function:
          set env into user's .bashrc file
        precondition:
          1.env list are valid
          2.user exist
        input:
          1.env list
          2.use name
        postcondition:na
        output:na
        hiden:
          the file to be set into
        """
        self.logger.debug("Setting user profile.")
        if self.mpprcFile != "":
            # have check its exists when check parameters,
            # so it should exist here
            userProfile = self.mpprcFile
        else:
            # check if user profile exist
            userProfile = ProfileFile.get_user_bashrc(self.user)
            if not os.path.exists(userProfile):
                self.logger.debug(
                    "User profile does not exist. Please create %s."
                    % userProfile)
                cmd = "su - %s -c 'touch %s && chmod %s %s'" % (
                    self.user, userProfile, DefaultValue.DIRECTORY_MODE,
                    userProfile)
                status, output = subprocess.getstatusoutput(cmd)
                if status != 0:
                    self.logger.logExit(ErrorCode.GAUSS_502[
                                            "GAUSS_50206"] % userProfile
                                        + " Error:\n%s" % output)

        # clean ENV in user bashrc file
        self.logger.debug("User profile exist. Deleting crash old ENV.")
        for env in userEnvConfig:
            FileUtil.deleteLine(userProfile, "^\\s*export\\s*%s=.*$" % env)
            self.logger.debug("Deleting %s in user profile" % env)

        # set ENV in user bashrc file
        self.logger.debug(
            "Successfully deleted crash old ENV. Setting new ENV.")
        for env in userEnvConfig:
            context = "export %s=%s" % (env, userEnvConfig[env])
            FileUtil.writeFile(userProfile, [context])

        self.logger.debug("Successfully set user profile.")

    def getUserProfile(self):
        """
        function: set env into /etc/profile
        input : OSEnvConfig
        output: NA
        """
        if self.mpprcFile != "":
            # have check its exists when check parameters,
            # so it should exist here
            userProfile = self.mpprcFile
        else:
            # check if os profile exist
            userProfile = ClusterConstants.ETC_PROFILE
            if not os.path.exists(userProfile):
                self.logger.debug(
                    "Profile does not exist. Please create %s." % userProfile)
                FileUtil.createFile(userProfile)
                FileUtil.changeMode(DefaultValue.DIRECTORY_MODE, userProfile)
        return userProfile

    def setDBUerProfile(self):
        """
        function:
        set database user's env into user's .bashrc file.
        env list are provided by user
        input : NA
        output: NA
        """
        self.logger.debug(
            "Setting %s user profile." % VersionInfo.PRODUCT_NAME)
        # check if need to set env parameter
        if len(self.envParams) == 0:
            self.logger.debug("No need to set ENV.")
            return

        # parse env user inputed
        for param in self.envParams:
            keyValue = param.split("=")
            if len(keyValue) != 2:
                self.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50000"] % param)
            envConfig[keyValue[0].strip()] = keyValue[1].strip()

        # set env into user's profile
        self.setUserProfile(envConfig)

        self.logger.debug(
            "Successfully set %s  user profile." % VersionInfo.PRODUCT_NAME)

    def clearToolEnv(self, userProfile):
        # clean ENV in os profile
        self.logger.debug("OS profile exists. Deleting crash old tool ENV.")
        # clean MPPRC FILE PATH
        if self.mpprcFile != "":
            FileUtil.deleteLine(userProfile,
                              "^\\s*export\\s*%s=.*$"
                              % DefaultValue.MPPRC_FILE_ENV)
            self.logger.debug(
                "Deleting crash MPPRC file path in"
                " user environment variables.")

        # clean GPHOME
        FileUtil.deleteLine(userProfile, "^\\s*export\\s*GPHOME=.*$")
        # clean GPHOME
        FileUtil.deleteLine(userProfile, "^\\s*export\\s*UNPACKPATH=.*$")
        self.logger.debug(
            "Deleting crash GPHOME in user environment variables.")
        # clean PGDATA
        FileUtil.deleteLine(userProfile, "^\\s*export\\s*PGDATA*")
        # clean LD_LIBRARY_PATH
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*LD_LIBRARY_PATH=\\$GPHOME\\/script"
                          "\\/gspylib\\/clib:\\$LD_LIBRARY_PATH$")
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*LD_LIBRARY_PATH=\\$GPHOME\\/lib:"
                          "\\$LD_LIBRARY_PATH$")
        self.logger.debug(
            "Deleting crash LD_LIBRARY_PATH in user environment variables.")

        # clean PATH
        if userProfile is ClusterConstants.ETC_PROFILE:
            FileUtil.deleteLine(userProfile,
                                "^\\s*export\\s*PATH=\\$PATH:\\$GPHOME\\/pssh-2.3.1\\/bin:"
                                "\\$GPHOME\\/script$")
            FileUtil.deleteLine(userProfile,
                                "^\\s*export\\s*PATH=\\$PATH:\\$GPHOME\\/script\\/gspylib\\"
                                "/pssh\\/bin:\\$GPHOME\\/script$")
            FileUtil.deleteLine(userProfile,
                                "^\\s*export\\s*PATH=\\$PATH:\\/root\\/gauss_om\\/%s\\"
                                "/script$" % self.user)
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PATH=\\$GPHOME\\/pssh-2.3.1\\/bin:"
                          "\\$GPHOME\\/script:\\$PATH$")
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PATH=\\$GPHOME\\/script\\/gspylib\\"
                          "/pssh\\/bin:\\$GPHOME\\/script:\\$PATH$")
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PATH=\\/root\\/gauss_om\\/%s\\"
                          "/script:\\$PATH$" % self.user)
        self.logger.debug("Deleting crash PATH in user environment variables.")
        # clean PYTHONPATH
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PYTHONPATH=\\$GPHOME\\/lib")
        self.logger.debug(
            "Deleting crash PYTHONPATH in user environment variables.")

    def setToolEnv(self):
        """
        function: set environment variables
        input : NA
        output: NA
        """
        self.logger.debug("Setting tool ENV.")
        userProfile = self.getUserProfile()

        self.clearToolEnv(userProfile)

        # set ENV in os profile
        self.logger.debug(
            "Successfully deleted crash old tool ENV. Setting new tool ENV.")
        # set env in user profile
        try:
            # check if the file is a link
            FileUtil.checkLink(userProfile)
            # set mpprc file
            if self.mpprcFile != "":
                context = "export %s=%s" % (
                    DefaultValue.MPPRC_FILE_ENV, self.mpprcFile)
                FileUtil.writeFile(userProfile, [context])
            # set GPHOME
            FileUtil.writeFile(userProfile,
                             ["export GPHOME=%s" % self.clusterToolPath])
            package_dir = os.path.realpath(os.path.join(os.path.realpath(__file__), "../../../"))
            FileUtil.writeFile(userProfile, ["export UNPACKPATH=%s" % package_dir])
            # set PGDATA
            hostName = NetUtil.GetHostIpOrName()
            node_info = self.clusterInfo.getDbNodeByName(hostName)
            datadir = node_info.datanodes[0].datadir
            FileUtil.writeFile(userProfile,
                             ["export PGDATA=%s" % datadir])
            # set PATH
            if userProfile is ClusterConstants.ETC_PROFILE:
                FileUtil.writeFile(userProfile, [
                    "export PATH=$PATH:$GPHOME/script/gspylib/pssh/bin:"
                    "$GPHOME/script"])
            else:
                FileUtil.writeFile(userProfile, [
                    "export PATH=$GPHOME/script/gspylib/pssh/bin:"
                    "$GPHOME/script:$PATH"])
            # set LD_LIBRARY_PATH
            FileUtil.writeFile(userProfile, [
                "export LD_LIBRARY_PATH="
                "$GPHOME/script/gspylib/clib:$LD_LIBRARY_PATH"])
            FileUtil.writeFile(userProfile, [
                "export LD_LIBRARY_PATH=$GPHOME/lib:$LD_LIBRARY_PATH"])
            # set PYTHONPATH
            FileUtil.writeFile(userProfile, ["export PYTHONPATH=$GPHOME/lib"])
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Successfully set tool ENV.")

    def setLibrary(self):
        """
        function: Setting Library
        input : NA
        output: NA
        """
        self.logger.debug("Setting Library.")
        config_file_dir = "/etc/ld.so.conf"
        alreadySet = False
        # check if the file is a link
        FileUtil.checkLink(config_file_dir)
        if os.path.isfile(config_file_dir):
            with open(config_file_dir, "r") as fp:
                libs = fp.read()
            for lib in libs.split("\n"):
                if lib.strip() == "/usr/local/lib":
                    alreadySet = True
            if alreadySet:
                pass
            else:
                cmd = "echo '/usr/local/lib' >> '/etc/ld.so.conf' && ldconfig"
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"]
                                        % cmd + " Error: \n%s" % output)
        self.logger.debug("Successfully set Library.")

    def needSetCgroup(self):
        """
        function: Determine whether the current node needs to set Cgroup
        input : NA
        output: True     #need to set cgroup
                False    #not need to set cgroup
        """
        #Determine whether action is expansion.
        hostName = NetUtil.GetHostIpOrName()
        if len(self.clusterInfo.newNodes) == 0:
            return True
        #Determine whether the current node is a new node
        for node in self.clusterInfo.newNodes:
            if hostName == node.name:
                return True
        self.logger.debug("The current node is the old node for expansion, no need to set cgroup.")
        return False

    def decompressPkg2Cgroup(self):
        """
        function: decompress server package to libcgroup path. gs_cgroup will be used in preinstall
                  step.
        input: NA
        output: NA
        """
        self.logger.debug("decompress server package to libcgroup path.")

        bz2FileName = PackageInfo.get_package_file_path()
        curPath = os.path.dirname(os.path.realpath(__file__))
        libCgroupPath = os.path.realpath("%s/../../libcgroup" % curPath)
        if not os.path.exists(libCgroupPath):
            os.makedirs(libCgroupPath)

        cmd = "tar -xf %s -C %s" % (bz2FileName, libCgroupPath)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50217"] % bz2FileName +
                                " Error: \n%s" % output)

        # load library path env
        ld_path = os.path.join(libCgroupPath, "lib")
        if 'LD_LIBRARY_PATH' not in os.environ:
            os.environ['LD_LIBRARY_PATH'] = ld_path
            os.execve(os.path.realpath(__file__), sys.argv, os.environ)
        if not os.environ.get('LD_LIBRARY_PATH').startswith(ld_path):
            os.environ['LD_LIBRARY_PATH'] = ld_path + ":" + os.environ['LD_LIBRARY_PATH']
            os.execve(os.path.realpath(__file__), sys.argv, os.environ)

    def setCgroup(self):
        """
        function: Setting Cgroup
        input : NA
        output: NA
        """
        if not self.needSetCgroup():
            return
        self.logger.debug("Setting Cgroup.")
        # decompress server pakcage
        self.decompressPkg2Cgroup()
        #create temp directory for libcgroup etc
        cgroup_etc_dir = "%s/%s/etc" % (self.clusterToolPath, self.user)
        dirName = os.path.dirname(os.path.realpath(__file__))
        libcgroup_dir = os.path.realpath("%s/../../libcgroup/lib/libcgroup.so" % dirName)
        cgroup_exe_dir = os.path.realpath("%s/../../libcgroup/bin/gs_cgroup" % dirName)
        cmd = "rm -rf '%s/%s'" % (self.clusterToolPath, self.user)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50207"] %
                                'crash Cgroup congiguration file' + " Error: \n%s" % output)
        cmd = "if [ ! -d '%s' ];then mkdir -p '%s' && " % (cgroup_etc_dir, cgroup_etc_dir)
        cmd += "chmod %s '%s'/../ -R && chown %s:%s '%s'/../ -R -h;fi" %\
               (DefaultValue.KEY_DIRECTORY_MODE, cgroup_etc_dir,
                self.user, self.group, cgroup_etc_dir)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50208"] %
                                cgroup_etc_dir + " Error: \n%s" % output)

        # check or prepare libcgroup lib
        libcgroup_target = "/usr/local/lib/libcgroup.so.1"
        cmd = "ldd %s | grep 'libcgroup.so.1'" % cgroup_exe_dir
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % output)
        elif str(output).find("not found") != -1:
            cmd = "cp '%s' '%s' && ldconfig" % (libcgroup_dir, libcgroup_target)
            self.logger.debug("Need copy libcgroup.so.1 from %s to %s." %
                              (libcgroup_dir, libcgroup_target))
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50214"] % libcgroup_target +
                                    " Error: \n%s" % output)

        GPHOME_cgroupCfgFile = "%s/%s/etc/gscgroup_%s.cfg" % (self.clusterToolPath, self.user,
                                                              self.user)
        GAUSSHOME_cgroupCfgFile = "%s/etc/gscgroup_%s.cfg" % (self.clusterInfo.appPath, self.user)

        cmd = "(if [ -f '%s' ]; then cp '%s' '%s';fi)" % (GAUSSHOME_cgroupCfgFile,
                                                          GAUSSHOME_cgroupCfgFile,
                                                          GPHOME_cgroupCfgFile)
        self.logger.debug("Command for copying GAUSSHOME gscgroup's config file to GPHOME: %s\n"
                          % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50214"] % GAUSSHOME_cgroupCfgFile +
                                " Error:\n%s" % output)

        #create cgroup log file.
        binPath = self.clusterInfo.logPath + "/%s/bin/gs_cgroup/" % self.user
        if not os.path.exists(binPath):
            FileUtil.createDirectory(binPath)
        cgroupLog = binPath + "gs_cgroup.log"
        c_logger = GaussLog(cgroupLog, "gs_cgroup")

        #Get OS startup file
        initFile = DefaultValue.getOSInitFile()
        if initFile == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % "startup file of current OS" +
                            "The startup file for euleros OS is /etc/rc.d/rc.local.")

        # call cgroup
        # generate cgroup config file under cluster tool path.
        # and then copy it to GAUSSHOME path in gs_install step.
        execute_cmd = "%s -U %s --upgrade -c -H %s/%s" % (cgroup_exe_dir, self.user,
                                                          self.clusterToolPath, self.user)
        c_logger.debug("Command for executing gs_cgroup: %s\n" % execute_cmd)
        (status, output) = subprocess.getstatusoutput(execute_cmd)
        c_logger.debug("The result of execute gs_cgroup is:\n%s." % output)

        # set cgroup cmd to OS initFile. it will be executed at restart os system.
        gauss_home = self.clusterInfo.appPath
        init_cmd = "export LD_LIBRARY_PATH=%s/lib/ && %s/bin/gs_cgroup -U %s --upgrade -c -H %s" % \
             (gauss_home, gauss_home, self.user, gauss_home)
        set_init_cmd = "sed -i \"/.* -U %s .* -c -H .*/d\" %s && " % (self.user, initFile)
        set_init_cmd += "echo \"%s\" >> %s" % (init_cmd, initFile)
        c_logger.debug("Command for call cgroup cmd to init file: %s\n" % set_init_cmd)

        (status, output) = subprocess.getstatusoutput(set_init_cmd)
        c_logger.debug("The result of init gs_cgroup is:\n%s." % output)
        c_logger.debug(str(output))
        #Change the owner and permission.
        FileUtil.checkLink(binPath)
        FileUtil.changeOwner(self.user, binPath, True, retry_flag=True, link=True)
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, binPath, retry_flag=True)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, (binPath + "*"), retry_flag=True)
        if self.clusterInfo.logPath.strip() != "":
            pre_bin_path = self.clusterInfo.logPath + "/%s/bin" % self.user
            FileUtil.changeOwner(self.user, pre_bin_path, True, retry_flag=True, link=True)
        c_logger.closeLog()
        if status != 0:
            self.logger.logExit(str(output))

        self.logger.debug("Successfully set Cgroup.")

    def checkaio(self):
        # check libaio.so file exist
        cmd = "ls /usr/local/lib | grep '^libaio.so' | wc -l"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % output)
        elif int(output) == 0:
            cmd = "ls /usr/lib64 | grep '^libaio.so' | wc -l"
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                    " Error: \n%s" % output)
            elif int(output) == 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % "libaio.so or libaio.so.*")

    def check_config(self):
        """
        function: Check the XML file information on the remote execution node.
        input : NA
        output: NA
        """
        self.initNodeInfo()
        app_path = self.clusterInfo.appPath
        tmp_path = ClusterConfigFile.readClusterTmpMppdbPath(self.user, self.clusterConfig)
        tool_path = self.clusterToolPath
        for path in [app_path, tmp_path, tool_path]:
            UserUtil.check_path_owner(path)
        # check cm, cn, gtm, etcd, dn
        # check cm
        UserUtil.check_path_owner(g_nodeInfo.cmDataDir)
        for cma_inst in g_nodeInfo.cmagents:
            UserUtil.check_path_owner(cma_inst.datadir)
        for cms_inst in g_nodeInfo.cmservers:
            UserUtil.check_path_owner(cms_inst.datadir)
        # check gtm
        for gtm_inst in g_nodeInfo.gtms:
            UserUtil.check_path_owner(gtm_inst.datadir)
        # check cn
        for coo_inst in g_nodeInfo.coordinators:
            UserUtil.check_path_owner(coo_inst.datadir)
            if len(coo_inst.ssdDir) != 0:
                UserUtil.check_path_owner(coo_inst.ssdDir)
        # check dn
        for dn_inst in g_nodeInfo.datanodes:
            UserUtil.check_path_owner(dn_inst.datadir)
            if len(dn_inst.ssdDir) != 0:
                UserUtil.check_path_owner(dn_inst.ssdDir)
        # check dn xlog
        for dn_inst in g_nodeInfo.datanodes:
            if dn_inst.xlogdir != '':
                UserUtil.check_path_owner(dn_inst.xlogdir)
        # check etcd
        for etcd_inst in g_nodeInfo.etcds:
            UserUtil.check_path_owner(etcd_inst.datadir)

    def checkPlatformArm(self):
        """
        function: Setting ARM Optimization
        input : NA
        output: NA
        """
        self.logger.debug("Check if platform is ARM.")
        try:
            global ARM_PLATE
            cmd = "python3 -c 'import platform;print(platform.machine())'"
            self.logger.debug("Command for getting querying platform: %s"
                              % cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error: \n%s" % output)
            if str(output) == "aarch64":
                ARM_PLATE = True
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Successfully check platform ARM.")

    def setArmOptimization(self):
        """
        function: Setting ARM Optimization
        input : NA
        output: NA
        """
        self.logger.debug("Set ARM Optimization.")
        try:
            initFile = DefaultValue.getOSInitFile()
            clusterToolPath = self.clusterToolPath
            # set_arm_optimization
            init_cmd = "sed -i \"/(if test -f \'.*setArmOptimization.sh\';" \
                       " then export LC_ALL=C;" \
                       " sh .*setArmOptimization.sh;fi)/d\"  %s && " \
                       % initFile
            init_cmd += "echo " \
                        "\"(if test -f \'%s/sudo/setArmOptimization.sh\';" \
                        " then export LC_ALL=C;" \
                        "sh %s/sudo/setArmOptimization.sh;fi)\" >> %s" \
                        % (clusterToolPath, clusterToolPath, initFile)
            (status, output) = subprocess.getstatusoutput(init_cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % init_cmd + " Error: \n%s" % output)
            cmd = "if test -f \'%s/sudo/setArmOptimization.sh\'; then export" \
                  " LC_ALL=C;sh %s/sudo/setArmOptimization.sh;fi" \
                  % (clusterToolPath, clusterToolPath)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error: \n%s" % output)
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Successfully set ARM Optimization.")

    def checkVirtualIp(self):
        """
        function: Checking virtual IP
        input : NA
        output: NA
        """
        self.logger.debug("Checking virtual IP...")
        try:
            global configuredIps
            configuredIps = DefaultValue.checkIsPing(g_nodeInfo.virtualIp)

            # check the self.hostnameList values are whether or not local IPs
            #  obtain the all local IPs
            localAddrs = NetUtil.getIpAddressList()
            for ip in g_nodeInfo.virtualIp:
                if (ip not in configuredIps) and (ip not in localAddrs):
                    self.logger.logExit(ErrorCode.GAUSS_512["GAUSS_51224"]
                                        % ip)
        except Exception as e:
            self.logger.logExit(str(e))
        self.logger.debug("Successfully check virtual IP.")

    # IP do operation with netmask
    def netNum(self, ip, mask):
        """
        function: net number
        input : ip,mask
        output: netAddress
        """
        ipArr = ip.split(".")
        maskArr = mask.split(".")
        binaryIpArr = []
        binaryMaskArr = []
        for element in ipArr:
            biElement = bin(int(element)).split("b")[1]
            binaryIpArr.append("0" * (8 - len(biElement)) + biElement)
        for element in maskArr:
            biElement = bin(int(element)).split("b")[1]
            binaryMaskArr.append("0" * (8 - len(biElement)) + biElement)
        binaryIp = ".".join(binaryIpArr)
        binaryMask = ".".join(binaryMaskArr)
        netAddress = ""
        for i in range(len(binaryMask)):
            if binaryMask[i] == ".":
                netAddress += "."
            elif binaryIp[i] == "0" or binaryMask[i] == "0":
                netAddress += "0"
            else:
                netAddress += "1"
        return netAddress

    def setVirtualIp(self):
        """
        function: creating Virtual Ip
        input : NA
        output: NA
        """
        # The node instance initialization information
        self.initNodeInfo()
        # Add temporary files, save the virtual IP The actual
        # configuration for the failure rollback
        if os.path.exists(self.tmpFile):
            FileUtil.removeFile(self.tmpFile)
        tmpFileFp = None
        # If this node is not configured virtual IP, exit
        if g_nodeInfo.virtualIp == []:
            return
        # Check whether have configured the virtual ip
        self.checkVirtualIp()
        # If the current node virtual iP are configured, Exit
        if configuredIps == []:
            self.logger.debug("All virtual IP are configured.")
            return
        self.logger.debug("Start setting virtual IP...")
        try:
            # check if the file is a link
            FileUtil.checkLink(self.tmpFile)
            tmpFileFp = open(self.tmpFile, "w+")
            # Obtain network interface card of backIp,
            # get this virtual IP network adapter card through it.
            backIpNIC = NetUtil.getNICNum(g_nodeInfo.backIps[0])

            # Get this node netcard identifier already existing netcard
            cmd = "/sbin/ifconfig -a | grep '%s' | awk '{print $1}'" \
                  % backIpNIC
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_506["GAUSS_50604"]
                                % g_nodeInfo.backIps[0]
                                + " Error: \n%s" % output)
            # Gets the currently available virtual NIC
            nicList = output.split('\n')
            flagValues = []
            for nic in nicList:
                if nic.find(':') >= 0:
                    flagList = nic.split(':')
                    flag = flagList[1].strip()
                    if flag.isdigit():
                        flagValues.append(int(flag))
            vipNo = 0
            if flagValues != []:
                flagValues.sort()
                vipNo = flagValues[-1] + 1
            # Determine whether the same IP network segment.
            subnetMasks = []
            for backIp in g_nodeInfo.backIps:
                # Get backIP subnet mask
                subnetMask = ""
                allNetworkInfo = NetUtil.getAllNetworkInfo()
                for network in allNetworkInfo:
                    if backIp == network.ipAddress:
                        subnetMask = network.networkMask
                # Check whether the same subnet mask backIP
                if not len(subnetMasks):
                    subnetMasks.append(subnetMask)
                else:
                    if subnetMask != subnetMasks[0]:
                        raise Exception(ErrorCode.GAUSS_506["GAUSS_50606"])
            # start setting virtual IP
            backIp = g_nodeInfo.backIps[0]
            # get network startup file
            # On SuSE12.X there is no /etc/init.d/network. so skip it
            distname, version = LinuxDistro.linux_distribution()[0:2]
            if not (distname == "SuSE" and version == "12"):
                network_startupFile = "/etc/init.d/network"
                if not os.path.exists(network_startupFile):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                    ("startup file of the node network [%s]"
                                     % network_startupFile))
                if not os.path.isfile(network_startupFile):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] %
                                    ("startup file of the node network [%s]"
                                     % network_startupFile))

            # Get OS startup file
            OS_initFile = DefaultValue.getOSInitFile()
            if OS_initFile == "":
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % "startup file of current OS" +
                                " The startup file for SUSE OS is "
                                "/etc/init.d/boot.local.The startup file"
                                " for Redhat OS is /etc/rc.d/rc.local.")
            for configuredIp in configuredIps:
                # Check with backup virtual IP on the same network segment
                if self.netNum(backIp, subnetMasks[0]) != self.netNum(
                        configuredIp, subnetMasks[0]):
                    raise Exception(ErrorCode.GAUSS_512["GAUSS_51226"]
                                    + "Invalid Virtual IP: %s. The Back IP:"
                                      " %s. The subnetMasks: %s"
                                    % (configuredIp, backIp, subnetMasks[0]))
                # Configuring Virtual Ip
                cmd_LABEL = "ifconfig -a | grep '%s:%d'" % (backIpNIC, vipNo)
                (status, output) = subprocess.getstatusoutput(cmd_LABEL)
                if status == 0 or self.IsLABELconfigured(backIpNIC, vipNo):
                    vipNo += 1
                cmd = "/sbin/ifconfig %s:%d %s netmask %s up" % (backIpNIC,
                                                                 vipNo,
                                                                 configuredIp,
                                                                 subnetMask)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error: \n%s" % output)

                # Virtual IP configuration write OS startup file
                lineInfo = '^\\/sbin\\/ifconfig .* %s netmask .* up$' \
                           % configuredIp
                FileUtil.deleteLine(OS_initFile, lineInfo)
                if distname == "SuSE":
                    if version == "11":
                        # get configure virtual IP line number position
                        # of network startup file for suse OS
                        cmd = "grep -rn '[ ]*$FAKE ifup-route noiface -o" \
                              " rc $MODE' /etc/init.d/network"
                        (status, output) = subprocess.getstatusoutput(cmd)
                        outputlist = output.split("\n")
                        if status != 0 or len(outputlist) != 1:
                            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                            % cmd + " Error: \n%s" % output)
                        LineNumber = int(outputlist[0].split(":")[0])
                        lineInfo = '[ ]*\\/sbin\\/ifconfig .* %s netmask' \
                                   ' .* up$' % configuredIp
                        FileUtil.deleteLine(network_startupFile, lineInfo)
                        cmd = "sed -i \"%di\                        %s\" %s \
                            " % (LineNumber + 1, cmd, network_startupFile)
                        (status, output) = subprocess.getstatusoutput(cmd)
                        if status != 0:
                            raise Exception(ErrorCode.GAUSS_502["GAUSS_50223"]
                                            % OS_initFile + " Error: \n%s"
                                            % output)
                    # if the Ip has been configured, do nothing,
                    # else if the ip not configured but the LABEL
                    # has been configured LABEL number +1,else do as privous
                    if (self.IsIPconfigured(backIpNIC,
                                            configuredIp, vipNo) == 0):
                        cmd = ""
                    elif (self.IsIPconfigured(backIpNIC,
                                              configuredIp, vipNo) == 1):
                        vipNo += 1
                        cmd = "sed -i '$a\\\nIPADDR_%d=%s\\nNETMASK_%d=%s\\" \
                              "nLABEL_%d=%d' /etc/sysconfig/network/ifcfg-%s \
                            " % (vipNo, configuredIp, vipNo, subnetMask,
                                 vipNo, vipNo, backIpNIC)
                    else:
                        cmd = "sed -i '$a\\\nIPADDR_%d=%s\\nNETMASK_%d=%s\\" \
                              "nLABEL_%d=%d' /etc/sysconfig/network/ifcfg-%s \
                            " % (vipNo, configuredIp, vipNo, subnetMask,
                                 vipNo, vipNo, backIpNIC)
                else:
                    vip_nic = "%s:%d" % (backIpNIC, vipNo)
                    nicFile = "/etc/sysconfig/network-scripts/ifcfg-%s" \
                              % vip_nic
                    networkConfiguredFile = \
                        NetUtil.getNetworkConfiguredFile(configuredIp)
                    if networkConfiguredFile == "":
                        networkConfiguredFile = nicFile
                    cmd = "rm -rf '%s' && touch '%s' && chmod %s '%s' \
                        && echo -e 'DEVICE=%s\nIPADDR=%s\nNETMASK=%s' >> %s\
                        " % (networkConfiguredFile, nicFile,
                             DefaultValue.FILE_MODE, nicFile, vip_nic,
                             configuredIp, subnetMask, nicFile)
                if cmd != "" and cmd is not None:
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if status != 0:
                        raise Exception(ErrorCode.GAUSS_502["GAUSS_50223"]
                                        % OS_initFile + " Error: \n%s"
                                        % output)
                    print("%s" % configuredIp, file=tmpFileFp)
                vipNo += 1
            tmpFileFp.flush()
            tmpFileFp.close()
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, self.tmpFile)
        except Exception as e:
            if tmpFileFp:
                tmpFileFp.close()
            if os.path.exists(self.tmpFile):
                os.remove(self.tmpFile)
            self.logger.logExit(str(e))
        self.logger.debug("Successfully set virtual IP.")

    def IsIPconfigured(self, backIpNIC, configuredIp, i):
        """
        function: check has the ip or LABEL been configured ,
                  if the ip has been configured return 0 ,
                  else if the LABEL has been configured
                  return 1, else return 2
        input :backIpNIC,  configuredIp, LABEL number
        output: 0, 1, 2
        """
        networkfile = '/etc/sysconfig/network/ifcfg-' + backIpNIC
        LABEL = "LABEL_" + str(i) + "=" + str(i)
        # check if the file is a link
        FileUtil.checkLink(networkfile)
        with open(networkfile, "r") as fp:
            for line in fp:
                if line.split("=")[1].strip() == configuredIp:
                    return 0
                elif LABEL in line:
                    return 1
        return 2

    def IsLABELconfigured(self, backIpNIC, i):
        """
        function: check does the label exists already in network file,
                  if yes, return True, if no, return False
        input : backIpNIC ,LABEL number
        output: bool
        """
        networkfile = '/etc/sysconfig/network/ifcfg-' + backIpNIC
        cmd = "cat '%s' | grep LABEL_%d=%d" % (networkfile, i, i)
        status = subprocess.getstatusoutput(cmd)[0]
        if status == 0:
            return True
        else:
            return False

    def checkRemoveIpc(self):
        """
        function: Checking RemoveIpc
        input : NA
        output: NA
        """
        self.logger.debug("Checking RemoveIpc.")
        ipcPath = "/etc/systemd/logind.conf"
        if not os.path.exists(ipcPath):
            return
        distname, version = LinuxDistro.linux_distribution()[0:2]
        ipcList = FileUtil.readFile(ipcPath)
        ipcFlag = False
        noFlag = False
        for line in ipcList:
            if "RemoveIPC" in line:
                ipcFlag = True
                self.logger.debug("Find the removeIPC in file"
                                  " /etc/systemd/logind.conf,"
                                  " the content is: %s." % line)
                if "no" in line.lower() and not line.startswith("#"):
                    self.logger.debug("The value of removeIPC is no.")
                    noFlag = True
        for line in ipcList:
            if "RemoveIPC" in line:
                if "yes" in line.lower() and noFlag:
                    if not line.startswith("#"):
                        self.logger.debug("The value of removeIPC is yes.")
                        self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                            + " The value of removeIPC"
                                              " must be no.")
                if "yes" in line.lower() and not noFlag:
                    if not line.startswith("#"):
                        self.logger.debug("The value of removeIPC is yes.")
                        self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                            + " The value of removeIPC"
                                              " must be no.")
                    # In Redhat/Centos 7.2, RemoveIPC default value is yes.
                    elif (distname in ("redhat", "centos") and
                          version in "7.2"):
                        self.logger.debug("The value of removeIPC is yes.")
                        self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                            + " The value of removeIPC must"
                                              " be no in Redhat/Centos 7.2.")
        if not ipcFlag:
            # In Redhat/Centos 7.2, RemoveIPC default value is yes.
            if distname in ("redhat", "centos") and version in "7.2":
                self.logger.debug("The value of removeIPC is yes.")
                self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                    + " The value of removeIPC can not be"
                                      " empty in Redhat/Centos 7.2,"
                                      " it must be no.")
            else:
                self.logger.debug("Do not find RemoveIPC.")
        self.logger.debug("Successfully check RemoveIpc.")

    def checkAbrt(self):
        """
        function: Checking abrt, make sure abrt-hook-ccpp does not work.
        input : NA
        output: NA
        """
        self.logger.debug("Checking core_pattern.")
        sysFile = "/etc/sysctl.conf"
        coreFile = "/proc/sys/kernel/core_pattern"
        coreFlag = False

        coreList = FileUtil.readFile(sysFile)
        for line in coreList:
            if "kernel.core_pattern" in line and not line.startswith("#"):
                coreFlag = True
                self.logger.debug("Find the kernel.core_pattern in file"
                                  " /etc/sysctl.conf, the content is: %s."
                                  % line)
                if "|" in line and "abrt-hook-ccpp" in line:
                    self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                        + " The value of kernel.core_pattern "
                                          "can not combine with "
                                          "abrt-hook-ccpp in sysctl file.")

        if not coreFlag:
            coreList = FileUtil.readFile(coreFile)
            for line in coreList:
                if ("|" in line and "abrt-hook-ccpp" in line and
                        not line.startswith("#")):
                    self.logger.debug("Find the abrt-hook-ccpp in file "
                                      "/proc/sys/kernel/core_pattern,"
                                      " the content is: %s." % line)
                    self.logger.logExit(ErrorCode.GAUSS_523["GAUSS_52301"]
                                        + " Core_pattern file can not use "
                                          "abrt-hook-ccpp to dump core.")
        self.logger.debug("Successfully check core_pattern.")

    def checkDiskSpace(self):
        """
        function: check the disk if it has enough space to decompress
        input : NA
        output: NA
        """
        self.logger.debug("Checking available space.")
        versionFile = VersionInfo.get_version_file()
        version, number, commitid = VersionInfo.get_version_info(versionFile)
        actualPath = self.clusterAppPath + "_" + commitid
        if not os.path.exists(actualPath):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % actualPath)
        cmd = "df -h %s | awk '{print $4}' | xargs" % actualPath
        self.logger.debug("Command to check available disk space is:\n%s"
                          % cmd)
        # output is this format: "Avail 104G"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + "Error: output is '%s'." % output)
        self.logger.debug(
            "The result of checking available disk space is:\n%s" % output)
        size = output.split(" ")[1][:-1]
        if not size.isdigit():
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51633"]
                                % "available disk space")
        if int(size) < DefaultValue.GREY_DISK_SIZE:
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50411"]
                            % (DefaultValue.GREY_DISK_SIZE + 'G'))
        self.logger.debug("Successfully check host available space.")

    def initGaussLog(self):
        """
        function: creating GaussLog path. Before we modify the owner
                  of the path, we must create the path
        input : NA
        output: NA
        """
        sys.exit(0)

    def getWhiteList(self, confFile):
        """
        function: get whiteList
        input  : NA
        output : NA
        """
        print(confFile)
        fp = configparser.RawConfigParser()
        fp.read(confFile)

        optionList = fp.options("WHITELIST")
        white_dict = {}
        for key in optionList:
            value = fp.get("WHITELIST", key)
            ip_list = value.strip("\"").split(',')
            white_dict[key] = ip_list
        self.white_list = white_dict

    def setDefaultIptables(self):
        """
        function: set default ip tables
        input  : NA
        output : NA
        """
        cmd = "iptables -A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -p tcp" \
              " --dport 49537 -j ACCEPT && "
        cmd += "iptables -A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -p udp" \
               " --dport 60129 -j ACCEPT && "
        cmd += "iptables -A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -p tcp" \
               " --dport 49537 -j ACCEPT"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + " Error: \n%s" % output)
        self.logger.debug("Set default iptables successfully.")

    def checkWhiteList(self):
        """
        function: check whiteList
        input  : NA
        output : NA
        """
        if len(self.white_list) != 2:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"]
                            % "White list, please check confFile.")
        if ("inner" not in self.white_list.keys() or
                "outter" not in self.white_list.keys()):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"]
                            % "White list file with key error.")
        if '' in self.white_list['inner']:
            self.white_list['inner'].remove("")
        if '' in self.white_list['outter']:
            self.white_list['outter'].remove("")
        if (len(self.white_list['inner']) > 0 or
            len(self.white_list['outter'])) > 0:
            self.logger.debug("Inner white list is %s"
                              % self.white_list['inner'])
            self.logger.debug("Outter white list is %s"
                              % self.white_list['outter'])
            for ip in self.white_list['inner']:
                NetUtil.isIpValid(ip)
            for ip in self.white_list['outter']:
                NetUtil.isIpValid(ip)
            compare_list = [ip for ip in self.white_list['inner']
                            if ip in self.white_list['outter']]
            if len(compare_list) > 0:
                raise Exception(ErrorCode.GAUSS_527["GAUSS_52708"] +
                                "Inner IP and Outter IP have the same node.%s"
                                % compare_list)
            return True
        elif len(self.white_list['inner']) == 0 and \
                len(self.white_list['outter']) == 0:
            self.clearIptables()
            self.setDefaultIptables()
            return False
        else:
            return False

    def clearIptablesItem(self, clear_length, chain_type):
        """
        function: clear Iptables item
        input  : NA
        output : NA
        """
        exe_cmd = ""
        cmd = "iptables -D %s 1" % chain_type
        if clear_length.isdigit():
            for i in range(int(clear_length)):
                if (i + 1) == int(clear_length):
                    exe_cmd += cmd
                else:
                    exe_cmd += cmd + " && "
            self.logger.debug("Execute command: %s" % exe_cmd)
            status, output = subprocess.getstatusoutput(exe_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % exe_cmd
                                + " Error: \n%s" % output)
        self.logger.debug("Clear %s in iptables success." % chain_type)

    def clearIptablesChain(self, tables_str, chain_type):
        """
        function: clear ip tables chain
        input  : NA
        output : NA
        """
        output_result = tables_str.split("Chain %s (policy ACCEPT)"
                                         % chain_type)[1]
        if output_result.find("Chain") >= 0:
            output_result = output_result.split("Chain")[0]
        self.logger.debug("RESULT IS %s" % output_result)
        if len(output_result.strip().split('\n')) == 1:
            self.logger.debug("no need to clear iptables.")
            return
        self.logger.debug(output_result.strip().split('\n')[-1])
        output_length = output_result.strip().split('\n')[-1].split()[0]
        self.clearIptablesItem(output_length, chain_type)

    def clearWhiteListChain(self, tables_str):
        """
        function: clear white list chain
        input  : NA
        output : NA
        """
        if "Chain whitelist" in tables_str:
            old_white_str = tables_str.split("Chain whitelist")[1]
            if "Chain " in old_white_str:
                old_white_str = old_white_str.split("Chain ")[0]
            white_length = old_white_str.split('\n')[-1].strip().split()[0]
            self.clearIptablesItem(white_length, "whitelist")
            cmd = "iptables -X whitelist"
            status, output = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % output)
        else:
            self.logger.debug("There is no white list chain.")

    def clearIptables(self):
        """
        function: clear ip tables
        input  : NA
        output : NA
        """
        self.logger.debug("Start clear IP tables chain list.")
        cmd = "iptables -nL --line-number"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + " Error: \n%s" % output)
        # clear INPUT
        self.clearIptablesChain(output, "INPUT")
        # clear FORWARD
        self.clearIptablesChain(output, "FORWARD")
        # clear OUTPUT
        self.clearIptablesChain(output, "OUTPUT")
        # clear whitelist
        self.clearWhiteListChain(output)

        self.logger.debug("Clear IP tables successfully.")

    def setWhiteList(self):
        """
        function: set white list
        input  : NA
        output : NA
        """
        white_list = []
        white_list.extend(self.white_list['inner'])
        white_list.extend(self.white_list['outter'])
        cmd = "iptables -N whitelist && "
        for ip in white_list:
            cmd += "iptables -A whitelist -s %s -j ACCEPT && " % ip

        cmd += "iptables -A INPUT -m state --state RELATED," \
               "ESTABLISHED -j ACCEPT && "
        cmd += "iptables -A INPUT -p all -j whitelist && "
        cmd += "iptables -A INPUT -i lo -j ACCEPT && "
        cmd += "iptables -A INPUT -j REJECT --reject-with " \
               "icmp-host-prohibited"

        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + " Error: \n%s" % output)
        self.logger.debug("Set white list success.")

    def checkOSSoftware(self):
        """
        function: Check whether software meets the installation requirements
        input : NA
        output: NA
        """
        self.logger.debug("Checking os software.")
        no_install_soft_list = []
        for softname in software_list:
            if softname.startswith("bzip2"):
                cmd = "which bzip2"
            else:
                cmd = "rpm -qa|grep -c " + softname
            self.logger.debug("Command to check %s by %s" \
                              % (softname, cmd))
            # output is num of softname
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.debug(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                  + "Error: output is '%s'." % output)
                no_install_soft_list.append(softname)
        if len(no_install_soft_list) > 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51405"] % \
                            str(no_install_soft_list))
        self.logger.debug("Successfully check OS software.")

    def separate_root_scripts(self):
        """
        fix packgae path permission and owner
        :return:
        """
        package_path = get_package_path()
        om_root_path = os.path.dirname(package_path)
        if om_root_path == DefaultValue.ROOT_SCRIPTS_PATH:
            return

        self.logger.log("Separate om root scripts.")
        self.logger.debug("Create om root path.")
        # /root/gauss_om/user_name
        dest_path = os.path.join(DefaultValue.ROOT_SCRIPTS_PATH, self.user)
        if os.path.exists(dest_path):
            shutil.rmtree(dest_path)
        os.makedirs(dest_path)
        FileUtil.changeOwner("root", dest_path)

        # cp cgroup to /root/gauss_om/xxx
        self.logger.debug("cp cgroup to /root/gauss_om/xxx.")
        root_lib_dir = os.path.join(dest_path, "lib")
        root_bin_dir = os.path.join(dest_path, "bin")
        FileUtil.createDirectory(root_lib_dir, mode=DefaultValue.KEY_DIRECTORY_MODE)
        FileUtil.createDirectory(root_bin_dir, mode=DefaultValue.KEY_DIRECTORY_MODE)
        libcgroup_dir = os.path.realpath("%s/libcgroup/lib/libcgroup.so*" % package_path)
        cgroup_exe_dir = os.path.realpath("%s/libcgroup/bin/gs_cgroup" % package_path)
        cp_cmd = "cp -rf %s %s; cp -rf %s %s" % (libcgroup_dir, root_lib_dir, cgroup_exe_dir, root_bin_dir)
        CmdExecutor.execCommandLocally(cp_cmd)
        
        # cp $GPHOME script lib to /root/gauss_om/xxx
        cmd = ("cp -rf %s/script %s/lib %s/version.cfg %s"
               % (self.clusterToolPath, self.clusterToolPath,
                  self.clusterToolPath, dest_path))
        CmdExecutor.execCommandLocally(cmd)
        root_scripts = ["gs_postuninstall", "gs_preinstall",
                        "gs_checkos"]
        common_scripts = ["gs_sshexkey", "killall", "gs_checkperf"]
        # the script files are not stored in the env path
        not_in_env_scripts = ["gs_expansion"]
        root_save_files = root_scripts + common_scripts
        self.logger.debug("Delete user scripts in om root path.")
        # delete user scripts in om root path
        om_root_path = os.path.join(dest_path, "script")
        root_om_files = os.listdir(om_root_path)
        for root_file in root_om_files:
            if root_file.startswith("gs_"):
                if root_file not in root_save_files:
                    FileUtil.removeFile("%s/%s" % (om_root_path, root_file))
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE,
                          dest_path, recursive=True)

        self.logger.debug("Delete root scripts in om user path.")

        # set om root script path
        userProfile = self.getUserProfile()
        if userProfile is ClusterConstants.ETC_PROFILE:
            FileUtil.writeFile(userProfile, ["export PATH=$PATH:%s" % om_root_path])
        else:
            FileUtil.writeFile(userProfile, ["export PATH=%s:$PATH" % om_root_path])
        # delete root scripts in GPHOME
        om_user_path = os.path.join(self.clusterToolPath, "script")
        user_om_files = os.listdir(om_user_path)
        for user_file in user_om_files:
            if user_file.startswith("gs_"):
                if user_file in root_scripts or user_file in not_in_env_scripts:
                    FileUtil.removeFile("%s/%s" % (om_user_path, user_file))
        self.logger.debug("Delete cluster decompress package in root path.")

    def fixop_xml_and_mpp_file(self):
        """
        fix config file owner
        :return:
        """
        self.logger.log("change '%s' files permission and owner."
                        % self.clusterConfig)
        FileUtil.changeOwner(self.user, self.clusterConfig, link=True)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, self.clusterConfig)
        if self.mpprcFile:
            self.logger.log("change '%s' files permission and owner."
                            % self.mpprcFile)
            FileUtil.checkLink(self.mpprcFile)
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, self.mpprcFile)
            FileUtil.changeOwner(self.user, self.mpprcFile, link=True)

    def fixop_tool_path(self):
        """
        fix cluster path owner
        :return:
        """
        toolPath = self.clusterToolPath
        self.logger.log("change '%s' files permission and owner." % toolPath)
        FileUtil.changeOwner(self.user, toolPath, recursive=True, link=True)
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE,
                          toolPath, recursive=True)
        FileUtil.changeMode(DefaultValue.SPE_FILE_MODE,
                          "%s/script/gs_*" % toolPath)
        FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.sha256" % toolPath)
        FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.tar.gz" % toolPath)
        FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.tar.bz2" %
                          toolPath)
        FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/version.cfg" %
                          toolPath)

    def fixop_package_path(self):
        """
        fix software path permission
        root permission
        :return:
        """
        package_path = get_package_path()
        gsom_path = os.path.dirname(package_path)
        if gsom_path != DefaultValue.ROOT_SCRIPTS_PATH:
            self.logger.log("Change file mode in path %s" % package_path)
            FileUtil.changeOwner("root", package_path, recursive=True, link=True)
            FileUtil.changeMode(DefaultValue.MAX_DIRECTORY_MODE, package_path)
            FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE,
                              "%s/script" % package_path, recursive=True)
            FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.sha256" %
                              package_path)
            FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.tar.gz" %
                              package_path)
            FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/*.tar.bz2" %
                              package_path)
            FileUtil.changeMode(DefaultValue.MIN_FILE_MODE, "%s/version.cfg" %
                              package_path)

    def fix_dss_cap_permission(self):
        '''
        Modifying the dss binary cap permissions.
        '''
        self.logger.debug("Modifying dss cap permissions.")
        clib_app = os.path.realpath(
            os.path.join(self.clusterToolPath, "script/gspylib/clib",
                         f"dss_app_{VersionInfo.getCommitid()}"))

        dss_files = ['dsscmd', 'perctrl', 'dss_clear.sh']
        for file_ in dss_files:
            FileUtil.changeMode(DefaultValue.BIN_FILE_MODE,
                                os.path.join(clib_app, file_))

        FileUtil.change_caps(DefaultValue.CAP_WIO,
                             os.path.join(clib_app, 'cm_persist'))
        FileUtil.change_caps('{},{}'.format(DefaultValue.CAP_ADM, DefaultValue.CAP_WIO),
                             os.path.join(clib_app, 'perctrl'))
        self.logger.debug("Successfully modified dss cap permissions.")

    def fix_dss_dir_permission(self):
        '''
        Modify the permissions on some DSS-related directories and
        escalate the permissions in binary mode.
        '''
        self.logger.debug("Modifying dss home permissions.")
        dss_home = self.clusterInfo.dss_home
        cfg_dir = os.path.realpath(os.path.join(dss_home, 'cfg'))
        log_path = os.path.realpath(os.path.join(dss_home, 'log'))
        FileUtil.changeOwner(self.user, dss_home, link=True, recursive=True)

        dirs = [cfg_dir, log_path]
        for dir_ in dirs:
            FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, dir_)

        files = ["{}/*ini".format(cfg_dir)]
        for file_ in files:
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, file_)
        self.logger.debug("Successfully modified dss home permissions.")

    def fix_dss_disk_permission(self):
        '''
        Modifying DSS Disk Permissions
        '''

        vg_path = self.clusterInfo.dss_vg_info
        for file_ in list(filter(None, re.split(r',|:', vg_path)))[1::2]:
            self.logger.debug("Modifying dss disk permissions: %s" % file_)
            FileUtil.changeOwner(self.user, path=file_)
            FileUtil.changeMode(DefaultValue.DSS_DISK_MODE, path=file_)

    def fix_cm_disk_permission(self):
        cm_vote_disk = self.clusterInfo.cm_vote_disk
        self.logger.debug("Modifying cm disk permissions: %s" % cm_vote_disk)
        FileUtil.changeOwner(self.user, path=cm_vote_disk)
        FileUtil.changeMode(DefaultValue.DSS_DISK_MODE, path=cm_vote_disk)

        self.logger.log("Modifying cm disk permissions: %s" % cm_vote_disk)
        cm_share_disk = self.clusterInfo.cm_share_disk
        FileUtil.changeOwner(self.user, path=cm_share_disk)
        FileUtil.changeMode(DefaultValue.DSS_DISK_MODE, path=cm_share_disk)

    def fix_owner_and_permission(self):
        """
        function: fix owner and permission
        input: NA
        output: NA
        """
        self.fixop_package_path()
        self.fixop_tool_path()
        self.fixop_xml_and_mpp_file()
        if self.clusterInfo.enable_dss == 'on':
            idx = DssConfig.get_current_dss_id_by_dn(self.clusterInfo.dbNodes,
                                                     self.dbNodeInfo)
            if idx == -1:
                self.logger.debug('In dss-mode, the dn does not' \
                     ' exist on the current node.')
                return
            self.fix_dss_cap_permission()
            if EnvUtil.is_fuzzy_upgrade(self.user, self.logger, self.mpprcFile):
                return
            self.fix_dss_dir_permission()
            self.fix_dss_disk_permission()
            self.fix_cm_disk_permission()

    def fix_server_pkg_permission(self):
        """
        fix server package permission
        :return:
        """
        self.fix_owner_and_permission()
        self.separate_root_scripts()

    def dss_init(self):
        '''
        unreg the disk of the dss and about
        '''

        idx = DssConfig.get_current_dss_id_by_dn(self.clusterInfo.dbNodes,
                                                 self.dbNodeInfo)
        if idx == -1:
            self.logger.debug('In dss-mode, the dn does not' \
                    ' exist on the current node.')
            return

        if EnvUtil.is_fuzzy_upgrade(self.user, self.logger, self.mpprcFile):
            self.logger.debug('In upgrade, the disk lock will not to be unregistered.')
            return

        clib_app = os.path.realpath(
            os.path.join(self.clusterToolPath, 'script', 'gspylib', 'clib',
                         f'dss_app_{VersionInfo.getCommitid()}'))
        Dss.unreg_disk(self.clusterInfo.dss_home,
                       user=self.user,
                       clib_app=clib_app,
                       logger=self.logger)

    def clean_dss_env(self, mpprc_file):
        '''
        Clearing DSS Environment Variables
        '''

        for env in [
            'VGNAME', 'CM_VOTE_DISK', 'CM_SHARE_DISK', 'DSS_HOME',
            'RDMA_TYPE', 'RDMA_CONFIG', 'DSS_SSL'
        ]:
            FileUtil.deleteLine(mpprc_file, "^\\s*export\\s*{}=.*$".format(env))
            self.logger.debug(
                "Deleting crash {} in user environment variables.".format(env))

    def add_dss_env(self, mpprc_file):
        '''
        Setting DSS Environment Variables
        '''
        if self.clusterInfo.ss_interconnect_type == 'RDMA':
            FileUtil.writeFile(mpprc_file, [
                "export RDMA_TYPE={}".format(
                    self.clusterInfo.ss_interconnect_type)
            ])
            if self.clusterInfo.ss_rdma_work_config:
                FileUtil.writeFile(mpprc_file, [
                    "export RDMA_CONFIG={}".format(
                        self.clusterInfo.ss_rdma_work_config.replace(
                            ' ', '/'))
                ])
        if self.clusterInfo.dss_ssl_enable == 'on':
            FileUtil.writeFile(mpprc_file, ["export DSS_SSL=on"])
        FileUtil.writeFile(
            mpprc_file,
            ["export VGNAME={}".format(self.clusterInfo.dss_vgname)])
        FileUtil.writeFile(
            mpprc_file,
            ["export DSS_HOME={}".format(self.clusterInfo.dss_home)])

    def changeToolEnv(self):
        """
        function: change software tool env path
        :return:
        """
        userpath = pwd.getpwnam(self.user).pw_dir
        userProfile = os.path.join(userpath, ".bashrc")

        if self.clusterInfo.enable_dss == 'on' and self.mpprcFile and os.path.isfile(
                self.mpprcFile):
            userProfile = self.mpprcFile
            self.clean_dss_env(userProfile)
            self.add_dss_env(userProfile)
            return

        if not os.path.exists(userProfile):
            self.logger.logExit(ErrorCode.GAUSS_502[
                                    "GAUSS_50201"] % 'user profile'
                                + " Please create %s." % userProfile)
        self.clean_tool_env(userProfile)
        self.clean_dss_env(userProfile)
        # set GPHOME
        FileUtil.writeFile(userProfile,
                         ["export GPHOME=%s" % self.clusterToolPath])
        # set PATH
        FileUtil.writeFile(userProfile, [
            "export PATH=$GPHOME/script/gspylib/pssh/bin:"
            "$GPHOME/script:$PATH"])
        # set LD_LIBRARY_PATH
        FileUtil.writeFile(userProfile, [
            "export LD_LIBRARY_PATH="
            "$GPHOME/script/gspylib/clib:$LD_LIBRARY_PATH"])
        FileUtil.writeFile(userProfile, [
            "export LD_LIBRARY_PATH=$GPHOME/lib:$LD_LIBRARY_PATH"])
        # set PYTHONPATH
        FileUtil.writeFile(userProfile, ["export PYTHONPATH=$GPHOME/lib"])

        if self.clusterInfo.enable_dss == 'on':
            self.add_dss_env(userProfile)

    def clean_tool_env(self, userProfile):
        # clean GPHOME
        FileUtil.deleteLine(userProfile, "^\\s*export\\s*GPHOME=.*$")
        self.logger.debug(
            "Deleting crash GPHOME in user environment variables.")

        # clean LD_LIBRARY_PATH
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*LD_LIBRARY_PATH=\\$GPHOME\\/script"
                          "\\/gspylib\\/clib:\\$LD_LIBRARY_PATH$")
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*LD_LIBRARY_PATH=\\$GPHOME\\/lib:"
                          "\\$LD_LIBRARY_PATH$")
        self.logger.debug(
            "Deleting crash LD_LIBRARY_PATH in user environment variables.")

        # clean PATH
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PATH=\\$GPHOME\\/pssh-2.3.1\\/bin:"
                          "\\$GPHOME\\/script:\\$PATH$")
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PATH=\\$GPHOME\\/script\\/gspylib\\"
                          "/pssh\\/bin:\\$GPHOME\\/script:\\$PATH$")
        self.logger.debug("Deleting crash PATH in user environment variables.")

        # clean PYTHONPATH
        FileUtil.deleteLine(userProfile,
                          "^\\s*export\\s*PYTHONPATH=\\$GPHOME\\/lib")
        self.logger.debug(
            "Deleting crash PYTHONPATH in user environment variables.")


    def run(self):
        """
        function: run method
        input  : NA
        output : NA
        """
        try:
            self.parseCommandLine()
            self.checkParameter()
            self.initGlobals()
        except Exception as e:
            GaussLog.exitWithError(str(e))

        try:
            if self.action == ACTION_PREPARE_PATH:
                self.prepareGivenPath(self.preparePath, self.checkEmpty)
            elif self.action == ACTION_CHECK_OS_VERSION:
                self.checkOSVersion()
            elif self.action == ACTION_CREATE_OS_USER:
                self.createOSUser()
            elif self.action == ACTION_CHECK_OS_USER:
                global checkOSUser
                checkOSUser = True
                self.createOSUser()
            elif self.action == ACTION_CHECK_HOSTNAME_MAPPING:
                self.checkMappingForHostName()
            elif self.action == ACTION_CREATE_CLUSTER_PATHS:
                self.createClusterPaths()
            elif self.action == ACTION_SET_FINISH_FLAG:
                self.checkAbrt()
                self.checkRemoveIpc()
                self.setFinishFlag()
            elif self.action == ACTION_SET_TOOL_ENV:
                self.setToolEnv()
            elif self.action == ACTION_SET_USER_ENV:
                self.setDBUerProfile()
            elif self.action == ACTION_PREPARE_USER_CRON_SERVICE:
                self.prepareUserCronService()
            elif self.action == ACTION_PREPARE_USER_SSHD_SERVICE:
                self.prepareUserSshdService()
            elif self.action == ACTION_SET_LIBRARY:
                self.setLibrary()
            elif self.action == ACTION_SET_VIRTUALIP:
                FileUtil.modifyFileOwnerFromGPHOME(self.logger.logFile)
                self.setVirtualIp()
            elif self.action == ACTION_INIT_GAUSSLOG:
                self.initGaussLog()
            elif self.action == ACTION_CHECK_DISK_SPACE:
                self.checkDiskSpace()
            elif self.action == ACTION_SET_ARM_OPTIMIZATION:
                self.checkPlatformArm()
                if ARM_PLATE:
                    self.setArmOptimization()
                else:
                    self.logger.debug("The plate is not arm,"
                                      " skip set arm options.")
            elif self.action == ACTION_CHECK_ENVFILE:
                (checkstatus, checkoutput) = \
                    ProfileFile.check_env_file(self.mpprcFile)
                if self.mpprcFile != "":
                    envfile = self.mpprcFile + " and /etc/profile"
                else:
                    envfile = "/etc/profile and ~/.bashrc"
                if not checkstatus:
                    self.logger.logExit(ErrorCode.GAUSS_518["GAUSS_51808"]
                                        % checkoutput + "Please check %s."
                                        % envfile)
            elif self.action == ACTION_SET_WHITELIST:
                self.logger.debug("Start setting white list.")
                confFile = os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "../../agent/om_agent.conf")
                if os.path.isfile(confFile):
                    self.getWhiteList(confFile)
                    if self.checkWhiteList():
                        self.clearIptables()
                        self.setWhiteList()
                else:
                    self.logger.debug("White list file not exist,"
                                      " skip set white list.")
            elif self.action == ACTION_CHECK_OS_SOFTWARE:
                self.checkOSSoftware()
            elif self.action == ACTION_FIX_SERVER_PACKAGE_OWNER:
                self.fix_server_pkg_permission()
            elif self.action == ACTION_DSS_NIT:
                self.dss_init()
            elif self.action == ACTION_CHANGE_TOOL_ENV:
                self.changeToolEnv()
            elif self.action == ACTION_SET_CGROUP:
                self.checkaio()
                self.setCgroup()
            elif self.action == ACTION_CHECK_CONFIG:
                self.check_config()
            else:
                self.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50000"]
                                    % self.action)
        except Exception as e:
            self.logger.logExit(str(e))


if __name__ == '__main__':
    """
    main function
    """
    try:
        preInstallUtility = PreInstall()
        preInstallUtility.run()
    except Exception as e:
        GaussLog.exitWithError(str(e))
