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
import pwd
import sys
import re
import getpass

sys.path.append(sys.path[0] + "/../")

from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import ClusterCommand, DefaultValue
from gspylib.common.OMCommand import OMCommand
from gspylib.os.gsfile import g_file
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.package_info import PackageInfo
from base_utils.os.password_util import PasswordUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil
from domain_utils.cluster_file.profile_file import ProfileFile

# action name
# prepare cluster tool package path
ACTION_PREPARE_PATH = "prepare_path"
# check the OS version
ACTION_CHECK_OS_VERSION = "check_os_Version"
# create os user
ACTION_CREATE_OS_USER = "create_os_user"
# check os user
ACTION_CHECK_OS_USER = "check_os_user"
# create cluster path
ACTION_CREATE_CLUSTER_PATHS = "create_cluster_paths"
# set finish flag
ACTION_SET_FINISH_FLAG = "set_finish_flag"
# set the user environment variable
ACTION_SET_USER_ENV = "set_user_env"
# set the tools environment variable
ACTION_SET_TOOL_ENV = "set_tool_env"
# prepare CRON service
ACTION_PREPARE_USER_CRON_SERVICE = "prepare_user_cron_service"
# prepare ssh service
ACTION_PREPARE_USER_SSHD_SERVICE = "prepare_user_sshd_service"
# set the dynamic link library
ACTION_SET_LIBRARY = "set_library"
# set virtual Ip
ACTION_SET_VIRTUALIP = "set_virtualIp"
# clean virtual Ip
ACTION_CLEAN_VIRTUALIP = "clean_virtualIp"
# check hostname on all nodes
ACTION_CHECK_HOSTNAME_MAPPING = "check_hostname_mapping"
# write /etc/hosts flag
HOSTS_MAPPING_FLAG = "#Gauss OM IP Hosts Mapping"
# init Gausslog
ACTION_INIT_GAUSSLOG = "init_gausslog"
# check envfile
ACTION_CHECK_ENVFILE = "check_envfile"
# check os software
ACTION_CHECK_OS_SOFTWARE = "check_os_software"
# change tool env
ACTION_CHANGE_TOOL_ENV = "change_tool_env"
#check config
ACTION_CHECK_CONFIG = "check_config"
#############################################################################
# Global variables
#   self.context.logger: globle logger
#   self.context.clusterInfo: global clueter information
#   self.context.sshTool: globle ssh tool interface
#   g_warningTpye: warning type
#############################################################################
iphostInfo = ""
topToolPath = ""
createTrustFlag = False


class PreinstallImpl:
    """
    init the command options
    save command line parameter values
    """

    def __init__(self, preinstall):
        """
        function: constructor
        """
        self.context = preinstall

    def installToolsPhase1(self):
        """
        function: install tools to local machine
        input: NA
        output: NA
        """
        pass

    def checkMpprcFile(self):
        """
        function: Check mpprc file path
        input : NA
        output: NA
        """
        clusterPath = []
        # get the all directorys list about cluster in the xml file
        dirs = self.context.clusterInfo.getClusterDirectorys()
        for checkdir in list(dirs.values()):
            # append directory to clusterPath
            clusterPath.extend(checkdir)
        # get tool path
        clusterPath.append(self.context.clusterToolPath)
        # get tmp path
        clusterPath.append(
            ClusterConfigFile.readClusterTmpMppdbPath(self.context.user,
                                                  self.context.xmlFile))
        self.context.logger.debug("Cluster paths %s." % clusterPath,
                                  "constant")
        # check directory
        FileUtil.checkIsInDirectory(self.context.mpprcFile, clusterPath)

    def getUserPasswd(self, name, point=""):
        """
        function:
            get user passwd
        input: name, point
        output: str
        """
        if point == "":
            self.context.logger.log("Please enter password for %s." % name,
                                    "constant")
        else:
            self.context.logger.log(
                "Please enter password for %s %s." % (name, point), "constant")
        passwdone = getpass.getpass()

        return passwdone

    def createTrustForRoot(self):
        """
        function:
          create SSH trust for user who call this script with root privilege
        precondition:
          1.create SSH trust tool has been installed on local host
        postcondition:
          caller's SSH trust has been created
        input: NA
        output: NA
        hideninfo:NA
        """
        if self.context.localMode or self.context.isSingle:
            if not self.context.skipHostnameSet:
                self.writeLocalHosts({"127.0.0.1": "localhost"})
            return
        try:
            # save the sshIps
            Ips = []
            # create trust for root
            # get the user name
            username = pwd.getpwuid(os.getuid()).pw_name
            # get the user sshIps
            sshIps = self.context.clusterInfo.getClusterSshIps()
            # save the sshIps to Ips
            for ips in sshIps:
                Ips.extend(ips)

            # create SSH trust for root user
            self.create_trust(Ips, username)
            self.context.logger.debug("Finished execute createTrustForRoot function.")

        except Exception as e:
            raise Exception(str(e))

    def create_trust(self, ip_list, username):
        """
        create ssh trust for root user
        """
        if self.context.preMode:
            return
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
        if flag.upper() in ("YES", "Y"):
            self.context.logger.log("Please enter password for root")
            retry_times = 0
            while True:
                try:
                    self.context.sshTool.createTrust(username, ip_list, self.context.mpprcFile,
                                                     self.context.skipHostnameSet)
                    break
                except Exception as err_msg:
                    if retry_times == 2:
                        raise Exception(str(err_msg))
                    if "Authentication failed" in str(err_msg):
                        self.context.logger.log(
                            "Password authentication failed, please try again.")
                        retry_times += 1
                    else:
                        raise Exception(str(err_msg))
            self.context.logger.debug("Finished execute sshTool.createTrust for root.")
            FileUtil.changeMode(DefaultValue.HOSTS_FILE, "/etc/hosts", False, "shell",
                              retry_flag=True)
            self.context.root_ssh_agent_flag = True
            self.context.logger.log("Successfully created SSH trust for the root permission user.")

    def delete_root_mutual_trust(self):
        """
        :return:
        """
        if self.context.localMode or self.context.isSingle:
            return
        if self.context.preMode or not self.context.root_ssh_agent_flag:
            return
        if not self.context.root_delete_flag:
            return
        self.context.logger.debug("Start Delete root mutual trust")

        # get dir path
        username = pwd.getpwuid(os.getuid()).pw_name
        homeDir = os.path.expanduser("~" + username)
        tmp_path = "%s/gaussdb_tmp" % homeDir
        authorized_keys = DefaultValue.SSH_AUTHORIZED_KEYS
        known_hosts = DefaultValue.SSH_KNOWN_HOSTS
        ssh_private = DefaultValue.SSH_PRIVATE_KEY
        ssh_pub = DefaultValue.SSH_PUBLIC_KEY

        # get cmd
        bashrc_file = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".bashrc")
        kill_ssh_agent_cmd = "ps ux | grep 'ssh-agent' | grep -v grep | awk '{print $2}' | " \
                             "xargs kill -9"
        delete_line_cmd = " ; sed -i '/^\\s*export\\s*SSH_AUTH_SOCK=.*$/d' %s" % bashrc_file
        delete_line_cmd += " && sed -i '/^\\s*export\\s*SSH_AGENT_PID=.*$/d' %s" % bashrc_file
        delete_shell_cmd = " && rm -rf %s" % tmp_path
        delete_shell_cmd += " && rm -f %s && rm -f %s" % (ssh_private, ssh_pub)
        delete_shell_cmd += " && sed -i '/#OM/d' %s " % authorized_keys
        delete_shell_cmd += " && sed -i '/#OM/d' %s " % known_hosts
        cmd = "%s" + delete_line_cmd + delete_shell_cmd

        # get remote node and local node
        host_list = self.context.clusterInfo.getClusterNodeNames()
        local_host = NetUtil.GetHostIpOrName()
        host_list.remove(local_host)

        # delete remote root mutual trust
        kill_remote_ssh_agent_cmd = DefaultValue.killInstProcessCmd("ssh-agent", True)
        self.context.sshTool.getSshStatusOutput(cmd % kill_remote_ssh_agent_cmd, host_list)
        # delete local root mutual trust
        CmdExecutor.execCommandLocally(cmd % kill_ssh_agent_cmd)
        self.context.logger.debug("Delete root mutual trust successfully.")

    def writeLocalHosts(self, result):
        """
        function:
         Write hostname and Ip into /etc/hosts
         when there's not the same one in /etc/hosts file
        precondition:
          NA
        postcondition:
           NA
        input: Dictionary result,key is IP and value is hostname
        output: NA
        hideninfo:NA
        """
        writeResult = []
        hostIPList = []
        hostIPInfo = ""
        # the temporary Files for /etc/hosts
        tmp_hostipname = "./tmp_hostsiphostname_%d" % os.getpid()
        # Delete the line with 'HOSTS_MAPPING_FLAG' in the /etc/hosts
        cmd = "grep -v '%s' %s > %s && cp %s %s && rm -rf '%s'" % \
              ("#Gauss.* IP Hosts Mapping", '/etc/hosts', tmp_hostipname, tmp_hostipname,
               '/etc/hosts', tmp_hostipname)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        # if cmd failed, append the output to writeResult
        if status != 0:
            FileUtil.removeFile(tmp_hostipname)
            writeResult.append(output)
        # cmd OK
        else:
            for (key, value) in list(result.items()):
                # set the string
                hostIPInfo = '%s  %s  %s' % (key, value, HOSTS_MAPPING_FLAG)
                hostIPList.append(hostIPInfo)
            # write the ip and hostname to /etc/hosts
            FileUtil.writeFile("/etc/hosts", hostIPList, mode="a+")

    def distributePackages(self):
        """
        function:
          distribute packages and xml to all nodes of cluster
        precondition:
          1.packages and xml exist on local host
          2.root SSH trust has been created
        postcondition:
          1.packages and xml exist on all hosts
          2.os user can access package and xml
        input:NA
        output:NA
        information hiding:
          1.the package and xml path
          2.node names
        ppp:
        check and create the server package path
        make compressed server package
        send server package
        Decompress package on every host
        change mode of packages
        check and create the xml path
        send xml
        change mode of xml file
        check and create the tool package path
        make compressed tool package
        send tool package
        change mode of packages
        """
        if self.context.localMode or self.context.isSingle:
            return

        self.context.logger.log("Distributing package.", "addStep")
        try:
            PackageInfo.makeCompressedToolPackage(self.context.clusterToolPath)

            # get the all node names in xml file
            hosts = self.context.clusterInfo.getClusterNodeNames()
            # remove the local node name
            hosts.remove(NetUtil.GetHostIpOrName())
            self.getTopToolPath(self.context.sshTool,
                                self.context.clusterToolPath, hosts,
                                self.context.mpprcFile)

            # Delete the old bak package in GPHOME before copy the new one.
            for bakPack in DefaultValue.PACKAGE_BACK_LIST:
                bakFile = os.path.join(self.context.clusterToolPath, bakPack)
                cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (bakFile, bakFile)
                self.context.logger.debug(
                    "Command for deleting bak-package: %s." % cmd)
                (status, output) = self.context.sshTool.getSshStatusOutput(
                    cmd, hosts)
                for ret in list(status.values()):
                    if ret != DefaultValue.SUCCESS:
                        self.context.logger.debug(
                            "Failed delete bak-package, result: %s." % output)

            # Retry 3 times, if distribute failed.
            for i in range(3):
                try:
                    self.context.logger.log(
                        "Begin to distribute package to tool path.")
                    # Send compressed package to every host
                    PackageInfo.distributePackagesToRemote(
                        self.context.sshTool,
                        self.context.clusterToolPath,
                        self.context.clusterToolPath,
                        hosts,
                        self.context.mpprcFile)
                    # Decompress package on every host
                except Exception as e:
                    # loop 3 times, if still wrong, exit with error code.
                    if i == 2:
                        raise Exception(str(e))
                    # If error, continue loop.
                    self.context.logger.log(
                        "Distributing package failed, retry.")
                    continue
                # If scp success, exit loop.
                self.context.logger.log(
                    "Successfully distribute package to tool path.")
                break
            # 2.distribute gauss server package
            # Get the path to the server package
            dirName = os.path.dirname(os.path.realpath(__file__))
            packageDir = os.path.join(dirName, "./../../../")
            packageDir = os.path.normpath(packageDir)
            for i in range(3):
                try:
                    self.context.logger.log(
                        "Begin to distribute package to package path.")
                    # distribute the distribute package to all node names
                    PackageInfo.distributePackagesToRemote(
                        self.context.sshTool,
                        self.context.clusterToolPath,
                        packageDir,
                        hosts,
                        self.context.mpprcFile)
                except Exception as e:
                    # loop 3 times, if still wrong, exit with error code.
                    if i == 2:
                        raise Exception(str(e))
                    # If error, continue loop.
                    self.context.logger.log(
                        "Distributing package failed, retry.")
                    continue
                # If scp success, exit loop.
                self.context.logger.log(
                    "Successfully distribute package to package path.")
                break
            # 3.distribute xml file
            DefaultValue.distributeXmlConfFile(self.context.sshTool,
                                               self.context.xmlFile, hosts,
                                               self.context.mpprcFile)
            cmd = "%s -t %s -u %s -X %s" % (OMCommand.getLocalScript("Local_PreInstall"),
                                      ACTION_CHECK_CONFIG,
                                      self.context.user,
                                      self.context.xmlFile)
            CmdExecutor.execCommandWithMode(cmd,
                                             self.context.sshTool,
                                             False,
                                             self.context.mpprcFile,
                                             hosts)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log("Successfully distributed package.",
                                "constant")


    def getTopToolPath(self, top_sshTool, clusterToolPath, hosts, mpprcFile):
        """
        function: find the top path of GPHOME in remote nodes.
        input: top_sshTool, clusterToolPath, hosts, mpprcFile
        output: NA
        """
        # get the String of each path & split it with space.
        global topToolPath
        topToolPath = {}
        pathList = clusterToolPath.split("/")
        pathStr = ""
        # get the string of GPHOME, split it by white spaces
        for path in pathList:
            if path == pathList[0]:
                pathStr = "/"
            elif path == pathList[1]:
                pathNext = "/" + path
                pathStr = pathNext
            else:
                pathNext = pathNext + "/" + path
                pathStr += " " + pathNext

        # use the shell command to get top path of gausstool
        cmd = "str='%s'; for item in \$str; " \
              "do if [ ! -d \$item ]; then TopPath=\$item; " \
              "break; fi; done; echo \$TopPath" % (
                  pathStr)
        top_sshTool.getSshStatusOutput(cmd, hosts, mpprcFile)
        outputMap = top_sshTool.parseSshOutput(hosts)
        for node in list(outputMap.keys()):
            topToolList = outputMap[node].split("\n")
            topToolPath[node] = topToolList[0]

    def fixServerPackageOwner(self):
        """
        function: when distribute server package,
        the os user has not been created, so we should fix
                  server package Owner here after user create.
        input: NA
        output: NA
        """
        pass

    def dss_init(self):
        '''
        unreg the disk of the dss and about
        '''
        pass

    def installToolsPhase2(self):
        """
        function: install the tools
        input: NA
        output: NA
        """
        # check if path have permission.
        if self.context.localMode or self.context.isSingle:
            # fix new created path's owner
            for onePath in self.context.needFixOwnerPaths:
                FileUtil.changeOwner(self.context.user, onePath, recursive=True,
                                     cmd_type="shell", link=True)
            return

        self.context.logger.log("Installing the tools in the cluster.",
                                "addStep")
        try:
            self.context.logger.debug(
                "Paths need to be fixed owner:%s."
                % self.context.needFixOwnerPaths)
            # fix new created path's owner
            for onePath in self.context.needFixOwnerPaths:
                FileUtil.changeOwner(self.context.user, onePath, recursive=True,
                                     cmd_type="shell", link=True)

            # fix remote toolpath's owner
            for node in list(topToolPath.keys()):
                nodelist = []
                nodelist.append(node)
                if os.path.exists(topToolPath[node]):
                    cmd = "chown -R %s:%s '%s'" % (
                        self.context.user, self.context.group,
                        topToolPath[node])
                    self.context.sshTool.executeCommand(
                        cmd,
                        DefaultValue.SUCCESS,
                        nodelist,
                        self.context.mpprcFile)

            # chown chmod top path file
            topDirFile = ClusterConstants.TOP_DIR_FILE
            cmd = "(if [ -f '%s' ];then cat '%s' " \
                  "| awk -F = '{print $1}' " \
                  "| xargs chown -R -h %s:%s; rm -rf '%s';fi)" % \
                  (topDirFile, topDirFile, self.context.user,
                   self.context.group, topDirFile)
            self.context.sshTool.executeCommand(cmd,
                                                DefaultValue.SUCCESS,
                                                [],
                                                self.context.mpprcFile)

            # change owner of packages
            self.context.logger.debug("Changing package path permission.")
            dirName = os.path.dirname(os.path.realpath(__file__))
            packageDir = os.path.realpath(
                os.path.join(dirName, "./../../../")) + "/"

            list_dir = FileUtil.getDirectoryList(packageDir)
            for directory in list_dir:
                dirPath = packageDir + directory
                dirPath = os.path.normpath(dirPath)
                if directory.find('sudo') >= 0:
                    continue
                FileUtil.changeOwner(self.context.user, dirPath, recursive=True,
                                   cmd_type="python")

            # check enter permission
            cmd = "su - %s -c 'cd '%s''" % (self.context.user, packageDir)
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then exit
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % output)

            # change owner of GaussLog dir
            self.context.logger.debug("Changing the owner of Gauss log path.")
            user_dir = "%s/%s" % (
                self.context.clusterInfo.logPath, self.context.user)
            # the user_dir may not been created now,
            # so we need check its exists
            if os.path.exists(user_dir):

                FileUtil.changeOwner(self.context.user, user_dir, recursive=True,
                                   cmd_type="shell", retry_flag=True,
                                   retry_time=15, waite_time=1, link=True)

                # check enter permission
                cmd = "su - %s -c 'cd '%s''" % (self.context.user, user_dir)
                (status, output) = subprocess.getstatusoutput(cmd)
                # if cmd failed, then exit
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error: \n%s" % output)
            # user can specify log file,
            # so we need change the owner of log file alonely
            FileUtil.changeOwner(self.context.user, self.context.logger.logFile,
                               recursive=False, cmd_type="shell", link=True)
            FileUtil.changeMode(DefaultValue.FILE_MODE,
                              self.context.logger.logFile, recursive=False,
                              cmd_type="shell")

            # check enter permission
            log_file_dir = os.path.dirname(self.context.logger.logFile)
            cmd = "su - %s -c 'cd '%s''" % (self.context.user, log_file_dir)
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then exit
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % output)

            # set tool env on all hosts
            cmd = "%s -t %s -u %s -l %s -X '%s' -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_TOOL_ENV,
                self.context.user,
                self.context.localLog,
                self.context.xmlFile,
                self.context.clusterToolPath)
            if self.context.mpprcFile != "":
                cmd += " -s '%s' -g %s" % (
                    self.context.mpprcFile, self.context.group)
            self.context.sshTool.executeCommand(cmd,
                                                DefaultValue.SUCCESS,
                                                [],
                                                self.context.mpprcFile)
            cmd = "%s -t %s -u %s -g %s -P %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_PREPARE_PATH,
                self.context.user,
                self.context.group,
                self.context.clusterToolPath,
                self.context.localLog)
            # prepare cluster tool package path
            self.context.sshTool.executeCommand(
                cmd,
                DefaultValue.SUCCESS,
                [],
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log(
            "Successfully installed the tools in the cluster.", "constant")

    def changeToolEnv(self):
        """
        function:
          change software tool env path
        input:NA
        output:NA
        """
        try:
            # Change software tool env path
            cmd = "%s -t %s -u %s -l %s -X '%s' -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHANGE_TOOL_ENV,
                self.context.user,
                self.context.localLog,
                self.context.xmlFile,
                self.context.clusterToolPath)
            if os.path.isfile(self.context.mpprcFile
                              ) and self.context.clusterInfo.enable_dss == 'on':
                cmd += ' -s {}'.format(self.context.mpprcFile)

            if self.context.mpprcFile == "" or (
                    os.path.isfile(self.context.mpprcFile)
                    and self.context.clusterInfo.enable_dss == 'on'):
                CmdExecutor.execCommandWithMode(cmd, self.context.sshTool,
                                                self.context.localMode)
                self.context.logger.debug("Command for change env: %s" % cmd)
        except Exception as e:
            raise Exception(str(e))

    def checkMappingForHostName(self):
        """
        function: check mpping for hostname
        input: NA
        output: NA
        """
        if self.context.localMode or self.context.isSingle:
            return

        self.context.logger.log("Checking hostname mapping.", "addStep")
        try:
            # check hostname mapping
            cmd = "%s -t %s -u %s -X '%s' -l '%s'" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHECK_HOSTNAME_MAPPING,
                self.context.user,
                self.context.xmlFile,
                self.context.localLog)
            self.context.sshTool.executeCommand(cmd,
                                                DefaultValue.SUCCESS,
                                                [],
                                                self.context.mpprcFile,
                                                DefaultValue.getCpuSet())
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log("Successfully checked hostname mapping.",
                                "constant")

    def createTrustForCommonUser(self):
        """
        function:
          create SSH trust for common user
        precodition:
          config file /etc/hosts has been modified correctly on local host
        input: NA
        output: NA
        """
        if self.context.localMode or self.context.isSingle:
            return

        if createTrustFlag:
            return
        self.context.logger.log(
            "Creating SSH trust for [%s] user." % self.context.user)
        try:
            # the IP for create trust
            allIps = []
            sshIps = self.context.clusterInfo.getClusterSshIps()
            # get all IPs
            for ips in sshIps:
                allIps.extend(ips)
            # create trust
            self.context.sshTool.createTrust(self.context.user, allIps, self.context.mpprcFile)
            self.context.user_ssh_agent_flag = True
            self.context.logger.debug("{debug exception010} Finished execute sshTool."
                                      "createTrust for common user.")
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully created SSH trust for [%s] user." % self.context.user)

    def checkOSVersion(self):
        """
        function:
          check if os version is support
        precondition:
        postcondition:
        input:NA
        output:NA
        hiden info:support os version
        ppp:
        """
        self.context.logger.log("Checking OS version.", "addStep")
        try:
            # Checking OS version
            cmd = "%s -t %s -u %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHECK_OS_VERSION,
                self.context.user,
                self.context.localLog)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully checked OS version.", "constant")

    def createOSUser(self):
        """
        function:
          create os user and create trust for user
        precondition:
          1.user group passwd has been initialized
          2.create trust tool has been installed
        postcondition:
          1.user has been created
          2.user's trust has been created
        input:NA
        output:NA
        hiden:NA
        """
        # single cluster also need to create user without local mode
        self.context.logger.debug("Creating OS user and create trust for user")
        if self.context.localMode:
            return

        global createTrustFlag
        try:
            # check the interactive mode
            # if the interactive mode is True
            if not self.context.preMode:
                try:
                    # get the input
                    if(self.context.isSingle):
                        flag = input("Are you sure you want to create "
                                     "the user[%s] (yes/no)? " % self.context.user)
                    else:
                        flag = input("Are you sure you want to create the user[%s] "
                                     "and create trust for it (yes/no)? " % self.context.user)
                    while(True):
                        # check the input
                        if(flag.upper() != "YES" and flag.upper() != "NO"
                                and flag.upper() != "Y" and flag.upper() != "N"):
                            flag = input("Please type 'yes' or 'no': ")
                            continue
                        break

                    # set the flag for create user trust
                    self.context.logger.debug(
                        "Setting the flag for creating user's trust.")
                    if flag.upper() == "NO" or flag.upper() == "N":
                        createTrustFlag = True
                        cmd = "%s -t %s -u %s -l %s" % (
                            OMCommand.getLocalScript("Local_PreInstall"),
                            ACTION_INIT_GAUSSLOG,
                            self.context.user,
                            self.context.localLog)
                        CmdExecutor.execCommandWithMode(
                            cmd,
                            self.context.sshTool,
                            self.context.isSingle,
                            self.context.mpprcFile)
                        return
                    # check the user is not exist on all nodes
                    cmd = "%s -t %s -u %s -g %s -l %s" % (
                        OMCommand.getLocalScript("Local_PreInstall"),
                        ACTION_CHECK_OS_USER,
                        self.context.user,
                        self.context.group,
                        self.context.localLog)
                    CmdExecutor.execCommandWithMode(cmd,
                                                    self.context.sshTool,
                                                    self.context.isSingle,
                                                    self.context.mpprcFile)
                    self.context.logger.debug(
                        "Successfully set the flag for creating user's trust")
                    return
                except Exception as e:
                    # An exception is thrown when the user and user group are inconsistent.
                    self.check_error_code(str(e))
                    i = 0
                    # get the password
                    while i < 3:
                        self.context.password = self.getUserPasswd(
                            "cluster user")
                        PasswordUtil.checkPasswordVaild(
                            self.context.password)
                        self.context.passwordsec = self.getUserPasswd(
                            "cluster user", "again")

                        if self.context.password != self.context.passwordsec:
                            i = i + 1
                            self.context.logger.printMessage(
                                "Sorry. passwords do not match.")
                            continue
                        break

                    # check the password is not OK
                    if i == 3:
                        self.context.logger.printMessage(
                            "passwd: Have exhausted maximum number "
                            "of retries for service.")
                        sys.exit(1)
            else:
                createTrustFlag = True
                cmd = "%s -t %s -u %s -l %s" % (
                    OMCommand.getLocalScript("Local_PreInstall"),
                    ACTION_INIT_GAUSSLOG,
                    self.context.user,
                    self.context.localLog)
                CmdExecutor.execCommandWithMode(cmd,
                                                 self.context.sshTool,
                                                 self.context.isSingle,
                                                 self.context.mpprcFile)
                return

            self.context.logger.debug(
                "Successfully created [%s] user on all nodes."
                % self.context.user)

            # create the user on all nodes
            # write the password into temporary file
            tmp_path = "/tmp/os_user_pwd"
            ClusterCommand.aes_cbc_encrypt_with_multi(self.context.password, tmp_path,
                                                      self.context.logger)
            # change the temporary file permissions
            FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, tmp_path,
                              recursive=True, cmd_type="shell", retry_flag=True)

            if not self.context.isSingle:
                # send the temporary file to all remote nodes
                try:
                    self.context.sshTool.scpFiles(tmp_path, "/tmp/", self.context.sshTool.hostNames)
                except Exception as e:
                    cmd = "rm -rf %s" % tmp_path
                    CmdExecutor.execCommandWithMode(cmd,
                                                    self.context.sshTool,
                                                    self.context.isSingle,
                                                    self.context.mpprcFile)
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50216"]
                                    % "temporary files")

            # create the user on all nodes
            cmd = "%s -t %s -u %s -g %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CREATE_OS_USER,
                self.context.user,
                self.context.group,
                self.context.localLog)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

            # delete the temporary file on all nodes
            cmd = "rm -rf %s" % tmp_path
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

            # Successfully created user on all nodes
            self.context.logger.log(
                "Successfully created [%s] user on all nodes."
                % self.context.user)
        except Exception as e:
            # delete the temporary file on all nodes
            tmp_path = "/tmp/os_user_pwd"
            cmd = "rm -rf %s" % tmp_path
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
            raise Exception(str(e))

    def check_error_code(self,error_message):
        if (error_message.find("GAUSS-50305") > 0):
            raise Exception(str(error_message))

    def createDirs(self):
        """
        function: create directorys
        input: NA
        output: NA
        """
        self.context.logger.log("Creating cluster's path.", "addStep")
        try:
            # fix new created path's owner after create user for single cluster
            if self.context.isSingle:
                self.context.logger.debug(
                    "Paths need to be fixed owner:%s."
                    % self.context.needFixOwnerPaths)
                for onePath in self.context.needFixOwnerPaths:
                    FileUtil.changeOwner(self.context.user, onePath,
                                         recursive=True, cmd_type="shell", link=True)

                topDirFile = ClusterConstants.TOP_DIR_FILE
                if os.path.exists(topDirFile):
                    keylist = FileUtil.readFile(topDirFile)
                    if keylist != []:
                        for key in keylist:
                            FileUtil.changeOwner(self.context.user, key.strip(),
                                               True, "shell", link=True)

                    FileUtil.removeFile(topDirFile)

            # create the directory on all nodes
            cmd = "%s -t %s -u %s -g %s -Q %s -X '%s' -l '%s'" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CREATE_CLUSTER_PATHS,
                self.context.user,
                self.context.group,
                self.context.clusterToolPath,
                self.context.xmlFile,
                self.context.localLog)
            # check the env file
            if self.context.mpprcFile != "":
                cmd += " -s '%s'" % self.context.mpprcFile
            # exec the cmd
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
            self.context.logger.debug(
                f"The cmd of the create cluster path: {cmd}.")
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully created cluster's path.",
                                "constant")

    def setAndCheckOSParameter(self):
        """
        function: set and check OS parameter.
        If skipOSSet is true, pass; else call gs_checkos to do it.
        input: NA
        output: NA
        """
        self.context.logger.log("Set and check OS parameter.", "addStep")
        try:
            # get all node hostnames
            NodeNames = self.context.clusterInfo.getClusterNodeNames()
            namelist = ""

            # set the localmode
            if self.context.localMode or self.context.isSingle:
                # localmode
                namelist = NetUtil.GetHostIpOrName()
            else:
                # Non-native mode
                namelist = ",".join(NodeNames)

            # check skip-os-set parameter
            if self.context.skipOSSet:
                # check the OS parameters
                self.checkOSParameter(namelist)
            else:
                # set and check parameters
                self.setOSParameter(namelist)
                self.checkOSParameter(namelist)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Set and check OS parameter completed.",
                                "constant")

    def setOSParameter(self, namelist):
        """
        function: set and check OS parameter.
        If skipOSSet is true, pass; else call gs_checkos to do it.
        input: namelist
        output: NA
        """
        self.context.logger.log("Setting OS parameters.")

        # set OS parameters
        cmd = "%s -h %s -i B -l '%s' -X '%s'" % (
            OMCommand.getLocalScript("Gauss_CheckOS"),
            namelist,
            self.context.localLog,
            self.context.xmlFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        # if cmd failed, then raise
        if status != 0 and output.strip() == "":
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + "Error:\n%s." % output)

        self.context.logger.log("Successfully set OS parameters.")

    def checkOSParameter(self, namelist):
        """
        check OS parameter.
        If skipOSSet is true, pass; else call gs_checkos to do it.
        """
        self.context.logger.debug("Checking OS parameters.")
        try:
            # check the OS parameters
            if self.context.skipOSCheck:
                cmd = "%s -h %s -i A -l '%s' -X '%s --skip-os-check '%s''" % (
                    OMCommand.getLocalScript("Gauss_CheckOS"),
                    namelist,
                    self.context.localLog,
                    self.context.xmlFile,
                    self.context.skipOSCheck)
            else:
                cmd = "%s -h %s -i A -l '%s' -X '%s'" % (
                    OMCommand.getLocalScript("Gauss_CheckOS"),
                    namelist,
                    self.context.localLog,
                    self.context.xmlFile)
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then raise
            if status != 0 and output.strip() == "":
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + "Error:\n%s." % output)

            # parse the result
            result = ""
            abnormal_num = 0
            warning_num = 0
            # get the total numbers
            for line in output.split('\n'):
                if line.find("Total numbers") >= 0:
                    result = line
                    break
            if result == "":
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + "Error:\n%s." % output)
            # type [Total numbers:14. Abnormal numbers:0. Warning number:1.]
            try:
                # get the abnormal numbers
                abnormal_num = int(result.split('.')[1].split(':')[1].strip())
                # get the warning numbers
                warning_num = int(result.split('.')[2].split(':')[1].strip())
            except Exception as e:
                abnormal_num = 1
                warning_num = 0

            # get the path where  the script is located
            current_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "./../../")
            gs_checkos_path = os.path.realpath(
                os.path.join(current_path, "gs_checkos"))
            if abnormal_num > 0:
                raise Exception(
                    ErrorCode.GAUSS_524["GAUSS_52400"]
                    + "\nPlease get more details by \"%s "
                      "-i A -h %s --detail\"."
                    % (gs_checkos_path, namelist))
            if warning_num > 0:
                self.context.logger.log(
                    "Warning: Installation environment "
                    "contains some warning messages." + \
                    "\nPlease get more details by \"%s "
                    "-i A -h %s --detail\"."
                    % (gs_checkos_path, namelist))

        except Exception as e:
            raise Exception(str(e))

        self.context.logger.debug("Successfully check OS parameters.")

    def prepareCronService(self):
        """
        function: preparing CRON service
        input: NA
        output: NA
        """
        self.context.logger.log("Preparing CRON service.", "addStep")
        try:
            # Preparing CRON service
            cmd = "%s -t %s -u %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_PREPARE_USER_CRON_SERVICE,
                self.context.user,
                self.context.localLog)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        # Successfully prepared CRON service
        self.context.logger.log("Successfully prepared CRON service.",
                                "constant")

    def prepareSshdService(self):
        """
        function: preparing SSH service
        input: NA
        output: NA
        """
        self.context.logger.log("Preparing SSH service.", "addStep")
        try:
            # Preparing SSH service
            cmd = "%s -t %s -u %s -g %s -X %s -l %s" % \
                (OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_PREPARE_USER_SSHD_SERVICE,
                self.context.user,
                self.context.group,
                self.context.xmlFile,
                self.context.localLog)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        # Successfully prepared SSH service
        self.context.logger.log("Successfully prepared SSH service.",
                                "constant")

    def setEnvParameter(self):
        """
        function: setting cluster environmental variables
        input: NA
        output: NA
        """
        pass

    def setLibrary(self):
        """
        function: setting the dynamic link library
        input: NA
        output: NA
        """
        self.context.logger.log("Setting the dynamic link library.", "addStep")
        try:
            # Setting the dynamic link library
            cmd = "%s -t %s -u %s -l %s " % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_LIBRARY,
                self.context.user,
                self.context.localLog)
            self.context.logger.debug("Command for setting library: %s" % cmd)
            # exec the cmd for set library
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            # failed to set the dynamic link library
            raise Exception(str(e))
        # Successfully set the dynamic link library
        self.context.logger.log("Successfully set the dynamic link library.",
                                "constant")

    def setCgroup(self):
        """
        function: setting Cgroup
        input: NA
        output: NA
        """
        pass

    def setCorePath(self):
        """
        function: setting core path
        input: NA
        output: NA
        """
        pass

    def setPssh(self):
        """
        function: setting pssh
        input: NA
        output: NA
        """
        pass

    def setVirtualIp(self):
        """
        function: set the virtual IPs
        input: NA
        output: NA
        """
        pass

    def doPreInstallSucceed(self):
        """
        function: setting finish flag
        input: NA
        output: NA
        """
        # Before set finish flag,
        # we need to check if path permission is correct in local mode.
        self.checkLocalPermission()

        self.context.logger.log("Setting finish flag.", "addStep")
        try:
            # set finish flag
            cmd = "%s -t %s -u %s -l '%s' -X '%s' -Q %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_SET_FINISH_FLAG,
                self.context.user,
                self.context.localLog,
                self.context.xmlFile,
                self.context.clusterToolPath)
            # check the mpprcFile
            if self.context.mpprcFile != "":
                cmd += " -s '%s'" % self.context.mpprcFile
            # exec the cmd for set finish flag
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            # failed set finish flag
            raise Exception(str(e))
        # Successfully set finish flag
        self.context.logger.log("Successfully set finish flag.", "constant")

    def checkLocalPermission(self):
        """
        function: check if path have permission in local mode or single mode.
        input : NA
        output: NA
        """
        # check if path have permission in local mode or single mode.
        if self.context.localMode or self.context.isSingle:
            dirName = os.path.dirname(os.path.realpath(__file__))
            packageDir = os.path.realpath(
                os.path.join(dirName, "./../../../")) + "/"

            # check enter permission
            cmd = "su - %s -c 'cd '%s''" % (self.context.user, packageDir)
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then exit
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % output)

            user_dir = "%s/%s" % (
                self.context.clusterInfo.logPath, self.context.user)

            # the user_dir may not been created now,
            # so we need check its exists
            if os.path.exists(user_dir):
                # check enter permission
                cmd = "su - %s -c 'cd '%s''" % (self.context.user, user_dir)
                (status, output) = subprocess.getstatusoutput(cmd)
                # if cmd failed, then exit
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error: \n%s" % output)

            # check enter permission
            log_file_dir = os.path.dirname(self.context.logger.logFile)

            cmd = "su - %s -c 'cd '%s''" % (self.context.user, log_file_dir)
            (status, output) = subprocess.getstatusoutput(cmd)
            # if cmd failed, then exit
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % output)

    def checkEnvFile(self):
        """
        function: delete step tmp file
        input : NA
        output: NA
        """
        if self.context.localMode or self.context.isSingle:
            return

        try:
            cmd = "%s -t %s -u %s -l %s" % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHECK_ENVFILE,
                self.context.user,
                self.context.localLog)
            if self.context.mpprcFile != "":
                cmd += " -s '%s'" % self.context.mpprcFile
            self.context.sshTool.executeCommand(cmd)
        except Exception as e:
            raise Exception(str(e))

    def checkDiskSpace(self):
        """
        function: check remain disk space of GAUSSHOME for olap
        input: NA
        output: NA
        """
        pass

    def setHostIpEnv(self):
        """
        function: set host ip env
        input  : NA
        output : NA
        """
        pass
    
    def check_enabledssinenv(self, source_file):
        """
        function: check enabledss in env
        input  : NA
        output : NA
        """
        if self.context.clusterInfo.enable_dss == 'on':
            file_lines = []
            found_enabledss = False
            is_enabledssset = "export ENABLE_DSS="
            with open(source_file, "r") as file:
                for line in file:
                    if is_enabledssset in line:
                        found_enabledss = True
                    else:
                        file_lines.append(line)

            if found_enabledss:
                with open(source_file, "w") as file:
                    file.writelines(file_lines)

    def checkRepeat(self):
        """
        function: check repeat
        input  : NA
        output : NA
        """
        if self.context.mpprcFile and os.path.isfile(self.context.mpprcFile):
            source_file = self.context.mpprcFile
        elif self.context.mpprcFile:
            self.context.logger.debug(
                "Environment file is not exist environment file,"
                " skip check repeat.")
            return []
        elif os.path.isfile(ProfileFile.get_user_bashrc(self.context.user)):
            source_file = ProfileFile.get_user_bashrc(self.context.user)
        else:
            self.context.logger.debug(
                "There is no environment file, skip check repeat.")
            return []
        self.check_enabledssinenv(source_file)
        with open(source_file, 'r') as f:
            env_list = f.readlines()
        new_env_list = []
        if not self.context.mpprcFile:
            with open(os.path.join("/etc", "profile"), "r") as etc_file:
                gp_home_env = etc_file.readlines()
            gphome_env_list = [env.replace('\n', '') for env in gp_home_env]
            for env in gphome_env_list:
                if env.startswith("export GPHOME="):
                    if len(new_env_list) != 0:
                        new_env_list = []
                    new_env_list.append(env.strip())

        new_env_list.extend([env.replace('\n', '') for env in env_list])
        return new_env_list

    def check_env_repeat(self):
        gphome = gausshome = pghost = gausslog \
            = agent_path = agent_log_path = ""
        new_env_list = self.checkRepeat()
        if not new_env_list:
            return
        if "export GAUSS_ENV=2" not in new_env_list:
            self.context.logger.debug(
                "There is no install cluster exist. "
                "Skip check repeat install.")
            return
        for env in new_env_list:
            if env.startswith("export GPHOME=") and env.split('=')[1] != "":
                gphome = env.split('=')[1]
            if env.startswith("export GAUSSHOME="):
                gausshome = env.split('=')[1]
            if env.startswith("export PGHOST="):
                pghost = env.split('=')[1]
            if env.startswith("export GAUSSLOG="):
                gausslog = env.split('=')[1]
            if env.startswith("export AGENTPATH="):
                agent_path = env.split('=')[1]
            if env.startswith("export AGENTLOGPATH="):
                agent_log_path = env.split('=')[1]

        gaussdbToolPath = ClusterDir.getPreClusterToolPath(
            self.context.xmlFile)
        gaussdbAppPath = ClusterConfigFile.getOneClusterConfigItem(
            "gaussdbAppPath",
            self.context.xmlFile)
        DefaultValue.checkPathVaild(gaussdbAppPath)
        tmpMppdbPath = ClusterConfigFile.readClusterTmpMppdbPath(
            self.context.user, self.context.xmlFile)
        gaussdbLogPath = ClusterConfigFile.readClusterLogPath(
            self.context.xmlFile)
        agentToolPath = ClusterConfigFile.getOneClusterConfigItem(
            "agentToolPath",
            self.context.xmlFile)
        DefaultValue.checkPathVaild(agentToolPath)
        agentLogPath = ClusterConfigFile.getOneClusterConfigItem(
            "agentLogPath",
            self.context.xmlFile)
        DefaultValue.checkPathVaild(agentLogPath)
        if gphome and gphome.strip() != gaussdbToolPath:
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "gaussdbToolPath [%s] is not same with environment[%s]" % (
                    gaussdbToolPath, gphome))
        if gausshome and gausshome.strip() != gaussdbAppPath:
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "gaussdbAppPath [%s] is not same with environment[%s]" % (
                    gaussdbAppPath, gausshome))
        if pghost and pghost.strip() != tmpMppdbPath:
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "tmpMppdbPath [%s] is not same with environment[%s]" % (
                    tmpMppdbPath, pghost))
        if gausslog and gausslog.strip() != os.path.join(
                gaussdbLogPath.strip(), self.context.user):
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "gaussdbLogPath [%s] is not same with environment[%s]"
                % (os.path.join(gaussdbLogPath.strip(), self.context.user),
                   gausslog))
        if agent_path and agentToolPath \
                and agent_path.strip() != agentToolPath.strip():
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "agentToolPath [%s] is not same with environment[%s]" % (
                    agentToolPath, agent_path))
        if agent_log_path \
                and agentLogPath \
                and agent_log_path.strip() != agentLogPath.strip():
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52704"] % "preinstall repeat" +
                "agentLogPath [%s] is not same with environment[%s]" % (
                    agentLogPath, agent_log_path))

        self.context.logger.debug("Preinstall check repeat success.")

    def checkInstanceDir(self):
        """
        function : Check whether the instance path is in the gausshome path
        input : None
        output : None
        """
        appPath = self.context.clusterInfo.appPath
        self.check_env_repeat()
        for dbNode in self.context.clusterInfo.dbNodes:
            # dn
            for dataInst in dbNode.datanodes:
                if os.path.dirname(dataInst.datadir) == appPath:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50232"] % (
                        dataInst.datadir, appPath))

    def checkAzPriorityValue(self):
        """
        function : Check azName and azPriority value, The azName is different, and the value of azPriority must be different.
        input : None
        output : None
        """
        priority_map = {}
        for db_node in self.context.clusterInfo.dbNodes:
            for data_inst in db_node.datanodes:
                az_name = data_inst.azName
                priority = data_inst.azPriority
                if (az_name not in priority_map):
                    priority_map[az_name] = priority

        result = set()
        for value in priority_map.values():
            result.add(value)
        if len(result) < len(priority_map.values()):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51658"])

    def checkOSSoftware(self):
        """
        function: setting the dynamic link library
        input: NA
        output: NA
        """
        self.context.logger.log("Checking OS software.", "addStep")
        try:
            # Checking software
            cmd = "%s -t %s -u %s -l %s " % (
                OMCommand.getLocalScript("Local_PreInstall"),
                ACTION_CHECK_OS_SOFTWARE,
                self.context.user,
                self.context.localLog)
            self.context.logger.debug("Checking OS software: %s" % cmd)
            # exec the cmd for Checking software
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.localMode or self.context.isSingle,
                self.context.mpprcFile)
        except Exception as e:
            # failed to Check software
            raise Exception(str(e))
        # Successfully Check software
        self.context.logger.log("Successfully check os software.",
                                "constant")

    def get_package_path(self):
        """
        get package path, then can get script path, /package_path/script/
        :return:
        """
        dir_name = os.path.dirname(os.path.realpath(__file__))
        package_dir = os.path.join(dir_name, "./../../../")
        return os.path.realpath(package_dir)

    def set_user_crontab(self):
        """
        :return:
        """
        if not self.context.user_ssh_agent_flag:
            return
        self.context.logger.debug("Start set cron for %s" %self.context.user)
        tmp_path = ClusterConfigFile.readClusterTmpMppdbPath(
            self.context.user, self.context.xmlFile)
        gaussdb_tool_path = ClusterDir.getPreClusterToolPath(self.context.xmlFile)
        cron_file = "%s/gauss_cron_%s" % (tmp_path, self.context.user)
        set_cron_cmd = "crontab -u %s -l > %s && " % (self.context.user, cron_file)
        set_cron_cmd += "sed -i '/CheckSshAgent.py/d' %s;" % cron_file
        set_cron_cmd += "echo '*/1 * * * * source ~/.bashrc;python3 %s/script/local/CheckSshAgent.py >>/dev/null 2>&1 &' >> %s;" % (gaussdb_tool_path, cron_file)

        set_cron_cmd += "crontab -u %s %s;service cron restart;" % (self.context.user, cron_file)
        set_cron_cmd += "rm -f '%s'" % cron_file
        self.context.logger.debug("Command for setting CRON: %s" % set_cron_cmd)
        CmdExecutor.execCommandWithMode(set_cron_cmd,
                                        self.context.sshTool,
                                        self.context.localMode or self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Successfully to set cron for %s" %self.context.user)

    def do_perf_config(self):
        """
        run gs_perfconfig to tune os configure.
        """
        if not self.context.enable_perf_config:
            return
        self.context.logger.log("gs_preinstall has finished, start gs_perfconfig now.")

        cmd = 'gs_perfconfig tune -t os,suggest --apply -y'
        if self.context.mpprcFile:
            cmd += (' --env ' + self.context.mpprcFile)
        CmdExecutor.execCommandLocally(cmd)

    def doPreInstall(self):
        """
        function: the main process of preinstall
        input: NA
        output: NA
        """
        self.context.logger.debug(
            "gs_preinstall execution takes %s steps in total" % \
            ClusterCommand.countTotalSteps(
                "gs_preinstall", "",
                self.context.localMode or self.context.isSingle))
        # Check whether the instance directory
        # conflicts with the application directory.
        self.checkInstanceDir()
        # check azPriotity
        self.checkAzPriorityValue()
        # install tools phase1
        self.installToolsPhase1()
        # exchange user key for root user
        self.createTrustForRoot()
        # distribute server package
        # set HOST_IP env
        self.setHostIpEnv()
        self.distributePackages()
        # create user and exchange keys for database user
        self.createOSUser()
        # prepare sshd service for user.
        # This step must be nearly after createOSUser,
        # which needs sshd service to be restarted.
        self.prepareSshdService()
        # check env file
        self.checkEnvFile()
        # install tools phase2
        self.installToolsPhase2()
        # check whether the /etc/hosts file correct
        self.checkMappingForHostName()
        # exchage user key for common user
        self.createTrustForCommonUser()
        # change tool env path
        self.changeToolEnv()
        # the end of functions which do not use in in local mode
        #check software
        self.checkOSSoftware()
        # check os version
        self.checkOSVersion()
        # create path and set mode
        self.createDirs()
        # set os parameters
        self.setAndCheckOSParameter()
        # prepare cron service for user
        self.prepareCronService()
        # set environment parameters
        self.setEnvParameter()
        # set virtual IP
        self.setVirtualIp()
        # set Library
        self.setLibrary()
        # set core path
        self.setCorePath()
        # set core path
        self.setPssh()
        # set cgroup
        self.setCgroup()

        self.setArmOptimization()
        # fix server package mode
        self.fixServerPackageOwner()

        # unreg the disk of the dss and about
        self.dss_init()

        # set user cron
        self.set_user_crontab()
        # set user env and a flag,
        # indicate that the preinstall.py has been execed succeed
        self.doPreInstallSucceed()
        # delete root mutual trust
        self.delete_root_mutual_trust()

        self.context.logger.log("Preinstallation succeeded.")

        # gs_perfconfig is not a step in the preinstall, so do it after log succeeded.
        self.do_perf_config()

    def run(self):
        """
        function: run method
        """
        try:
            # do preinstall option
            self.doPreInstall()
            # close log file
            self.context.logger.closeLog()
        except Exception as e:
            is_upgrade_func = lambda x: re.findall(r'GAUSS_ENV[ ]*=[ ]*2', x)
            for rmPath in self.context.needFixOwnerPaths:
                if os.path.isfile(rmPath):
                    if FileUtil.is_in_file_with_context(
                            rmPath, call_back_context=is_upgrade_func):
                        self.context.logger.debug(
                            f'In upgrade process, no need to delete {rmPath}.')
                    else:
                        FileUtil.removeFile(rmPath)
                elif os.path.isdir(rmPath):
                    if not EnvUtil.is_fuzzy_upgrade(
                            self.context.user,
                            logger=self.context.logger,
                            env_file=self.context.mpprcFile):
                        FileUtil.removeDirectory(rmPath)
                    else:
                        self.context.logger.debug(
                            f'In upgrade process, no need to delete {rmPath}.')
            self.context.logger.logExit(str(e))
        sys.exit(0)
