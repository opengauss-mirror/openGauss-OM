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
# Description  : SshTool.py is utility to support ssh tools
#############################################################################
import socket
import subprocess
import os
import sys
import datetime
import weakref
import time
from random import sample

sys.path.append(sys.path[0] + "/../../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.cmd_util import CmdUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.security.sensitive_mask import SensitiveMask
from gspylib.common.Constants import Constants

try:
    import paramiko
except ImportError as ex:
    try:
        local_path = os.path.dirname(os.path.realpath(__file__))
        clib_path = os.path.realpath(os.path.join(local_path, "../../gspylib/clib/"))
        ld_path = os.getenv("LD_LIBRARY_PATH")
        if not ld_path or not ld_path.startswith(clib_path):
            if not ld_path:
                os.environ['LD_LIBRARY_PATH'] = clib_path
            else:
                os.environ['LD_LIBRARY_PATH'] = clib_path + ":" + ld_path
        try:
            os.execl(sys.executable, sys.executable, *sys.argv)
        except Exception as ex:
            sys.exit("Failed to set the enviroment variable: %s" % str(ex))
        import paramiko
    except ImportError as ex:
            raise Exception(ErrorCode.GAUSS_522["GAUSS_52200"] % str(ex))

class SshTool():
    """
    Class for controling multi-hosts
    """

    def __init__(self, hostNames, logFile=None,
                 timeout=DefaultValue.TIMEOUT_PSSH_COMMON, key=""):
        '''
        Constructor
        '''
        self.hostNames = hostNames
        self.__logFile = logFile
        self.__pid = os.getpid()
        self.__timeout = timeout + 10
        self._finalizer = weakref.finalize(self, self.clenSshResultFiles)
        self.__sessions = {}

        currentTime = str(datetime.datetime.now()).replace(" ", "_").replace(
            ".", "_")
        randomnum = ''.join(sample('0123456789', 3))
        # can tmp path always access?
        if key == "":
            self.__hostsFile = "/tmp/gauss_hosts_file_%d_%s_%s" % (
                self.__pid, currentTime, randomnum)
            self.__resultFile = "/tmp/gauss_result_%d_%s_%s.log" % (
                self.__pid, currentTime, randomnum)
            self.__outputPath = "/tmp/gauss_output_files_%d_%s_%s" % (
                self.__pid, currentTime, randomnum)
            self.__errorPath = "/tmp/gauss_error_files_%d_%s_%s" % (
                self.__pid, currentTime, randomnum)
        else:
            self.__hostsFile = "/tmp/gauss_hosts_file_%d_%s_%s_%s" % (
                self.__pid, key, currentTime, randomnum)
            self.__resultFile = "/tmp/gauss_result_%d_%s_%s_%s.log" % (
                self.__pid, key, currentTime, randomnum)
            self.__outputPath = "/tmp/gauss_output_files_%d_%s_%s_%s" % (
                self.__pid, key, currentTime, randomnum)
            self.__errorPath = "/tmp/gauss_error_files_%d_%s_%s_%s" % (
                self.__pid, key, currentTime, randomnum)

        self.__resultStatus = {}
        if logFile is None:
            self.__logFile = ClusterConstants.DEV_NULL

        # before using, clean the old ones
        FileUtil.removeFile(self.__hostsFile)
        FileUtil.removeFile(self.__resultFile)

        if os.path.exists(self.__outputPath):
            FileUtil.removeDirectory(self.__outputPath)

        if os.path.exists(self.__errorPath):
            FileUtil.removeDirectory(self.__errorPath)

        self.__writeHostFiles()

    def get_result_file(self):
        return self.__hostsFile

    def clenSshResultFiles(self):
        """
        function: Delete file
        input : NA
        output: NA
        """
        if os.path.exists(self.__hostsFile):
            FileUtil.removeFile(self.__hostsFile)

        if os.path.exists(self.__resultFile):
            FileUtil.removeFile(self.__resultFile)

        if os.path.exists(self.__outputPath):
            FileUtil.removeDirectory(self.__outputPath)

        if os.path.exists(self.__errorPath):
            FileUtil.removeDirectory(self.__errorPath)

    def __del__(self):
        """
        function: Delete file
        input : NA
        output: NA
        """
        self._finalizer()

    def createTrust(self, user, ips=[], mpprcFile="", skipHostnameSet=False):
        """
        function: create trust for specified user with both ip and hostname,
        when using N9000 tool create trust failed
        do not support using a normal user to create trust for another user.
        input : user, pwd, ips, mpprcFile, skipHostnameSet 
        output: NA
        """
        tmp_hosts = Constants.TMP_HOSTS_FILE % self.__pid
        status = 0
        output = ""
        if ips is None:
            ips = []
        try:
            FileUtil.removeFile(tmp_hosts)
            # 1.prepare hosts file
            for ip in ips:
                cmd = "echo %s >> %s 2>/dev/null" % (ip, tmp_hosts)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                                    % tmp_hosts + " Error:\n%s." % output
                                    + "The cmd is %s" % cmd)
            FileUtil.changeMode(DefaultValue.KEY_HOSTS_FILE, tmp_hosts, False,
                              "python")

            # 2.call createtrust script
            create_trust_file = "gs_sshexkey"
            gphome = os.getenv("GPHOME")
            if user == "root":
                if mpprcFile != "" and FileUtil.check_file_permission(mpprcFile, True) and \
                        self.checkMpprcfile(user, mpprcFile):
                    cmd = "source %s; %s -f %s -l '%s'" % \
                          (mpprcFile, create_trust_file,
                           tmp_hosts, self.__logFile)
                elif mpprcFile == "" and FileUtil.check_file_permission(
                        ClusterConstants.ETC_PROFILE, True):
                    cmd = "source %s; %s -f %s -l '%s'" % (ClusterConstants.ETC_PROFILE,
                                                           create_trust_file, tmp_hosts,
                                                           self.__logFile)
            else:
                if mpprcFile != "" and FileUtil.check_file_permission(mpprcFile, True) and \
                        self.checkMpprcfile(user, mpprcFile):
                    cmd = "source %s; %s/script/%s -f %s -l '%s'" % \
                          (mpprcFile, gphome,
                           create_trust_file, tmp_hosts, self.__logFile)
                elif mpprcFile == "" and FileUtil.check_file_permission(
                        ClusterConstants.ETC_PROFILE, True):
                    cmd = "source %s; %s/script/%s -f %s -l '%s'" % \
                          (ClusterConstants.ETC_PROFILE, gphome, create_trust_file,
                           tmp_hosts, self.__logFile)
                    
            if skipHostnameSet:
                cmd += " --skip-hostname-set"

            if os.getuid() == 0:
                cmd = "su - %s -c \"%s\" 2>&1" % (user, cmd)
            else:
                cmd += " 2>&1"
            if user == "root":
                status, output = subprocess.getstatusoutput(cmd)
            else:
                status = os.system(cmd)

            if status != 0:
                # we can not print cmd here, because it include user's passwd
                FileUtil.removeFile(tmp_hosts)
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "gs_sshexkey" +
                                "Error: %s" % output if output else "")

            # 3.delete hosts file
            FileUtil.removeFile(tmp_hosts)
        except Exception as e:
            FileUtil.removeFile(tmp_hosts)
            raise Exception(str(e))

    def checkMpprcfile(self, username, filePath):
        """
        function:
          check if given user has operation permission for Mpprcfile
        precondition:
          1.user should be exist---root/cluster user
          2.filePath should be an absolute path
        postcondition:
          1.return True or False
        input : username,filePath
        output: True/False
        """
        ownerPath = os.path.split(filePath)[0]
        cmd = "su - %s -c 'cd %s'" % (username, ownerPath)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"]
                            % '-sep-env-file' + " Error:\n%s." % output
                            + "The cmd is %s" % cmd)

        return True

    def getUserOSProfile(self, env_file=""):
        """
        function: get user os profile
        input : env_file
        output: mpprcFile, userProfile, osProfile
        """
        if env_file != "":
            mpprcFile = env_file
        else:
            mpprcFile = EnvUtil.getEnv(DefaultValue.MPPRC_FILE_ENV)

        if mpprcFile != "" and mpprcFile is not None:
            userProfile = mpprcFile
        else:
            userProfile = ClusterConstants.BASHRC
        osProfile = ClusterConstants.ETC_PROFILE
        return mpprcFile, userProfile, osProfile

    def getGPHOMEPath(self, osProfile):
        """
        function: get GPHOME path
        input : osProfile
        output: output
        """
        try:
            cmd = "source %s && echo $GPHOME" % osProfile
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0 or not output or output.strip() == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "GPHOME"
                                + "The cmd is %s" % cmd)
            return output.strip()
        except Exception as e:
            raise Exception(str(e))

    def parseSshResult(self, hostList=None):
        """
        function: parse ssh result
        input : hostList
        output: resultMap, outputCollect
        """
        try:
            if hostList is None:
                hostList = []
            outputCollect = ""
            prefix = ""
            resultMap = self.__readCmdResult(self.__resultFile, len(hostList))
            for host in hostList:
                sshOutPutFile = "%s/%s" % (self.__outputPath, host)
                sshErrorPutFile = "%s/%s" % (self.__errorPath, host)
                if resultMap[host] == DefaultValue.SUCCESS:
                    prefix = "SUCCESS"
                else:
                    prefix = "FAILURE"
                outputCollect += "[%s] %s:\n" % (prefix, str(host))
                if os.path.isfile(sshOutPutFile):
                    context = ""
                    with open(sshOutPutFile, "r") as fp:
                        context = fp.read()
                    outputCollect += context
                if os.path.isfile(sshErrorPutFile):
                    context = ""
                    with open(sshErrorPutFile, "r") as fp:
                        context = fp.read()
                    outputCollect += context
        except Exception as e:
            raise Exception(str(e))
        return resultMap, outputCollect

    def timeOutClean(self, cmd, psshpre, hostList=None, env_file="",
                     parallel_num=300, signal=9, logger=None):
        """
        function: timeout clean
        """
        if hostList is None:
            hostList = []
        pstree = "python3 %s -sc" % os.path.realpath(os.path.dirname(
            os.path.realpath(__file__)) + "/../../py_pstree.py")
        mpprcFile, userProfile, osProfile = self.getUserOSProfile(env_file)
        # kill the parent and child process. get all process by py_pstree.py
        timeOutCmd = "source %s && pidList=\`ps aux | grep \\\"%s\\\" |" \
                     " grep -v 'grep' | awk '{print \$2}' | xargs \`; " \
                     % (osProfile, cmd)
        timeOutCmd += "for pid in \$pidList; do %s \$pid | xargs -r -n 100" \
                      " kill -%s; done" % (pstree, str(signal))
        if len(hostList) == 0:
            if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                         " %s \"source %s; %s\" 2>&1 | tee %s" % \
                         (
                             osProfile, psshpre, self.__timeout,
                             self.__hostsFile,
                             parallel_num, self.__outputPath,
                             self.__errorPath, osProfile, timeOutCmd,
                             self.__resultFile)
            else:
                sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                         " %s \"source %s;source %s;%s\" 2>&1 | tee %s" % \
                         (
                             osProfile, psshpre, self.__timeout,
                             self.__hostsFile,
                             parallel_num, self.__outputPath,
                             self.__errorPath, osProfile, userProfile,
                             timeOutCmd,
                             self.__resultFile)
        else:
            if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                         " %s \"source %s; %s\" 2>&1 | tee %s" % \
                         (osProfile, psshpre, self.__timeout,
                          " -H ".join(hostList), parallel_num,
                          self.__outputPath,
                          self.__errorPath, osProfile, timeOutCmd,
                          self.__resultFile)
            else:
                sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                         " %s \"source %s;source %s;%s\" 2>&1 | tee %s" % \
                         (osProfile, psshpre, self.__timeout,
                          " -H ".join(hostList), parallel_num,
                          self.__outputPath,
                          self.__errorPath, osProfile, userProfile,
                          timeOutCmd, self.__resultFile)
        (status, output) = CmdUtil.getstatusoutput_by_fast_popen(sshCmd)
        if logger:
            logger.debug("{timeout clean} status: %s, output: %s" % (
                status, SensitiveMask.mask_pwd(output)))

    def executeCommand(self, cmd, cmdReturn=DefaultValue.SUCCESS,
                       hostList=None, env_file="", parallel_num=300,
                       checkenv=False):
        """
        function: Execute command on all hosts
        input : cmd, descript, cmdReturn, hostList, env_file, parallel_num
        output: NA
        """
        sshCmd = ""
        localMode = False
        resultMap = {}
        outputCollect = ""
        isTimeOut = False
        if hostList is None:
            hostList = []
        try:
            mpprcFile, userProfile, osProfile = self.getUserOSProfile(
                env_file)
            if os.getuid() == 0:
                unpathpath = os.path.dirname(os.path.realpath(__file__))
                GPHOME = os.path.realpath(os.path.join(unpathpath, "../../../"))
            else:
                GPHOME = self.getGPHOMEPath(osProfile)
            psshpre = "python3 %s/script/gspylib/pssh/bin/pssh" % GPHOME

            # clean result file
            if os.path.exists(self.__resultFile):
                os.remove(self.__resultFile)

            if len(hostList) == 0:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                             " %s \"source %s; %s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                self.__hostsFile, parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, cmd, self.__resultFile)
                else:
                    sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                             " %s \"source %s;source %s;%s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                self.__hostsFile, parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, userProfile, cmd,
                                self.__resultFile)
                hostList = self.hostNames
            else:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                             " %s \"source %s; %s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                " -H ".join(hostList), parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, cmd, self.__resultFile)
                else:
                    sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                             " %s \"source %s;source %s;%s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                " -H ".join(hostList), parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, userProfile, cmd,
                                self.__resultFile)

            # single cluster or execute only in local node.
            if (len(hostList) == 1 and
                    hostList[0] == NetUtil.GetHostIpOrName()
                    and cmd.find(" --lock-cluster ") < 0):
                localMode = True
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s ; %s 2>&1" % (osProfile, cmd)
                else:
                    sshCmd = "source %s ; source %s; %s 2>&1" \
                             % (osProfile, userProfile, cmd)

            # if it is localMode, it means does not call pssh,
            # so there is no time out
            (status, output) = subprocess.getstatusoutput(sshCmd)
            # when the pssh is time out, kill parent and child process
            if not localMode:
                if output.find("Timed out, Killed by signal 9") > 0:
                    self.timeOutClean(cmd, psshpre, hostList, env_file,
                                      parallel_num)
                    isTimeOut = True
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % SensitiveMask.mask_pwd(sshCmd) +
                                    " Error:\n%s" % SensitiveMask.mask_pwd(output))
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % SensitiveMask.mask_pwd(sshCmd) +
                                    " Error:\n%s" % SensitiveMask.mask_pwd(output))

            if localMode:
                resultMap[hostList[0]] = DefaultValue.SUCCESS if status == 0 \
                    else DefaultValue.FAILURE
                outputCollect = "[%s] %s:\n%s" \
                                % ("SUCCESS" if status == 0 else "FAILURE",
                                   hostList[0], SensitiveMask.mask_pwd(output))
            else:
                # ip and host name should match here
                resultMap, outputCollect = self.parseSshResult(hostList)
        except Exception as e:
            if not isTimeOut:
                self.clenSshResultFiles()
            raise Exception(str(e))

        for host in hostList:
            if resultMap.get(host) != cmdReturn:
                if outputCollect.find("GAUSS-5") == -1:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % cmd + " Result:%s.\nError:\n%s"
                                    % (resultMap, SensitiveMask.mask_pwd(outputCollect)))
                else:
                    raise Exception(SensitiveMask.mask_pwd(outputCollect))
        if checkenv:
            for res in output.split("\n"):
                if res.find("[SUCCESS]") >= 0:
                    continue
                elif res == "":
                    continue
                else:
                    if mpprcFile != "" and mpprcFile is not None:
                        envfile = mpprcFile + " and /etc/profile"
                    else:
                        envfile = "/etc/profile and ~/.bashrc"
                    raise Exception(ErrorCode.GAUSS_518["GAUSS_51808"]
                                    % res + "Please check %s." % envfile)

    def getSshStatusOutput(self, cmd, hostList=None, env_file="",
                           gp_path="", parallel_num=300, ssh_config=""):
        """
        function: Get command status and output
        input : cmd, hostList, env_file, gp_path, parallel_num
        output: resultMap, outputCollect
        """
        sshCmd = ""
        localMode = False
        resultMap = {}
        outputCollect = ""
        isTimeOut = False
        need_replace_quotes = False

        if hostList is None:
            hostList = []

        if cmd.find("[need_replace_quotes]") != -1:
            cmd = cmd.replace("[need_replace_quotes]", "")
            need_replace_quotes = True
        fp = None

        try:
            mpprcFile, userProfile, osProfile = self.getUserOSProfile(
                env_file)
            # clean result file
            if os.path.exists(self.__resultFile):
                os.remove(self.__resultFile)

            if gp_path.strip():
                GPHOME = gp_path.strip()
            elif os.getuid() == 0:
                unpathpath = os.path.dirname(os.path.realpath(__file__))
                GPHOME = os.path.realpath(os.path.join(unpathpath, "../../../"))
            else:
                GPHOME = self.getGPHOMEPath(osProfile)
            psshpre = "python3 %s/script/gspylib/pssh/bin/pssh" % GPHOME
            if ssh_config:
                if os.path.exists(ssh_config) and os.path.isfile(ssh_config):
                    psshpre += ' -x "-F %s" ' % ssh_config

            if len(hostList) == 0:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                             " %s \"source %s; %s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                self.__hostsFile, parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, cmd, self.__resultFile)
                else:
                    sshCmd = "source %s && %s -t %s -h %s -P -p %s -o %s -e" \
                             " %s \"source %s;source %s;%s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                self.__hostsFile, parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, userProfile, cmd,
                                self.__resultFile)
                hostList = self.hostNames
            else:
                if need_replace_quotes:
                    remote_cmd = cmd.replace("\"", "\\\"")
                else:
                    remote_cmd = cmd
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                             " %s \"source %s; %s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                " -H ".join(hostList), parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, remote_cmd, self.__resultFile)
                else:
                    sshCmd = "source %s && %s -t %s -H %s -P -p %s -o %s -e" \
                             " %s \"source %s;source %s;%s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                " -H ".join(hostList), parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, userProfile, remote_cmd,
                                self.__resultFile)

            # single cluster or execute only in local node.
            if (len(hostList) == 1 and
                    hostList[0] == NetUtil.GetHostIpOrName()):
                localMode = True
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s ; %s 2>&1" % (osProfile, cmd)
                else:
                    sshCmd = "source %s ; source %s; %s 2>&1" % (osProfile,
                                                                 userProfile,
                                                                 cmd)

            (status, output) = subprocess.getstatusoutput(sshCmd)
            # when the pssh is time out, kill parent and child process
            if not localMode:
                if output.find("Timed out, Killed by signal 9") > 0:
                    isTimeOut = True
                    self.timeOutClean(cmd, psshpre, hostList, env_file,
                                      parallel_num)
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % sshCmd + " Error:\n%s" % SensitiveMask.mask_pwd(output))
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                    % sshCmd + " Error:\n%s" % SensitiveMask.mask_pwd(output))

            if localMode:
                dir_permission = 0o700
                if status == 0:
                    resultMap[hostList[0]] = DefaultValue.SUCCESS
                    outputCollect = "[%s] %s:\n%s" % ("SUCCESS", hostList[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__outputPath):
                        os.makedirs(self.__outputPath, mode=dir_permission)
                    file_path = os.path.join(self.__outputPath, hostList[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
                else:
                    resultMap[hostList[0]] = DefaultValue.FAILURE
                    outputCollect = "[%s] %s:\n%s" % ("FAILURE", hostList[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__errorPath):
                        os.makedirs(self.__errorPath, mode=dir_permission)
                    file_path = os.path.join(self.__errorPath, hostList[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
            else:
                resultMap, outputCollect = self.parseSshResult(hostList)
        except Exception as e:
            if fp:
                fp.close()
            if not isTimeOut:
                self.clenSshResultFiles()
            raise Exception(str(e))

        for host in hostList:
            if resultMap.get(host) != DefaultValue.SUCCESS:
                if outputCollect.find("GAUSS-5") == -1:
                    outputCollect = ErrorCode.GAUSS_514["GAUSS_51400"] \
                                    % SensitiveMask.mask_pwd(cmd) \
                                    + " Error:\n%s." % SensitiveMask.mask_pwd(outputCollect)
                    break

        return resultMap, outputCollect

    def parseSshOutput(self, hostList):
        """
        function:
          parse ssh output on every host
        input:
          hostList: the hostname list of all hosts
        output:
          a dict, like this "hostname : info of this host"
        hiden info:
          the output info of all hosts
        ppp:
          for a host in hostList
            if outputfile exists
              open file with the same name
              read context into a str
              close file
              save info of this host
            else
              raise exception
          return host info list
        """
        resultMap = {}
        try:
            for host in hostList:
                context = ""
                sshOutPutFile = "%s/%s" % (self.__outputPath, host)
                sshErrorPutFile = "%s/%s" % (self.__errorPath, host)

                if os.path.isfile(sshOutPutFile):
                    with open(sshOutPutFile, "r") as fp:
                        context = fp.read()
                    resultMap[host] = context
                if os.path.isfile(sshErrorPutFile):
                    with open(sshErrorPutFile, "r") as fp:
                        context += fp.read()
                    resultMap[host] = context
                if (not os.path.isfile(sshOutPutFile) and
                        not os.path.isfile(sshErrorPutFile)):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                                    % "%s or %s"
                                    % (sshOutPutFile, sshErrorPutFile))
        except Exception as e:
            raise Exception(str(e))

        return resultMap

    def scpFiles(self, srcFile, targetDir, hostList=None, env_file="",
                 gp_path="", parallel_num=300):
        """
        function: copy files to other path
        input : srcFile, targetDir, hostList, env_file, gp_path, parallel_num
        output: NA
        """
        scpCmd = "source /etc/profile"
        outputCollect = ""
        localMode = False
        resultMap = {}
        if hostList is None:
            hostList = []
        try:
            if env_file != "":
                mpprcFile = env_file
            else:
                mpprcFile = EnvUtil.getEnv(DefaultValue.MPPRC_FILE_ENV)
            if mpprcFile != "" and mpprcFile is not None:
                scpCmd += " && source %s" % mpprcFile

            if gp_path == "":
                cmdpre = "%s && echo $GPHOME" % scpCmd
                (status, output) = subprocess.getstatusoutput(cmdpre)
                if status != 0 or not output or output.strip() == "":
                    raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"]
                                    % "GPHOME" + "The cmd is %s" % cmdpre)
                GPHOME = output.strip()
            else:
                GPHOME = gp_path.strip()
            pscppre = "python3 %s/script/gspylib/pssh/bin/pscp" % GPHOME

            if len(hostList) == 0:
                scpCmd += " && %s -r -v -t %s -p %s -h %s -o %s -e %s %s %s" \
                          " 2>&1 | tee %s" % (pscppre, self.__timeout,
                                              parallel_num, self.__hostsFile,
                                              self.__outputPath,
                                              self.__errorPath, srcFile,
                                              targetDir, self.__resultFile)
                hostList = self.hostNames
            if len(hostList) == 1 and hostList[0] == socket.gethostname() and \
                srcFile != targetDir and \
                srcFile != os.path.join(targetDir, os.path.split(srcFile)[1]):
                localMode = True
                scpCmd = "cp -r %s %s" % (srcFile, targetDir)
            else:
                scpCmd += " && %s -r -v -t %s -p %s -H %s -o %s -e %s %s %s" \
                          " 2>&1 | tee %s" % (pscppre, self.__timeout,
                                              parallel_num,
                                              " -H ".join(hostList),
                                              self.__outputPath,
                                              self.__errorPath, srcFile,
                                              targetDir, self.__resultFile)
            (status, output) = subprocess.getstatusoutput(scpCmd)

            # If sending the file fails, we retry after 3s to avoid the 
            # failure caused by intermittent network disconnection.
            # If the fails is caused by timeout. no need to retry.
            if status != 0 and output.find("Timed out") < 0:
                time.sleep(3)
                (status, output) = subprocess.getstatusoutput(scpCmd)

            if status != 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50216"]
                                % ("file [%s]" % srcFile) +
                                " To directory: %s."
                                % targetDir + " Error:\n%s" % output)
            if output.find("Timed out") > 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % scpCmd
                                + " Error:\n%s" % output)

            # ip and host name should match here
            if localMode:
                dir_permission = 0o700
                if status == 0:
                    resultMap[hostList[0]] = DefaultValue.SUCCESS
                    outputCollect = "[%s] %s:\n%s" % ("SUCCESS", hostList[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__outputPath):
                        os.makedirs(self.__outputPath, mode=dir_permission)
                    file_path = os.path.join(self.__outputPath, hostList[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
                else:
                    resultMap[hostList[0]] = DefaultValue.FAILURE
                    outputCollect = "[%s] %s:\n%s" % ("FAILURE", hostList[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__errorPath):
                        os.makedirs(self.__errorPath, mode=dir_permission)
                    file_path = os.path.join(self.__errorPath, hostList[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
            else:
                resultMap, outputCollect = self.parseSshResult(hostList)
        except Exception as e:
            self.clenSshResultFiles()
            raise Exception(str(e))

        for host in hostList:
            if resultMap.get(host) != DefaultValue.SUCCESS:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50216"]
                                % ("file [%s]" % srcFile) +
                                " To directory: %s." % targetDir +
                                " Command: %s.\nError:\n%s" % (SensitiveMask.mask_pwd(scpCmd),
                                    SensitiveMask.mask_pwd(outputCollect)))

    def checkRemoteFileExist(self, node, fileAbsPath, mpprcFile):
        """
        check remote node exist file
        this method depend on directory permisstion 'x'
        if exist return true,else retrun false
        """
        sshcmd = "if [ -e '%s' ];then echo 'exist tar file yes flag';" \
                 "else echo 'exist tar file no flag';fi" % fileAbsPath
        if node != NetUtil.GetHostIpOrName():
            outputCollect = self.getSshStatusOutput(sshcmd,
                                                                 [node],
                                                                 mpprcFile)[1]
        else:
            outputCollect = subprocess.getstatusoutput(sshcmd)[1]
        if 'exist tar file yes flag' in outputCollect:
            return True
        elif 'exist tar file no flag' in outputCollect:
            return False
        else:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % sshcmd
                            + "On node %s" % node)

    def __writeHostFiles(self):
        """
        function: Write all hostname to a file
        input : NA
        output: NA
        """
        try:
            FileUtil.createFileInSafeMode(self.__hostsFile)
            with open(self.__hostsFile, "w") as fp:
                for host in self.hostNames:
                    fp.write("%s\n" % host)
                fp.flush()
            subprocess.getstatusoutput("chmod %s '%s'"
                                       % (DefaultValue.FILE_MODE,
                                          self.__hostsFile))
        except Exception as e:
            FileUtil.removeFile(self.__hostsFile)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % "host file"
                            + " Error: \n%s" % str(e))

        # change the mode
        # if it created by root user,and permission is 640, then
        # install user will have no permission to read it, so we should set
        # its permission 644.
        FileUtil.changeMode(DefaultValue.KEY_HOSTS_FILE, self.__hostsFile, False,
                          "python")

    def __readCmdResult(self, resultFile, hostNum):
        """
        function: Read command result
        input : resultFile, hostNum, cmd
        output: resultMap
        """
        resultMap = {}
        try:
            with open(resultFile, "r") as fp:
                lines = fp.readlines()
            context = "".join(lines)
            for line in lines:
                resultPair = line.strip().split(" ")
                if len(resultPair) >= 4 and resultPair[2] == "[FAILURE]":
                    resultMap[resultPair[3]] = "Failure"
                if len(resultPair) >= 4 and resultPair[2] == "[SUCCESS]":
                    resultMap[resultPair[3]] = "Success"

            if len(resultMap) != hostNum:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"]
                                % ("valid return item number [%d]"
                                   % len(resultMap), "host number[%d]"
                                   % hostNum) + " The return result:\n%s."
                                % context)
        except Exception as e:
            raise Exception(str(e))

        return resultMap

    def setTimeOut(self, timeout):
        """
        function: Set a new timeout value for ssh tool.
        :param timeout: The new timeout value in seconds.
        :return: void
        """
        self.__timeout = timeout

    def get_ssh_session(self, remote_ip):
        """
        get ssh login session
        :param remote_ip:
        :return:
        """

        if remote_ip in self.__sessions.keys():
            return self.__sessions[remote_ip]
        return None

    def create_all_sessions(self, user, all_ips, passwds):
        """
        :param user:
        :param all_ips:
        :param passwds:
        :return:
        """
        for ip in all_ips:
            session = self.create_ssh_session(user, ip, passwds)
            if session:
                self.__sessions[ip] = session
            if not session:
                raise Exception(ErrorCode.GAUSS_535["GAUSS_53501"] +"IP is:%s" %ip)


    def create_ssh_session(self, user, ip, passwd):
        """
        create ssh session
        :param user:
        :param remote_ip:
        :param _passwd:
        :return:
        """
        try:
            ssh = paramiko.Transport((ip, 22))
        except Exception as e:
            raise Exception(
                ErrorCode.GAUSS_512["GAUSS_51220"] % ip + " Error: \n%s" % str(
                    e))
        try:
            ssh.connect(username=user, password=passwd[0])
            return ssh
        except Exception as e:
            ssh.close()
            raise Exception(ErrorCode.GAUSS_511["GAUSS_51107"] +
                            "Failed to ssh connect to node[%s]. Error:\n%s" % (ip, e))

    def close_all_session(self):
        """
        close all sessions
        :return:
        """
        for session in self.__sessions.values():
            session.close()

