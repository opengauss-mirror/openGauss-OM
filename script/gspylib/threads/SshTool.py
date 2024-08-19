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
import copy
import socket
import subprocess
import os
import sys
import datetime
import weakref
import time
from random import sample
import copy
import re
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
from base_utils.security.security_checker import SecurityChecker
from base_utils.os.hosts_util import HostsUtil

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

def get_package_path():
    """
    get package path, then can get script path, /package_path/script/
    :return:
    """
    dir_name = os.path.dirname(os.path.realpath(__file__))
    package_dir = os.path.join(dir_name, "./../../")
    return os.path.realpath(package_dir)

def get_sshexkey_file():
    """
    get gs_sshexkey file
    """
    gphome = os.environ.get("GPHOME")
    if gphome:
        trust_file = os.path.normpath(os.path.join(gphome, "script", "gs_sshexkey"))
    else:
        package_path = get_package_path()
        trust_file = os.path.normpath(os.path.join(package_path, "gs_sshexkey"))
    return trust_file

def check_local_mode(host):
    """
    function: check single host valid
    input : host
    output: NA
    """
    if host is None or not host:
        host = []
    if len(host) == 1:
        if host[0] == NetUtil.GetHostIpOrName() or host[0] in NetUtil.getIpAddressList():
            return True
    return False

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
        self.is_ip = False

        if hostNames:
            # if not ip, convert hostname to ip
            if not SecurityChecker.check_is_ip(hostNames[0]):
                self.is_ip = False
                # key:value hostname:ip
                host_ip_list = HostsUtil.hostname_list_to_ip_list(hostNames)
                if not host_ip_list:
                    raise Exception("Failed to hostname to ip.")
                self.hostNames = host_ip_list
            else:
                self.is_ip = True

        current_time = str(datetime.datetime.now()).replace(" ", "_").replace(
            ".", "_")
        randomnum = ''.join(sample('0123456789', 3))
        # can tmp path always access?
        if key == "":
            self.__hostsFile = "/tmp/gauss_hosts_file_%d_%s_%s" % (
                self.__pid, current_time, randomnum)
            self.__resultFile = "/tmp/gauss_result_%d_%s_%s.log" % (
                self.__pid, current_time, randomnum)
            self.__outputPath = "/tmp/gauss_output_files_%d_%s_%s" % (
                self.__pid, current_time, randomnum)
            self.__errorPath = "/tmp/gauss_error_files_%d_%s_%s" % (
                self.__pid, current_time, randomnum)
        else:
            self.__hostsFile = "/tmp/gauss_hosts_file_%d_%s_%s_%s" % (
                self.__pid, key, current_time, randomnum)
            self.__resultFile = "/tmp/gauss_result_%d_%s_%s_%s.log" % (
                self.__pid, key, current_time, randomnum)
            self.__outputPath = "/tmp/gauss_output_files_%d_%s_%s_%s" % (
                self.__pid, key, current_time, randomnum)
            self.__errorPath = "/tmp/gauss_error_files_%d_%s_%s_%s" % (
                self.__pid, key, current_time, randomnum)

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

    def createTrust(self, user, ips=[], skipHostnameSet=False, action=''):
        """
        function: create trust for specified user with both ip and hostname,
        when using N9000 tool create trust failed
        do not support using a normal user to create trust for another user.
        input : user, pwd, ips, skipHostnameSet 
        output: NA
        """
        tmp_log_file = copy.deepcopy(self.__logFile)
        if action == 'gs_postuninstall' and self.__logFile:
            tmp_log_file = os.path.realpath(
                os.path.join(os.path.dirname(self.__logFile), f'{action}.log'))

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
            trust_file = get_sshexkey_file()
            cmd = "%s -f %s -l '%s'" % (trust_file, tmp_hosts, tmp_log_file)
            if skipHostnameSet:
                cmd += " --skip-hostname-set"

            if os.getuid() == 0:
                cmd = "su - %s -c \"%s\" 2>&1" % (user, cmd)
            else:
                cmd += " 2>&1"
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
        if os.getuid() == 0:
            cmd = "su - %s -c 'cd %s'" % (username, ownerPath)
        else:
            cmd = "cd %s" % ownerPath
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
            gp_home = ""
            # osProfile if exists
            if osProfile and os.path.isfile(osProfile):
                cmd = "source %s && echo $GPHOME" % osProfile
                (status, output) = subprocess.getstatusoutput(cmd)
                if status == 0:
                    gp_home = output.strip()
            if not gp_home:
                gp_home = os.environ.get('GPHOME')
            if not gp_home:
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "GPHOME")
            return gp_home
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

            if not self.is_ip:
                res_map = {}
                for key, value in resultMap.items():
                    name = HostsUtil.ip_to_hostname(key)
                    res_map[name] = value
                resultMap = res_map
                
            for host in hostList:
                sshOutPutFile = "%s/%s" % (self.__outputPath, host)
                sshErrorPutFile = "%s/%s" % (self.__errorPath, host)
                # ip to hostname
                if not self.is_ip:
                    host = HostsUtil.ip_to_hostname(host)
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
        localMode = False
        localMode = check_local_mode(hostList)
        hostList = self.check_host_ip_list(hostList)
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
            hostList = self.hostNames
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
        if localMode:
            if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                sshCmd = "source %s ; %s 2>&1" % (osProfile, cmd)
            else:
                sshCmd = "source %s ; source %s; %s 2>&1" \
                            % (osProfile, userProfile, cmd)
        (status, output) = subprocess.getstatusoutput(sshCmd)

        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                            % sshCmd + " Error:\n%s" % SensitiveMask.mask_pwd(output))

        if logger:
            logger.debug("{timeout clean} status: %s, output: %s" % (
                status, SensitiveMask.mask_pwd(output)))

    def check_host_ip_list(self, host_list):
        """
        function: check host valid
        input : host_list
        output: NA
        """
        host = []
        if host_list is None or not host_list:
            return host
        else:
            if SecurityChecker.check_is_ip(host_list[0]):
                self.is_ip = True
                host = host_list
            else:
                self.is_ip = False
                host = HostsUtil.hostname_list_to_ip_list(host_list)
        return host

    def executeCommand(self, cmd, cmdReturn=DefaultValue.SUCCESS,
                       hostList=None, env_file="", parallel_num=300,
                       checkenv=False, parallelism=True ):
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
        localMode = check_local_mode(hostList)
        hostList = self.check_host_ip_list(hostList)
        try:
            mpprcFile, userProfile, osProfile = self.getUserOSProfile(
                env_file)
            if os.getuid() == 0:
                unpathpath = os.path.dirname(os.path.realpath(__file__))
                GPHOME = os.path.realpath(os.path.join(unpathpath, "../../../"))
            else:
                GPHOME = self.getGPHOMEPath(userProfile)
            psshpre = "python3 %s/script/gspylib/pssh/bin/pssh" % GPHOME

            # clean result file
            if os.path.exists(self.__resultFile):
                os.remove(self.__resultFile)

            if len(hostList) == 0:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s && %s -t %s parallelism_flag -P -p %s -o %s -e" \
                             " %s \"source %s; %s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                              parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, cmd, self.__resultFile)
                else:
                    sshCmd = "source %s && %s -t %s parallelism_flag -P -p %s -o %s -e" \
                             " %s \"source %s;source %s;%s\" 2>&1 | tee %s" \
                             % (osProfile, psshpre, self.__timeout,
                                 parallel_num,
                                self.__outputPath, self.__errorPath,
                                osProfile, userProfile, cmd,
                                self.__resultFile)
                if parallelism:
                    sshCmd = sshCmd.replace('parallelism_flag',
                                            '-h ' + self.__hostsFile)
                hostList = self.hostNames
                localMode = check_local_mode(hostList)
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
            if localMode:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s ; %s 2>&1" % (osProfile, cmd)
                else:
                    sshCmd = "source %s ; source %s; %s 2>&1" \
                             % (osProfile, userProfile, cmd)

            # if it is localMode, it means does not call pssh,
            # so there is no time out
            if not parallelism:
                for dss_host in hostList:
                    dss_cmd = sshCmd.replace('parallelism_flag',
                                            '-H ' + dss_host)
                    status, output = subprocess.getstatusoutput(dss_cmd)
                    # killed by signal 9 or Signals.SIGKILL
                    if output.find("Timed out, Killed by signal") > 0:
                        self.timeOutClean(cmd, psshpre, hostList, env_file,
                                        parallel_num)
                        isTimeOut = True
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                        % SensitiveMask.mask_pwd(dss_cmd) +
                                        " Error:\n%s" % SensitiveMask.mask_pwd(output))
                    if status != 0:
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                        % SensitiveMask.mask_pwd(dss_cmd) +
                                        " Error:\n%s" % SensitiveMask.mask_pwd(output))
                    dsts, dout = self.parseSshResult([dss_host])
                    if dsts.get(dss_host, '') == DefaultValue.FAILURE:
                        # pssh already has errorcdoe
                        raise Exception(SensitiveMask.mask_pwd(dout))
                return
            else:
                status, output = subprocess.getstatusoutput(sshCmd)
            # when the pssh is time out, kill parent and child process
            if not localMode and parallelism:
                if output.find("Timed out, Killed by signal") > 0:
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
                if not self.is_ip:
                    hostList = [HostsUtil.ip_to_hostname(hostList[0])]
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
            if not localMode and not self.is_ip:
                host = HostsUtil.ip_to_hostname(host)
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
        localMode = check_local_mode(hostList)
        hostList = self.check_host_ip_list(hostList)

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
                GPHOME = self.getGPHOMEPath(userProfile)
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
                localMode = check_local_mode(hostList)
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
            if localMode:
                if os.getuid() == 0 and (mpprcFile == "" or not mpprcFile):
                    sshCmd = "source %s ; %s 2>&1" % (osProfile, cmd)
                else:
                    sshCmd = "source %s ; source %s; %s 2>&1" % (osProfile,
                                                                 userProfile,
                                                                 cmd)

            (status, output) = subprocess.getstatusoutput(sshCmd)
            # when the pssh is time out, kill parent and child process
            if not localMode:
                # killed by signal 9 or Signals.SIGKILL
                if output.find("Timed out, Killed by signal") > 0:
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
                if not self.is_ip:
                    hostList = [HostsUtil.ip_to_hostname(hostList[0])]
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
            if not localMode and not self.is_ip:
                host = HostsUtil.ip_to_hostname(host)
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
            if not SecurityChecker.check_is_ip(hostList[0]):
                hostList = HostsUtil.hostname_list_to_ip_list(hostList)
            for host in hostList:
                context = ""
                sshOutPutFile = "%s/%s" % (self.__outputPath, host)
                sshErrorPutFile = "%s/%s" % (self.__errorPath, host)

                if not self.is_ip:
                    host = HostsUtil.ip_to_hostname(host)
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
        gp_home = ""
        outputCollect = ""
        localMode = False
        resultMap = {}
        ssh_hosts = []
        localMode = False
        localMode = check_local_mode(hostList)
        hostList = self.check_host_ip_list(hostList)
        try:
            if env_file != "":
                mpprcFile = env_file
            else:
                mpprcFile = EnvUtil.getEnv(DefaultValue.MPPRC_FILE_ENV)
            
            if mpprcFile and os.path.isfile(mpprcFile):
                cmd = "source %s && echo $GPHOME" % mpprcFile
                (status, output) = subprocess.getstatusoutput(cmd)
                if status == 0:
                    gp_home = output.strip()
            if not gp_home:
                gp_home = os.environ.get('GPHOME')
            if gp_path != "":
                gp_home = gp_path.strip()
            pscppre = "python3 %s/script/gspylib/pssh/bin/pscp" % gp_home

            if len(hostList) == 0:
                ssh_hosts = copy.deepcopy(self.hostNames)
                localMode = check_local_mode(ssh_hosts)
            else:
                ssh_hosts = copy.deepcopy(hostList)
            if localMode and \
                srcFile != targetDir and \
                srcFile != os.path.join(targetDir, os.path.split(srcFile)[1]):
                scpCmd = "cp -r %s %s" % (srcFile, targetDir)
            else:
                # cp file on local node
                self.cp_file_on_local_node(srcFile, targetDir, resultMap, ssh_hosts)
                if not ssh_hosts:
                    return
                scpCmd = "%s -r -v -t %s -p %s -H %s -o %s -e %s %s %s" \
                          " 2>&1 | tee %s" % (pscppre, self.__timeout,
                                              parallel_num,
                                              " -H ".join(ssh_hosts),
                                              self.__outputPath,
                                              self.__errorPath, srcFile,
                                              targetDir, self.__resultFile)
            (status, output) = subprocess.getstatusoutput(scpCmd)

            # If sending the file fails, we retry  3 * 10s to avoid the 
            # failure caused by intermittent network disconnection. such as Broken pipe.
            # If the fails is caused by timeout. no need to retry.
            max_retry_times = 3
            while(max_retry_times > 0 and status != 0 and output.find("Timed out") < 0):
                max_retry_times -= 1
                time.sleep(10)
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
                if not self.is_ip:
                    ssh_hosts = [HostsUtil.ip_to_hostname(ssh_hosts[0])]
                if status == 0:
                    resultMap[ssh_hosts[0]] = DefaultValue.SUCCESS
                    outputCollect = "[%s] %s:\n%s" % ("SUCCESS", ssh_hosts[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__outputPath):
                        os.makedirs(self.__outputPath, mode=dir_permission)
                    file_path = os.path.join(self.__outputPath, ssh_hosts[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
                else:
                    resultMap[ssh_hosts[0]] = DefaultValue.FAILURE
                    outputCollect = "[%s] %s:\n%s" % ("FAILURE", ssh_hosts[0],
                                                      SensitiveMask.mask_pwd(output))

                    if not os.path.exists(self.__errorPath):
                        os.makedirs(self.__errorPath, mode=dir_permission)
                    file_path = os.path.join(self.__errorPath, ssh_hosts[0])
                    FileUtil.createFileInSafeMode(file_path)
                    with open(file_path, "w") as fp:
                        fp.write(SensitiveMask.mask_pwd(output))
                        fp.flush()
                        fp.close()
            else:
                resultMap, outputCollect = self.parseSshResult(ssh_hosts)
        except Exception as e:
            self.clenSshResultFiles()
            raise Exception(str(e))
        
        for host in ssh_hosts:
            if not self.is_ip:
                host = HostsUtil.ip_to_hostname(host)
            if resultMap.get(host) != DefaultValue.SUCCESS:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50216"]
                                % ("file [%s]" % srcFile) +
                                " To directory: %s." % targetDir +
                                " Command: %s.\nError:\n%s" % (SensitiveMask.mask_pwd(scpCmd),
                                    SensitiveMask.mask_pwd(outputCollect)))

    def cp_file_on_local_node(self, src_file, target_dir, result_map, ssh_hosts):
        """"
        copy file on local node
        """
        local_name_or_ip = ""
        local_name = socket.gethostname()
        if not self.is_ip:
            local_name_or_ip = HostsUtil.hostname_list_to_ip_list([local_name])[0]
        else:
            local_name_or_ip = local_name
        if local_name_or_ip in ssh_hosts:
            localhost_idx = ssh_hosts.index(local_name_or_ip)
            ssh_hosts.pop(localhost_idx)
            cpcmd = "cp -r %s %s" % (src_file, target_dir)
            if src_file != target_dir and src_file != os.path.join(target_dir, os.path.basename(src_file)):
                (status, output) = subprocess.getstatusoutput(cpcmd)
                if status == 0:
                    result_map[local_name_or_ip] = DefaultValue.SUCCESS
                else:
                    result_map[local_name_or_ip] = DefaultValue.FAILURE

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
                if len(resultPair) < 4:
                    continue

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
