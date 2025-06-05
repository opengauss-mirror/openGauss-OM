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
# Description  :
#############################################################################

# ---------------command path--------------------
import os
import subprocess
import threading
import time
from subprocess import PIPE, Popen
from datetime import datetime
from datetime import timedelta
import pwd
from gspylib.common.ErrorCode import ErrorCode
from base_utils.common.exceptions import CommandNotFoundException
from base_utils.common.fast_popen import FastPopen
from base_utils.security.security_checker import SecurityChecker

CMD_PATH = ['/bin', '/usr/local/bin', '/usr/bin', '/sbin', '/usr/sbin']
CMD_CACHE = {}
BLANK_SPACE = " "
COLON = ":"


class CmdUtil(object):
    """ Cmd util"""

    SOURCE_CMD = 'source'
    ENV_SOURCE_CMD = "source /etc/profile;source ~/.bashrc;" \
                     "if [ $MPPDB_ENV_SEPARATE_PATH ]; " \
                     "then source $MPPDB_ENV_SEPARATE_PATH; fi"
    PING_IPV4_TOOL = "ping"
    PING_IPV6_TOOL = "ping6"
    
    @staticmethod
    def execCmd(cmd, noexcept=False):
        """
        function: execute cmd
        input: cmd, noexcept
        output: output of cmd
        """
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            if noexcept:
                return output
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % str(output))
        return output

    @staticmethod
    def findCmdInPath(cmd, additional_paths=None, print_error=True):
        """
        function: find cmd in path
        input: cmd, additional_paths, printError
        output: NA
        """
        global CMD_CACHE
        if additional_paths is None:
            additional_paths = []
        if cmd not in CMD_CACHE:
            # Search additional paths and don't add to cache.
            for p in additional_paths:
                f = os.path.join(p, cmd)
                if os.path.exists(f):
                    return f

            for p in CMD_PATH:
                f = os.path.join(p, cmd)
                if os.path.exists(f):
                    CMD_CACHE[cmd] = f
                    return f

            if cmd == "killall":
                gphome = os.getenv("GPHOME")
                if gphome is None or \
                        not os.path.exists(os.path.join(gphome, "script/killall")):
                    gphome = os.path.dirname(os.path.realpath(__file__)) \
                             + "/../../.."
                gphome = gphome.replace("\\", "\\\\").replace('"', '\\"\\"')
                SecurityChecker.check_injection_char(gphome)
                if gphome != "" and os.path.exists(os.path.join(gphome,
                                                                "script/killall")):
                    return os.path.join(gphome, "script/killall")
                else:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % "killall")

            if print_error:
                print('Command %s not found' % cmd)
            search_path = CMD_PATH[:]
            search_path.extend(additional_paths)
            raise CommandNotFoundException(cmd, search_path)
        else:
            return CMD_CACHE[cmd]

    @staticmethod
    def getCreateFileCmd(path):
        """
        function: get create file cmd
        input  : path
        output : str
        """
        return "touch '%s'" % path

    @staticmethod
    def getMoveFileCmd(src, dest):
        """
        function: get move file cmd
        input  : src, dest
        output : str
        """
        cmd = "mv '%s' '%s'" % (src, dest)
        return cmd

    @staticmethod
    def getRemoveCmd(path_type):
        """
        function: get remove cmd
        input  : path_type
        output : str
        """
        opts = " "
        if path_type == "file":
            opts = " -f "
        elif path_type == "directory":
            opts = " -rf "
        return CmdUtil.findCmdInPath('rm') + opts

    @staticmethod
    def getChmodCmd(permission, src, recursive=False):
        """
        function: get chmod cmd
        input  : permission, src, recursive
        output : str
        """
        return CmdUtil.findCmdInPath('chmod') + \
               (" -R " if recursive else BLANK_SPACE) + \
               permission + BLANK_SPACE + src

    @staticmethod
    def getChownCmd(owner, group, src, recursive=False):
        """
        function: get chown cmd
        input  : owner, group, src, recursive
        output : str
        """
        return CmdUtil.findCmdInPath('chown') + \
               (" -R " if recursive else BLANK_SPACE) + owner + \
               COLON + group + BLANK_SPACE + src

    @staticmethod
    def getCopyCmd(src, dest, path_type=""):
        """
        function: get copy cmd
        input  : src, dest, path_type
        output : str
        """
        opts = " "
        if path_type == "directory":
            opts = " -r "
        return CmdUtil.findCmdInPath('cp') + " -p  -f " + opts + BLANK_SPACE + "'" + \
               src + "'" + BLANK_SPACE + "'" + dest + "'"

    @staticmethod
    def getMoveCmd(src, dest):
        """
        function: get move cmd
        input  : src, dest
        output : str
        """
        return CmdUtil.findCmdInPath('mv') + " -f " + "'" + src + \
               "'" + BLANK_SPACE + "'" + dest + "'"

    @staticmethod
    def getMakeDirCmd(src, recursive=False):
        """
        function: get make dir cmd
        input  : src, recursive
        output : str
        """
        return CmdUtil.findCmdInPath('mkdir') + \
               (" -p " if recursive else BLANK_SPACE) + "'" + src + "'"

    @staticmethod
    def getPingCmd(host, count, interval, packet_size=56):
        """
        function: get ping cmd
        input  : host, count, interval, packet_size
        output : str
        """
        ping_tool = CmdUtil.PING_IPV4_TOOL
        if os.getenv("IP_TYPE") == "ipv6":
            ping_tool = CmdUtil.PING_IPV6_TOOL
        opts = " "
        if int(packet_size) != int(56):
            opts = " -s " + str(packet_size)
        return CmdUtil.findCmdInPath(ping_tool) + BLANK_SPACE + host + " -c " + \
                    count + " -i " + interval + opts

    @staticmethod
    def get_ping_tool():
        ping_tool = CmdUtil.PING_IPV4_TOOL
        if os.getenv("IP_TYPE") == "ipv6":
            ping_tool = CmdUtil.PING_IPV6_TOOL
        return ping_tool

    @staticmethod
    def getWcCmd():
        """
        function: get wc cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('wc')

    @staticmethod
    def getTarCmd():
        """
        function: get tar cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('tar')

    @staticmethod
    def getZipCmd():
        """
        function: get zip cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('zip')

    @staticmethod
    def getUnzipCmd():
        """
        function: get unzip cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('unzip')

    @staticmethod
    def getSedCmd():
        """
        function: get sed cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('sed')

    @staticmethod
    def getGrepCmd():
        """
        function: get grep cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('grep')

    @staticmethod
    def getDateCmd():
        """
        function: get date cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('date')

    @staticmethod
    def getAwkCmd():
        """
        function: get awk cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('awk')

    @staticmethod
    def getFindCmd():
        """
        function: get find cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('find')

    @staticmethod
    def getTouchCmd(file_name):
        """
        function: get touch cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('touch') + BLANK_SPACE + file_name

    @staticmethod
    def getListCmd():
        """
        function: get list cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('ls')

    @staticmethod
    def getSHA256Cmd():
        """
        function: get sha256 cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('sha256sum')

    @staticmethod
    def getCatCmd():
        """
        function: get cat cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('cat')

    @staticmethod
    def getCdCmd(path):
        """
        function: get cd cmd
        input  : path
        output : str
        """
        return 'cd' + BLANK_SPACE + "'" + path + "'"

    @staticmethod
    def getAllCrontabCmd():
        """
        function: get all crontab cmd
        input  : NA
        output : str
        """
        cmd = CmdUtil.findCmdInPath('crontab') + BLANK_SPACE + " -l"
        return cmd

    @staticmethod
    def getCrontabCmd():
        """
        function: get crontab cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('crontab')

    @staticmethod
    def getKillProcessCmd(signal, pid):
        """
        function: get kill process cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('kill') + " -" + signal + BLANK_SPACE + pid

    @staticmethod
    def getKillallProcessCmd(signal, user_name, proc_name=""):
        """
        function: get killall process cmd
        input  : signal, username, proc_name
        output : str
        """
        if proc_name != "":
            return CmdUtil.findCmdInPath('killall') + " -s " + signal + " -u " + \
                   user_name + BLANK_SPACE + proc_name
        return CmdUtil.findCmdInPath('killall') + " -s " + signal + " -u " + \
                   user_name

    @staticmethod
    def getXargsCmd():
        """
        function: get xargs cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('xargs')

    @staticmethod
    def getServiceCmd(service_name, action):
        """
        function: get service cmd
        input  : service_name, action
        output : str
        """
        return CmdUtil.findCmdInPath('service') + BLANK_SPACE + service_name + \
               BLANK_SPACE + action

    @staticmethod
    def getSystemctlCmd(service_name, action):
        """
        function: get systemctl cmd
        input  : service_name, action
        output : str
        """
        return CmdUtil.findCmdInPath('systemctl') + BLANK_SPACE + action + \
               BLANK_SPACE + service_name

    @staticmethod
    def getSysctlCmd():
        """
        function: get sysctl cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('sysctl')

    @staticmethod
    def getUlimitCmd():
        """
        function: get ulimit cmd
        input  : NA
        output : str
        """
        return 'ulimit'

    @staticmethod
    def getGetConfValueCmd():
        """
        function: get conf value cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('getconf') + " PAGESIZE "

    @staticmethod
    def getMountCmd():
        """
        function: get dd cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('mount')

    @staticmethod
    def getEthtoolCmd():
        """
        function: get eth tool cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('ethtool')

    @staticmethod
    def getTailCmd():
        """
        function: get tail cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('tail')

    @staticmethod
    def getWhichCmd():
        """
        function: get which cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('which')

    @staticmethod
    def getLscpuCmd():
        """
        function: get lscpu cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('lscpu')

    @staticmethod
    def getDmidecodeCmd():
        """
        function: get dmidecode cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('dmidecode')

    @staticmethod
    def getSshCmd(address, timeout=None):
        """
        function: get ssh cmd
        input  : NA
        output : str
        """
        env_source_cmd = CmdUtil.get_env_source_cmd()
        if timeout:
            return "%s;pssh --trace-id %s -s -t %s -H %s" % (env_source_cmd,
                threading.currentThread().getName(), str(timeout), address)
        return "%s;pssh --trace-id %s -s -H %s" % (env_source_cmd, 
                threading.currentThread().getName(), address)

    @staticmethod
    def getSshCommand(ip, cmd, timeout=None):
        """
        function : Get ssh command
        input  : null
        output : exe_cmd
        """
        exe_cmd = "%s \"%s\"" % (CmdUtil.getSshCmd(ip, timeout=timeout), cmd)
        return exe_cmd

    @staticmethod
    def getNtpqCmd():
        """
        function: get ntpq cmd
        input  : NA
        output : str
        """
        return "/usr/sbin/ntpq -p "

    @staticmethod
    def getShellCmd():
        """
        function: get shell cmd
        input  : NA
        output : str
        """
        return CmdUtil.findCmdInPath('sh')

    @staticmethod
    def getFileSHA256Cmd(fileName):
        """
        function: get file sha256 cmd
        input  : fileName
        output : str
        """
        cmd = "%s '%s' | %s -F\" \" '{print $1}' " % (CmdUtil.getSHA256Cmd(),
                                                      fileName,
                                                      CmdUtil.getAwkCmd())
        return cmd

    @staticmethod
    def getDiskFreeCmd(mounted="", inode=False):
        # -P is for POSIX formatting.  Prevents error
        # on lines that would wrap
        return CmdUtil.findCmdInPath('df') + " -Pk " + \
               (" -i " if inode else " -h ") + mounted

    @staticmethod
    def getReplaceFileLineContentCmd(old_line, new_line, path):
        """
        function: get replace file line content cmd
        input  : old_line, new_line, path
        output : str
        """
        cmd = "%s -i \"s/%s/%s/g\" '%s'" % (CmdUtil.getSedCmd(), old_line,
                                            new_line, path)
        return cmd

    @staticmethod
    def getDirSizeCmd(path, unit=""):
        # -s only shows the total size
        # unit specify the output size unit
        return CmdUtil.findCmdInPath('du') + " -s " + (" -B %s " % unit
                                               if unit else " -h ") + path

    @staticmethod
    def getSysConfiguration():
        """
        function : The size range of PAGE_SIZE obtained by getconf
        input : NA
        output: string
        """
        config_cmd = CmdUtil.getGetConfValueCmd()
        (status, output) = subprocess.getstatusoutput(config_cmd)
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            "system config pagesize" +
                            "The cmd is %s" % config_cmd)
        return output

    @staticmethod
    def getExecuteCmdWithUserProfile(user, user_profile, execute_cmd,
                                     ignore_error=True):
        """
        """
        if (user != "") and (os.getuid() == 0):
            cmd = "su - %s -c 'source %s; %s'" % (user, user_profile, execute_cmd)
        else:
            cmd = "source %s; %s" % (user_profile, execute_cmd)
        if ignore_error:
            cmd += " 2>/dev/null"
        return cmd

    @staticmethod
    def getUserLimits(limit_type):
        """
        function : Get current user process limits
        input : string
        output: string
        """
        limit = CmdUtil.getUlimitCmd()
        limit_cmd = "%s -a | %s -F '%s'" % (limit, CmdUtil.getGrepCmd(), limit_type)
        (status, output) = subprocess.getstatusoutput(limit_cmd)
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % limit_cmd +
                            " Error:\n%s" % output)
        return output

    @staticmethod
    def retryGetstatusoutput(cmd, retry_time=3, sleep_time=1, check_output=False):
        """
        function : retry getStatusoutput
        @param cmd: command  going to be execute
        @param retry_time: default retry 3 times after execution failure
        @param sleep_time: default sleep 1 second then start retry
        """
        retry_time += 1
        for _ in range(retry_time):
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                time.sleep(sleep_time)
            elif check_output:
                if str(output).strip():
                    break
                else:
                    time.sleep(sleep_time)
            else:
                break
        return status, output

    @staticmethod
    def retry_util_timeout(cmd, timeout, sleep_time=1):
        """
        retry execute cmd with giving timeout.
        """
        end_time = datetime.now() + timedelta(seconds=int(timeout))
        status, output = 1, 1
        while datetime.now() < end_time:
            status, output = CmdUtil.getstatusoutput_by_fast_popen(cmd)
            if status == 0:
                break
            else:
                time.sleep(sleep_time)
        return status, output

    @staticmethod
    def getstatusoutput_by_fast_popen(cmd):
        """
        get status, output by executing command by fast popen
        """
        fast_popen = FastPopen(cmd, stdout=PIPE, stderr=PIPE,
                               close_fds=True, preexec_fn=os.setsid)
        stdout, stderr = fast_popen.communicate()
        output = (stdout + stderr).strip()
        return fast_popen.returncode, output

    @staticmethod
    def exec_by_popen(cmd):
        """
        execute cmd by popen
        """
        env_source_cmd = CmdUtil.get_env_source_cmd()
        proc = Popen("%s;%s" % (env_source_cmd, cmd), shell=True, stdout=PIPE,
                     stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            return True, stdout
        return False, stderr

    @staticmethod
    def get_env_source_cmd():
        """
        get env source cmd
        """
        env_source_cmd = CmdUtil.ENV_SOURCE_CMD
        return env_source_cmd

    @staticmethod
    def retry_exec_by_popen(cmd, retry_time=3, sleep_time=1, check_out=False):
        """
        function : retry exec_by_popen
        @param cmd: command  going to be execute
        @param retry_time: default retry 3 times after execution failure
        @param sleep_time: default sleep 1 second then start retry
        """
        retry_time += 1
        for _ in range(retry_time):
            (status, output) = CmdUtil.exec_by_popen(cmd)
            if not status:
                time.sleep(sleep_time)

            elif check_out:
                if str(output).strip():
                    break
                else:
                    time.sleep(sleep_time)
            else:
                break
        return status, output

    @staticmethod
    def interactive_with_popen(cmd, password):
        """
        function : Interactive password entry
        input : cmd, password
        output: NA
        """
        env_source_cmd = CmdUtil.get_env_source_cmd()
        if isinstance(password, str):
            password = bytes(password, 'utf-8')
        try:
            proc = Popen("%s; %s" % (env_source_cmd, cmd),
                         shell=True,
                         stdout=PIPE,
                         stderr=PIPE,
                         stdin=PIPE)

            proc.stdin.write(password)
            proc.stdin.write(bytes("\n", 'utf-8'))
            proc.stdin.flush()
        except Exception:
            output, error = proc.communicate()
            return proc.returncode, output, error
        else:
            # Increase the system response time
            time.sleep(0.1)
            proc.stdin.write(password)
            proc.stdin.write(bytes("\n", 'utf-8'))
            proc.stdin.flush()
            output, error = proc.communicate()
            return proc.returncode, output, error

    @staticmethod
    def doesBinExist(bin):
        """
        function : which bin
        input : bin name
        output: bool
        """
        cmd = CmdUtil.getWhichCmd() + BLANK_SPACE + bin
        try:
            status, output = subprocess.getstatusoutput(cmd)
            if status == 0:
                return True
        except Exception:
            pass

        return False
    
    @staticmethod
    def get_user_exec_cmd(is_root, user, cmd):
        """
        function : user exec cmd
        input : is_root user cmd
        output: result_cmd
        """
        result_cmd = cmd
        if is_root:
            result_cmd = "su - %s -c '%s' " % (user, result_cmd)
        return result_cmd