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
#############################################################################
import sys
import subprocess
import os
import pwd
import time
import re
from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from os_platform.UserPlatform import g_Platform
from gspylib.inspection.common.Exception import ShellCommandException,\
    SshCommandException, SQLCommandException
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.sql_handler.sql_file import SqlFile
from base_utils.os.net_util import NetUtil
from os_platform.linux_distro import LinuxDistro
from base_diff.sql_commands import SqlCommands
from base_utils.os.hosts_util import HostsUtil

localPath = os.path.dirname(__file__)
sys.path.insert(0, localPath + "/../lib")

FILE_MODE = 640
DIRECTORY_MODE = 750
KEY_FILE_MODE = 600
KEY_DIRECTORY_MODE = 700
INIT_FILE_SUSE = "/etc/init.d/boot.local"
INIT_FILE_REDHAT = "/etc/rc.d/rc.local"


def runShellCmd(cmd, user=None, mpprcFile=""):
    """
    function: run shell cmd
    input  : md, user, mpprcFile
    output : str
    """
    if (mpprcFile):
        cmd = "source '%s'; %s" % (mpprcFile, cmd)
    # Set the output LANG to English
    cmd = "export LC_ALL=C; %s" % cmd
    # change user but can not be root user
    if (user and user != getCurrentUser()):
        cmd = "su - %s -c \"source /etc/profile 2>/dev/null; %s\"" % (
        user, cmd)
        cmd = cmd.replace("$", "\$")
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0 and DefaultValue.checkDockerEnv()):
        return output
    if (status != 0):
        raise ShellCommandException(cmd, output)
    return output


def runSshCmd(cmd, host, user="", mpprcFile="", timeout=""):
    """
    function: run ssh cmd
    input  : cmd, host, user, mpprcFile, timeout
    output : str
    """
    if (timeout):
        timeout = "-o ConnectTimeout=%s" % timeout
    if (mpprcFile):
        cmd = "source '%s'; %s" % (mpprcFile, cmd)
    # Set the output LANG to English
    cmd = "export LC_ALL=C; %s" % cmd
    # RedHat does not automatically source /etc/profile
    # but SuSE executes when using ssh to remotely execute commands
    # Some environment variables are written in /etc/profile
    # when there is no separation of environment variables
    if (host == NetUtil.GetHostIpOrName() or host in NetUtil.getIpAddressList()):
        sshCmd = cmd
    else:
        sshCmd = "pssh -s -H %s %s 'source /etc/profile 2>/dev/null;%s'" % (
        host, timeout, cmd)
    if (user and user != getCurrentUser()):
        sshCmd = "su - %s -c \"%s\"" % (user, sshCmd)
    (status, output) = subprocess.getstatusoutput(sshCmd)
    if (status != 0):
        raise SshCommandException(host, sshCmd, output)
    return output


def runSshCmdWithPwd(cmd, host, user="", passwd="", mpprcFile="", port=DefaultValue.DEFAULT_SSH_PORT):
    """
    function: run ssh cmd with password
    input  : cmd, host, user, passwd, mpprcFile
    output : str
    """
    # Environment variables separation
    if (mpprcFile):
        cmd = "source '%s'; %s" % (mpprcFile, cmd)
    ssh = None
    try:
        if (passwd):
            import paramiko
            cmd = "export LC_ALL=C; source /etc/profile 2>/dev/null; %s" % cmd
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Remote Connection
            ssh.connect(host, port, user, passwd)
            stdout, stderr = ssh.exec_command(cmd)[1:3]
            output = stdout.read()
            error = stderr.read()
            if error:
                raise SshCommandException(host, cmd, error)
            return output.decode()
        else:
            cmd = \
                "pssh -s -H %s \"export LC_ALL=C; " \
                "source /etc/profile 2>/dev/null; %s\"" % (
            host, cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                raise SshCommandException(host, cmd, output)
            return output
    except Exception as e:
        raise Exception(str(e))
    finally:
        if (ssh):
            ssh.close()


def runRootCmd(cmd, rootuser, passwd, mpprcFile='', port=DefaultValue.DEFAULT_SSH_PORT):
    """
    function: run root cmd
    input  : cmd, rootuser, passwd, mpprcFile
    output : str
    """
    if (mpprcFile):
        cmd = "source '%s'; %s" % (mpprcFile, cmd)
    ssh = None
    try:
        import paramiko
        cmd = "export LC_ALL=C;source /etc/profile 2>/dev/null;export PYTHONIOENCODING=utf-8; %s" % cmd
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('localhost', port, rootuser, passwd)
        stdout, stderr = ssh.exec_command(cmd, get_pty=True)[1:3]
        output = stdout.read()
        error = stderr.read()
        if error:
            raise SshCommandException(cmd, "localhost", error)
        return output
    except Exception as e:
        raise Exception(str(e))
    finally:
        if ssh:
            ssh.close()


def verifyPasswd(host, user, pswd=None, port=DefaultValue.DEFAULT_SSH_PORT):
    """
    function: verify password
        Connect to the remote node
    input  : host, user, pswd
    output : bool
    """
    import paramiko
    ssh = paramiko.Transport((host, port))
    try:
        ssh.connect(username=user, password=pswd)
        return True
    except paramiko.AuthenticationException:
        return False
    finally:
        ssh.close()


def runSqlCmd(sql, user, host, port, tmpPath, database="postgres",
              mpprcFile="", maintenance=False):
    """
    function : Execute sql command
    input : String,String,String,int
    output : String
    """
    database = database.replace('$', '\$')
    # Get the current time
    currentTime = time.strftime("%Y-%m-%d_%H%M%S")
    # Get the process ID
    pid = os.getpid()
    # init SQL query file
    sqlFile = os.path.join(tmpPath,
                           "check_query.sql_%s_%s_%s" % (
                           str(port), str(currentTime), str(pid)))
    # init SQL result file
    queryResultFile = os.path.join(tmpPath,
                                   "check_result.sql_%s_%s_%s" % (
                                   str(port), str(currentTime), str(pid)))
    # Clean up the file
    cleanFile("%s,%s" % (queryResultFile, sqlFile))

    # create an empty sql query file
    try:
        cmd = "touch %s && chmod %s %s" % \
              (sqlFile, DefaultValue.KEY_FILE_MODE, sqlFile)
        runShellCmd(cmd, user, mpprcFile)
    except ShellCommandException as e:
        raise SQLCommandException(sql,
                                  "create sql query file failed." + e.output)

    # write the SQL command into sql query file
    try:
        with open(sqlFile, 'w') as fp:
            fp.writelines(sql)
    except Exception as e:
        # Clean up the file
        cleanFile(sqlFile)
        raise SQLCommandException(sql,
                                  "write into sql query file failed. " + str(
                                      e))

    # read the content of query result file.
    try:
        # init host
        hostPara = (
                    "-h %s" % host) \
            if host != "" and host != "localhost" \
               and host != NetUtil.GetHostIpOrName() else ""
        # build shell command
        gsql_cmd = SqlCommands.getSQLCommand(port, database)
        gsql_cmd += " %s" % hostPara
        cmd = "%s -f %s --output %s -t -A -X" % (gsql_cmd, sqlFile, queryResultFile)
        if (maintenance):
            cmd += ' -m'
        # Environment variables separation
        if mpprcFile != "":
            cmd = "source '%s' && " % mpprcFile + cmd
        # Execute the shell command
        output = runShellCmd(cmd, user)
        if SqlFile.findErrorInSqlFile(sqlFile, output):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + "Error:\n%s" % output)

        # Reading documents
        fp = None
        with open(queryResultFile, 'r') as fp:
            rowList = fp.readlines()
    except Exception as e:
        cleanFile("%s,%s" % (queryResultFile, sqlFile))
        if isinstance(e, ShellCommandException):
            output = e.output
        else:
            output = str(e)
        raise SQLCommandException(sql, output)

    # remove local sqlFile
    cleanFile("%s,%s" % (queryResultFile, sqlFile))

    return "".join(rowList)[:-1]


def runSqlSimplely(sql, user, host, port, tmpPath, database="postgres",
                   mpprcFile="", needmpara=False):
    """
    function : Execute sql command
    input : String,String,String,int
    output : String
    """
    # Get the current time
    currentTime = time.strftime("%Y-%m-%d_%H%M%S")
    # Get the process ID
    pid = os.getpid()
    # init SQL query file
    sqlFile = os.path.join(tmpPath,
                           "check_query.sql_%s_%s_%s" % (
                           str(port), str(currentTime), str(pid)))

    # Clean up the file
    if (os.path.exists(sqlFile)):
        cleanFile("%s" % (sqlFile))

    # create an empty sql query file
    try:
        cmd = "touch %s && chmod %s %s" % \
              (sqlFile, DefaultValue.KEY_FILE_MODE, sqlFile)
        runShellCmd(cmd, user, mpprcFile)
    except ShellCommandException as e:
        raise SQLCommandException(sql, "create sql query file failed.")

    # write the SQL command into sql query file
    try:
        with open(sqlFile, 'w') as fp:
            fp.writelines(sql)
    except Exception as e:
        # Clean up the file
        cleanFile(sqlFile)
        raise SQLCommandException(sql,
                                  "write into sql query file failed. " + str(
                                      e))

    # read the content of query result file.
    try:
        # init host
        hostPara = (
                    "-h %s" % host) \
            if host != "" and host != "localhost" else ""
        # build shell command
        if (needmpara):
            cmd = "gsql %s -p %s -d %s -f %s  -m" % (
            hostPara, port, database, sqlFile)
        else:
            cmd = "gsql %s -p %s -d %s -f %s" % (
            hostPara, port, database, sqlFile)
        # Environment variables separation
        if mpprcFile != "":
            cmd = "source '%s' && " % mpprcFile + cmd
        # Execute the shell command
        output = runShellCmd(cmd, user)
        if SqlFile.findErrorInSqlFile(sqlFile, output):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + "Error:\n%s" % output)

        # Reading documents
    except Exception as e:
        cleanFile("%s" % (sqlFile))
        if isinstance(e, ShellCommandException):
            output = e.output
        else:
            output = str(e)
        raise SQLCommandException(sql, output)

    # remove local sqlFile
    cleanFile("%s" % (sqlFile))

    return output

def cleanFile(fileName, hostname=""):
    """
    function : remove file
    input : String,hostname
    output : NA
    """
    fileList = fileName.split(",")
    cmd = ""
    for fileStr in fileList:
        if cmd != "":
            cmd += ';(if [ -f %s ];then rm -f %s;fi)' % (fileStr, fileStr)
        else:
            cmd = '(if [ -f %s ];then rm -f %s;fi)' % (fileStr, fileStr)
    if hostname == "":
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] % "file"
                            + " Error: \n%s." % output
                            + "The cmd is %s " % cmd)
    else:
        ip = HostsUtil.hostname_to_ip(hostname)
        sshCmd = "pssh -s -H %s '%s'" % (ip, cmd)
        (status, output) = subprocess.getstatusoutput(sshCmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] % "file"
                            + " Error: \n%s." % output
                            + "The cmd is %s " % sshCmd)


def checkComplete(checkId, host, hostname, user, tmpPath, passwd=None):
    """
    function: check whether has completed or not
    input  : NA
    output : NA
    """
    cmd = "cd %s && ls -l |grep %s_%s.out|wc -l" % (tmpPath, hostname, checkId)
    if (is_local_node(host)):
        output = runShellCmd(cmd, user)
    elif (passwd):
        output = runSshCmdWithPwd(cmd, host, user, passwd)
    else:
        output = runSshCmd(cmd, host, user)
    if (len(output.splitlines()) > 1):
        output = output.splitlines()[-1]
    return output


def getVersion():
    """
    Get current file version by VersionInfo
    
    """
    return ("%s %s" % (sys.argv[0].split("/")[-1], VersionInfo.COMMON_VERSION))


def createFile(fileName, path, permission=FILE_MODE, user=""):
    # file path
    fileName = os.path.join(path, fileName)
    # Create a file
    FileUtil.createFile(fileName, True, permission)
    # change owner
    if (user):
        FileUtil.changeOwner(user, fileName)
    return fileName


def chmodFile(fileName, permission=FILE_MODE, user=""):
    # Modify the file permissions
    FileUtil.changeMode(permission, fileName)
    if (user):
        FileUtil.changeOwner(user, fileName)


def writeFile(fileName, content, path, permission=FILE_MODE, user=""):
    """
    function: write file
    input  : NA
    output : NA
    """
    filePath = os.path.join(path, fileName)
    # Create a file
    FileUtil.createFile(filePath, True, permission)
    # Modify the file permissions
    if (user):
        FileUtil.changeOwner(user, filePath)
    FileUtil.writeFile(filePath, [content])


def readFile(fileName):
    # Get the contents of the file
    text = FileUtil.readFile(fileName)
    return "\n".join(text)


def sendFile(fileName, host, user, path, passwd=None, port=DefaultValue.DEFAULT_SSH_PORT):
    # Copy files remotely
    t = None
    if (passwd):
        try:
            import paramiko
            t = paramiko.Transport((host, port))
            t.connect(username=user, password=passwd)
            sftp = paramiko.SFTPClient.from_transport(t)
            sftp.put(fileName, os.path.join(path, os.path.basename(fileName)))
        except Exception as e:
            raise Exception(str(e))
        finally:
            if (t):
                t.close()
    else:
        if "HOST_IP" not in list(os.environ.keys()):
            if NetUtil.get_ip_version(host) == NetUtil.NET_IPV6:
                host = "[" + host + "]"
            host = "%s@%s" % (user, host)
        cmd = "pscp -H %s '%s' %s" % (host, fileName, path)
        if (os.getuid() == 0):
            cmd = "su - %s -c \"%s\"" % (user, cmd)
        runShellCmd(cmd)


def receiveFile(fileName, host, user, path, passwd=None, port=DefaultValue.DEFAULT_SSH_PORT):
    # Receive remote files
    t = None
    if (passwd):
        try:
            import paramiko
            t = paramiko.Transport((host, port))
            t.connect(username=user, password=passwd)
            sftp = paramiko.SFTPClient.from_transport(t)
            if (type(fileName) == list):
                for fname in fileName:
                    sftp.get(fname,
                             os.path.join(path, os.path.basename(fname)))
            else:
                sftp.get(fileName, os.path.join(path, fileName))
        except Exception as e:
            raise Exception(str(e))
        finally:
            if (t):
                t.close()
    else:
        if "HOST_IP" not in list(os.environ.keys()):
            host = "%s@%s" % (user, host)
        cmd = "pssh -s -H %s 'pscp -H %s %s %s' " % (
        host, NetUtil.GetHostIpOrName(), fileName, path)
        if (os.getuid() == 0):
            cmd = "su - %s -c \"%s\"" % (user, cmd)
        runShellCmd(cmd)


def getCurrentUser():
    return pwd.getpwuid(os.getuid())[0]


def checkAuthentication(host, user):
    """
    function: check authentication
    input  : NA
    output : NA
    """
    cmd = 'pssh -s -H %s true' % host
    try:
        runSshCmd(cmd, host, user)
    except Exception:
        return (False, host)
    return (True, host)


def checkClusterUser(username, mpprcFile=''):
    """
    function: check cluster user
    input  : NA
    output : NA
    """
    try:
        pwd.getpwnam(username).pw_gid
    except Exception:
        return False
    mpprc = mpprcFile if mpprcFile else '~/.bashrc'
    cmd = "echo \"%s$GAUSS_ENV\" 2>/dev/null" % (
        "\\" if (username and username != getCurrentUser()) else "")
    try:
        output = runShellCmd(cmd, username, mpprc)
        gaussEnv = output.split("\n")[0]
        if not gaussEnv:
            return False
    except Exception:
        return False
    return True


def getMasterDnNum(user, mpprcFile):
    """
    function : get cluster master DB number
    input  : string, string
    output : List
    """
    masterDnList = []
    cmd = "gs_om -t query |grep Primary"
    output = runShellCmd(cmd, user, mpprcFile)
    line = output.splitlines()[0]
    instanceinfo = line.split()
    for idx in range(len(instanceinfo)):
        if (instanceinfo[idx] == "Primary"):
            if (idx > 2 and instanceinfo[idx - 2].isdigit()):
                masterDnList.append(int(instanceinfo[idx - 2]))
    return masterDnList


def checkBondMode(bondingConfFile):
    """
    function : Check Bond mode
    input  : String, bool
    output : List
    """

    netNameList = []
    cmd = "grep -w 'Bonding Mode' %s | awk  -F ':' '{print $NF}'" \
          % bondingConfFile
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0 or output.strip() == ""):
        raise Exception(ErrorCode.GAUSS_514["GAUSS_51403"] % "Bonding Mode" +
                        "The cmd is %s " % cmd)
    cmd = "grep -w 'Slave Interface' %s | awk  -F ':' '{print $NF}'" \
          % bondingConfFile
    (status, output) = subprocess.getstatusoutput(cmd)
    if (status != 0):
        raise Exception(ErrorCode.GAUSS_514["GAUSS_51403"] %
                        "Slave Interface" + "The cmd is %s " % cmd)

    for networkname in output.split('\n'):
        netNameList.append(networkname.strip())
    return netNameList


def is_local_node(host):
    """
    function: check whether is or not local node
    input  : NA
    output : NA
    """
    if (host == NetUtil.GetHostIpOrName()):
        return True
    allNetworkInfo = NetUtil.getAllNetworkIp(NetUtil.get_ip_version(host))
    for network in allNetworkInfo:
        if (host == network.ipAddress):
            return True
    return False


def validate_ipv4(ip_str):
    """
    function: check whether is or not validate ipv4
    input  : NA
    output : NA
    """
    sep = ip_str.split('.')
    if len(sep) != 4:
        return False
    for i, x in enumerate(sep):
        try:
            int_x = int(x)
            if int_x < 0 or int_x > 255:
                return False
        except ValueError:
            return False
    return True


def SetLimitsConf(typeList, item, value, limitFile):
    """
    function: set limits conf
    input  : NA
    output : NA
    """
    for typeName in typeList:
        cmd = """sed -i '/^.* %s *%s .*$/d' %s &&
           echo "*       %s    %s  %s" >> %s""" % (
            typeName, item, limitFile, typeName, item, value, limitFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            return "Failed to set variable '%s %s'. Error: \n%s." % (
                typeName, item, output) + "The cmd is %s " % cmd
    return "Success"


def isSupportSystemOs():
    """
    function: check whether is or not redhat
    input  : NA
    output : NA
    """
    osName = LinuxDistro.linux_distribution()[0]
    if osName in ["redhat", "centos", "euleros", "openEuler", "FusionOS", "H3Linux", "NingOS"]:
        return True
    else:
        return False


def getInitFile():
    """
    function: get init file
    input  : NA
    output : NA
    """
    if isSupportSystemOs():
        return INIT_FILE_REDHAT
    else:
        return INIT_FILE_SUSE


def getNICNum(ipAddress):
    """
    function: get nic num
    input  : NA
    output : NA
    """
    if g_Platform.isPlatFormEulerOSOrRHEL7X():
        cmd = "/sbin/ifconfig -a | grep -B1 \"inet %s \" | " \
              "grep -v \"inet %s \" | awk '{print $1}'" % (
            ipAddress, ipAddress)
    else:
        cmd = "/sbin/ifconfig -a | grep -B1 \"addr:%s \" | " \
              "grep -v \"addr:%s \" | awk '{print $1}'" % (
            ipAddress, ipAddress)
    output = runShellCmd(cmd)
    if g_Platform.isPlatFormEulerOSOrRHEL7X():
        return output.strip()[:-1]
    else:
        return output.strip()


def getIpByHostName(host):
    """
    function: get ip by hostname
    input  : NA
    output : NA
    """
    ipList = FileUtil.readFile("/etc/hosts", host)

    pattern = re.compile(
        r'^[1-9 \t].*%s[ \t]*#Gauss.* IP Hosts Mapping' % host)
    for ipInfo in ipList:
        match = pattern.match(ipInfo.strip())
        if (match):
            return match.group().split(' ')[0].strip()
    #If no ip address is found, the first ip address
    # that is not commented out is returned
    for ip_info in ipList:
        ip_info = ip_info.replace("\t", " ").strip()
        if not ip_info.startswith("#"):
            return ip_info.split(' ')[0]

    # get local host by os function
    # Replace host with the IP address.
    hostIp = host
    return hostIp


def getNetWorkConfFile(networkCardNum):
    """
    function: get network conf file
    input  : NA
    output : NA
    """
    SuSENetWorkConfPath = "/etc/sysconfig/network"
    RedHatNetWorkConfPath = "/etc/sysconfig/network-scripts"
    if isSupportSystemOs():
        NetWorkConfFile = "%s/ifcfg-%s" % (
        RedHatNetWorkConfPath, networkCardNum)
    else:
        NetWorkConfFile = "%s/ifcfg-%s" % (SuSENetWorkConfPath, networkCardNum)

    if (not os.path.exists(NetWorkConfFile)):
        if isSupportSystemOs():
            cmd = "find %s -iname 'ifcfg-*-%s' -print" % (
            RedHatNetWorkConfPath, networkCardNum)
        else:
            cmd = "find %s -iname 'ifcfg-*-%s' -print" % (
            SuSENetWorkConfPath, networkCardNum)
        output = runShellCmd(cmd)
        if (DefaultValue.checkDockerEnv() and
                output.find("No such file or directory") >= 0):
            return output.strip()
        if (output.strip() == "" or len(output.split('\n')) != 1):
            if DefaultValue.checkDockerEnv():
                return ""
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                            % NetWorkConfFile)
        NetWorkConfFile = output.strip()
    return NetWorkConfFile


def CheckNetWorkBonding(serviceIP):
    """
    function: check network bonding
    input  : NA
    output : NA
    """
    networkCardNum = getNICNum(serviceIP)
    NetWorkConfFile = getNetWorkConfFile(networkCardNum)
    if ((NetWorkConfFile.find("No such file or directory") >= 0
         or NetWorkConfFile == "") and DefaultValue.checkDockerEnv()):
        return "Shell command faild"
    bondingConfFile = "/proc/net/bonding/%s" % networkCardNum
    networkCardNumList = [networkCardNum]
    cmd = "grep -i 'BONDING_OPTS\|BONDING_MODULE_OPTS' %s" % NetWorkConfFile
    (status, output) = subprocess.getstatusoutput(cmd)
    if ((status == 0) and (output.strip() != "")):
        if ((output.find("mode") > 0) and os.path.exists(bondingConfFile)):
            networkCardNumList = networkCardNumList + checkBondMode(
                bondingConfFile)
        else:
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50611"] +
                            "The cmd is %s " % cmd)
    return networkCardNumList



def getTHPandOSInitFile():
    """
    function : We know that the centos have same init file
    and THP file as RedHat.
    input  : NA
    output : String, String
    """
    THPFile = "/sys/kernel/mm/transparent_hugepage/enabled"
    initFile = getOSInitFile()
    if (initFile == ""):
        raise Exception(ErrorCode.GAUSS_506["GAUSS_50618"]
                        % "startup file of current OS")
    return (THPFile, initFile)


def getOSInitFile():
    """
    function : Get the OS initialization file
    input : NA
    output : String
    """
    distname = LinuxDistro.linux_distribution()[0]
    systemd_system_dir = "/usr/lib/systemd/system/"
    systemd_system_file = "/usr/lib/systemd/system/gs-OS-set.service"
    # OS init file
    #     now we only support SuSE and RHEL
    initFileSuse = "/etc/init.d/boot.local"
    initFileRedhat = "/etc/rc.d/rc.local"
    # system init file
    initSystemFile = "/usr/local/gauss/script/gauss-OS-set.sh"
    dirName = os.path.dirname(os.path.realpath(__file__))
    # Get the startup file of suse or redhat os
    if (os.path.isdir(systemd_system_dir)):
        if (not os.path.exists(systemd_system_file)):
            cmd = "cp '%s'/gs-OS-set.service '%s'; chmod %s '%s'" % (
            dirName, systemd_system_file, DefaultValue.KEY_FILE_MODE,
            systemd_system_file)
            runShellCmd(cmd)
            cmd = "systemctl enable gs-OS-set.service"
            runShellCmd(cmd)
        if (not os.path.exists(initSystemFile)):
            cmd = "mkdir -p '%s'" % os.path.dirname(initSystemFile)
            runShellCmd(cmd)
            FileUtil.createFileInSafeMode(initSystemFile)
            with open(initSystemFile, "w") as fp:
                fp.write("#!/bin/bash\n")
        cmd = "chmod %s '%s'" % (DefaultValue.KEY_FILE_MODE, initSystemFile)
        runShellCmd(cmd)
        return initSystemFile
    if (distname == "SuSE" and os.path.isfile(initFileSuse)):
        initFile = initFileSuse
    elif (distname in (
    "redhat", "centos", "euleros", "openEuler", "FusionOS") and os.path.isfile(
            initFileRedhat)):
        initFile = initFileRedhat
    else:
        initFile = ""
    return initFile


def getMaskByIP(IPAddr):
    """
    function: get netMask by ip addr
    """
    if g_Platform.isPlatFormEulerOSOrRHEL7X():
        cmd = "/sbin/ifconfig -a |grep -E '\<%s\>'| awk '{print $4}'" % IPAddr
    else:
        cmd = \
            "/sbin/ifconfig -a |grep -E '\<%s\>'| awk -F ':' '{print $NF}'" \
            % IPAddr
    netMask = runShellCmd(cmd)
    return netMask
