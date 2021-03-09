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
# Description  : ExpansionImpl.py
#############################################################################

import subprocess
import sys
import re
import os
import getpass
import pwd
import datetime
import weakref
from random import sample
import time
import grp
import socket
import stat
from multiprocessing import Process, Value

sys.path.append(sys.path[0] + "/../../../../")
from gspylib.common.DbClusterInfo import dbClusterInfo, queryCmd
from gspylib.threads.SshTool import SshTool
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.common.GaussLog import GaussLog

sys.path.append(sys.path[0] + "/../../../lib/")
DefaultValue.doConfigForParamiko()
import paramiko


#boot/build mode
MODE_PRIMARY = "primary"
MODE_STANDBY = "standby"
MODE_NORMAL = "normal"
MODE_CASCADE = "cascade_standby"

# instance local_role
ROLE_NORMAL = "normal"
ROLE_PRIMARY = "primary"
ROLE_STANDBY = "standby"
ROLE_CASCADE = "cascade standby"

#db state
STAT_NORMAL = "normal"

# master 
MASTER_INSTANCE = 0
# standby 
STANDBY_INSTANCE = 1

# statu failed
STATUS_FAIL = "Failure"

class ExpansionImpl():
    """
    class for expansion standby node.
    step:
        1. preinstall database on new standby node
        2. install as single-node database
        3. establish primary-standby relationship of all node
    """

    def __init__(self, expansion):
        """
        """
        self.context = expansion

        self.user = self.context.user
        self.group = self.context.group
        self.existingHosts = []
        self.expansionSuccess = {}
        for newHost in self.context.newHostList:
            self.expansionSuccess[newHost] = False
        self.logger = self.context.logger

        envFile = DefaultValue.getEnv("MPPDB_ENV_SEPARATE_PATH")
        if envFile:
            self.envFile = envFile
        else:
            userpath = pwd.getpwnam(self.user).pw_dir
            mpprcFile = os.path.join(userpath, ".bashrc")
            self.envFile = mpprcFile

        currentTime = str(datetime.datetime.now()).replace(" ", "_").replace(
            ".", "_")

        self.commonGsCtl = GsCtlCommon(expansion)
        self.tempFileDir = "/tmp/gs_expansion_%s" % (currentTime)
        self.logger.debug("tmp expansion dir is %s ." % self.tempFileDir)

        self._finalizer = weakref.finalize(self, self.clearTmpFile)

    def sendSoftToHosts(self):
        """
        create software dir and send it on each nodes
        """
        self.logger.log("Start to send soft to each standby nodes.")
        srcFile = self.context.packagepath
        targetDir = os.path.realpath(os.path.join(srcFile, "../"))
        # change mode of package dir to set privileges for users
        tPathList = os.path.split(targetDir)
        path2ChangeMode = targetDir
        if len(tPathList) > 2:
            path2ChangeMode = os.path.join(tPathList[0],tPathList[1])
        changeModCmd =  "chmod -R a+x {srcFile}".format(user = self.user,
            group = self.group, srcFile = path2ChangeMode)
        for host in self.context.newHostList:
            sshTool = SshTool([host], timeout = 300)
            # mkdir package dir and send package to remote nodes.
            sshTool.executeCommand("mkdir -p %s" % srcFile , "",
                DefaultValue.SUCCESS, [host])
            sshTool.scpFiles(srcFile, targetDir, [host])
            sshTool.executeCommand(changeModCmd, "", DefaultValue.SUCCESS,
                [host])
            self.cleanSshToolFile(sshTool)
        self.logger.log("End to send soft to each standby nodes.")

    def generateAndSendXmlFile(self):
        """
        """
        self.logger.debug("Start to generateAndSend XML file.\n")

        tempXmlFile = "%s/clusterconfig.xml" % self.tempFileDir
        cmd = "mkdir -p %s; touch %s; cat /dev/null > %s" % \
        (self.tempFileDir, tempXmlFile, tempXmlFile)
        (status, output) = subprocess.getstatusoutput(cmd)

        cmd = "chown -R %s:%s %s" % (self.user, self.group, self.tempFileDir)
        (status, output) = subprocess.getstatusoutput(cmd)
        
        newHosts = self.context.newHostList
        for host in newHosts:
            # create single deploy xml file for each standby node
            xmlContent = self.__generateXml(host)
            with os.fdopen(os.open("%s" % tempXmlFile, os.O_WRONLY | os.O_CREAT,
             stat.S_IWUSR | stat.S_IRUSR),'w') as fo:
                fo.write( xmlContent )
                fo.close()
            # send single deploy xml file to each standby node
            sshTool = SshTool([host])
            retmap, output = sshTool.getSshStatusOutput("mkdir -p %s" % 
            self.tempFileDir , [host], self.envFile)
            retmap, output = sshTool.getSshStatusOutput("chown %s:%s %s" % 
            (self.user, self.group, self.tempFileDir), [host], self.envFile)
            sshTool.scpFiles("%s" % tempXmlFile, "%s" % 
            tempXmlFile, [host], self.envFile)
            self.cleanSshToolFile(sshTool)
        
        self.logger.debug("End to generateAndSend XML file.\n")

    def __generateXml(self, backIp):
        """
        """
        nodeName = self.context.backIpNameMap[backIp]
        nodeInfo = self.context.clusterInfoDict[nodeName]
        clusterName = self.context.clusterInfo.name

        backIp = nodeInfo["backIp"]
        sshIp = nodeInfo["sshIp"]
        port = nodeInfo["port"]
        dataNode = nodeInfo["dataNode"]

        appPath = self.context.clusterInfoDict["appPath"]
        logPath = self.context.clusterInfoDict["logPath"]
        corePath = self.context.clusterInfoDict["corePath"]
        toolPath = self.context.clusterInfoDict["toolPath"]
        mppdbconfig = ""
        tmpMppdbPath = DefaultValue.getEnv("PGHOST")
        if tmpMppdbPath:
            mppdbconfig = '<PARAM name="tmpMppdbPath" value="%s" />' % tmpMppdbPath
        azName = self.context.hostAzNameMap[backIp]
        azPriority = nodeInfo["azPriority"]

        xmlConfig = """\
<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
    <CLUSTER>
        <PARAM name="clusterName" value="{clusterName}" />
        <PARAM name="nodeNames" value="{nodeName}" />
        <PARAM name="backIp1s" value="{backIp}"/>
        <PARAM name="gaussdbAppPath" value="{appPath}" />
        <PARAM name="gaussdbLogPath" value="{logPath}" />
        <PARAM name="gaussdbToolPath" value="{toolPath}" />
        {mappdbConfig}
        <PARAM name="corePath" value="{corePath}"/>
        <PARAM name="clusterType" value="single-inst"/>
    </CLUSTER>
    <DEVICELIST>
        <DEVICE sn="{nodeName}">
            <PARAM name="name" value="{nodeName}"/>
            <PARAM name="azName" value="{azName}"/>
            <PARAM name="azPriority" value="{azPriority}"/>
            <PARAM name="backIp1" value="{backIp}"/>
            <PARAM name="sshIp1" value="{sshIp}"/>
            <!--dbnode-->
            <PARAM name="dataNum" value="1"/>
            <PARAM name="dataPortBase" value="{port}"/>
            <PARAM name="dataNode1" value="{dataNode}"/>
        </DEVICE>
    </DEVICELIST>
</ROOT>
        """.format(clusterName = clusterName, nodeName = nodeName, backIp = backIp,
        appPath = appPath, logPath = logPath, toolPath = toolPath, corePath = corePath,
        sshIp = sshIp, port = port, dataNode = dataNode, azName = azName,
        azPriority = azPriority, mappdbConfig = mppdbconfig)
        return xmlConfig

    def changeUser(self):
        user = self.user
        try:
            pw_record = pwd.getpwnam(user)
        except Exception:
            GaussLog.exitWithError(ErrorCode.GAUSS_503["GAUSS_50300"] % user)

        user_name = pw_record.pw_name
        user_uid = pw_record.pw_uid
        user_gid = pw_record.pw_gid
        os.setgid(user_gid)
        os.setuid(user_uid)
        os.environ["HOME"] = pw_record.pw_dir
        os.environ["USER"] = user_name
        os.environ["LOGNAME"] = user_name
        os.environ["SHELL"] = pw_record.pw_shell


    def initSshConnect(self, host, user='root'):
        
        try:
            getPwdStr = "Please enter the password of user [%s] on node [%s]: " \
             % (user, host)
            passwd = getpass.getpass(getPwdStr)
            self.sshClient = paramiko.SSHClient()
            self.sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.sshClient.connect(host, 22, user, passwd)
        except paramiko.ssh_exception.AuthenticationException as e :
            self.logger.log("Authentication failed.")
            self.initSshConnect(host, user)

    def hasNormalStandbyInAZOfCascade(self, cascadeIp, existingStandbys):
        # check whether there are normal standbies in hostAzNameMap[cascadeIp] azZone
        hasStandbyWithSameAZ = False
        hostAzNameMap = self.context.hostAzNameMap
        for existingStandby in existingStandbys:
            existingStandbyName = self.context.backIpNameMap[existingStandby]
            existingStandbyDataNode = \
                self.context.clusterInfoDict[existingStandbyName]["dataNode"]
            insType, dbStat = self.commonGsCtl.queryInstanceStatus(
                existingStandby, existingStandbyDataNode, self.envFile)
            if dbStat != STAT_NORMAL:
                continue
            if hostAzNameMap[cascadeIp] != hostAzNameMap[existingStandby]:
                continue
            hasStandbyWithSameAZ = True
            break
        return hasStandbyWithSameAZ

    def installDatabaseOnHosts(self):
        """
        install database on each standby node
        """
        standbyHosts = self.context.newHostList
        tempXmlFile = "%s/clusterconfig.xml" % self.tempFileDir
        installCmd = "source {envFile} ; gs_install -X {xmlFile} "\
            "2>&1".format(envFile = self.envFile, xmlFile = tempXmlFile)
        self.logger.debug(installCmd)
        primaryHostName = self.getPrimaryHostName()
        primaryHostIp = self.context.clusterInfoDict[primaryHostName]["backIp"]
        existingStandbys = list(set(self.existingHosts) - (set([primaryHostIp])))
        failedInstallHosts = []
        notInstalledCascadeHosts = []
        for newHost in standbyHosts:
            if not self.expansionSuccess[newHost]:
                continue
            self.logger.log("Installing database on node %s:" % newHost)
            hostName = self.context.backIpNameMap[newHost]
            sshIp = self.context.clusterInfoDict[hostName]["sshIp"]
            if self.context.newHostCasRoleMap[newHost] == "on":
                # check whether there are normal standbies in hostAzNameMap[host] azZone
                hasStandbyWithSameAZ = self.hasNormalStandbyInAZOfCascade(newHost,
                    existingStandbys)
                if not hasStandbyWithSameAZ:
                    notInstalledCascadeHosts.append(newHost)
                    self.expansionSuccess[newHost] = False
                    continue
            self.initSshConnect(sshIp, self.user)
            stdin, stdout, stderr = self.sshClient.exec_command(installCmd, 
                get_pty=True)
            channel = stdout.channel
            echannel = stderr.channel

            while not channel.exit_status_ready():
                try:
                    recvOut = channel.recv(1024)
                    outDecode = recvOut.decode("utf-8")
                    outStr = outDecode.strip()
                    if(len(outStr) == 0):
                        continue
                    if(outDecode.endswith("\r\n")):
                        self.logger.log(outStr)
                    else:
                        value = ""
                        if re.match(r".*yes.*no.*", outStr):
                            value = input(outStr)
                            while True:
                                # check the input
                                if (
                                    value.upper() != "YES"
                                    and value.upper() != "NO"
                                    and value.upper() != "Y"
                                    and value.upper() != "N"):
                                    value = input("Please type 'yes' or 'no': ")
                                    continue
                                break
                        else:
                            value = getpass.getpass(outStr)
                        stdin.channel.send("%s\r\n" %value)
                        stdin.flush()
                    stdout.flush()
                except Exception as e:
                    sys.exit(1)
                    pass
                if channel.exit_status_ready() and  \
                    not channel.recv_stderr_ready() and \
                    not channel.recv_ready(): 
                    channel.close()
                    break
            stdout.close()
            stderr.close()
            if channel.recv_exit_status() != 0:
                self.expansionSuccess[newHost] = False
                failedInstallHosts.append(newHost)
            else:
                if self.context.newHostCasRoleMap[newHost] == "off":
                    existingStandbys.append(newHost)
                self.logger.log("%s install success." % newHost)
        if notInstalledCascadeHosts:
            self.logger.log("OpenGauss won't be installed on cascade_standby"
                " %s, because there is no Normal standby in the same azZone." % 
                ", ".join(notInstalledCascadeHosts))
        if failedInstallHosts:
            self.logger.log(ErrorCode.GAUSS_527["GAUSS_52707"] %
                ", ".join(failedInstallHosts))
        self.logger.log("Finish to install database on all nodes.")
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "install")
    
    def preInstallOnHosts(self):
        """
        execute preinstall step
        """
        self.logger.log("Start to preinstall database step.")
        tempXmlFile = "%s/clusterconfig.xml" % self.tempFileDir

        if not DefaultValue.getEnv("MPPDB_ENV_SEPARATE_PATH"):
            preinstallCmd = "{softPath}/script/gs_preinstall -U {user} -G {group} "\
                "-X {xmlFile} --non-interactive 2>&1".format(
                softPath = self.context.packagepath, user = self.user,
                group = self.group, xmlFile = tempXmlFile)
        else:
            preinstallCmd = "{softPath}/script/gs_preinstall -U {user} -G {group} "\
                "-X {xmlFile} --sep-env-file={envFile} --non-interactive 2>&1".format(
                softPath = self.context.packagepath, user = self.user,
                group = self.group, xmlFile = tempXmlFile, envFile = self.envFile)

        failedPreinstallHosts = []
        for host in self.context.newHostList:
            sshTool = SshTool([host], timeout = 300)
            resultMap, output = sshTool.getSshStatusOutput(preinstallCmd, [], self.envFile)
            if resultMap[host] == DefaultValue.SUCCESS:
                self.expansionSuccess[host] = True
                self.logger.log("Preinstall %s success" % host)
            else:
                failedPreinstallHosts.append(host)
            self.cleanSshToolFile(sshTool)
        if failedPreinstallHosts:
            self.logger.log("Failed to preinstall on: \n%s" % ", ".join(failedPreinstallHosts))
        self.logger.log("End to preinstall database step.")
    
    def buildStandbyRelation(self):
        """
        func: after install single database on standby nodes. 
        build the relation with primary and standby nodes.
        step:
        1. set all nodes' guc config parameter: replconninfo, available_zone(only for new)
        2. add trust on all hosts
        3. generate GRPC cert on new hosts, and primary if current cluster is single instance
        4. build new hosts :
           (1) restart new instance with standby mode
           (2) build new instances
        5. rollback guc config of existing hosts if build failed
        6. generate cluster static file and send to each node.
        """
        self.setGucConfig()
        self.addTrust()
        self.generateGRPCCert()
        self.buildStandbyHosts()
        self.rollback()
        self.generateClusterStaticFile()

    def getExistingHosts(self):
        """
        get the exiting hosts
        """
        self.logger.debug("Get the existing hosts.")
        primaryHost = self.getPrimaryHostName()
        command = ""
        if DefaultValue.getEnv("MPPDB_ENV_SEPARATE_PATH"):
            command = "su - %s -c 'source %s;gs_om -t status --detail'" % \
                (self.user, self.envFile)
        else:
            command = "su - %s -c 'source /etc/profile;source /home/%s/.bashrc;"\
                "gs_om -t status --detail'" % (self.user, self.user)
        sshTool = SshTool([primaryHost])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command,
            [primaryHost], self.envFile)
        self.logger.debug(outputCollect)
        if resultMap[primaryHost] != DefaultValue.SUCCESS:
            GaussLog.exitWithError("Unable to query current cluster state.")
        instances = re.split('(?:\|)|(?:\n)', outputCollect)
        self.existingHosts = []
        pattern = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*')
        for inst in instances:
            existingHosts = pattern.findall(inst)
            if len(existingHosts) != 0:
                self.existingHosts.append(existingHosts[0])

    def setGucConfig(self):
        """
        set replconninfo on all hosts
        """
        self.logger.debug("Start to set GUC config on all hosts.\n")
        gucDict = self.getGUCConfig()
        tempShFile = "%s/guc.sh" % self.tempFileDir
        hostIpList = list(self.existingHosts)
        for host in self.expansionSuccess:
            hostIpList.append(host)

        nodeDict = self.context.clusterInfoDict
        backIpNameMap = self.context.backIpNameMap
        hostAzNameMap = self.context.hostAzNameMap
        for host in hostIpList:
            hostName = backIpNameMap[host]
            # set Available_zone for the new standby
            if host in self.context.newHostList:
                dataNode = nodeDict[hostName]["dataNode"]
                gucDict[hostName] += """\
gs_guc set -D {dn} -c "available_zone='{azName}'"
                    """.format(dn=dataNode, azName=hostAzNameMap[host])
            command = "source %s ; " % self.envFile + gucDict[hostName]
            self.logger.debug("[%s] gucCommand:%s" % (host, command))

            sshTool = SshTool([host])
            # create temporary dir to save guc command bashfile.
            mkdirCmd = "mkdir -m a+x -p %s; chown %s:%s %s" % \
                (self.tempFileDir, self.user, self.group, self.tempFileDir)
            sshTool.getSshStatusOutput(mkdirCmd, [host], self.envFile)
            subprocess.getstatusoutput("touch %s; cat /dev/null > %s" %
                (tempShFile, tempShFile))
            with os.fdopen(os.open("%s" % tempShFile, os.O_WRONLY | os.O_CREAT,
                stat.S_IWUSR | stat.S_IRUSR), 'w') as fo:
                fo.write("#bash\n")
                fo.write(command)
                fo.close()

            # send guc command bashfile to each host and execute it.
            sshTool.scpFiles("%s" % tempShFile, "%s" % tempShFile, [host],
                self.envFile)
            resultMap, outputCollect = sshTool.getSshStatusOutput(
                "sh %s" % tempShFile, [host], self.envFile)

            self.logger.debug(outputCollect)
            self.cleanSshToolFile(sshTool)

    def addTrust(self):
        """
        add authentication rules about new host ip in existing hosts and
        add authentication rules about other all hosts ip in new hosts
        """
        self.logger.debug("Start to set host trust on all node.")
        allHosts = self.existingHosts + self.context.newHostList
        for hostExec in allHosts:
            hostExecName = self.context.backIpNameMap[hostExec]
            dataNode = self.context.clusterInfoDict[hostExecName]["dataNode"]
            cmd = "source %s;gs_guc set -D %s" % (self.envFile, dataNode)
            if hostExec in self.existingHosts:
                for hostParam in self.context.newHostList:
                    cmd += " -h 'host    all    all    %s/32    trust'" % \
                        hostParam
            else:
                for hostParam in allHosts:
                    if hostExec != hostParam:
                        cmd += " -h 'host    all    all    %s/32    trust'" % \
                            hostParam
            self.logger.debug("[%s] trustCmd:%s" % (hostExec, cmd))
            sshTool = SshTool([hostExec])
            resultMap, outputCollect = sshTool.getSshStatusOutput(cmd,
                [hostExec], self.envFile)
            self.cleanSshToolFile(sshTool)
        self.logger.debug("End to set host trust on all node.")

    def generateGRPCCert(self):
        """
        generate GRPC cert for single node
        """
        primaryHost = self.getPrimaryHostName()
        dataNode = self.context.clusterInfoDict[primaryHost]["dataNode"]
        needGRPCHosts = []
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
                needGRPCHosts.append(host)
        insType, dbStat = self.commonGsCtl.queryInstanceStatus(primaryHost,
            dataNode,self.envFile)
        if insType != MODE_PRIMARY:
            primaryHostIp = self.context.clusterInfoDict[primaryHost]["backIp"]
            needGRPCHosts.append(primaryHostIp)
        self.logger.debug("Start to generate GRPC cert.")
        if needGRPCHosts:
            self.context.initSshTool(needGRPCHosts)
            self.context.createGrpcCa(needGRPCHosts)
        self.logger.debug("End to generate GRPC cert.")

    def reloadPrimaryConf(self):
        """
        """
        primaryHost = self.getPrimaryHostName()
        dataNode = self.context.clusterInfoDict[primaryHost]["dataNode"]
        command = "gs_ctl reload -D %s " % dataNode
        sshTool = SshTool([primaryHost])
        self.logger.debug(command)
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
            [primaryHost], self.envFile)
        self.logger.debug(outputCollect)
        self.cleanSshToolFile(sshTool)

    def getPrimaryHostName(self):
        """
        """
        primaryHost = ""
        for nodeName in self.context.nodeNameList:
            if self.context.clusterInfoDict[nodeName]["instanceType"] \
                    == MASTER_INSTANCE:
                primaryHost = nodeName
                break
        return primaryHost


    def buildStandbyHosts(self):
        """
        stop the new standby host`s database and build it as standby mode
        """
        self.logger.debug("Start to build new nodes.")
        
        standbyHosts = self.context.newHostList
        hostAzNameMap = self.context.hostAzNameMap
        primaryHostName = self.getPrimaryHostName()
        primaryHost = self.context.clusterInfoDict[primaryHostName]["backIp"]
        existingStandbys = list(set(self.existingHosts).difference(set([primaryHost])))
        primaryDataNode = self.context.clusterInfoDict[primaryHostName]["dataNode"]
        self.reloadPrimaryConf()
        time.sleep(10)
        insType, dbStat = self.commonGsCtl.queryInstanceStatus( 
            primaryHost, primaryDataNode, self.envFile)
        primaryExceptionInfo = ""
        if insType != ROLE_PRIMARY:
            primaryExceptionInfo = "The server mode of primary host" \
                "is not primary."
        if dbStat != STAT_NORMAL:
            primaryExceptionInfo = "The primary is not in Normal state."
        if primaryExceptionInfo != "":
            self.rollback()
            GaussLog.exitWithError(primaryExceptionInfo)

        for host in standbyHosts:
            if not self.expansionSuccess[host]:
                continue
            hostName = self.context.backIpNameMap[host]
            dataNode = self.context.clusterInfoDict[hostName]["dataNode"]
            buildMode = ""
            hostRole = ""
            if self.context.newHostCasRoleMap[host] == "on":
                buildMode = MODE_CASCADE
                hostRole = ROLE_CASCADE
                # check whether there are normal standbies in hostAzNameMap[host] azZone
                hasStandbyWithSameAZ = self.hasNormalStandbyInAZOfCascade(host,
                    existingStandbys)
                if not hasStandbyWithSameAZ:
                    self.logger.log("There is no Normal standby in %s" %
                        hostAzNameMap[host])
                    self.expansionSuccess[host] = False
                    continue
            else:
                buildMode = MODE_STANDBY
                hostRole = ROLE_STANDBY
            self.logger.log("Start to build %s %s." % (hostRole, host))
            self.checkTmpDir(hostName)
            # start new host as standby mode
            self.commonGsCtl.stopInstance(hostName, dataNode, self.envFile)
            result, output = self.commonGsCtl.startInstanceWithMode(host, 
                dataNode, MODE_STANDBY, self.envFile)
            if result[host] != DefaultValue.SUCCESS:
                if "uncompleted build is detected" not in output:
                    self.expansionSuccess[host] = False
                    self.logger.log("Failed to start %s as standby "
                        "before building." % host)
                else:
                    self.logger.debug("Uncompleted build is detected on %s." %
                        host)
            else:
                insType, dbStat = self.commonGsCtl.queryInstanceStatus(
                    hostName, dataNode, self.envFile)
                if insType != ROLE_STANDBY:
                    self.logger.log("Build %s failed." % host)
                    self.expansionSuccess[host] = False
                    continue
            
            # build new host
            sshTool = SshTool([host])
            tempShFile = "%s/buildStandby.sh" % self.tempFileDir
            # create temporary dir to save gs_ctl build command bashfile.
            mkdirCmd = "mkdir -m a+x -p %s; chown %s:%s %s" % \
                (self.tempFileDir, self.user, self.group, self.tempFileDir)
            sshTool.getSshStatusOutput(mkdirCmd, [host], self.envFile)
            subprocess.getstatusoutput("touch %s; cat /dev/null > %s" %
                (tempShFile, tempShFile))
            buildCmd = "gs_ctl build -D %s -M %s" % (dataNode, buildMode)
            gs_ctlBuildCmd = "source %s ;nohup " % self.envFile + buildCmd + " 1>/dev/null 2>/dev/null &"
            self.logger.debug("[%s] gs_ctlBuildCmd: %s" % (host, gs_ctlBuildCmd))
            with os.fdopen(os.open("%s" % tempShFile, os.O_WRONLY | os.O_CREAT,
                    stat.S_IWUSR | stat.S_IRUSR),'w') as fo:
                fo.write("#bash\n")
                fo.write(gs_ctlBuildCmd)
                fo.close()
            # send gs_ctlBuildCmd bashfile to the standby host and execute it.
            sshTool.scpFiles(tempShFile, tempShFile, [host], self.envFile)
            resultMap, outputCollect = sshTool.getSshStatusOutput("sh %s" % \
                tempShFile, [host], self.envFile)
            if resultMap[host] != DefaultValue.SUCCESS:
                self.expansionSuccess[host] = False
                self.logger.debug("Failed to send gs_ctlBuildCmd bashfile "
                    "to %s." % host)
                self.logger.log("Build %s %s failed." % (hostRole, host))
                continue
            # check whether build process has finished
            checkProcessExistCmd = "ps x"
            while True:
                resultMap, outputCollect = sshTool.getSshStatusOutput(
                    checkProcessExistCmd, [host])
                if buildCmd not in outputCollect:
                    break
                else:
                    time.sleep(10)
            # check build result after build process finished
            insType, dbStat = self.commonGsCtl.queryInstanceStatus( 
                hostName, dataNode, self.envFile)
            if insType == hostRole and dbStat == STAT_NORMAL:
                if self.context.newHostCasRoleMap[host] == "off":
                    existingStandbys.append(host)
                self.logger.log("Build %s %s success." % (hostRole, host))
            else:
                self.expansionSuccess[host] = False
                self.logger.log("Build %s %s failed." % (hostRole, host))
        if self._isAllFailed():
            self.rollback()
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "build")

    def checkTmpDir(self, hostName):
        """
        if the tmp dir id not exist, create it.
        """
        tmpDir = os.path.realpath(DefaultValue.getTmpDirFromEnv())
        checkCmd = 'if [ ! -d "%s" ]; then exit 1;fi;' % (tmpDir)
        sshTool = SshTool([hostName])
        resultMap, outputCollect = sshTool.getSshStatusOutput(checkCmd, 
        [hostName], self.envFile)
        ret = resultMap[hostName]
        if ret == STATUS_FAIL:
            self.logger.debug("Node [%s] does not have tmp dir. need to fix.")
            fixCmd = "mkdir -p %s" % (tmpDir)
            sshTool.getSshStatusOutput(fixCmd, [hostName], self.envFile)
        self.cleanSshToolFile(sshTool)

    def generateClusterStaticFile(self):
        """
        generate static_config_files and send to all hosts
        """
        self.logger.log("Start to generate and send cluster static file.")

        primaryHost = self.getPrimaryHostName()
        result = self.commonGsCtl.queryOmCluster(primaryHost, self.envFile)
        for nodeName in self.context.nodeNameList:
            nodeInfo = self.context.clusterInfoDict[nodeName]
            nodeIp = nodeInfo["backIp"]
            dataNode = nodeInfo["dataNode"]
            exist_reg = r"(.*)%s[\s]*%s(.*)%s(.*)" % (nodeName, nodeIp, dataNode)
            dbNode = self.context.clusterInfo.getDbNodeByName(nodeName)
            if not re.search(exist_reg, result) and nodeIp not in self.context.newHostList:
                self.logger.debug("The node ip [%s] will not be added to cluster." % nodeIp)
                self.context.clusterInfo.dbNodes.remove(dbNode)
            if nodeIp in self.context.newHostList and not self.expansionSuccess[nodeIp]:
                self.context.clusterInfo.dbNodes.remove(dbNode)
        
        toolPath = self.context.clusterInfoDict["toolPath"]
        appPath = self.context.clusterInfoDict["appPath"]

        static_config_dir = "%s/script/static_config_files" % toolPath
        if not os.path.exists(static_config_dir):
            os.makedirs(static_config_dir)

        # valid if dynamic config file exists.
        dynamic_file = "%s/bin/cluster_dynamic_config" % appPath
        dynamic_file_exist = False
        if os.path.exists(dynamic_file):
            dynamic_file_exist = True
        
        for dbNode in self.context.clusterInfo.dbNodes:
            hostName = dbNode.name
            staticConfigPath = "%s/script/static_config_files/cluster_static_config_%s" % \
                (toolPath, hostName)
            self.context.clusterInfo.saveToStaticConfig(staticConfigPath, dbNode.id)
            srcFile = staticConfigPath
            if not os.path.exists(srcFile):
                GaussLog.exitWithError("Generate static file [%s] not found." % srcFile)
            hostSsh = SshTool([hostName])
            targetFile = "%s/bin/cluster_static_config" % appPath
            hostSsh.scpFiles(srcFile, targetFile, [hostName], self.envFile)
            # if dynamic config file exists, freshconfig it.
            if dynamic_file_exist:
                refresh_cmd = "gs_om -t refreshconf"
                hostSsh.getSshStatusOutput(refresh_cmd, [hostName], self.envFile)
            self.cleanSshToolFile(hostSsh)
        self.logger.log("End to generate and send cluster static file.\n")
        
        self.logger.log("Expansion results:")
        for newHost in self.context.newHostList:
            if self.expansionSuccess[newHost]:
                self.logger.log("%s:\tSuccess" % newHost)
            else:
                self.logger.log("%s:\tFailed" % newHost)

    def getGUCConfig(self):
        """
        get guc config of each node:
            replconninfo[index]
        """
        clusterInfoDict = self.context.clusterInfoDict
        hostIpList = list(self.existingHosts)
        for host in self.expansionSuccess:
            hostIpList.append(host)
        hostNames = []
        for host in hostIpList:
            hostNames.append(self.context.backIpNameMap[host])
        
        gucDict = {}
        for hostName in hostNames:
            localeHostInfo = clusterInfoDict[hostName]
            index = 1
            guc_tempate_str = "source %s; " % self.envFile
            for remoteHost in hostNames:
                if remoteHost == hostName:
                    continue
                remoteHostInfo = clusterInfoDict[remoteHost]
                guc_repl_template = """\
gs_guc set -D {dn} -c "replconninfo{index}=\
'localhost={localhost} localport={localport} \
localheartbeatport={localeHeartPort} \
localservice={localservice} \
remotehost={remoteNode} \
remoteport={remotePort} \
remoteheartbeatport={remoteHeartPort} \
remoteservice={remoteservice}'"
                """.format(dn=localeHostInfo["dataNode"],
                index=index,
                localhost=localeHostInfo["sshIp"],
                localport=localeHostInfo["localport"],
                localeHeartPort=localeHostInfo["heartBeatPort"],
                localservice=localeHostInfo["localservice"],
                remoteNode=remoteHostInfo["sshIp"],
                remotePort=remoteHostInfo["localport"],
                remoteHeartPort=remoteHostInfo["heartBeatPort"],
                remoteservice=remoteHostInfo["localservice"])
                guc_tempate_str += guc_repl_template
                index += 1

            gucDict[hostName] = guc_tempate_str
        return gucDict

    def checkLocalModeOnStandbyHosts(self):
        """
        expansion the installed standby node. check standby database.
        1. if the database is installed correctly
        2. if the databases version are same before existing and new
        """
        standbyHosts = self.context.newHostList
        envFile = self.envFile
        for host in standbyHosts:
            self.expansionSuccess[host] = True
        self.logger.log("Checking if the database is installed correctly with local mode.")
        getversioncmd = "source %s;gaussdb --version" % envFile
        primaryHostName = self.getPrimaryHostName()
        sshPrimary = SshTool([primaryHostName])
        resultMap, outputCollect = sshPrimary.getSshStatusOutput(
            getversioncmd, [], envFile)
        if resultMap[primaryHostName] != DefaultValue.SUCCESS:
            GaussLog.exitWithError("Fail to check the version of primary.")
        ipPattern = re.compile("\[.*\] (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):")
        versionPattern = re.compile("gaussdb \((.*)\) .*")
        primaryVersion = versionPattern.findall(outputCollect)[0]
        notInstalledHosts = []
        wrongVersionHosts = []
        for host in standbyHosts:
            hostName = self.context.backIpNameMap[host]
            dataNode = self.context.clusterInfoDict[hostName]["dataNode"]
            sshTool = SshTool([host])
            resultMap, outputCollect = sshTool.getSshStatusOutput(
                getversioncmd, [], envFile)
            if resultMap[host] != DefaultValue.SUCCESS:
                self.expansionSuccess[host] = False
                notInstalledHosts.append(host)
            else:
                version = versionPattern.findall(outputCollect)[0]
                if version != primaryVersion:
                    self.expansionSuccess[host] = False
                    wrongVersionHosts.append(host)
        if notInstalledHosts:
            self.logger.log("In local mode, database is not installed "
                "correctly on these nodes:\n%s" % ", ".join(notInstalledHosts))
        if wrongVersionHosts:
            self.logger.log("In local mode, the database version is not same "
                "with primary on these nodes:\n%s" % ", ".join(wrongVersionHosts))
        self.logger.log("End to check the database with locale mode.")

    def preInstall(self):
        """
        preinstall on new hosts.
        """
        self.logger.log("Start to preinstall database on new nodes.")
        self.sendSoftToHosts()
        self.generateAndSendXmlFile()
        self.preInstallOnHosts()
        self.logger.log("End to preinstall database on new nodes.\n")
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "preinstall")

    def clearTmpFile(self):
        """
        clear temporary file after expansion success
        """
        self.logger.debug("start to delete temporary file %s" % self.tempFileDir)
        clearCmd = "if [ -d '%s' ];then rm -rf %s;fi" % \
            (self.tempFileDir, self.tempFileDir)
        hostNames = self.context.nodeNameList
        try:
            sshTool = SshTool(hostNames)
            result, output = sshTool.getSshStatusOutput(clearCmd, 
            hostNames, self.envFile)
            self.logger.debug(output)
            self.cleanSshToolFile(sshTool)
        except Exception as e:
            self.logger.debug(str(e))
            self.cleanSshToolFile(sshTool)
        

    def cleanSshToolFile(self, sshTool):
        """
        """
        try:
            sshTool.clenSshResultFiles()
        except Exception as e:
            self.logger.debug(str(e))

    
    def checkNodesDetail(self):
        """
        """
        self.checkUserAndGroupExists()
        self.checkXmlFileAccessToUser()
        self.checkClusterStatus()
        self.validNodeInStandbyList()

    def checkClusterStatus(self):
        """
        Check whether the cluster status is normal before expand.
        """
        self.logger.debug("Start to check cluster status.\n")

        curHostName = socket.gethostname()
        command = ""
        if DefaultValue.getEnv("MPPDB_ENV_SEPARATE_PATH"):
            command = "su - %s -c 'source %s;gs_om -t status --detail'" % \
                (self.user, self.envFile)
        else:
            command = "su - %s -c 'source /etc/profile;source /home/%s/.bashrc;"\
                "gs_om -t status --detail'" % (self.user, self.user)
        sshTool = SshTool([curHostName])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command,
            [curHostName], self.envFile)
        if outputCollect.find("Primary Normal") == -1:
            GaussLog.exitWithError("Unable to query current cluster status. " + \
                "Please import environment variables or " +\
                "check whether the cluster status is normal.")
        
        self.logger.debug("The primary database is normal.\n")

    
    def _adjustOrderOfNewHostList(self):
        """
        Adjust the order of hostlist so that 
        standby comes first and cascade standby comes last
        """
        newHostList = self.context.newHostList
        newHostCasRoleMap = self.context.newHostCasRoleMap
        i, j = 0, len(newHostList) - 1
        while i < j:
            while i < j and newHostCasRoleMap[newHostList[i]] == "off":
                i += 1
            while i < j and newHostCasRoleMap[newHostList[j]] == "on":
                j -= 1
            newHostList[i], newHostList[j] = newHostList[j], newHostList[i]
            i += 1
            j -= 1

    def validNodeInStandbyList(self):
        """
        check if the node has been installed in the cluster.
        """
        self.logger.debug("Start to check if the nodes in standby list.")
        self.getExistingHosts()
        newHostList = self.context.newHostList
        existedNewHosts = \
            [host for host in newHostList if host in self.existingHosts]
        if existedNewHosts:
            newHostList = \
                [host for host in newHostList if host not in existedNewHosts]
            self.context.newHostList = newHostList
            self.expansionSuccess = {}
            for host in newHostList:
                self.expansionSuccess[host] = False
            self.logger.log("These nodes [%s] are already in the cluster. "
                "Skip expand these nodes." % ",".join(existedNewHosts))
        if len(newHostList) == 0:
            self.logger.log("There is no node can be expanded.")
            sys.exit(0)
        self._adjustOrderOfNewHostList()

    def checkXmlFileAccessToUser(self):
        """
        Check if the xml config file has readable access to user.
        """
        userInfo = pwd.getpwnam(self.user)
        uid = userInfo.pw_uid
        gid = userInfo.pw_gid

        xmlFile = self.context.xmlFile
        fstat = os.stat(xmlFile)
        mode = fstat[stat.ST_MODE]
        if (fstat[stat.ST_UID] == uid and (mode & stat.S_IRUSR > 0)) or \
           (fstat[stat.ST_GID] == gid and (mode & stat.S_IRGRP > 0)):
            pass
        else:
            self.logger.debug("User %s has no access right for file %s" \
                 % (self.user, xmlFile))
            os.chown(xmlFile, uid, gid)
            os.chmod(xmlFile, stat.S_IRUSR)

    def checkUserAndGroupExists(self):
        """
        check system user and group exists and be same 
        on primary and standby nodes
        """
        inputUser = self.user
        inputGroup = self.group
        
        user_group_id = ""
        isUserExits = False
        localHost = socket.gethostname()
        for user in pwd.getpwall():
            if user.pw_name == self.user:
                user_group_id = user.pw_gid
                isUserExits = True
                break
        if not isUserExits:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                % ("User", self.user, localHost))

        isGroupExits = False
        group_id = ""
        for group in grp.getgrall():
            if group.gr_name == self.group:
                group_id = group.gr_gid
                isGroupExits = True
        if not isGroupExits:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                % ("Group", self.group, localHost))
        if user_group_id != group_id:
            GaussLog.exitWithError("User [%s] is not in the group [%s]."\
                 % (self.user, self.group))
        
        hostNames = self.context.newHostList
        envfile = self.envFile
        sshTool = SshTool(hostNames)

        #get username in the other standy nodes 
        getUserNameCmd = "cat /etc/passwd | grep -w %s" % inputUser
        resultMap, outputCollect = sshTool.getSshStatusOutput(getUserNameCmd, 
        [], envfile)
        
        for hostKey in resultMap:
            if resultMap[hostKey] == STATUS_FAIL:
                self.cleanSshToolFile(sshTool)
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                       % ("User", self.user, hostKey))
        
        #get groupname in the other standy nodes   
        getGroupNameCmd = "cat /etc/group | grep -w %s" % inputGroup
        resultMap, outputCollect = sshTool.getSshStatusOutput(getGroupNameCmd, 
        [], envfile)
        for hostKey in resultMap:
            if resultMap[hostKey] == STATUS_FAIL:
                self.cleanSshToolFile(sshTool)
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                       % ("Group", self.group, hostKey))
        self.cleanSshToolFile(sshTool)

    
    def installAndExpansion(self):
        """
        install database and expansion standby node with db om user
        """
        pvalue = Value('i', 0)
        proc = Process(target=self.installProcess, args=(pvalue,)) 
        proc.start()
        proc.join()
        if not pvalue.value:
            sys.exit(1)
        else:
            proc.terminate()

    def installProcess(self, pvalue):
        # change to db manager user. the below steps run with db manager user.
        self.changeUser()

        if not self.context.standbyLocalMode:
            self.logger.log("Start to install database on new nodes.")
            self.installDatabaseOnHosts()
        else:
            self.checkLocalModeOnStandbyHosts()

        self.logger.log("Database on standby nodes installed finished.\n")
        self.logger.log("Start to establish the relationship.")
        self.buildStandbyRelation()
        # process success
        pvalue.value = 1

    def rollback(self):
        """
        rollback all hosts' replconninfo about failed hosts 
        """
        existingHosts = self.existingHosts
        failedHosts = []
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
                existingHosts.append(host)
            else:
                failedHosts.append(host)
        clusterInfoDict = self.context.clusterInfoDict
        for failedHost in failedHosts:
            self.logger.debug("Start to rollback replconninfo about %s" % failedHost)
            for host in existingHosts:
                hostName = self.context.backIpNameMap[host]
                dataNode = clusterInfoDict[hostName]["dataNode"]
                confFile = os.path.join(dataNode, "postgresql.conf")
                rollbackReplconninfoCmd = "sed -i '/remotehost=%s/s/^/#&/' %s" \
                    % (failedHost, confFile)
                self.logger.debug("[%s] rollbackReplconninfoCmd:%s" % (host,
                    rollbackReplconninfoCmd))
                sshTool = SshTool([host])
                (statusMap, output) = sshTool.getSshStatusOutput(rollbackReplconninfoCmd, [host])
                pg_hbaFile = os.path.join(dataNode, "pg_hba.conf")
                rollbackPg_hbaCmd = "sed -i '/%s/s/^/#&/' %s" \
                    % (failedHost, pg_hbaFile)
                self.logger.debug("[%s] rollbackPg_hbaCmd:%s" % (host,
                    rollbackPg_hbaCmd))
                (statusMap, output) = sshTool.getSshStatusOutput(rollbackPg_hbaCmd, [host])
                reloadGUCCommand = "source %s ; gs_ctl reload -D %s " % \
                    (self.envFile, dataNode)
                resultMap, outputCollect = sshTool.getSshStatusOutput(
                    reloadGUCCommand, [host], self.envFile)
                self.logger.debug(outputCollect)
                self.cleanSshToolFile(sshTool)

    def _isAllFailed(self):
        """
        check whether all new hosts preinstall/install/build failed
        """
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
                return False
        return True

    def run(self):
        """
        start expansion
        """
        self.checkNodesDetail()
        # preinstall on standby nodes with root user.
        if not self.context.standbyLocalMode:
            self.preInstall()

        self.installAndExpansion()
        self.logger.log("Expansion Finish.")


class GsCtlCommon:

    def __init__(self, expansion):
        """
        """
        self.logger = expansion.logger
        self.user = expansion.user
    
    def queryInstanceStatus(self, host, datanode, env):
        """
        """
        command = "source %s ; gs_ctl query -D %s" % (env, datanode)
        sshTool = SshTool([datanode])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(outputCollect)
        localRole = re.findall(r"local_role.*: (.*?)\n", outputCollect)
        db_state = re.findall(r"db_state.*: (.*?)\n", outputCollect)

        insType = ""

        if(len(localRole)) == 0:
            insType = ""
        else:
            insType = localRole[0]
        
        dbStatus = ""
        if(len(db_state)) == 0:
            dbStatus = ""
        else:
            dbStatus = db_state[0]
        self.cleanSshToolTmpFile(sshTool)
        return insType.strip().lower(), dbStatus.strip().lower()

    def stopInstance(self, host, datanode, env):
        """
        """
        command = "source %s ; gs_ctl stop -D %s" % (env, datanode)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        self.cleanSshToolTmpFile(sshTool)
    
    def startInstanceWithMode(self, host, datanode, mode, env):
        """
        """
        command = "source %s ; gs_ctl start -D %s -M %s" % (env, datanode, mode)
        self.logger.debug(command)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        self.cleanSshToolTmpFile(sshTool)
        return resultMap, outputCollect

    def buildInstance(self, host, datanode, mode, env):
        command = "source %s ; gs_ctl build -D %s -M %s" % (env, datanode, mode)
        self.logger.debug(command)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        self.cleanSshToolTmpFile(sshTool)

    def startOmCluster(self, host, env):
        """
        om tool start cluster
        """
        command = "source %s ; gs_om -t start" % env
        self.logger.debug(command)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        self.cleanSshToolTmpFile(sshTool)
    
    def queryOmCluster(self, host, env):
        """
        query om cluster detail with command:
        gs_om -t status --detail
        """
        command = "source %s ; gs_om -t status --detail" % env
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, 
        [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        if resultMap[host] == STATUS_FAIL:
            GaussLog.exitWithError("Query cluster failed. Please check " \
                "the cluster status or " \
                "source the environmental variables of user [%s]." % self.user)
        self.cleanSshToolTmpFile(sshTool)
        return outputCollect

    def cleanSshToolTmpFile(self, sshTool):
        """
        """
        try:
            sshTool.clenSshResultFiles()
        except Exception as e:
            self.logger.debug(str(e))