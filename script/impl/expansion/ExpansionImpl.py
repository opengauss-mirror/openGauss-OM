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

from enum import Flag
import subprocess
import sys
import re
import os
import getpass
import pwd
import datetime
import weakref
import time
import grp
import socket
import stat
from multiprocessing import Process, Value

sys.path.append(sys.path[0] + "/../../../../")
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.threads.SshTool import SshTool
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.common.GaussLog import GaussLog
# from gspylib.os.gsOSlib import g_OSlib
import impl.upgrade.UpgradeConst as Const
from gspylib.common.OMCommand import OMCommand
from gspylib.os.gsfile import g_file


from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.env_util import EnvUtil
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.cluster_file.package_info import PackageInfo
from base_utils.os.net_util import NetUtil
from base_diff.comm_constants import CommConstants
from base_utils.os.file_util import FileUtil

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
STATE_NORMAL = "normal"
STATE_STARTING = "starting"
STATE_CATCHUP = "catchup"

# master 
MASTER_INSTANCE = 0
# standby 
STANDBY_INSTANCE = 1

# statu failed
STATUS_FAIL = "Failure"

BASE_ID_DATANODE = 6001
MAX_DATANODE_NUM = 9

ACTION_INSTALL_CLUSTER = "install_cluster"

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

        envFile = EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH")
        if envFile:
            self.envFile = envFile
        else:
            userpath = pwd.getpwnam(self.user).pw_dir
            mpprcFile = os.path.join(userpath, ".bashrc")
            self.envFile = mpprcFile

        currentTime = str(datetime.datetime.now()).replace(" ", "_").replace(
            ".", "_").replace(":", "_")

        self.commonGsCtl = GsCtlCommon(expansion)
        self.tempFileDir = "/tmp/gs_expansion_%s" % (currentTime)
        dir_name = os.path.dirname(os.path.realpath(__file__))
        self.remote_pkg_dir = os.path.normpath(os.path.join(dir_name, "./../../../"))
        self.logger.debug("tmp expansion dir is %s ." % self.tempFileDir)
        self.logger.debug("remote_pkg_dir is %s ." % self.remote_pkg_dir)
        # primary's wal_keep_segments value
        self.walKeepSegments = -1

        self._finalizer = weakref.finalize(self, self.final)

        globals()["paramiko"] = __import__("paramiko")

    def queryPrimaryWalKeepSegments(self):
        """
        query primary's wal_keep_segments, when current user is root
        """
        primaryHostName = self.getPrimaryHostName()
        primaryHostIp = self.context.clusterInfoDict[primaryHostName]["backIp"]
        primaryDataNode = self.context.clusterInfoDict[primaryHostName]["dataNode"]
        status, walKeepSegments = self.commonGsCtl.queryGucParaValue(
            primaryHostIp, self.envFile, primaryDataNode, "wal_keep_segments", self.user)
        if status != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50021"] % "wal_keep_segments")
        return eval(walKeepSegments)

    def rollbackPrimaryWalKeepSegments(self):
        """
        rollback primary's wal_keep_segments, when current user is root
        """
        self.logger.debug("Start to rollback primary's wal_keep_segments")
        primary = self.getPrimaryHostName()
        primaryDataNode = self.context.clusterInfoDict[primary]["dataNode"]
        status = self.commonGsCtl.setGucPara(primary, self.envFile, primaryDataNode,
            "wal_keep_segments", self.walKeepSegments, self.user)
        if status != DefaultValue.SUCCESS:
            self.logger.log("Failed to rollback wal_keep_segments, please manually "
                "set it to original value %s." % self.walKeepSegments)
        else:
            self.reloadPrimaryConf()

    def final(self):
        """
        function:
            1. Make sure primary's wal_keep_segments is restored to its
               original value if it has been changed,
            2. rollback,
            3. clear temp file
        input : NA
        output: NA
        """
        if self.walKeepSegments != -1:
            currentWalKeepSegments = self.queryPrimaryWalKeepSegments()
            if currentWalKeepSegments != "NULL" \
                and self.walKeepSegments != int(currentWalKeepSegments):
                self.rollbackPrimaryWalKeepSegments()
        self.rollback()
        self.clearTmpFile()

    def sendSoftToHosts(self, send_pkg=True):
        """
        create software dir and send it on each nodes
        """
        self.logger.log("Start to send soft to each standby nodes.")
        srcFile = self.context.packagepath
        pkgfiles = self.generatePackages(srcFile)
        time_out = self.context.time_out if self.context.time_out else 300
        for host in self.context.newHostList:
            sshTool = SshTool([host], timeout=time_out)
            # mkdir package dir and send package to remote nodes.
            sshTool.executeCommand("umask 0022;mkdir -m a+x -p %s; mkdir -m a+x -p %s; chown %s:%s %s" % \
                (self.remote_pkg_dir, self.tempFileDir, self.user, self.group, self.tempFileDir),
                DefaultValue.SUCCESS, [host])
            if send_pkg:
                for file in pkgfiles:
                    if not os.path.exists(file):
                        GaussLog.exitWithError("Package [%s] is not found." % file)
                    sshTool.scpFiles(file, self.remote_pkg_dir, [host])
                sshTool.executeCommand("cd %s;tar -xf %s" % (self.remote_pkg_dir, 
                    os.path.basename(pkgfiles[0])), DefaultValue.SUCCESS, [host])
            self.cleanSshToolFile(sshTool)
        self.logger.log("End to send soft to each standby nodes.")
    
    def generatePackages(self, pkgdir):
        server_file = PackageInfo.getPackageFile(CommConstants.PKG_SERVER)
        sha_file = PackageInfo.getPackageFile(CommConstants.PKG_SHA256)
        upgrade_sql_file = os.path.join(pkgdir,
                                             Const.UPGRADE_SQL_FILE)
        upgrade_sha_file = os.path.join(pkgdir,
                                             Const.UPGRADE_SQL_SHA)
        om_file = server_file.replace("Server", "OM").replace("tar.bz2", 'tar.gz')
        cm_file = []
        if self.context.check_cm_component():
            cm_file = [server_file.replace("Server", "CM").replace("tar.bz2", 'tar.gz')]

        return [om_file, server_file, sha_file, upgrade_sql_file,
             upgrade_sha_file] + cm_file

    def generateAndSendXmlFile(self):
        """
        """
        self.logger.debug("Start to generateAndSend XML file.")

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
                fo.write(xmlContent)
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
        
        self.logger.debug("End to generateAndSend XML file.")

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
        core_path_config = ""
        if corePath:
            core_path_config = '<PARAM name="corePath" value="%s" />' % corePath
        toolPath = self.context.clusterInfoDict["toolPath"]
        mppdbconfig = ""
        tmpMppdbPath = EnvUtil.getEnv("PGHOST")
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
        {core_path_config}
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
        appPath = appPath, logPath = logPath, toolPath = toolPath, core_path_config = core_path_config,
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

    def hasNormalStandbyInAZOfCascade(self, cascadeIp, existingStandbys):
        """
        check whether there are normal standbies in hostAzNameMap[cascadeIp] azZone
        """
        hasStandbyWithSameAZ = False
        hostAzNameMap = self.context.hostAzNameMap
        for existingStandby in existingStandbys:
            existingStandbyName = self.context.backIpNameMap[existingStandby]
            existingStandbyDataNode = \
                self.context.clusterInfoDict[existingStandbyName]["dataNode"]
            insType, dbState = self.commonGsCtl.queryInstanceStatus(
                existingStandby, existingStandbyDataNode, self.envFile)
            if dbState != STATE_NORMAL:
                continue
            if hostAzNameMap[cascadeIp] != hostAzNameMap[existingStandby]:
                continue
            hasStandbyWithSameAZ = True
            break
        return hasStandbyWithSameAZ

    def check_casrole_node_azname_parameter(self):
        for host in self.context.newHostList:
            if not self.query_casrole_node_azname_parameter(host):
                self.expansionSuccess[host] = False
            else:
                self.expansionSuccess[host] = True
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "check enable_availablezone")

    def query_casrole_node_azname_parameter(self, host):
        """
        query casrole node guc parameter
        """
        if self.context.newHostCasRoleMap[host] == "on":
            if not self.check_enable_availablezone_parameter(host):
                self.logger.debug("enable_availablezone is off on new host %s" % host)
                return True
            self.logger.debug("enable_availablezone is on on new host %s" % host)
            primary_hostname = self.getPrimaryHostName()
            primary_hostip = self.context.clusterInfoDict[primary_hostname]["backIp"]
            existing_standbys = list(set(self.existingHosts) - (set([primary_hostip])))
            # check whether there are normal standbies in hostAzNameMap[host] azZone
            has_standby_with_same_az = self.hasNormalStandbyInAZOfCascade(host, existing_standbys)
            if not has_standby_with_same_az:
                self.logger.log("There is no azName that is the same as %s" % host)
                return False
        return True

    def check_enable_availablezone_parameter(self, cascade_ip):
        """
        Check whether enable_availablezone is on on new host
        """
        if os.getuid() == 0:
            self.changeUser()
        pg_data = EnvUtil.getEnv("PGDATA")
        check_cmd = "source %s; gs_guc check -D %s -c enable_availablezone" % (self.envFile, pg_data)
        self.logger.debug("Command for checking enable_availablezone: %s" % check_cmd)
        ssh_tool = SshTool([cascade_ip])
        result_map, output = ssh_tool.getSshStatusOutput(check_cmd, [cascade_ip], self.envFile)
        self.logger.debug("Output for checking enable_availablezone: %s" % output)
        self.logger.debug("ResultMap for checking enable_availablezone: %s" % result_map)
        if result_map[cascade_ip] != DefaultValue.SUCCESS:
            self.logger.logExit("Failed to get enable_availablezone on new host %s" % cascade_ip)
        self.cleanSshToolFile(ssh_tool)
        if output.find("enable_availablezone=on") > 0:
            self.logger.debug("enable_availablezone is on on new host %s" % cascade_ip)
            return True
        else:
            self.logger.debug("enable_availablezone is off on new host %s" % cascade_ip)
            return False
        
    def check_cm_enable_availablezone(self):
        """
        Check enable availablezone only when cascading nodes.
        """
        for host in self.context.newHostList:
            if self.context.newHostCasRoleMap[host] == "on": 
                check_enable_az = self.check_enable_availablezone_parameter(host)
                if not check_enable_az:
                    continue
                primary_hostname = self.getPrimaryHostName()
                primary_hostip = self.context.clusterInfoDict[primary_hostname]["backIp"]
                existing_standbys = list(set(self.existingHosts) - (set([primary_hostip])))
                has_standby_with_same_az = self.hasNormalStandbyInAZOfCascade(host, existing_standbys)
                if not has_standby_with_same_az:
                    self.logger.log("There is no azName that is the same as %s" % host)
                    self.expansionSuccess[host] = False
                    continue

    def getIncreaseAppNames(self, num):
        """
        the default new database application_name is 'dn_6001' which same with
        primary host. It case standby node cannot set synchronization by name.
        """
        clusterInfo = dbClusterInfo()
        
        appPath = self.context.clusterInfoDict["appPath"]
        staticFile = os.path.join(appPath, "bin", "cluster_static_config")
        clusterInfo.initFromStaticConfigWithoutUser(staticFile)
        dbNodes = clusterInfo.dbNodes

        newInsIds = []
        existInsIds = []
        for dbNode in dbNodes:
            for dnInst in dbNode.datanodes:
                self.context.clusterInfoDict[dbNode.name]["instanceId"] = dnInst.instanceId
                existInsIds.append(int(dnInst.instanceId))
        idx = 0
        while idx <= MAX_DATANODE_NUM and num > 0:
            insId = BASE_ID_DATANODE + idx
            if insId not in existInsIds:
                newInsIds.append(insId)
                existInsIds.append(insId)
                num -= 1
            idx += 1
        return newInsIds

    def installDatabaseOnHosts(self):
        """
        install database on each standby node
        """
        standbyHosts = self.context.newHostList
        tempXmlFile = "%s/clusterconfig.xml" % self.tempFileDir
        primaryHostName = self.getPrimaryHostName()
        primaryHostIp = self.context.clusterInfoDict[primaryHostName]["backIp"]
        existingStandbys = list(set(self.existingHosts) - (set([primaryHostIp])))
        failedInstallHosts = []
        notInstalledCascadeHosts = []
        for newHost in standbyHosts:
            if not self.expansionSuccess[newHost]:
                continue
            hostName = self.context.backIpNameMap[newHost]
            sshIp = self.context.clusterInfoDict[hostName]["sshIp"]
            port = self.context.clusterInfoDict[hostName]["port"]
            
            ssh_tool = SshTool([sshIp], timeout=300)
            
            # installing applications
            cmd = "source %s;" % self.envFile
            cmd += "%s -t %s -U %s -X %s -R %s -c %s -l %s" % (
                OMCommand.getLocalScript("Local_Install"),
                ACTION_INSTALL_CLUSTER,
                self.user + ":" + self.group,
                tempXmlFile,
                self.context.clusterInfoDict["appPath"],
                EnvUtil.getEnvironmentParameterValue("GS_CLUSTER_NAME",
                                                      self.user),
                self.context.localLog)
            self.logger.debug(
                "Command for installing application: %s" % cmd)
            result_map, output = ssh_tool.getSshStatusOutput(cmd, [], self.envFile)
            if result_map[sshIp] != DefaultValue.SUCCESS:
                self.logger.debug("install application failed: %s %s" % (newHost, output))
                self.expansionSuccess[newHost] = False
                failedInstallHosts.append(newHost)
                continue
            
            # send ca file dir
            ca_file_dir = os.path.realpath(os.path.join(
                self.context.clusterInfoDict["appPath"], "share", "sslcert"))
            self.logger.debug(
                "Command for sending ca file dir: %s" % ca_file_dir)
            ssh_tool.scpFiles(ca_file_dir,
                               os.path.dirname(ca_file_dir),
                               [sshIp])
            
            # init database datanode
            cmd = "source {0}; " \
              "{1} -U {2} -l {3}".format(self.envFile,
                                         OMCommand.getLocalScript("Local_Init_Instance"),
                                         self.user, self.context.localLog)
            self.logger.debug(
                "Command for installing database datanode: %s" % cmd)
            result_map, output = ssh_tool.getSshStatusOutput(cmd, [], self.envFile)
            if result_map[sshIp] != DefaultValue.SUCCESS:
                self.logger.debug("install datanode failed: %s %s" % (newHost, output))
                self.expansionSuccess[newHost] = False
                failedInstallHosts.append(newHost)
                continue

            # query enable_availablezone on cas node
            if not self.query_casrole_node_azname_parameter(newHost):
                self.expansionSuccess[newHost] = False
                continue
            
            # set guc config
            inst_dir = self.context.clusterInfoDict[hostName]["dataNode"]
            guc_path = os.path.join(self.context.clusterInfoDict["appPath"],
                                "bin", "gs_guc")
            para_str = " -c \"listen_addresses='localhost,{0}'\"" \
                " -c \"port='{1}'\"".format(newHost, port)
            cmd = "source {0}; {1} set -D {2} {3}".format(self.envFile, 
                                                          guc_path, inst_dir, para_str)
            self.logger.debug(
                "Command for set guc params: %s" % cmd)
            self.guc_executor(ssh_tool, cmd, sshIp)
            self.logger.log("%s install success." % newHost)
            
            if self.context.newHostCasRoleMap[newHost] == "off":
                existingStandbys.append(newHost)
             
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

    def resetStandbyAppName(self, hostName, sshIp):
        if not self.newInsIds:
            return
        appName = self.newInsIds[0]
        # update new instance id
        self.context.clusterInfoDict[hostName]["instanceId"] = appName
        logPath = ClusterDir.getUserLogDirWithUser(self.user)
        logDir = "%s/pg_log/dn_%d" % (logPath, appName)
        auditDir = "%s/pg_audit/dn_%d" % (logPath, appName)
        instDir = self.context.clusterInfoDict[hostName]["dataNode"]
        gucPath = os.path.join(self.context.clusterInfoDict["appPath"],
            "bin", "gs_guc")
        paraStr = " -c \"application_name='dn_{0}'\" " \
            "-c \"log_directory='{1}'\" " \
            " -c \"audit_directory='{2}'\" " \
            "".format(appName, logDir, auditDir)
        cmd = "source {0}; {1} set -D {2} {3}".format(
            self.envFile, gucPath, instDir, paraStr)
        self.logger.debug("Command for set guc params: %s" % cmd)
        sshTool = SshTool([sshIp], timeout=300)
        self.guc_executor(sshTool, cmd, sshIp)

    def reset_sync_standby_names(self, hostname, ssh_ip):
        """
        reset sync standby names
        """
        self.logger.debug("Reset sync standby names.")
        if not self.context.standbyLocalMode:
            return
        dn_dir = self.context.clusterInfoDict[hostname]["dataNode"]
        cmd = "source {0}; gs_guc set -D {1} -c \"synchronous_standby_names=''\"".format(self.envFile, dn_dir)
        ssh_tool = SshTool([ssh_ip], timeout=300)
        self.guc_executor(ssh_tool, cmd, ssh_ip)
        self.logger.debug("Successfully reset sync standby names.")

    def preInstallOnHosts(self):
        """
        execute preinstall step
        """
        self.logger.log("Start to preinstall database step.")
        tempXmlFile = "%s/clusterconfig.xml" % self.tempFileDir
        preinstallCmd = "{softPath}/script/gs_preinstall -U {user} -G {group} -X {xmlFile} " \
                        "--non-interactive".format(softPath=self.remote_pkg_dir,
                                                   user=self.user,
                                                   group=self.group,
                                                   xmlFile=tempXmlFile)
        if EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH"):
            preinstallCmd += " --sep-env-file={envFile}".format(envFile = self.envFile)
        if not os.listdir(os.path.join(EnvUtil.getEnv("GPHOME"),"lib")):
            preinstallCmd += " --unused-third-party"
        preinstallCmd += " --skip-hostname-set 2>&1"

        failedPreinstallHosts = []
        for host in self.context.newHostList:
            sshTool = SshTool([host], timeout = 300)
            resultMap, output = sshTool.getSshStatusOutput(preinstallCmd, [], self.envFile)
            self.logger.debug(resultMap)
            self.logger.debug(output)
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
        5. generate cluster static file and send to each node.
        """
        self.check_casrole_node_azname_parameter()
        self.refreshClusterInfoState()
        self.setGucConfig()
        self.addTrust()
        if DefaultValue.is_create_grpc(self.logger,
                                       self.context.clusterInfo.appPath):
            self.generateGRPCCert()
        self.distributeCipherFile()
        self.buildStandbyHosts()
        self.generateClusterStaticFile()

    def getExistingHosts(self, isRootUser=True):
        """
        get the exiting hosts
        """
        self.logger.debug("Get the existing hosts.")
        primaryHost = self.getPrimaryHostName()
        command = ""
        if EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH"):
            command = "source %s;gs_om -t status --detail" % self.envFile
        else:
            command = "source /etc/profile;source %s;"\
                "gs_om -t status --detail" % self.envFile
        if isRootUser and self.context.current_user_root:
            command = "su - %s -c '%s'" % (self.user, command)
        self.logger.debug(command)
        sshTool = SshTool([primaryHost])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command,
            [primaryHost], self.envFile)
        self.cleanSshToolFile(sshTool)
        self.logger.debug("Expansion cluster status result:{0}".format(resultMap))
        self.logger.debug("Expansion cluster status output:{0}".format(outputCollect))
        if resultMap[primaryHost] != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51600"])
        instances = re.split('(?:\|)|(?:\n)', outputCollect)
        self.existingHosts = []
        pattern_ip = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){7})\b')
        for inst in instances:
            existing_hosts_ip = pattern_ip.findall(inst)
            if len(existing_hosts_ip) != 0:
                self.existingHosts.append(existing_hosts_ip[0])
        self.existingHosts = list(set(self.existingHosts))

    def refreshClusterInfoState(self):
        """
        fresh cluster info state
        """
        self.logger.debug("Start refresh cluster info state.")
        # get xml config node info
        clusterInfoDict = self.context.clusterInfoDict
        nodeNames = self.context.nodeNameList
        # get gs_om node info
        primaryHost = self.getPrimaryHostName()
        result = self.commonGsCtl.queryOmCluster(primaryHost, self.envFile)
        instances = re.split('(?:\|)|(?:\n)', result)
        pattern_ip = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){7})\b')
        host_ip = []
        for ins in instances:
            if re.findall('Primary', ins):
                host_ip = pattern_ip.findall(ins)
                break
        # update xml config node info
        primary_host_ip = "".join(host_ip)
        for nodename in nodeNames:
            if clusterInfoDict[nodename]["instanceType"] == MASTER_INSTANCE:
                clusterInfoDict[nodename]["instanceType"] = STANDBY_INSTANCE
            if clusterInfoDict[nodename]["backIp"] == primary_host_ip:
                clusterInfoDict[nodename]["instanceType"] = MASTER_INSTANCE
        
    def setGucConfig(self):
        """
        set replconninfo on all hosts
        """
        self.logger.debug("Start to set GUC config on all hosts.\n")
        gucDict = self.getGUCConfig()
        tempShFile = "%s/guc.sh" % self.tempFileDir
        hostIpList = list(self.existingHosts)
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
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
            self.logger.debug("[%s] guc command is:%s" % (host, command))

            sshTool = SshTool([host])
            # create temporary dir to save guc command bashfile.
            mkdirCmd = "mkdir -m a+x -p %s; chown %s:%s %s" % \
                (self.tempFileDir, self.user, self.group, self.tempFileDir)
            sshTool.getSshStatusOutput(mkdirCmd, [host], self.envFile)
            exitcode, output = subprocess.getstatusoutput("if [ ! -e '%s' ]; then mkdir -m a+x -p %s;"
                " fi; touch %s; cat /dev/null > %s" % (self.tempFileDir,
                self.tempFileDir, tempShFile, tempShFile))
            if exitcode != 0:
                self.expansionSuccess[host] = False
                self.logger.debug("Failed to create temp file guc.sh.")
                self.logger.debug(exitcode)
                self.logger.debug(output)
                continue
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
            self.logger.debug(f"resultMap={resultMap}")
            self.logger.debug(f"outputCollect={outputCollect}")
            self.cleanSshToolFile(sshTool)
        self.logger.debug("Set guc result: {0}".format(self.expansionSuccess))
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "set guc")

    def get_add_float_ip_cmd(self, host_ip):
        """
        Get cmd for adding float IP to pg_hba.conf
        """
        if not self.context.clusterInfo.float_ips:
            self.logger.debug("The current cluster does not support VIP.")
            return ""

        cmd = ""
        name = self.context.backIpNameMap[host_ip]
        node = self.context.clusterInfo.getDbNodeByName(name)
        for inst in node.datanodes:
            for float_ip in inst.float_ips:
                ip_address = self.context.clusterInfo.float_ips[float_ip]
                # Check whether the IP address is ipv4 or ipv6 and obtain the corresponding mask length
                submask_length = NetUtil.get_submask_len(ip_address)
                cmd += " -h 'host    all    all    %s/%s    sha256'" % (ip_address, submask_length)
        return cmd

    def addTrust(self):
        """
        add authentication rules about new host ip in existing hosts and
        add authentication rules about other all hosts ip in new hosts
        """
        self.logger.debug("Start to set host trust on all node.")
        allHosts = list(self.existingHosts)
        for host in self.context.newHostList:
            if self.expansionSuccess[host]:
                allHosts.append(host)
        for hostExec in allHosts:
            hostExecName = self.context.backIpNameMap[hostExec]
            dataNode = self.context.clusterInfoDict[hostExecName]["dataNode"]
            cmd = "source %s;gs_guc set -D %s" % (self.envFile, dataNode)
            if hostExec in self.existingHosts:
                for hostParam in self.context.newHostList:
                    submask_length = NetUtil.get_submask_len(hostParam)
                    cmd += " -h 'host    all    %s    %s/%s    trust'" % (self.user, hostParam, submask_length)
                    cmd += self.get_add_float_ip_cmd(hostParam)
            else:
                for hostParam in allHosts:
                    if hostExec != hostParam:
                        submask_length = NetUtil.get_submask_len(hostParam)
                        cmd += " -h 'host    all    %s    %s/%s    trust'" % (self.user, hostParam, submask_length)
                        cmd += self.get_add_float_ip_cmd(hostParam)
            self.logger.debug("[%s] trustCmd:%s" % (hostExec, cmd))
            sshTool = SshTool([hostExec])
            sshTool.getSshStatusOutput(cmd, [hostExec], self.envFile)
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
        insType, _ = self.commonGsCtl.queryInstanceStatus(primaryHost,
            dataNode,self.envFile)
        if insType != MODE_PRIMARY:
            primaryHostIp = self.context.clusterInfoDict[primaryHost]["backIp"]
            needGRPCHosts.append(primaryHostIp)
        self.logger.debug("Start to generate GRPC cert.")
        if needGRPCHosts:
            self.context.initSshTool(needGRPCHosts, DefaultValue.TIMEOUT_PSSH_INSTALL)
            self.context.createGrpcCa(needGRPCHosts)
        self.logger.debug("End to generate GRPC cert.")

    def distributeCipherFile(self):
        """
        distribute cipher file to new host
        """
        hostList = []
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
                hostList.append(host)

        if len(hostList) == 0:
            return

        self.logger.debug("Start to distribute cipher file.")
        cipherFileList = ["datasource.key.cipher",
                      "datasource.key.rand",
                      "usermapping.key.cipher",
                      "usermapping.key.rand",
                      "subscription.key.cipher",
                      "subscription.key.rand"]

        sshTool = SshTool(hostList)
        appPath = self.context.clusterInfoDict["appPath"]
        filePath = os.path.join(appPath, "bin")
        for cipherFile in cipherFileList:
            scpFile = os.path.join(filePath, "%s" % cipherFile)
            self.logger.debug("try to send file: %s" % scpFile)
            if os.path.exists(scpFile):
                sshTool.scpFiles(scpFile, filePath, hostList)
        self.logger.debug("End to distribute cipher file.")

    def reloadPrimaryConf(self, user=""):
        """
        """
        primaryHost = self.getPrimaryHostName()
        dataNode = self.context.clusterInfoDict[primaryHost]["dataNode"]
        command = "source %s; gs_ctl reload -D %s " % (self.envFile, dataNode)
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
        walKeepSegmentsChanged = False
        status, synchronous_commit = self.commonGsCtl.queryGucParaValue(
            primaryHost, self.envFile, primaryDataNode, "synchronous_commit")
        if status != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50021"] % "synchronous_commit")
        if synchronous_commit == "off" and self.walKeepSegments < 1024:
            status = self.commonGsCtl.setGucPara(primaryHost, self.envFile, primaryDataNode,
                "wal_keep_segments", 1024)
            if status != DefaultValue.SUCCESS:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50007"] % "wal_keep_segments")
            walKeepSegmentsChanged = True
        self.reloadPrimaryConf()
        time.sleep(10)
        insType, dbState = self.commonGsCtl.queryInstanceStatus(
            primaryHost, primaryDataNode, self.envFile)
        primaryExceptionInfo = ""
        if insType != ROLE_PRIMARY:
            primaryExceptionInfo = ErrorCode.GAUSS_357["GAUSS_35709"] % \
                ("local_role", "primary", "primary")
        if dbState != STATE_NORMAL:
            primaryExceptionInfo = ErrorCode.GAUSS_357["GAUSS_35709"] % \
                ("db_state", "primary", "Normal")
        if primaryExceptionInfo != "":
            GaussLog.exitWithError(primaryExceptionInfo)
        waitChars = ["\\", "|", "/", "-"]
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
            else:
                buildMode = MODE_STANDBY
                hostRole = ROLE_STANDBY
            self.logger.log("Start to build %s %s." % (hostRole, host))
            self.checkTmpDir(hostName)
            # reset current standby's application name before started
            self.resetStandbyAppName(hostName=hostName, sshIp=host)
            self.reset_sync_standby_names(hostName, host)
            # start new host as standby mode
            self.commonGsCtl.stopInstance(hostName, dataNode, self.envFile)
            result, output = self.commonGsCtl.startInstanceWithMode(host,
                dataNode, MODE_STANDBY, self.envFile)
            if result[host] != DefaultValue.SUCCESS:
                if "Uncompleted build is detected" not in output:
                    self.expansionSuccess[host] = False
                    self.logger.log("Failed to start %s as standby "
                        "before building." % host)
                    continue
                else:
                    self.logger.debug("Uncompleted build is detected on %s." %
                        host)
            else:
                insType, dbState = self.commonGsCtl.queryInstanceStatus(
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
            self.logger.debug(resultMap)
            self.logger.debug(outputCollect)
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
                    self.logger.debug("Build %s complete." % host)
                    break
                timeFlush = 0.5
                for i in range(0, int(60 / timeFlush)):
                    index = i % 4
                    print("\rThe program is running {}".format(waitChars[index]), end="")
                    time.sleep(timeFlush)
            # check build result after build process finished
            while True:
                timeFlush = 0.5
                for i in range(0, int(60 / timeFlush)):
                    index = i % 4
                    print("\rThe program is running {}".format(waitChars[index]), end="")
                    time.sleep(timeFlush)
                insType, dbState = self.commonGsCtl.queryInstanceStatus(
                    hostName, dataNode, self.envFile)
                if dbState not in [STATE_STARTING, STATE_CATCHUP]:
                    self.logger.debug("%s starting and catchup complete." % host)
                    break
            insType, dbState = self.commonGsCtl.queryInstanceStatus(
                hostName, dataNode, self.envFile)
            if insType == hostRole and dbState == STATE_NORMAL:
                if self.context.newHostCasRoleMap[host] == "off":
                    existingStandbys.append(host)
                self.logger.log("\rBuild %s %s success." % (hostRole, host))
                # after current standby build successfully,
                # the minimum dn id has been used, so pop it from newInsIds
                self.newInsIds.pop(0)
            else:
                self.expansionSuccess[host] = False
                self.logger.log("\rBuild %s %s failed." % (hostRole, host))
        if walKeepSegmentsChanged:
            self.logger.debug("Start to rollback primary's wal_keep_segments")
            status = self.commonGsCtl.setGucPara(primaryHost, self.envFile, primaryDataNode,
                "wal_keep_segments", self.walKeepSegments)
            if status != DefaultValue.SUCCESS:
                self.logger.debug(ErrorCode.GAUSS_500["GAUSS_50007"] % "wal_keep_segments")
            self.reloadPrimaryConf()
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "build")

    def checkTmpDir(self, hostName):
        """
        if the tmp dir id not exist, create it.
        """
        tmpDir = os.path.realpath(EnvUtil.getTmpDirFromEnv())
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

    def is_rename_tblspc_dir(self, new_host, node_name, tblspc_path):
        """
        Rename tblspc dir.
        """
        paths = []
        for path, dir_lis, _ in os.walk(tblspc_path):
            for dir_name in dir_lis:
                paths.append(os.path.join(path, dir_name))
        
        if not paths:
            return
        
        sshTool = SshTool([new_host])
        for path in paths:
            cmd = "cd %s && find . -type d -iname 'PG_9.2*'" % path
            result_map, output_map = sshTool.getSshStatusOutput(cmd, [new_host], self.envFile)
            results = output_map.split("\n")
            res_dirs = [res for res in results if "PG" in res]
            for dir_name in res_dirs:
                if node_name not in dir_name:
                    old_pgxc_name = dir_name[dir_name.find("dn"):]
                    pgxc_dir_name = dir_name.replace(old_pgxc_name, node_name)
                    pgxc_cmd = "cd %s && if [ ! -d %s ]; then mkdir %s; fi && cp -r %s/. %s && rm -rf %s" % (
                                path, pgxc_dir_name, pgxc_dir_name, dir_name, pgxc_dir_name, dir_name)
                    res_map, _ = sshTool.getSshStatusOutput(pgxc_cmd, [new_host], self.envFile)
                    if res_map[new_host] != DefaultValue.SUCCESS:
                        self.logger.debug("Failed to rename tblspc directory.")
                        continue

    def check_tblspc_directory(self, pvalue):
        """
        Check tblspc_directory if exists.
        """
        if os.getuid() == 0:
            self.changeUser()
        pgdata_path = EnvUtil.getEnv("PGDATA")
        tblspc_path = pgdata_path + "/pg_tblspc"
        pg_port = EnvUtil.getEnv("PGPORT")
        if os.path.exists(tblspc_path):
            for host in self.context.newHostList:
                sql = "show pgxc_node_name;"
                gsql_cmd = "source %s; gsql -d postgres -p %s -A -t -c '%s'" % (self.envFile, pg_port, sql)
                sshTool = SshTool([host])
                result_map, output_collect = \
                    sshTool.getSshStatusOutput(gsql_cmd, [host], self.envFile)
                if result_map[host] != DefaultValue.SUCCESS:
                    self.logger.debug("Failed to get pgxc_node_name on new host %s" % host)
                    continue
                res_dict = self._parse_ssh_tool_output_collect(output_collect)
                pgxc_node_name = res_dict[host]
                self.is_rename_tblspc_dir(host, pgxc_node_name, tblspc_path)
        pvalue.value = 1

    def check_new_node_state(self, is_root_user):
        """
        Check new node state.
        """
        self.logger.log("Expansion results:")
        self.getExistingHosts(is_root_user)
        for newHost in self.context.newHostList:
            if newHost in self.existingHosts:
                self.logger.log("%s:\tSuccess" % newHost)
            else:
                self.logger.log("%s:\tFailed" % newHost)

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
            self.context.clusterInfo.setDbNodeInstancdIdByName(nodeName, self.context.clusterInfoDict[nodeName]["instanceId"])
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

        # valid if dynamic config file exists on primary node.
        dynamic_file = os.path.join(appPath, "bin", "cluster_dynamic_config")
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
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35710"] % srcFile)
            
            targetFile = "%s/bin/cluster_static_config" % appPath
            # if dynamic config file exists on primary node, refreshconf on each host.
            # if not, remove it on standby nodes if exists.
            dynamic_opt_cmd = ""
            if dynamic_file_exist:
                dynamic_opt_cmd = "gs_om -t refreshconf"
            else:
                dynamic_opt_cmd = "if [ -f '%s' ];then rm %s;fi" % \
                    (dynamic_file, dynamic_file)
                        
            if hostName != socket.gethostname():
                hostSsh = SshTool([hostName], timeout=300)
                hostSsh.scpFiles(srcFile, targetFile, [hostName], self.envFile)
                hostSsh.getSshStatusOutput(dynamic_opt_cmd, [hostName], self.envFile)
                self.cleanSshToolFile(hostSsh)
            else:
                scpcmd = "cp %s %s" % (srcFile, targetFile)
                (status, output) = subprocess.getstatusoutput(scpcmd)
                if status != 0:
                    GaussLog.exitWithError("Copy file faild. %s" % output)
                
        self.logger.log("End to generate and send cluster static file.")
        if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) > 0:
            self.logger.debug("Check new host state after restart.")
            return
        self.check_new_node_state(False)

    def getGUCConfig(self):
        """
        get guc config of each node:
            replconninfo[index]
        """
        clusterInfoDict = self.context.clusterInfoDict
        hostIpList = list(self.existingHosts)
        for host in self.expansionSuccess:
            if self.expansionSuccess[host]:
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
remoteservice={remoteservice}'"\
""".format(dn=localeHostInfo["dataNode"],
                    index=index,
                    localhost=localeHostInfo["backIp"],
                    localport=localeHostInfo["localport"],
                    localeHeartPort=localeHostInfo["heartBeatPort"],
                    localservice=localeHostInfo["localservice"],
                    remoteNode=remoteHostInfo["backIp"],
                    remotePort=remoteHostInfo["localport"],
                    remoteHeartPort=remoteHostInfo["heartBeatPort"],
                    remoteservice=remoteHostInfo["localservice"])

                if "remoteuwalhost" in remoteHostInfo:
                    # add uwal replconninfo
                    guc_repluwal_template = " remotenodeid=%d remoteuwalhost=%s remoteuwalport=%d" % \
                        (remoteHostInfo["remotenodeid"], remoteHostInfo["remoteuwalhost"], remoteHostInfo["remoteuwalport"])
                    guc_repl_template = guc_repl_template[:-2] + guc_repluwal_template + guc_repl_template[-2:] + "\n"
                    guc_tempate_str += guc_repl_template
                    
                    # add other config
                    uwal_id = localeHostInfo["localnodeid"]
                    uwal_ip = localeHostInfo["backIp"]
                    uwal_port = remoteHostInfo["remoteuwalport"]
                    uwal_config = "'{\\\"uwal_nodeid\\\": %d, \\\"uwal_ip\\\": \\\"%s\\\", \\\"uwal_port\\\": %d}'" % (uwal_id, uwal_ip, uwal_port)

                    guc_uwal_template = """\
                        gs_guc set -D {dn} -c "uwal_config={uwal_config_json}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_config_json=uwal_config)
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "enable_uwal={enable_uwal}"
                    """.format(dn=localeHostInfo["dataNode"],
                            enable_uwal=localeHostInfo["enable_uwal"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_disk_size={uwal_disk_size}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_disk_size=localeHostInfo["uwal_disk_size"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_devices_path={uwal_devices_path}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_devices_path=localeHostInfo["uwal_devices_path"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_log_path={uwal_log_path}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_log_path=localeHostInfo["uwal_log_path"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_rpc_compression_switch={uwal_rpc_compression_switch}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_rpc_compression_switch=localeHostInfo["uwal_rpc_compression_switch"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_rpc_flowcontrol_switch={uwal_rpc_flowcontrol_switch}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_rpc_flowcontrol_switch=localeHostInfo["uwal_rpc_flowcontrol_switch"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_rpc_flowcontrol_value={uwal_rpc_flowcontrol_value}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_rpc_flowcontrol_value=localeHostInfo["uwal_rpc_flowcontrol_value"])
                    guc_uwal_template += """\
                        gs_guc set -D {dn} -c "uwal_async_append_switch={uwal_async_append_switch}"
                    """.format(dn=localeHostInfo["dataNode"],
                            uwal_async_append_switch=localeHostInfo["uwal_async_append_switch"])
                    guc_tempate_str += guc_uwal_template
                    
                else:
                    guc_tempate_str += guc_repl_template + "\n"

                index += 1

            gucDict[hostName] = guc_tempate_str
        return gucDict

    def checkGaussdbAndGsomVersionOfStandby(self):
        """
        check whether gaussdb and gs_om version of standby are same with priamry
        """
        standbyHosts = list(self.context.newHostList)
        envFile = self.envFile
        if self.context.standbyLocalMode:
            for host in standbyHosts:
                self.expansionSuccess[host] = True
        self.logger.log("Checking gaussdb and gs_om version.")
        getGaussdbVersionCmd = "source %s;gaussdb --version" % envFile
        getGsomVersionCmd = "source %s;gs_om --version" % envFile
        gaussdbVersionPattern = re.compile("gaussdb \((.*)\) .*")
        gsomVersionPattern = re.compile("gs_om \(.*\) .*")
        primaryHostName = self.getPrimaryHostName()
        sshPrimary = SshTool([primaryHostName])
        resultMap, outputCollect = sshPrimary.getSshStatusOutput(
            getGaussdbVersionCmd, [], envFile)
        self.logger.debug(resultMap)
        self.logger.debug(outputCollect)
        if resultMap[primaryHostName] != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35707"] %
                ("gaussdb", "primary"))
        primaryGaussdbVersion = gaussdbVersionPattern.findall(outputCollect)[0]
        resultMap, outputCollect = sshPrimary.getSshStatusOutput(
            getGsomVersionCmd, [], envFile)
        self.logger.debug(resultMap)
        self.logger.debug(outputCollect)
        if resultMap[primaryHostName] != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35707"] %
                ("gs_om", "primary"))
        primaryGsomVersion = gsomVersionPattern.findall(outputCollect)[0]
        self.cleanSshToolFile(sshPrimary)

        failCheckGaussdbVersionHosts = []
        failCheckGsomVersionHosts = []
        wrongGaussdbVersionHosts = []
        wrongGsomVersionHosts = []
        for backIp in standbyHosts:
            if not self.expansionSuccess[backIp]:
                continue
            host = self.context.backIpNameMap[backIp]
            sshTool = SshTool([host])
            # get gaussdb version
            resultMap, outputCollect = sshTool.getSshStatusOutput(
                getGaussdbVersionCmd, [], envFile)
            self.logger.debug(resultMap)
            self.logger.debug(outputCollect)
            if resultMap[host] != DefaultValue.SUCCESS:
                self.expansionSuccess[host] = False
                failCheckGaussdbVersionHosts.append(host)
            else:
                gaussdbVersion = gaussdbVersionPattern.findall(outputCollect)[0]
                if gaussdbVersion != primaryGaussdbVersion:
                    self.expansionSuccess[host] = False
                    wrongGaussdbVersionHosts.append(host)
                    self.cleanSshToolFile(sshTool)
                    continue
            # get gs_om version
            resultMap, outputCollect = sshTool.getSshStatusOutput(
                getGsomVersionCmd, [], envFile)
            self.logger.debug(resultMap)
            self.logger.debug(outputCollect)
            if resultMap[host] != DefaultValue.SUCCESS:
                self.expansionSuccess[host] = False
                failCheckGsomVersionHosts.append(host)
            else:
                gsomVersion = gsomVersionPattern.findall(outputCollect)[0]
                if gsomVersion != primaryGsomVersion:
                    self.expansionSuccess[host] = False
                    wrongGsomVersionHosts.append(host)
            self.cleanSshToolFile(sshTool)
        if failCheckGaussdbVersionHosts:
            self.logger.log(ErrorCode.GAUSS_357["GAUSS_35707"] %
                ("gaussdb", ", ".join(failCheckGaussdbVersionHosts)))
        if failCheckGsomVersionHosts:
            self.logger.log(ErrorCode.GAUSS_357["GAUSS_35707"] %
                ("gs_om", ", ".join(failCheckGsomVersionHosts)))
        if wrongGaussdbVersionHosts:
            self.logger.log(ErrorCode.GAUSS_357["GAUSS_35708"] %
                ("gaussdb", ", ".join(wrongGaussdbVersionHosts)))
        if wrongGsomVersionHosts:
            self.logger.log(ErrorCode.GAUSS_357["GAUSS_35708"] %
                ("gs_om", ", ".join(wrongGsomVersionHosts)))
        self.logger.log("End to check gaussdb and gs_om version.")
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] %
                "check gaussdb and gs_om version")

    def preInstall(self):
        """
        preinstall on new hosts.
        """
        self.logger.log("Start to preinstall database on new nodes.")
        self.sendSoftToHosts()
        self.generateAndSendXmlFile()
        self.preInstallOnHosts()
        self.logger.log("End to preinstall database on new nodes.")
        if self._isAllFailed():
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35706"] % "preinstall")

    def clearTmpFile(self):
        """
        clear temporary file after expansion success
        """
        self.logger.debug("start to delete temporary file %s" % self.tempFileDir)
        clearCmd = "if [ -d '%s' ];then rm -rf %s;fi" % \
            (self.tempFileDir, self.tempFileDir)
        hosts = list(set(self.existingHosts + self.context.newHostList))
        try:
            sshTool = SshTool(hosts)
            result, output = sshTool.getSshStatusOutput(clearCmd,
                hosts, self.envFile)
            self.logger.debug(output)
            self.cleanSshToolFile(sshTool)
        except Exception as e:
            self.logger.debug(str(e))
            self.cleanSshToolFile(sshTool)
        

    def cleanSshToolFile(self, sshTool):
        """
        """
        try:
            sshTool.clen_ssh_result_files()
        except Exception as e:
            self.logger.debug(str(e))

    def guc_executor(self, ssh_tool, guc_command, host_name):
        """
        Execute gs_guc command
        """
        current_time = str(datetime.datetime.now()).replace(" ", "_").replace(
            ".", "_")
        temp_file_dir = "/tmp/gs_expansion_%s" % (current_time)
        temp_sh_file = os.path.join(temp_file_dir, "guc.sh")
        command = "source %s ; %s" % (self.envFile, guc_command)
        self.logger.debug("[%s] ready to run guc command is:%s" % (host_name, command))
        # create temporary dir to save guc command bashfile.
        try:
            mkdir_cmd = "mkdir -m a+x -p %s; chown %s:%s %s" % \
                        (temp_file_dir, self.user, self.group, temp_file_dir)
            ssh_tool.getSshStatusOutput(mkdir_cmd, hostList=[host_name],
                                             env_file=self.envFile)
            local_create_file_cmd = "if [ ! -e '{0}' ]; then mkdir -m a+x -p {0};" \
                                    "fi; touch {0}; cat /dev/null > {0}; " \
                                    "chown {1}:{2} {0}".format(temp_file_dir,
                                                               self.user, self.group)
            status, output = subprocess.getstatusoutput(local_create_file_cmd)
            if status != 0:
                self.logger.debug("Failed to create temp file guc.sh.")
                self.logger.debug("guc command result status: {0}".format(status))
                self.logger.debug("guc command result output: {0}".format(output))
                raise Exception(ErrorCode.GAUSS_535["GAUSS_53506"])
            with os.fdopen(os.open("%s" % temp_sh_file, os.O_WRONLY | os.O_CREAT,
                                   stat.S_IWUSR | stat.S_IRUSR), 'w') as fo:
                fo.write("#bash\n")
                fo.write(command)
                fo.close()

            # send guc command bashfile to each host and execute it.
            if socket.gethostname() != host_name:
                ssh_tool.scpFiles("%s" % temp_sh_file, "%s" % temp_sh_file, [host_name],
                                       self.envFile)
                result_map, output_collect = \
                    ssh_tool.getSshStatusOutput("sh %s" % temp_sh_file,
                                                     hostList=[host_name], env_file=self.envFile)
                self.logger.debug("Execute gs_guc command output: {0}".format(output_collect))
                if [fail_flag for fail_flag in result_map.values() if not fail_flag]:
                    self.logger.debug("Execute gs_guc command failed. "
                                      "result_map is : {0}".format(result_map))
                    raise Exception(ErrorCode.GAUSS_535["GAUSS_53507"] % command)
            else:
                status, output = subprocess.getstatusoutput("sh %s" % temp_sh_file)
                if status != 0:
                    self.logger.debug("Local execute gs_guc command failed. "
                                      "output is : {0}".format(output))
                    raise Exception(ErrorCode.GAUSS_535["GAUSS_53507"] % command)
        except Exception as exp:
            raise Exception(str(exp))
        finally:
            ssh_tool.getSshStatusOutput(
                g_file.SHELL_CMD_DICT["deleteDir"] % (temp_file_dir, temp_file_dir),
                hostList=[host_name])
    
    def checkNodesDetail(self):
        """
        """
        self.checkNetworkDelay()
        self.checkUserAndGroupExists()
        self.checkXmlFileAccessToUser()
        self.checkClusterStatus()
        self.validNodeInStandbyList()
        self.checkXMLConsistency()
        self.checkDnDirEmpty()

    def checkNetworkDelay(self):
        """
        check if network delay greater than 1000ms
        """
        backips = self.context.newHostList
        ping_tool = CmdUtil.get_ping_tool()
        for backip in backips:
            ck_net_delay = "%s -s 8192 -c 5 -i 0.3 %s | "\
                    "awk -F / '{print $5}'| awk '{print $1}'" % (ping_tool, backip)
            (status, output) = subprocess.getstatusoutput(ck_net_delay)
            if status == 0:
                try:
                    delay_val = float(output.strip())
                    # if delay greater than 1000ms, it need to warn.
                    if delay_val > 1000:
                        self.logger.warn("[WARNING] The node[%s] has a high "\
                            "latency[%s ms]." % (backip, delay_val))
                except ValueError: 
                    self.logger.debug("The node[%s] failed to query\
                         the delay" % backip)


    def checkDnDirEmpty(self):
        """
        Check whether datanode dir is empty on new nodes.
        If not empty, we assume that the datanode directory exists 
        with other database. We should exit and check it.
        """
        if self.context.standbyLocalMode:
            return
        excepNodes = []
        for node in self.context.newHostList:
            nodename = self.context.backIpNameMap[node]
            dn_dir = self.context.clusterInfoDict[nodename]["dataNode"]
            cmd = """
            if [ ! -d "%s" ]; then echo ""; else ls %s; fi;
            """ % (dn_dir,dn_dir)
            sshTool = SshTool([node])
            (statusMap, output) = sshTool.getSshStatusOutput(cmd, 
                env_file="/etc/profile")
            if statusMap[node] == DefaultValue.SUCCESS:
                prefix = '[%s] %s:' % ("SUCCESS", node)
                result = output[len(prefix):]
                if result.strip():
                    excepNodes.append(node)
        if len(excepNodes) > 0:
            self.logger.log("The datanode dir of [%s] is not empty.\
                 Please check it." % ",".join(excepNodes))
            sys.exit(1)
        self.logger.debug("Successfully Check datanode dir is empty.")


    def checkXMLConsistency(self):
        """
        Check whether XML information is consistent with cluster information
        """
        self.logger.debug("Checking whether XML information is "
            "consistent with cluster information")
        self._checkDataNodes()
        self._checkAvailableZone()

    def _checkDataNodes(self):
        """
        check datanodes
        """
        self.logger.debug("Checking the consistence of datanodes.")
        primary_name = self.getPrimaryHostName()
        cmd = "source %s;gs_om -t status --detail" % (self.envFile)
        cmd = CmdUtil.get_user_exec_cmd(self.context.current_user_root, self.user, cmd)
        ssh_tool = SshTool([primary_name])
        result_map, output_collect = ssh_tool.getSshStatusOutput(cmd,
            [primary_name], self.envFile)
        self.logger.debug(f"resultMap={result_map}")
        self.logger.debug(f"outputCollect={output_collect}")
        if result_map[primary_name] != DefaultValue.SUCCESS:
            GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51600"])
        self.cleanSshToolFile(ssh_tool)
        node_states = str(output_collect).splitlines()
        data_nodes = {}
        pattern = re.compile(r"[ ]+[^ ]+[ ]+((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[0-9a-fA-F:]+))[ ]+[^ ]+[ ]+[^ ]+[ ]+([^ ]+)[ ]+")
        for node_state in node_states:
            result = pattern.findall(node_state.strip())
            if result:
                data_nodes[result[0][0]] = result[0][1]
        clusterInfoDict = self.context.clusterInfoDict
        backIpNameMap = self.context.backIpNameMap
        for hostIp in self.existingHosts:
            host_name = backIpNameMap[hostIp]
            data_node = clusterInfoDict[host_name]["dataNode"]
            if data_node != data_nodes.get(hostIp):
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35711"] %
                    ("dataNode of %s" % hostIp))

    def _checkAvailableZone(self):
        """
        check available_zone
        """
        self.logger.debug("Checking the consistence of azname")
        clusterInfoDict = self.context.clusterInfoDict
        backIpNameMap = self.context.backIpNameMap
        hostAzNameMap = self.context.hostAzNameMap
        primary = self.getPrimaryHostName()
        for hostIp in self.existingHosts:
            hostName = backIpNameMap[hostIp]
            if hostName == primary:
                continue
            dataNode = clusterInfoDict[hostName]["dataNode"]
            cmd = "source /etc/profile;source %s;" \
                      "gs_guc check -D %s -c \"available_zone\"" % \
                      (self.envFile, dataNode)
            cmd = CmdUtil.get_user_exec_cmd(self.context.current_user_root, self.user, cmd)
            sshTool = SshTool([hostIp])
            resultMap, output = sshTool.getSshStatusOutput(cmd,
                [hostIp], self.envFile)
            self.logger.debug(f"{cmd} resultMap={resultMap}")
            self.logger.debug(f"{cmd} output={output}")
            if resultMap[hostIp] != DefaultValue.SUCCESS:
                GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51600"])
            self.cleanSshToolFile(sshTool)
            azPattern = re.compile("available_zone='(.*)'")
            azName = azPattern.findall(output)
            if len(azName) != 0:
                azName = azName[0]
            if azName != hostAzNameMap[hostIp]:
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35711"] %
                    ("azName of %s" % hostIp))

    def checkClusterStatus(self):
        """
        Check whether the cluster status is normal before expand.
        """
        self.logger.debug("Start to check cluster status.")

        curHostName = socket.gethostname()
        command = "source %s; gs_om -t status --detail" % (self.envFile)
        command = CmdUtil.get_user_exec_cmd(self.context.current_user_root, self.user, command)
        sshTool = SshTool([curHostName])
        resultMap, outputCollect = sshTool.getSshStatusOutput(command,
            [curHostName], self.envFile)
        self.logger.debug(f"{command} resultMap={resultMap}")
        self.logger.debug(f"{command} outputCollect={outputCollect}")
        self.cleanSshToolFile(sshTool)
        if outputCollect.find("Primary Normal") == -1:
            GaussLog.exitWithError((ErrorCode.GAUSS_357["GAUSS_35709"] %
                ("status", "primary", "Normal")) + "\nExpansion failed.")

        self.logger.debug("The primary database is normal.\n")
        currentWalKeepSegments = self.queryPrimaryWalKeepSegments()
        if currentWalKeepSegments != "NULL":
            self.walKeepSegments = int(currentWalKeepSegments)
        else:
            self.walKeepSegments = 16
    
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
        elif self.context.current_user_root:
            self.logger.debug(ErrorCode.GAUSS_501["GAUSS_50100"]
                 % (xmlFile, self.user))
            os.chown(xmlFile, uid, gid)
            os.chmod(xmlFile, stat.S_IRUSR)
        else:
            GaussLog.exitWithError(ErrorCode.GAUSS_501["GAUSS_50100"]
                 % (xmlFile, self.user))

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
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35712"]
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

        # newInsIds indicates unused dn id list
        self.newInsIds = self.getIncreaseAppNames(len(self.context.newHostList))
        if not self.context.standbyLocalMode:
            self.logger.log("Start to install database on new nodes.")
            self.installDatabaseOnHosts()
        self.logger.log("Database on standby nodes installed finished.")
        self.checkGaussdbAndGsomVersionOfStandby()
        self.logger.log("Start to establish the relationship.")
        self.buildStandbyRelation()
        self.send_hosts_file_to_remote_nodes()
        # process success
        pvalue.value = 1
    
    def rollback(self):
        """
        rollback all hosts' replconninfo about failed hosts
        """
        self.getExistingHosts()
        failedHosts = list(set(self.context.newHostList) - set(self.existingHosts))
        clusterInfoDict = self.context.clusterInfoDict
        for failedHost in failedHosts:
            # rollback GRPC cert on failed hosts
            self.logger.debug("Start to rollback GRPC cert of %s" % failedHost)
            appPath = ClusterDir.getInstallDir(self.user)
            removeGRPCCertCmd = "ls %s/share/sslcert/grpc/* | grep -v openssl.cnf | " \
                "xargs rm -rf" % appPath
            sshTool = SshTool([failedHost])
            sshTool.getSshStatusOutput(removeGRPCCertCmd, [failedHost])
            self.cleanSshToolFile(sshTool)
            for host in self.expansionSuccess:
                if not self.expansionSuccess[host]:
                    sshTool = SshTool([host])
                    sshTool.getSshStatusOutput(removeGRPCCertCmd, [host], self.envFile)
                    self.cleanSshToolFile(sshTool)
            self.logger.debug("Start to rollback replconninfo about %s" % failedHost)
            for host in self.existingHosts:
                dataNode = clusterInfoDict[self.context.backIpNameMap[host]]["dataNode"]
                confFile = os.path.join(dataNode, "postgresql.conf")
                rollbackReplconninfoCmd = "sed -i '/remotehost=%s/s/^/#&/' %s" \
                    % (failedHost, confFile)
                self.logger.debug("[%s] rollbackReplconninfoCmd:%s" % (host,
                    rollbackReplconninfoCmd))
                sshTool = SshTool([host])
                sshTool.getSshStatusOutput(rollbackReplconninfoCmd, [host])
                rollbackPg_hbaCmd = "sed -i '/%s/s/^/#&/' %s" \
                    % (failedHost, os.path.join(dataNode, "pg_hba.conf"))
                self.logger.debug("[%s] rollbackPg_hbaCmd:%s" % (host,
                    rollbackPg_hbaCmd))
                sshTool.getSshStatusOutput(rollbackPg_hbaCmd, [host])
                reload_guc_command = "source %s; gs_ctl reload " \
                        "-D %s" % (self.envFile, dataNode)
                reload_guc_command = CmdUtil.get_user_exec_cmd(self.context.current_user_root, self.user, reload_guc_command)
                self.logger.debug(reload_guc_command)
                resultMap, outputCollect = sshTool.getSshStatusOutput(
                    reload_guc_command, [host], self.envFile)
                self.logger.debug(resultMap)
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

    def _parse_ssh_tool_output_collect(self, collect_result_str):
        """
        Parse SshTool getSshStatusOutput method result
        """
        self.logger.debug("Start parse SshTool output collect result.")
        collect_result_list = collect_result_str.split("\n")
        # node_name_str like this : [[SUCCESS] pekpomdev00006:
        key_list = [node_name_str.split()[-1].strip(":")
                    for node_name_str in collect_result_list[::2] if node_name_str]
        # gsql version display like (gsql (openGauss x.x.0 build xxxxxxx)
        # compiled at 2029-02-26 02:07:00 commit 0 last mr xxxx)
        value_list = [output_str.split(")")[0].split()[-1]
                      for output_str in collect_result_list[1::2] if output_str]
        parse_result = dict(zip(key_list, value_list))
        self.logger.debug("Parse result is: {0}".format(parse_result))
        return parse_result
    
    def send_hosts_file_to_remote_nodes(self):
        """
        send hosts file to remote node
        """
        static_cluster_info = dbClusterInfo()
        static_cluster_info.initFromStaticConfig(self.user)
        node_names = static_cluster_info.getClusterNodeNames()
        # GPHOME path
        gp_home = os.environ.get("GPHOME")
        hosts_file1 = os.path.normpath(os.path.join(gp_home, "hosts"))
        hosts_dir1 = os.path.dirname(hosts_file1)
        # gauss_om path
        user_home = os.path.expanduser(f"~{self.user}")
        gauss_om = os.path.normpath(os.path.join(user_home, "gauss_om"))
        hosts_file2 = os.path.join(gauss_om, "hosts")
        hosts_dir2 = os.path.dirname(hosts_file2)

        node_names.remove(NetUtil.GetHostIpOrName())
        ssh_tool = SshTool(node_names)
        self.send_file_common(node_names, hosts_file1, hosts_dir1, ssh_tool)
        self.send_file_common(node_names, hosts_file2, hosts_dir2, ssh_tool)
        ssh_tool.clen_ssh_result_files()

    def send_file_common(self, names, hosts_file, hosts_dir, ssh_tool):
        cmd = "(if [ -f '%s' ]; then rm -f '%s';fi)" % (hosts_file, hosts_file)
        ssh_tool.executeCommand(cmd)
        ssh_tool.scpFiles(hosts_file, hosts_dir, names)
        cmd = CmdUtil.getChmodCmd(str(DefaultValue.HOSTS_FILE), hosts_file)
        ssh_tool.executeCommand(cmd)
        cmd = CmdUtil.getChownCmd(self.user, self.group, hosts_file)
        ssh_tool.executeCommand(cmd)
    
    def transmit_upgrade_record(self):
        """
        sends the upgrade record file to the expansion nodes to ensure that records are not lost after scaling. 
        """
        omPath = EnvUtil.getEnv("GPHOME")
        upgradeRecord = os.path.join(omPath, "upgradeRecord.txt")
        if not os.path.exists(upgradeRecord):
            return
        sshTool = SshTool(self.context.newHostList)
        sshTool.scpFiles(upgradeRecord, upgradeRecord, self.context.newHostList)
        

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
        # transmit upgrade records
        self.transmit_upgrade_record()



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
        sshTool = SshTool([host])
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
            GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51600"] +
                "Please check the cluster status or source the environmental"
                " variables of user [%s]." % self.user)
        self.cleanSshToolTmpFile(sshTool)
        return outputCollect

    def queryGucParaValue(self, host, env, datanode, para, user=""):
        """
        query guc parameter value
        """
        value = ""
        command = ""
        if os.getuid() == 0 and user:
            command = "su - %s -c 'source %s; gs_guc check -D %s -c \"%s\"'" % \
                (user, env, datanode, para)
        else:
            command = "source %s; gs_guc check -D %s -c \"%s\"" % \
                (env, datanode, para)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(
            command, [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        if resultMap[host] == STATUS_FAIL:
            return resultMap[host], ""
        self.cleanSshToolTmpFile(sshTool)
        paraPattern = re.compile("    %s=(.+)" % para)
        value = paraPattern.findall(outputCollect)
        if len(value) != 0:
            value = value[0]
        else:
            value = "NULL"
        return resultMap[host], value

    def setGucPara(self, host, env, datanode, para, value, user=""):
        """
        set guc parameter
        """
        command = ""
        if not user:
            command = "source %s; gs_guc set -D %s -c \"%s=%s\"" % \
                (env, datanode, para, value)
        else:
            command = "su - %s -c 'source %s; gs_guc set -D %s -c \"%s=%s\"'" % \
                (user, env, datanode, para, value)
        sshTool = SshTool([host])
        resultMap, outputCollect = sshTool.getSshStatusOutput(
            command, [host], env)
        self.logger.debug(host)
        self.logger.debug(outputCollect)
        self.cleanSshToolTmpFile(sshTool)
        return resultMap[host]

    def cleanSshToolTmpFile(self, sshTool):
        """
        """
        try:
            sshTool.clen_ssh_result_files()
        except Exception as e:
            self.logger.debug(str(e))