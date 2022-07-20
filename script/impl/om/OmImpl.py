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
# Description  : gs_om is a utility to manage a Gauss200 cluster.
#############################################################################

import subprocess
import os
import sys
import pwd

from datetime import datetime

sys.path.append(sys.path[0] + "/../../../")
from gspylib.common.DbClusterInfo import dbClusterInfo, queryCmd
from gspylib.threads.SshTool import SshTool
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue, ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.os.gsfile import g_file
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.compress_util import CompressUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.user_util import UserUtil
from base_utils.common.constantsbase import ConstantsBase

# Cert
EMPTY_CERT = "emptyCert"


###########################################
class OmImpl:
    """
    init the command options
    save command line parameter values
    """

    def __init__(self, OperationManager):
        """
        function: constructor
        """
        # global
        self.context = OperationManager
        self.logger = OperationManager.logger
        self.user = OperationManager.user
        self.newClusterInfo = None
        self.oldClusterInfo = None
        self.utilsPath = None
        self.mpprcFile = ""
        self.nodeId = OperationManager.g_opts.nodeId
        self.time_out = OperationManager.g_opts.time_out
        self.mode = OperationManager.g_opts.mode
        self.clusterInfo = OperationManager.clusterInfo
        self.dataDir = OperationManager.g_opts.dataDir
        self.sshTool = None

    def doStopCluster(self):
        """
        function: do stop cluster
        input: NA
        output: NA
        """
        pass

    def doStart(self):
        """
        function:Start cluster or node
        input:NA
        output:NA
        """
        self.doStartCluster()

    def doStop(self):
        """
        function:Stop cluster or node
        input:NA
        output:NA
        """
        self.logger.debug("Operating: Stopping.")
        self.doStopCluster()

    def getNodeStatus(self, nodename):
        """
        function: get node status
        input: nodename
        output: NA
        """
        try:
            # Create a temporary file to save cluster status
            tmpDir = EnvUtil.getTmpDirFromEnv()
            tmpFile = os.path.join(tmpDir, "gauss_cluster_status.dat_" + \
                                   str(datetime.now().strftime(
                                       '%Y%m%d%H%M%S')) + "_" + str(
                os.getpid()))

            # Perform the start operation
            # Writes the execution result to a temporary file
            cmd = ClusterCommand.getQueryStatusCmd("", tmpFile, True)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                self.logger.debug("The cmd is %s " % cmd)
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % \
                                cmd + "Error: \n%s" % output)

            # Initialize cluster status information for the temporary file
            clusterStatus = DbClusterStatus()
            clusterStatus.initFromFile(tmpFile)

            # Get node status
            nodeStatusInfo = None
            for dbNode in clusterStatus.dbNodes:
                if (dbNode.name == nodename):
                    nodeStatusInfo = dbNode
            if (nodeStatusInfo and nodeStatusInfo.isNodeHealthy()):
                nodeStatus = clusterStatus.OM_NODE_STATUS_NORMAL
            else:
                nodeStatus = clusterStatus.OM_NODE_STATUS_ABNORMAL

            FileUtil.cleanTmpFile(tmpFile)
            return nodeStatus
        except Exception as e:
            FileUtil.cleanTmpFile(tmpFile)
            self.logger.debug(
                "Failed to get node status. Error: \n%s." % str(e))
            return "Abnormal"

    def getQueryStatusByCm(self, nodeId):
        """
        function: query status by cm
        :param nodeId:
        :return:
        """
        # Call cm_ctl to query the cluster status
        get_cluster_status_cmd = ClusterCommand.getQueryStatusCmdForDisplay(
                                nodeId,
                                self.context.g_opts.outFile,
                                self.context.clusterInfo.clusterType,
                                self.context.g_opts.show_detail,
                                self.context.g_opts.showAll)

        if self.context.g_opts.outFile != "":
            get_cluster_status_cmd += "&& chmod %s '%s'" % (
            DefaultValue.KEY_FILE_MODE, self.context.g_opts.outFile)
        # Call cm_ctl to query the cluster status
        (status, output) = subprocess.getstatusoutput(get_cluster_status_cmd)
        if status != 0:
            if not(status == 255 and "Down" in output):
                raise Exception(ErrorCode.GAUSS_516[
                                    "GAUSS_51600"] + "\nCommand:%s\nError: \n%s" % (
                                    get_cluster_status_cmd, output))
        node_status_line = ""
        if self.context.g_opts.nodeName != "":
            node_status = self.getNodeStatus(self.context.g_opts.nodeName)
            node_status_line = "node_state                : %s\n\n" % node_status + \
                    "-----------------------------------------------------------------------\n"

        # Outputs the check result if no output file is specified
        if self.context.g_opts.outFile == "":
            if status == 0 and self.context.g_opts.show_detail:
                temp_lines = output.splitlines()
                node_head = temp_lines[-3].split("|")[0]
                node_split = "-" * len(node_head)
                node_info = [info.strip() for info in temp_lines[-1].split("|")]
                self.logger.log("\n".join(temp_lines[:-3] + [node_head] + [node_split] +
                                          node_info))
            else:
                self.logger.log(output)
            if node_status_line:
                self.logger.log(node_status_line)
        else:
            if node_status_line:
                FileUtil.createFileInSafeMode(self.context.g_opts.outFile)
                with open(self.context.g_opts.outFile, "a") as fp:
                    fp.write(node_status_line)
                    fp.write(os.linesep)
                    fp.flush()
                    fp.close()
            self.logger.log("Status check is completed.")

    def getQueryStatusWithoutCm(self, nodeId=0, sshtool=None, hostName=""):
        """
        function:query status without cm
        :param nodeId:
        :param sshtool:
        :param hostName:
        :return:
        """
        cmd = queryCmd()
        if self.context.g_opts.outFile != "":
            cmd.outputFile = self.context.g_opts.outFile
        else:
            cmd.outputFile = self.logger.logFile
        if self.context.g_opts.show_detail:
            if (self.context.clusterInfo.clusterType
                    == DefaultValue.CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY):
                cmd.dataPathQuery = True
                cmd.azNameQuery = True
            else:
                cmd.dataPathQuery = True
        else:
            if nodeId > 0:
                self.context.clusterInfo.queryNodeInfo(sshtool, hostName,
                                                       nodeId, cmd.outputFile)
                return
            az_name = self.context.g_opts.azName
            if az_name:
                self.context.clusterInfo.queryNodeInfo(sshtool, hostName,
                                                       nodeId, cmd.outputFile, az_name)
                return
            if self.context.g_opts.showAll:
                self.context.clusterInfo.queryNodeInfo(sshtool, hostName,
                                                       nodeId, cmd.outputFile)
                return
            cmd.clusterStateQuery = True
        db_nums = len(self.context.clusterInfo.dbNodes)
        ssh_tools = []
        for _ in range(db_nums - 1):
            ssh_tools.append(SshTool([], timeout=self.time_out))
        self.context.clusterInfo.queryClsInfo(hostName, ssh_tools,
                                              self.context.mpprcFile, cmd)
    def doStatus(self):
        """
        function:Get the status of cluster or node
        input:NA
        output:NA
        """
        host_name = NetUtil.GetHostIpOrName()
        sshtool = SshTool(self.context.clusterInfo.getClusterNodeNames(), timeout=self.time_out)
        node_id = 0
        if self.context.g_opts.nodeName != "":
            for db_node in self.context.clusterInfo.dbNodes:
                if db_node.name == self.context.g_opts.nodeName:
                    node_id = db_node.id
            if node_id == 0:
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51619"]
                    % self.context.g_opts.nodeName)
        if ((not self.context.clusterInfo.hasNoCm())
            and DefaultValue.isgreyUpgradeNodeSpecify(self.context.user,
            DefaultValue.GREY_UPGRADE_STEP_UPGRADE_PROCESS, None, self.context.logger)):
            self.getQueryStatusByCm(node_id)
        else:
            self.getQueryStatusWithoutCm(node_id, sshtool, host_name)
        self.logger.debug("Successfully obtained the cluster status.")

    def change_cluster_info(self):
        temp_change_dic = {}
        for i in range(0, len(self.context.g_opts.old_values)):
            temp_change_dic['90123456789%d' % i] = (self.context.g_opts.old_values[i],
                                                    self.context.g_opts.new_values[i])
        # change old value to middle value
        for key, value in temp_change_dic.items():
            for node in self.context.clusterInfo.dbNodes:
                self.change_node_info(node, key, value[0])
                for inst in node.datanodes:
                    self.change_inst_info(inst, key, value[0])
        # change middle value to new value
        for key, value in temp_change_dic.items():
            for node in self.context.clusterInfo.dbNodes:
                self.change_node_info(node, value[1], key)
                for inst in node.datanodes:
                    self.change_inst_info(inst, value[1], key)

    def change_node_info(self, node, new_value, old_value):
        if node.name == old_value:
            node.name = new_value
        for i in range(len(node.backIps)):
            if node.backIps[i] == old_value:
                node.backIps[i] = new_value
        for i in range(len(node.virtualIp)):
            if node.virtualIp[i] == old_value:
                node.virtualIp[i] = new_value
        for i in range(len(node.sshIps)):
            if node.sshIps[i] == old_value:
                node.sshIps[i] = new_value
        self.logger.debug("Change the info of node %s successfully." % node.name)

    def change_inst_info(self, inst, new_value, old_value):
        if inst.hostname == old_value:
            inst.hostname = new_value
        if str(inst.port) == old_value:
            inst.port = int(new_value)
        if str(inst.haPort) == old_value:
            inst.haPort = int(new_value)
        for i in range(len(inst.listenIps)):
            if inst.listenIps[i] == old_value:
                inst.listenIps[i] = new_value
        for i in range(len(inst.haIps)):
            if inst.haIps[i] == old_value:
                inst.haIps[i] = new_value
        self.logger.debug("Change the DN inst on %s successfully." % inst.hostname)

    def doRebuildConf(self):
        """
        generating static configuration files for all nodes
        input:NA
        output:NA
        """
        try:
            self.logger.log(
                "Generating static configuration files for all nodes.")
            tmpDirName = ""
            # Initialize the cluster information according to the XML file
            self.context.clusterInfo = dbClusterInfo()
            if self.context.g_opts.old_values:
                self.context.clusterInfo.initFromStaticConfig(self.context.user)
                self.change_cluster_info()
            else:
                self.context.clusterInfo.initFromXml(self.context.g_opts.confFile)

            # 1.create a tmp dir
            self.logger.log(
                "Creating temp directory to store static configuration files.")
            dirName = os.path.dirname(os.path.realpath(__file__))
            tmpDirName = os.path.realpath(
                "%s/../../static_config_files" % dirName)
            cmd = "mkdir -p -m %s '%s'" % (
                DefaultValue.KEY_DIRECTORY_MODE, tmpDirName)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50208"]
                    % "temporary directory" + "\nCommand:%s\nError: %s"
                    % (cmd, output))
            self.logger.log("Successfully created the temp directory.")

            # create static files
            self.logger.log("Generating static configuration files.")
            for dbNode in self.context.clusterInfo.dbNodes:
                staticConfigPath = "%s/cluster_static_config_%s" % (
                    tmpDirName, dbNode.name)
                self.context.clusterInfo.saveToStaticConfig(staticConfigPath,
                                                            dbNode.id)
            self.logger.log(
                "Successfully generated static configuration files.")
            self.logger.log(
                "Static configuration files for all nodes are saved in %s."
                % tmpDirName)

            # check if need send static config files
            if not self.context.g_opts.distribute:
                self.logger.debug(
                    "No need to distribute static configuration files "
                    "to installation directory.")
                return

            # distribute static config file
            self.logger.log(
                "Distributing static configuration files to all nodes.")
            for dbNode in self.context.clusterInfo.dbNodes:
                if (dbNode.name != NetUtil.GetHostIpOrName()):
                    cmd = \
                        "pscp -H %s '%s'/cluster_static_config_%s '%s'" \
                        "/bin/cluster_static_config" % (
                            dbNode.name, tmpDirName,
                            dbNode.name, self.context.clusterInfo.appPath)
                else:
                    cmd = \
                        "cp '%s'/cluster_static_config_%s '%s'" \
                        "/bin/cluster_static_config" % (
                            tmpDirName,
                            dbNode.name, self.context.clusterInfo.appPath)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50216"]
                        % "static configuration file"
                        + "Node: %s.\nCommand: \n%s\nError: \n%s"
                        % (dbNode.name, cmd, output))
            self.logger.log(
                "Successfully distributed static configuration files.")

        except Exception as e:
            FileUtil.removeDirectory(tmpDirName)
            raise Exception(str(e))

    ##########################################################################
    # doReplaceSSLCert start
    ##########################################################################
    def doReplaceSSLCert(self):
        """
        function: replace ssl cert files
        input: NA
        output: NA
        """
        try:
            # Initialize the cluster information according to the xml file
            self.context.clusterInfo = dbClusterInfo()
            self.context.clusterInfo.initFromStaticConfig(
                UserUtil.getPathOwner(self.context.g_opts.certFile)[0])
            self.sshTool = SshTool(
                self.context.clusterInfo.getClusterNodeNames(),
                self.logger.logFile)
        except Exception as e:
            raise Exception(str(e))

        try:
            self.logger.log("Starting ssl cert files replace.", "addStep")
            tempDir = os.path.join(EnvUtil.getTmpDirFromEnv(),
                                   "tempCertDir")

            # unzip files to temp directory
            if (os.path.exists(tempDir)):
                FileUtil.removeDirectory(tempDir)
            FileUtil.createDirectory(tempDir, True,
                                   DefaultValue.KEY_DIRECTORY_MODE)
            CompressUtil.decompressZipFiles(self.context.g_opts.certFile, tempDir)

            realCertList = DefaultValue.CERT_FILES_LIST
            clientCertList = DefaultValue.CLIENT_CERT_LIST
            # check file exists
            for clientCert in clientCertList:
                sslFile = os.path.join(tempDir, clientCert)
                if (not os.path.isfile(sslFile)):
                    raise Exception(
                        (ErrorCode.GAUSS_502["GAUSS_50201"] % sslFile) + \
                        "Missing SSL client cert file in ZIP file.")

            certList = []
            dnDict = self.getDnNodeDict()
            for cert in realCertList:
                sslFile = os.path.join(tempDir, cert)

                if (not os.path.isfile(
                        sslFile) and cert != DefaultValue.SSL_CRL_FILE):
                    raise Exception(
                        (ErrorCode.GAUSS_502["GAUSS_50201"] % sslFile) + \
                        "Missing SSL server cert file in ZIP file.")
                if (os.path.isfile(sslFile)):
                    certList.append(cert)

            # distribute cert files to datanodes
            self.doDNBackup()
            self.distributeDNCert(certList, dnDict)

            # clear temp directory
            FileUtil.removeDirectory(tempDir)
            if (not self.context.g_opts.localMode):
                self.logger.log(
                    "Successfully distributed cert files on all nodes.")
        except Exception as e:
            FileUtil.removeDirectory(tempDir)
            raise Exception(str(e))

    def isDnEmpty(self, nodeName=""):
        """
        function: Is there exists empty file in dbnodes directory.
        input: node name
        output: True/False
        """
        allDnNodeDict = self.getDnNodeDict()
        nodeDnDir = allDnNodeDict[nodeName]
        emptyCert = os.path.join(nodeDnDir, EMPTY_CERT)
        status = self.sshTool.checkRemoteFileExist(
            nodeName, emptyCert,
            self.context.g_opts.mpprcFile)
        return status

    def doDNBackup(self):
        """
        function: backup SSL cert files on single_inst cluster.
        input: backupFlag is a flag of exist DB in node
        output: NA
        """
        self.logger.log("Backing up old ssl cert files.")

        backupList = DefaultValue.CERT_FILES_LIST[:]
        allDnNodeDict = self.getDnNodeDict()
        normalNodeList = []

        tarBackupList = []
        if (self.context.g_opts.localMode):
            self.logger.debug("Backing up database node SSL cert files.")
            nodeDnDir = allDnNodeDict[NetUtil.GetHostIpOrName()]
            backupFlagFile = os.path.join(nodeDnDir, "certFlag")
            if (os.path.isfile(backupFlagFile)):
                self.logger.log("There is no need to backup ssl cert files.")
                return

            os.mknod(backupFlagFile, ConstantsBase.KEY_FILE_PERMISSION)
            for certFile in backupList:
                realCertFile = os.path.join(nodeDnDir, certFile)
                if (os.path.isfile(realCertFile)):
                    tarBackupList.append(certFile)

            if (len(tarBackupList) == 0):
                os.mknod(os.path.join(nodeDnDir, EMPTY_CERT))
                cmd = " %s && " % CmdUtil.getCdCmd(nodeDnDir)
                cmd += CompressUtil.getCompressFilesCmd(
                    DefaultValue.CERT_BACKUP_FILE, EMPTY_CERT)
            else:
                cmd = " %s && " % CmdUtil.getCdCmd(nodeDnDir)
                cmd += "tar -zcvf %s" % (DefaultValue.CERT_BACKUP_FILE)
                for certFile in tarBackupList:
                    cmd += " %s" % certFile
            (status, output) = CmdUtil.retryGetstatusoutput(cmd)
            if (status != 0):
                raise Exception(
                    ErrorCode.GAUSS_514["GAUSS_51400"]
                    % cmd + "Failed backup gds cert files on local node."
                    + "Error: \n%s" % output)

            # Clear empty file
            if (os.path.isfile(os.path.join(nodeDnDir, EMPTY_CERT))):
                os.remove(os.path.join(nodeDnDir, EMPTY_CERT))
            self.logger.log("Successfully executed local backup.")
            return
        # 1 check backup flag file on all dbnodes.
        for node in allDnNodeDict.keys():
            nodeDnDir = allDnNodeDict[node]
            backupFlagFile = os.path.join(nodeDnDir, "certFlag")
            status = self.sshTool.checkRemoteFileExist(
                node, backupFlagFile,
                self.context.g_opts.mpprcFile)
            if not status:
                normalNodeList.append(node)
        # 2 if exists flag file on anyone node, there will be return.
        if (len(normalNodeList) != len(allDnNodeDict.keys())):
            self.logger.log("There is no need to backup on all dbnodes.")
            return
        # 3 backup cert files on all dbnodes.
        for node in allDnNodeDict.keys():
            nodeDnDir = allDnNodeDict[node]
            backupFlagFile = os.path.join(nodeDnDir, "certFlag")
            backupTar = os.path.join(nodeDnDir, DefaultValue.CERT_BACKUP_FILE)
            sshcmd = g_file.SHELL_CMD_DICT["overWriteFile"] % (
                "backupflagfile", backupFlagFile)
            sshcmd += " && " + g_file.SHELL_CMD_DICT["changeMode"] % (
                DefaultValue.KEY_FILE_MODE, backupFlagFile)
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS, [node],
                                        self.context.g_opts.mpprcFile)
            for certFile in backupList:
                realCertFile = os.path.join(nodeDnDir, certFile)
                status = self.sshTool.checkRemoteFileExist(
                    node, realCertFile,
                    self.context.g_opts.mpprcFile)
                if status:
                    tarBackupList.append(certFile)
                # if no cert files,
                # there will be create a file for '.tar' file.
                if (len(tarBackupList) == 0):
                    sshcmd = CmdUtil.getCreateFileCmd(
                        os.path.join(nodeDnDir, EMPTY_CERT))
                    self.sshTool.executeCommand(sshcmd,
                                                DefaultValue.SUCCESS, [node],
                                                self.context.g_opts.mpprcFile)
                    sshcmd = " %s && " % CmdUtil.getCdCmd(nodeDnDir)
                    sshcmd += CompressUtil.getCompressFilesCmd(
                        DefaultValue.CERT_BACKUP_FILE, EMPTY_CERT)
                else:
                    sshcmd = " %s && " % CmdUtil.getCdCmd(nodeDnDir)
                    sshcmd += "tar -zcvf %s" % (DefaultValue.CERT_BACKUP_FILE)
                    for certDir in tarBackupList:
                        sshcmd += " %s" % certDir
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS, [node],
                                        self.context.g_opts.mpprcFile)
            # Clear empty file
            if (self.isDnEmpty(node)):
                sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                    os.path.join(nodeDnDir, EMPTY_CERT),
                    os.path.join(nodeDnDir, EMPTY_CERT))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS, [node],
                                            self.context.g_opts.mpprcFile)
            self.logger.log(
                "Successfully backup SSL cert files on [%s]." % node)
            sshcmd = g_file.SHELL_CMD_DICT["changeMode"] % (
                DefaultValue.KEY_FILE_MODE, backupTar)
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS, [node],
                                        self.context.g_opts.mpprcFile)

    def doDNSSLCertRollback(self):
        """
        function: rollback SSL cert file in DN instance directory
        input:  NA
        output: NA
        """
        self.context.clusterInfo = dbClusterInfo()
        self.context.clusterInfo.initFromStaticConfig(
            pwd.getpwuid(os.getuid()).pw_name)
        self.sshTool = SshTool(self.context.clusterInfo.getClusterNodeNames(),
                               self.logger.logFile)
        backupList = DefaultValue.CERT_FILES_LIST[:]

        allDnNodeDict = self.getDnNodeDict()
        noBackupList = []

        temp = "tempDir"
        if self.context.g_opts.localMode:
            if ((NetUtil.GetHostIpOrName() in allDnNodeDict.keys()) and
                    os.path.isfile(os.path.join(
                        allDnNodeDict[NetUtil.GetHostIpOrName()],
                        DefaultValue.CERT_BACKUP_FILE))):

                localDnDir = allDnNodeDict[NetUtil.GetHostIpOrName()]
                tempDir = os.path.join(localDnDir, temp)
                if (os.path.exists(tempDir)):
                    FileUtil.removeDirectory(tempDir)
                os.mkdir(tempDir, ConstantsBase.KEY_DIRECTORY_PERMISSION)

                for certFile in backupList:
                    realCertFile = os.path.join(localDnDir, certFile)
                    if (os.path.exists(realCertFile)):
                        FileUtil.moveFile(realCertFile, tempDir)

                cmd = "cd '%s' && if [ -f '%s' ];then tar -zxvf %s;fi" % \
                      (localDnDir, DefaultValue.CERT_BACKUP_FILE,
                       DefaultValue.CERT_BACKUP_FILE)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    cmd = "cp '%s'/* '%s' && rm -rf '%s'" % (
                        tempDir, localDnDir, tempDir)
                    (status, output) = subprocess.getstatusoutput(cmd)
                    raise Exception(
                        (ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
                        + "Failed uncompression SSL backup file."
                        + "Error: \n%s" % output)

                # remove temp directory
                if (os.path.exists(tempDir)):
                    FileUtil.removeDirectory(tempDir)

                # set guc option
                if (os.path.isfile(
                        os.path.join(localDnDir, DefaultValue.SSL_CRL_FILE))):
                    cmd = \
                        "gs_guc set -D %s " \
                        "-c \"ssl_crl_file=\'%s\'\"" \
                        % (localDnDir, DefaultValue.SSL_CRL_FILE)
                else:
                    cmd = \
                        "gs_guc set -D %s " \
                        "-c \"ssl_crl_file=\'\'\"" % localDnDir
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(
                        ErrorCode.GAUSS_514["GAUSS_51400"]
                        % cmd + "Error: \n%s" % output)

                if (os.path.isfile(os.path.join(localDnDir, EMPTY_CERT))):
                    os.remove(os.path.join(localDnDir, EMPTY_CERT))

                self.logger.log(
                    "Successfully rollback SSL cert files with local mode.")
                return
            else:
                self.logger.log("There is not exists backup files.")
                return
                # 1.check backup file "gsql_cert_backup.tar.gz" on all dbnodes.
        for node in allDnNodeDict.keys():
            backupGzFile = os.path.join(allDnNodeDict[node],
                                        DefaultValue.CERT_BACKUP_FILE)
            status = self.sshTool.checkRemoteFileExist(
                node, backupGzFile,
                self.context.g_opts.mpprcFile)
            if not status:
                noBackupList.append(node)
        if (len(noBackupList) > 0):
            raise Exception(
                (ErrorCode.GAUSS_502["GAUSS_50201"]
                 % DefaultValue.CERT_BACKUP_FILE)
                + "Can't rollback SSL cert files on %s." % noBackupList)

        # 2.perform rollback on all dbnodes.
        for node in allDnNodeDict.keys():
            backupGzFile = os.path.join(
                allDnNodeDict[node], DefaultValue.CERT_BACKUP_FILE)
            # 2-1.move SSL cert files in dn directory to temp directory.
            sshcmd = "cd '%s' && if [ -d '%s' ];then rm -rf '%s'" \
                     " && mkdir '%s';else mkdir '%s';fi" % \
                     (allDnNodeDict[node], temp, temp, temp, temp)
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS,
                                        [node], self.context.g_opts.mpprcFile)
            for certFile in backupList:
                realCertFile = os.path.join(allDnNodeDict[node], certFile)
                sshcmd = " %s && " % CmdUtil.getCdCmd(
                    os.path.join(allDnNodeDict[node], temp))
                sshcmd += g_file.SHELL_CMD_DICT["renameFile"] % (
                    realCertFile, realCertFile, "./")
                self.sshTool.executeCommand(
                    sshcmd,
                    DefaultValue.SUCCESS,
                    [node],
                    self.context.g_opts.mpprcFile)

            # 2-2.uncompression "gsql_cert_backup.tar.gz" file
            sshcmd = "cd '%s' && if [ -f '%s' ];then tar -zxvf %s;fi" % \
                     (allDnNodeDict[node], DefaultValue.CERT_BACKUP_FILE,
                      DefaultValue.CERT_BACKUP_FILE)
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS,
                                        [node],
                                        self.context.g_opts.mpprcFile)

            # 2-3.clear temp directory
            sshcmd = " %s && " % CmdUtil.getCdCmd(allDnNodeDict[node])
            sshcmd += g_file.SHELL_CMD_DICT["deleteDir"] % (temp, temp)
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS,
                                        [node],
                                        self.context.g_opts.mpprcFile)

            # 2-4.is have "sslcrl-file.crl",config 'ssl_crl_file' option
            status = self.sshTool.checkRemoteFileExist(
                node, os.path.join(
                    allDnNodeDict[node],
                    DefaultValue.SSL_CRL_FILE),
                self.context.g_opts.mpprcFile)
            # exists 'sslcrl-file.crl' file ,config option of 'postgresql.conf'
            if (status):
                if node == NetUtil.GetHostIpOrName():
                    sshcmd = \
                        "gs_guc set -D %s " \
                        "-c \"ssl_crl_file='%s'\"" \
                        % (allDnNodeDict[node], DefaultValue.SSL_CRL_FILE)
                else:
                    sshcmd = "gs_guc set -D %s " \
                             "-c \"ssl_crl_file=\\\\\\'%s\\\\\\'\"" \
                             % (allDnNodeDict[node], DefaultValue.SSL_CRL_FILE)
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
            else:
                if (node == NetUtil.GetHostIpOrName()):
                    sshcmd = "gs_guc set " \
                             "-D %s -c \"ssl_crl_file=''\"" % (
                                 allDnNodeDict[node])
                else:
                    sshcmd = "gs_guc set " \
                             "-D %s -c \"ssl_crl_file=\\\\\\'\\\\\\'\"" \
                             % (allDnNodeDict[node])
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)

            # Clear empty file.
            if (self.isDnEmpty(node)):
                sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                    os.path.join(allDnNodeDict[node], EMPTY_CERT),
                    os.path.join(allDnNodeDict[node], EMPTY_CERT))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
            self.logger.log(
                "Successfully rollback SSL cert files on [%s]." % node)

    def getDnNodeDict(self):
        """
        function: get dbnodes information
        input: NA
        output: dictionary
        """
        clusterDnNodes = {}
        if (not self.context.clusterInfo.isSingleInstCluster()):
            return clusterDnNodes
        for node in self.context.clusterInfo.dbNodes:
            if (len(node.datanodes) > 0):
                clusterDnNodes[node.datanodes[0].hostname] = node.datanodes[
                    0].datadir
        self.logger.debug("Successfully get database node dict.")
        return clusterDnNodes

    def distributeDNCert(self, certList, dnDict=None):
        """
        function: distribute ssl cert files on single_inst cluster
        input: certList:     cert files list
               dnDict:       dictionary
        output: NA
        """
        tempDir = "tempCertDir"
        gphost = EnvUtil.getTmpDirFromEnv()
        if dnDict is None:
            dnDict = {}
        dnName = dnDict.keys()
        certPathList = []
        self.logger.debug(certList)

        for num in iter(certList):
            sslPath = os.path.join(os.path.join(gphost, tempDir), num)
            certPathList.append(sslPath)
        # local mode
        if self.context.g_opts.localMode:
            localDnDir = dnDict[NetUtil.GetHostIpOrName()]
            for num in range(len(certList)):
                # distribute gsql SSL cert
                if (os.path.isfile(os.path.join(localDnDir, certList[num]))):
                    os.remove(os.path.join(localDnDir, certList[num]))
                if (os.path.isfile(certPathList[num])):
                    FileUtil.cpFile(certPathList[num],
                                  os.path.join(localDnDir, certList[num]))
                    FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                                      os.path.join(localDnDir, certList[num]))

                    # remove 'sslcrl-file.crl' file
            if (DefaultValue.SSL_CRL_FILE not in certList and
                    os.path.isfile(
                        os.path.join(localDnDir, DefaultValue.SSL_CRL_FILE))):
                os.remove(os.path.join(localDnDir, DefaultValue.SSL_CRL_FILE))

                # config 'sslcrl-file.crl' option in 'postgresql.conf'
            if (os.path.isfile(
                    os.path.join(localDnDir, DefaultValue.SSL_CRL_FILE))):
                cmd = "gs_guc set " \
                      "-D %s -c \"ssl_crl_file=\'%s\'\"" % \
                      (localDnDir, DefaultValue.SSL_CRL_FILE)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(
                        (ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
                        + "Failed set 'ssl_crl_file' option."
                        + "Error: \n%s" % output)
            else:
                cmd = "gs_guc set -D %s -c \"ssl_crl_file=\'\'\"" \
                      % localDnDir
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(
                        (ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
                        + "Failed set 'ssl_crl_file' option."
                        + "Error: \n%s" % output)
                    # remove backup flag file 'certFlag'
            if (os.path.isfile(os.path.join(localDnDir, 'certFlag'))):
                os.remove(os.path.join(localDnDir, 'certFlag'))
            self.logger.log(
                "Replace SSL cert files with local mode successfully.")
            return
        # not local mode
        for node in dnName:
            for num in range(len(certList)):
                sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                    os.path.join(dnDict[node], certList[num]),
                    os.path.join(dnDict[node], certList[num]))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)

                if (os.path.exists(certPathList[num])):
                    self.sshTool.scpFiles(certPathList[num], dnDict[node],
                                          [node])

                # change permission of cert file 600,
                # there no need to is exists file,
                # because the files must be exist.
                sshcmd = g_file.SHELL_CMD_DICT["changeMode"] % (
                    DefaultValue.KEY_FILE_MODE,
                    os.path.join(dnDict[node], certList[num]))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)

            if (DefaultValue.SSL_CRL_FILE in certList):
                if (node == NetUtil.GetHostIpOrName()):
                    sshcmd = "gs_guc set " \
                             "-D %s -c \"ssl_crl_file='%s'\"" \
                             % (dnDict[node], DefaultValue.SSL_CRL_FILE)
                else:
                    sshcmd = "gs_guc set " \
                             " -D %s -c \"ssl_crl_file=\\\\\\'%s\\\\\\'\"" \
                             % (dnDict[node], DefaultValue.SSL_CRL_FILE)
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
            else:
                # no ssl cert file there will delete old cert file,
                # and config option ssl_crl_file = ''
                sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                    os.path.join(dnDict[node], DefaultValue.SSL_CRL_FILE),
                    os.path.join(dnDict[node], DefaultValue.SSL_CRL_FILE))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
                if (node == NetUtil.GetHostIpOrName()):
                    sshcmd = "gs_guc set " \
                             "-D %s -c \"ssl_crl_file=\'\'\"" % (dnDict[node])
                else:
                    sshcmd = \
                        "gs_guc set " \
                        "-D %s " \
                        "-c \"ssl_crl_file=\\\\\\'\\\\\\'\"" % (dnDict[node])
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
                # remove file 'sslcrl-file.crl'
                sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                    os.path.join(dnDict[node], DefaultValue.SSL_CRL_FILE),
                    os.path.join(dnDict[node], DefaultValue.SSL_CRL_FILE))
                self.sshTool.executeCommand(sshcmd,
                                            DefaultValue.SUCCESS,
                                            [node],
                                            self.context.g_opts.mpprcFile)
            # remove backup flag file 'certFlag'
            sshcmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
                os.path.join(dnDict[node], "certFlag"),
                os.path.join(dnDict[node], "certFlag"))
            self.sshTool.executeCommand(sshcmd,
                                        DefaultValue.SUCCESS,
                                        [node],
                                        self.context.g_opts.mpprcFile)
            self.logger.log("%s replace SSL cert files successfully." % node)

    ###########################################################################
    # Kerberos Flow
    ###########################################################################
    def doKerberos(self):
        """
        function: operation kerberos
        input: NA
        output: NA
        """
        try:
            if self.context.g_opts.kerberosMode == "install":
                self.logger.log("Starting install Kerberos.", "addStep")
                cmd = "%s -m %s -U %s --%s" % \
                      (OMCommand.getLocalScript("Local_Kerberos"),
                       "install",
                       self.context.g_opts.clusterUser,
                       self.context.g_opts.kerberosType)
                # local mode
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                    "Command: %s. Error:\n%s" % (cmd, output))
                self.logger.log("Successfully install Kerberos.")
            elif self.context.g_opts.kerberosMode == "uninstall":
                self.logger.log("Starting uninstall Kerberos.", "addStep")
                cmd = "%s -m %s -U %s" % \
                      (OMCommand.getLocalScript("Local_Kerberos"),
                       "uninstall",
                       self.context.g_opts.clusterUser)
                # local mode
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                    "Command: %s. Error:\n%s" % (cmd, output))
                self.logger.log("Successfully uninstall Kerberos.")
        except Exception as e:
            raise Exception(str(e))

    def checkRemoteFileExist(self, filepath):
        """
        funciton:check file exist on remote node
        input:filepath
        output:dictionary
        """
        existNodes = []
        for nodeName in self.context.clusterInfo.getClusterNodeNames():
            if (nodeName == NetUtil.GetHostIpOrName()):
                continue
            if (self.sshTool.checkRemoteFileExist(nodeName, filepath, "")):
                existNodes.append(nodeName)

        return existNodes

    def recursivePath(self, filepath):
        """
        function: recursive path
        input: filepath
        output: NA
        """
        fileList = os.listdir(filepath)
        for fileName in fileList:
            fileName = os.path.join(filepath, fileName)
            # change the owner of files
            FileUtil.changeOwner(self.context.g_opts.user, fileName)
            if (os.path.isfile(fileName)):
                # change fileName permission
                FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, fileName)
            else:
                # change directory permission
                FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, fileName,
                                  True)
                self.recursivePath(fileName)

    def stopCluster(self):
        """
        function:Stop cluster
        input:NA
        output:NA
        """
        pass

    def startCluster(self):
        """
        function:Start cluster
        input:NA
        output:NA
        """
        pass
