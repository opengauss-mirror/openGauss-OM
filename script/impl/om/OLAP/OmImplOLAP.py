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
# Description : omManagerImplOLAP.py is a utility to manage a Gauss200 cluster.
#############################################################################
import subprocess
import sys
import re
import time
import getpass

sys.path.append(sys.path[0] + "/../../../../")
from gspylib.common.DbClusterInfo import queryCmd
from gspylib.threads.SshTool import SshTool
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.Common import DefaultValue
from gspylib.common.OMCommand import OMCommand
from impl.om.OmImpl import OmImpl
from gspylib.os.gsfile import g_file
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil
from gspylib.component.DSS.dss_checker import DssConfig




###########################################
class OmImplOLAP(OmImpl):
    """
    class: OmImplOLAP
    """

    def __init__(self, OperationManager=None):
        """
        function:class init
        input:OperationManager
        output:NA
        """
        OmImpl.__init__(self, OperationManager)

    # AP
    def stopCluster(self):
        """
        function:Stop cluster
        input:NA
        output:NA
        """
        self.logger.log("Stopping the cluster.")
        # Stop cluster in 300 seconds
        cmd = "source %s; %s -t %d" % (
            self.context.g_opts.mpprcFile, OMCommand.getLocalScript("Gs_Stop"),
            DefaultValue.TIMEOUT_CLUSTER_STOP)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            self.logger.log(
                "Warning: Failed to stop cluster within 300 seconds,"
                "stopping cluster again at immediate mode.")
            cmd = "source %s; %s -m immediate -t %d" % (
                self.context.g_opts.mpprcFile,
                OMCommand.getLocalScript("Gs_Stop"),
                DefaultValue.TIMEOUT_CLUSTER_STOP)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                self.logger.log("The cmd is %s " % cmd)
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51610"]
                    % "the cluster at immediate mode"
                    + " Error: \n%s" % output)

        self.logger.log("Successfully stopped the cluster.")

    # AP
    def startCluster(self):
        """
        function:Start cluster
        input:NA
        output:NA
        """
        self.logger.log("Starting the cluster.", "addStep")
        # Delete cluster dynamic config if it is exist on all nodes
        clusterDynamicConf = "%s/bin/cluster_dynamic_config" \
                             % self.oldClusterInfo.appPath
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (
            clusterDynamicConf, clusterDynamicConf)
        self.logger.debug(
            "Command for removing the cluster dynamic configuration: %s."
            % cmd)
        self.sshTool.executeCommand(cmd)
        # Start cluster in 300 seconds
        cmd = "source %s; %s -t %s" % (
            self.context.g_opts.mpprcFile,
            OMCommand.getLocalScript("Gs_Start"),
            DefaultValue.TIMEOUT_CLUSTER_START)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            self.logger.debug("The cmd is %s " % cmd)
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51607"]
                % "the cluster" + " Error: \n%s" % output)

        self.logger.log("Successfully started the cluster.", "constant")

    ##########################################################################
    # Start Flow
    ##########################################################################
    def getNodeId(self):
        """
        function: get node Id
        input: NA
        output: NA
        """
        clusterType = "cluster"
        nodeId = 0
        if (self.context.g_opts.nodeName != ""):
            clusterType = "node"
            dbNode = self.context.clusterInfo.getDbNodeByName(
                self.context.g_opts.nodeName)
            if not dbNode:
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51619"]
                    % self.context.g_opts.nodeName)
            nodeId = dbNode.id
        elif (self.context.g_opts.azName != ""):
            clusterType = self.context.g_opts.azName
            # check whether the given azName is in the cluster
            if (
                    self.context.g_opts.azName
                    not in self.context.clusterInfo.getazNames()):
                raise Exception(
                    ErrorCode.GAUSS_500["GAUSS_50004"]
                    % '-az' + " The az name [%s] is not in the cluster."
                    % self.context.g_opts.azName)
        return nodeId, clusterType

    def doStartClusterByCm(self):
        """
        function: start cluster by cm
        :return: NA
        """
        (nodeId, startType) = self.getNodeId()
        if not self.context.cmCons[0]:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51622"] %
                            ("cm", "local"))

        cluster_normal_status = [DbClusterStatus.CLUSTER_STATUS_NORMAL,
                                 DbClusterStatus.CLUSTER_STATUS_DEGRADED]

        if EnvUtil.is_dss_mode(self.context.g_opts.user):
            cma_paths = DssConfig.get_cm_inst_path(
                self.clusterInfo.dbNodes[nodeId])
            if cma_paths and DssConfig.get_cma_res_value(
                    cma_paths[0], key='restart_delay') != str(
                        DssConfig.DMS_DEFAULT_RESTART_DELAY):
                DssConfig.reload_cm_resource(
                    self.logger, timeout=DssConfig.DMS_DEFAULT_RESTART_DELAY)
        if nodeId == 0 and self.dataDir:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51655"] % ("cm", "-D"))
        # start cluster
        is_success = self.context.cmCons[0].startCluster(
            self.context.g_opts.user,
            nodeId,
            self.context.g_opts.time_out,
            False,
            self.context.isSingle,
            cluster_normal_status,
            False,
            self.context.g_opts.azName,
            self.dataDir)
        if is_success:
            self.logger.log("Successfully started %s." % startType)
            self.logger.debug("Operation succeeded: Start by cm.")

    def doStartCluster(self):
        """
        function: do start cluster
        input: NA
        output: NA
        """
        self.logger.debug("Operating: Starting.")
        # if has cm, will start cluster by cm_ctl command
        if not self.context.clusterInfo.hasNoCm():
            self.context.logger.debug("Have CM configuration, upgrade all"
                                      " nodes together.")
            self.doStartClusterByCm()
            return
        else:
            self.context.logger.debug("Have CM configuration, rolling upgrade "
                                     "partial node but not all nodes, so "
                                     "start cluster with openGauss om.")
        # Specifies the stop node
        # Gets the specified node id
        startType = "node" if self.context.g_opts.nodeName != "" else "cluster"
        # Perform a start operation
        self.logger.log("Starting %s." % startType)
        self.logger.log("=========================================")
        hostName = NetUtil.GetHostIpOrName()
        # get the newest dynaminc config and send to other node
        self.clusterInfo.checkClusterDynamicConfig(self.context.user, hostName)
        if self.context.g_opts.nodeName == "":
            hostList = self.clusterInfo.getClusterNodeNames()
        else:
            hostList = []
            hostList.append(self.context.g_opts.nodeName)
        self.sshTool = SshTool(self.clusterInfo.getClusterNodeNames(), None,
                               DefaultValue.TIMEOUT_CLUSTER_START)
        if self.time_out is None:
            time_out = DefaultValue.TIMEOUT_CLUSTER_START
        else:
            time_out = self.time_out
        if self.context.g_opts.cluster_number:
            cmd = "source %s; %s -U %s -R %s -t %s --security-mode=%s --cluster_number=%s" % (
                self.context.g_opts.mpprcFile,
                OMCommand.getLocalScript("Local_StartInstance"),
                self.context.user, self.context.clusterInfo.appPath, time_out,
                self.context.g_opts.security_mode, self.context.g_opts.cluster_number)
        else:
            cmd = "source %s; %s -U %s -R %s -t %s --security-mode=%s" % (
                self.context.g_opts.mpprcFile,
                OMCommand.getLocalScript("Local_StartInstance"),
                self.context.user, self.context.clusterInfo.appPath, time_out,
                self.context.g_opts.security_mode)
        if self.dataDir != "":
            cmd += " -D %s" % self.dataDir
        failedOutput = ''
        for nodeName in hostList:
            (statusMap, output) = self.sshTool.getSshStatusOutput(cmd, [nodeName])
            if statusMap[nodeName] != 'Success':
                failedOutput += output
            elif re.search("another server might be running", output):
                self.logger.log(output)
            elif re.search("] WARNING:", output):
                tmp = '\n'.join(re.findall(".*] WARNING:.*", output))
                self.logger.log(output[0:output.find(":")] + '\n' + tmp)
        if len(failedOutput):
            self.logger.log("=========================================")
            raise Exception(
                ErrorCode.GAUSS_536["GAUSS_53600"] % (cmd, failedOutput))
        if startType == "cluster":
            starttime = time.time()
            cluster_state = ""
            cmd = "source %s; gs_om -t status|grep cluster_state" \
                  % self.context.g_opts.mpprcFile
            while time.time() <= 30 + starttime:
                status, output = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster" +
                        " After startup, check cluster_state failed")
                else:
                    cluster_state = output.split()[-1]
                    if cluster_state != "Normal":
                        self.logger.log("Waiting for check cluster state...")
                        time.sleep(5)
                    else:
                        break
            if cluster_state != "Normal":
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster"
                                + " After startup, the last check results were"
                                  " %s. Please check manually."
                                % cluster_state)
        self.logger.log("=========================================")
        self.logger.log("Successfully started.")
        self.logger.debug("Operation succeeded: Start.")

    def doStopClusterByCm(self):
        """
        function: stop cluster by cm
        :return: None
        """
        (nodeId, _) = self.getNodeId()
        if not self.context.cmCons[0]:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51622"] %
                            ("cm", "local"))
        if self.time_out is None:
            time_out = DefaultValue.TIMEOUT_CLUSTER_STOP
        else:
            time_out = int(self.time_out)
        if nodeId == 0 and self.dataDir:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51655"] % ("cm", "-D"))
        self.context.cmCons[0].stop_cluster((nodeId,
                                             self.mode,
                                             time_out,
                                             self.dataDir,
                                             self.context.g_opts.azName))
        self.logger.debug("Operation succeeded: Stop by cm.")

    def doStopCluster(self):
        """
        function: do stop cluster
        input: NA
        output: NA
        """
        self.logger.debug("Operating: Stopping.")
        # if has cm, will start cluster by cm_ctl command
        if not self.context.clusterInfo.hasNoCm():
            self.doStopClusterByCm()
            return
        # Specifies the stop node
        # Gets the specified node id
        stop_type = "node" if self.context.g_opts.nodeName != "" else "cluster"
        # Perform a stop operation
        self.logger.log("Stopping %s." % stop_type)
        self.logger.log("=========================================")
        if self.context.g_opts.nodeName == "":
            host_list = self.clusterInfo.getClusterNodeNames()
        else:
            host_list = []
            host_list.append(self.context.g_opts.nodeName)
        self.sshTool = SshTool(self.clusterInfo.getClusterNodeNames(), None,
                               DefaultValue.TIMEOUT_CLUSTER_START)
        if self.time_out is None:
            time_out = DefaultValue.TIMEOUT_CLUSTER_STOP
        else:
            time_out = self.time_out
        cmd = "source %s; %s -U %s -R %s -t %s" % (
            self.context.g_opts.mpprcFile,
            OMCommand.getLocalScript("Local_StopInstance"),
            self.context.user, self.context.clusterInfo.appPath, time_out)
        if self.dataDir != "":
            cmd += " -D %s" % self.dataDir
        if self.mode != "":
            cmd += " -m %s" % self.mode
        (statusMap, output) = self.sshTool.getSshStatusOutput(cmd, host_list)
        for nodeName in host_list:
            if statusMap[nodeName] != 'Success':
                raise Exception(
                    ErrorCode.GAUSS_536["GAUSS_53606"] % (cmd, output))
        self.logger.log("Successfully stopped %s." % stop_type)

        self.logger.log("=========================================")
        self.logger.log("End stop %s." % stop_type)
        self.logger.debug("Operation succeeded: Stop.")

    def doView(self):
        """
        function:get cluster node info
        input:NA
        output:NA
        """
        # view static_config_file
        self.context.clusterInfo.printStaticConfig(self.context.g_opts.outFile)

    def doQuery(self):
        """
        function: do query
        input  : NA
        output : NA
        """
        hostName = NetUtil.GetHostIpOrName()
        dbNums = len(self.context.clusterInfo.dbNodes)
        sshtools = []
        for _ in range(dbNums - 1):
            sshtools.append(SshTool([], timeout=self.time_out))
        cmd = queryCmd()
        if (self.context.g_opts.outFile != ""):
            cmd.outputFile = self.context.g_opts.outFile
        self.context.clusterInfo.queryClsInfo(hostName, sshtools,
                                              self.context.mpprcFile, cmd)

    def doRefreshConf(self):
        """
        function: do refresh conf
        input  : NA
        output : NA
        """
        if self.context.clusterInfo.isSingleNode():
            self.logger.log(
                "No need to generate dynamic configuration file for one node.")
            return
        if DefaultValue.cm_exist_and_is_disaster_cluster(self.context.clusterInfo, self.logger):
            self.logger.log(
                "Streaming disaster cluster do not need to generate dynamic configuration.")
            return
        self.logger.log("Generating dynamic configuration file for all nodes.")
        hostname = NetUtil.GetHostIpOrName()
        sshtool = SshTool(self.context.clusterInfo.getClusterNodeNames())
        self.context.clusterInfo.doRefreshConf(self.context.user, hostname,
                                               sshtool)

        self.logger.log("Successfully generated dynamic configuration file.")
