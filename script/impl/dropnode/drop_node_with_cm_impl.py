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
# Description  : drop_node_with_cm_impl.py
#############################################################################

import sys
import os
import re
import subprocess
from time import sleep

sys.path.append(sys.path[0] + "/../../../../")
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil
from base_utils.executor.cmd_executor import CmdExecutor

from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.component.CM.CM_OLAP.CM_OLAP import CM_OLAP
from gspylib.threads.SshTool import SshTool
from gspylib.os.gsfile import g_file
from impl.dropnode.DropnodeImpl import DropnodeImpl


class DropNodeWithCmImpl(DropnodeImpl):
    def __init__(self, drop_node):
        super(DropNodeWithCmImpl, self).__init__(drop_node)
        self.drop_nodes = list()
        self.stoped_nodes = list()
        self.cm_component = None
        self.ssh_tool = None

    def init_global_value(self):
        """
        Initial global value
        """
        self.drop_nodes = [node for node in self.context.clusterInfo.dbNodes
                           for drop_ip in self.context.hostIpListForDel
                           if drop_ip in node.backIps]
        self.ssh_tool = SshTool([node.name for node in self.context.clusterInfo.dbNodes])

        self.cm_component = CM_OLAP()
        self.cm_component.binPath = os.path.realpath(os.path.join(
            self.context.clusterInfo.appPath, "bin"))
        local_node = [node for node in self.context.clusterInfo.dbNodes
                      if NetUtil.GetHostIpOrName() == node.name][0]
        self.cm_component.instInfo = local_node.cmagents[0]
        self.cm_component.logger = self.logger

    def check_drop_cm_node(self):
        """
        Check drop CM node prerequisites
        """
        # 1.check node number
        if len(self.context.clusterInfo.dbNodes) < 3:
            raise Exception(ErrorCode.GAUSS_358["GAUSS_35811"])

        if len(self.context.clusterInfo.dbNodes) - len(self.context.hostIpListForDel) < 2:
            error_msg = "The current cluster contains {0} nodes. " \
                        "A maximum of {1} " \
                        "nodes can be dropped.".format(len(self.context.clusterInfo.dbNodes),
                                                       len(self.context.clusterInfo.dbNodes) - 2)
            raise Exception(ErrorCode.GAUSS_358["GAUSS_35811"] + error_msg)
        # 2.check cm_server number after drop_node
        all_cm_server_nodes = [node for node in self.context.clusterInfo.dbNodes if node.cmservers]
        drop_node_with_cm_server = [node for node in self.drop_nodes if node.cmservers]
        if (len(all_cm_server_nodes) - len(drop_node_with_cm_server)) < 2:
            raise Exception("Too many cm_server nodes are dropped.A maximum of {0} cm_server "
                            "nodes can be dropped.".format(len(all_cm_server_nodes) - 2))

    def _stop_drop_node(self):
        """
        try to stop drop nodes
        """
        for node in self.drop_nodes:
            stop_para = (node.id, "", 30, "", "")
            # stop node
            try:
                self.cm_component.stop_cluster(stop_para)
                self.stoped_nodes.append(node)
            except Exception as exp:
                self.logger.debug("Stop node failed [{0}]. Exception {1}".format(node.id,
                                                                                 str(exp)))
                self.logger.log("Success stoped node [{0}].".format(node.id))

    def _generate_flag_file_on_drop_nodes(self):
        """
        Modify static file on drop nodes
        """
        for drop_node in self.stoped_nodes:
            self.logger.debug("Start generate drop node flag file on drop node.")
            flag_file = os.path.realpath(os.path.join(self.context.clusterInfo.appPath,
                                                      "bin", "drop_node_flag"))
            cmd = g_file.SHELL_CMD_DICT["createFile"] % (flag_file,
                                                         DefaultValue.FILE_MODE, flag_file)
            CmdExecutor.execCommandWithMode(cmd, self.ssh_tool, host_list=[drop_node.name])

            self.logger.log("Generate drop flag file on "
                            "drop node {0} successfully.".format(drop_node.name))

    def restart_new_cluster(self):
        """
        Restart cluster
        """
        self.logger.log("Restarting cm_server cluster ...")
        stopCMProcessesCmd = "pkill -9 om_monitor -U {user}; pkill -9 cm_agent -U {user}; " \
            "pkill -9 cm_server -U {user};".format(user=self.user)
        self.logger.debug("stopCMProcessesCmd: " + stopCMProcessesCmd)
        gaussHome = EnvUtil.getEnv("GAUSSHOME")
        gaussLog = EnvUtil.getEnv("GAUSSLOG")
        hostList = [node.name for node in self.context.clusterInfo.dbNodes]
        CmdExecutor.execCommandWithMode(stopCMProcessesCmd, self.ssh_tool, host_list=hostList)
        # for flush dcc configuration
        DefaultValue.remove_metadata_and_dynamic_config_file(self.user, self.ssh_tool, self.logger)
        # execute gsctl reload
        dataPath = self.context.hostMapForExist[self.localhostname]['datadir'][0]
        gsctlReloadCmd = "source %s; gs_ctl reload -N all -D %s" % (self.envFile, dataPath)
        self.logger.debug("gsctlReloadCmd: " + gsctlReloadCmd)
        CmdExecutor.execCommandWithMode(gsctlReloadCmd, self.ssh_tool, host_list=[self.localhostname])
        # start CM processes
        startCMProcessedCmd = "source %s; nohup %s/bin/om_monitor -L %s/cm/om_monitor >> /dev/null 2>&1 &" % \
            (self.envFile, gaussHome, gaussLog)
        self.logger.debug("startCMProcessedCmd: " + startCMProcessedCmd)
        CmdExecutor.execCommandWithMode(startCMProcessedCmd, self.ssh_tool, host_list=hostList)
        queryClusterCmd = "source %s; cm_ctl query -Cv" % self.envFile
        self.logger.debug("queryClusterCmd: " + queryClusterCmd)
        tryCount = 0
        while tryCount <= 120:
            sleep(5)
            tryCount += 1
            status, output = subprocess.getstatusoutput(queryClusterCmd)
            if status != 0:
                continue
            if re.findall("cluster_state.*:.*Normal", output) != []:
                break
        if tryCount > 120:
            self.logger.logExit(
                "All steps of drop have finished, but failed to wait cluster to be normal in 600s!\n"
                "HINT: Maybe the cluster is continually being started in the background.\n"
                "You can wait for a while and check whether the cluster starts.")

    def run(self):
        """
        start dropnode
        """
        self.logger.log("Drop node with CM node is running.")
        self.init_global_value()
        self.check_drop_cm_node()
        self.change_user()
        self.logger.log("[gs_dropnode]Start to drop nodes of the cluster.")
        self.checkAllStandbyState()
        self.dropNodeOnAllHosts()
        self.operationOnlyOnPrimary()
        self._stop_drop_node()
        self._generate_flag_file_on_drop_nodes()
        self.modifyStaticConf()
        self.restart_new_cluster()
        self.logger.log("[gs_dropnode] Success to drop the target nodes.")
