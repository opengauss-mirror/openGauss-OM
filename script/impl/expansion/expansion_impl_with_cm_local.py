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
# Description  : expansion_impl_with_cm_local.py
#############################################################################

import os
import subprocess

from gspylib.common.Common import DefaultValue
from impl.expansion.expansion_impl_with_cm import ExpansionImplWithCm, change_user_executor


class ExpansionImplWithCmLocal(ExpansionImplWithCm):
    """
    This is expand subclass for add node with CM component
    """
    def __init__(self, expansion):
        super(ExpansionImplWithCmLocal, self).__init__(expansion)

    def _get_local_node_cluster_commit_id(self):
        """
        Get local node version
        """
        self.logger.log("Start get commit ID on local host.")
        # gp_home = self.context.clusterInfoDict["toolPath"]
        # version_file = os.path.realpath(os.path.join(gp_home, "version.cfg"))
        gsql_cmd = "source {0} ; gsql -V".format(self.envFile)
        status, output = subprocess.getstatusoutput(gsql_cmd)
        if status != 0 or not output.strip():
            self.logger.error("Gsql command error: {0}".format(output))
            raise Exception("Current node gsql command failed. {0}".format(output))
        self.logger.debug("Get current node gsql command successfully. "
                          "output is : {0}".format(output))
        # gsql version display like (gsql (openGauss x.x.0 build xxxxxxx)
        # compiled at 2029-02-26 02:07:00 commit 0 last mr xxxx)
        commit_id = output.strip().split(")")[0].split()[-1]
        self.logger.log("Current commit ID is : {0}".format(commit_id))
        return commit_id

    def _get_remote_node_commit_id(self):
        """
        Get local node version
        """
        self.logger.log("Start get commit ID on remote host.")
        # gp_home = self.context.clusterInfoDict["toolPath"]
        # version_file = os.path.realpath(os.path.join(gp_home, "version.cfg"))
        gsql_cmd = "source {0} ; gsql -V".format(self.envFile)
        result_map, output_collect = \
            self.ssh_tool.getSshStatusOutput(gsql_cmd,
                                             hostList=self.get_node_names(self.new_nodes))

        self.logger.debug("Check remote nodes commit ID , "
                          "result_map is : {0}".format(result_map))
        self.logger.debug("Check remote nodes commit ID , "
                          "output_collect is : {0}".format(output_collect))
        if DefaultValue.FAILURE in result_map.values():
            self.logger.error("Get commit ID on remote node failed. output: "
                              "{0}".format(result_map))
            raise Exception("Get commit ID on remote node failed. output: {0}".format(result_map))
        result_dict = self._parse_ssh_tool_output_collect(output_collect)
        if len(list(set(result_dict.values()))) != 1:
            self.logger.debug("The database version on the remote node is inconsistent. "
                              "result {0}".format(result_dict))
            raise Exception("The database version on the remote node is inconsistent.")
        self.logger.debug("result dict is : {0}".format(result_dict))
        return list(result_dict.values())[0]

    def check_remote_host_cluster_version(self):
        """
        Check remote node cluster version.
        """
        current_commit_id = self._get_local_node_cluster_commit_id()
        remote_commit_id = self._get_remote_node_commit_id()
        if current_commit_id != remote_commit_id:
            self.logger.error("The commit ID [{0}] of the new node is "
                              "inconsistent with the local ID "
                              "[{1}].".format(remote_commit_id, current_commit_id))
            raise Exception("The commit ID [{0}] of the new node is "
                            "inconsistent with the local ID "
                            "[{1}].".format(remote_commit_id, current_commit_id))

    def check_remote_host_cm_component(self):
        """
        Check remote node is contain CM component.
        """
        self.logger.log("Start check CM component on remote node.")
        for new_node in self.new_nodes:
            cm_agent_conf = os.path.realpath(os.path.join(new_node.cmagents[0].datadir,
                                                          "cm_agent.conf"))
            cmd = "ls {0} | wc -l".format(cm_agent_conf)
            _, output_collect = self.ssh_tool.getSshStatusOutput(cmd, hostList=[new_node.name])
            result_dict = self._parse_ssh_tool_output_collect(output_collect)
            if new_node.name not in result_dict:
                self.logger.error("Check remote node [{0}] cm_agent.conf failed. "
                                  "output: {1}".format(new_node.name, result_dict))
                raise Exception("Check remote node [{0}] cm_agent.conf failed. "
                                  "output: {1}".format(new_node.name, result_dict))
            if result_dict.get(new_node.name) != '1':
                self.logger.error("Check remote node [{0}] result failed. "
                                  "output: {1}".format(new_node.name, result_dict))
                raise Exception("Check remote node [{0}] result failed. "
                                "output: {1}".format(new_node.name, result_dict))
            self.logger.log("Check cm_agent.conf on node [{0}] "
                            "successfully.".format(new_node.name))
        self.logger.log("Check remote node CM compent successfully.")

    def expansion_check(self):
        """
        Check cluster for expansion local mode
        """
        self.checkUserAndGroupExists()
        self.checkXmlFileAccessToUser()
        self.checkClusterStatus()
        self.validNodeInStandbyList()
        self.check_remote_host_cluster_version()
        self.check_remote_host_cm_component()

    def do_config(self, p_value):
        """
        Config instance on new nodes
        """
        self._change_user_without_root()
        self._config_instance()
        if DefaultValue.is_create_grpc(self.logger,
                                       self.static_cluster_info.appPath):
            self.logger.log("Generate GRPC cert file.")
            self.generateGRPCCert()
        p_value.value = 1

    def run(self):
        """
        This is class enter.
        """
        self.sendSoftToHosts(send_pkg=False)
        self.send_xml()
        self.expansion_check()
        self._set_expansion_success()
        change_user_executor(self.do_config)
        self._set_pgxc_node_name()
        change_user_executor(self.do_start)
        self.check_new_node_state(True)
