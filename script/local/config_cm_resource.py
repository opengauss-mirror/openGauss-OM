#!/usr/bin/env python3
#-*- coding:utf-8 -*-
##############################################################################
#Copyright (c): 2020-2025, Huawei Tech. Co., Ltd.
#FileName     : config_cm_resource.py
#Version      : openGauss
#Date         : 2023-02-12
#Description  : config_cm_resource.py is a utility to config CM resource file.
##############################################################################

import os
import sys
import getopt

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.LocalBaseOM import LocalBaseOM
from domain_utils.domain_common.cluster_constants import ClusterConstants
from domain_utils.cluster_file.cluster_log import ClusterLog
from gspylib.threads.parallelTool import parallelTool
from base_utils.os.net_util import NetUtil


# Global variables define
g_opts = None

# Action type
ACTION_INSTALL_CLUSTER = "install_cluster"
ACTION_EXPAND_NODE ="expansion_node"
ACTION_DROP_NODE = "drop_node"


class CmdOptions():
    """
    Command line parameters
    """

    def __init__(self):
        """
        """
        self.action_type = ""
        self.cluster_user = ""
        self.cluster_conf = ""
        self.log_file = ""
        self.drop_nodes = []


def parse_command_line():
    """
    Parse command line
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:U:X:l:H:")
    except Exception as e:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

    if len(args) > 0:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    for (key, value) in opts:
        if key == "-t":
            g_opts.action_type = value
        elif key == "-U":
            g_opts.cluster_user = value
        elif key == "-X":
            g_opts.cluster_conf = value
        elif key == "-l":
            g_opts.log_file = value
        elif key == "-H":
            g_opts.drop_nodes = value.split(',')

def check_parameters():
    """
    Check parameters
    """
    if not g_opts.action_type:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + ".")

    if not g_opts.drop_nodes and g_opts.action_type == ACTION_DROP_NODE:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 'H' + ".")

    if not g_opts.cluster_user:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 'U' + ".")

    if g_opts.cluster_conf:
        if not os.path.exists(g_opts.cluster_conf):
            GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50201"] % g_opts.cluster_conf)

    if not g_opts.log_file:
        g_opts.log_file = ClusterLog.getOMLogPath(
                          ClusterConstants.LOCAL_LOG_FILE, g_opts.cluster_user, "")


class ConfigCMResource(LocalBaseOM):
    """
    class: ConfigCMResource
    """

    def __init__(self, action_type, cluster_user, cluster_conf, log_file, drop_nodes):
        """
        Init configuration on local node
        """
        LocalBaseOM.__init__(self, log_file, cluster_user, cluster_conf)
        if self.clusterConfig == "":
            self.readConfigInfo()
        else:
            self.readConfigInfoByXML()

        # Check user information
        self.getUserInfo()
        if self.user != cluster_user.strip():
            self.logger.debug("User parameter : %s." % self.user)
            self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50315"]
                                % (self.user, self.clusterInfo.appPath))
        self.initComponent()

        self.cm_res_info = {}
        self.base_ips = []
        self.action_type = action_type
        self.drop_nodes = drop_nodes

    def get_cm_res_info(self):
        """
        Get CM resource information for adding
        """
        # get all node names
        node_names = self.clusterInfo.getClusterNodeNames()
        for node_name in node_names:
            node_info = self.clusterInfo.getDbNodeByName(node_name)
            for inst in node_info.datanodes:
                for i, res_name in enumerate(inst.float_ips):
                    _tup = (self.clusterInfo.float_ips[res_name], inst.listenIps[i],
                           inst.instanceId, node_info.id)
                    if res_name not in self.cm_res_info:
                        self.cm_res_info[res_name] = [_tup]
                    else:
                        self.cm_res_info[res_name].append(_tup)

        self.logger.log("Successfully get cm res info: \n%s" % str(self.cm_res_info))

    def get_base_ips(self):
        """
        Get base IP for reducing
        """
        for node_name in self.drop_nodes:
            node_info = self.clusterInfo.getDbNodeByName(node_name)
            for inst in node_info.datanodes:
                self.base_ips.extend(inst.listenIps)

    def _config_an_instance(self, component):
        """
        Config CM resource file for single component
        """
        # check instance data directory
        inst_type = component.instInfo.datadir.split('/')[-1].strip()
        if inst_type != "cm_agent":
            self.logger.log("Current instance is not cm_agent")
            return

        if not os.path.exists(component.instInfo.datadir):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            "data directory of the cm_agent instance")

        component.config_cm_res_json(self.base_ips, self.cm_res_info)

    def add_cm_res_info(self):
        """
        Config CM resource file for "install/expansion"
        """
        self.get_cm_res_info()
        component_list = self.cmCons
        try:
            parallelTool.parallelExecute(self._config_an_instance, component_list)
        except Exception as e:
            raise Exception(str(e))

    def reduce_cm_res_info(self):
        """
        Config CM resource file for "dropnode"
        """
        self.get_base_ips()
        component_list = self.cmCons
        try:
            parallelTool.parallelExecute(self._config_an_instance, component_list)
        except Exception as e:
            raise Exception(str(e))

    def run(self):
        """
        Config CM resource file
        """
        fun_dict = {ACTION_INSTALL_CLUSTER : self.add_cm_res_info,
                    ACTION_EXPAND_NODE     : self.add_cm_res_info,
                    ACTION_DROP_NODE       : self.reduce_cm_res_info}

        if self.action_type in list(fun_dict.keys()):
            fun_dict[self.action_type]()
        else:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % 't' + \
                                " Value: %s." % self.action_type)

        self.logger.log("Successfully configured CM resource file on node[%s]" % \
                        NetUtil.GetHostIpOrName())


if __name__ == '__main__':
    """
    function: Main function
              1.Parse command line
              2.Check parameter
              3.Read config from xml config file
              4.Get the CM resource information to be configured
              5.Config CM resource file
    input : NA
    output: NA
    """
    try:
        parse_command_line()
        check_parameters()
        configer = ConfigCMResource(g_opts.action_type, g_opts.cluster_user,
                                    g_opts.cluster_conf, g_opts.log_file, g_opts.drop_nodes)
        configer.run()

    except Exception as e:
        GaussLog.exitWithError(str(e))

    sys.exit(0)
