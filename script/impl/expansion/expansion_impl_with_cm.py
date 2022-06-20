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
# Description  : expansion_impl_with_cm.py
#############################################################################

import os
import sys
import datetime
import subprocess
import stat
import socket

from multiprocessing import Process, Value

from base_utils.os.env_util import EnvUtil

from impl.expansion.ExpansionImpl import ExpansionImpl

from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.threads.SshTool import SshTool
from gspylib.common.OMCommand import OMCommand
from gspylib.os.gsfile import g_file

from base_utils.os.net_util import NetUtil
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_dir import ClusterDir

from gspylib.component.CM.CM_OLAP.CM_OLAP import CM_OLAP


ACTION_INSTALL_CLUSTER = "install_cluster"


def change_user_executor(perform_method):
    """
    install database and expansion standby node with db om user
    """
    p_value = Value('i', 0)
    proc = Process(target=perform_method, args=(p_value,))
    proc.start()
    proc.join()
    if not p_value.value:
        sys.exit(1)
    else:
        proc.terminate()


class ExpansionImplWithCm(ExpansionImpl):
    """
    This is expand subclass for add node with CM component
    """
    def __init__(self, expansion):
        super(ExpansionImplWithCm, self).__init__(expansion)
        self.static_cluster_info = dbClusterInfo()
        self.xml_cluster_info = dbClusterInfo()
        self.ssh_tool = None
        self.new_nodes = list()
        self._init_global()

    def _init_global(self):
        """
        Init global object
        """
        self.context.xmlFile = os.path.realpath(self.context.xmlFile)
        self.static_cluster_info.initFromStaticConfig(self.context.user)
        self.xml_cluster_info.initFromXml(self.context.xmlFile)

        self.ssh_tool = SshTool(self.xml_cluster_info.getClusterNodeNames())

        self.new_nodes = [node for node in self.xml_cluster_info.dbNodes
                          for back_ip in node.backIps if back_ip in self.context.newHostList]

    @staticmethod
    def get_node_names(nodes):
        """
        Get node names from db_node_info object
        """
        return [node.name for node in nodes]

    def _change_user_without_root(self):
        """
        Change user to cluster user
        """
        if os.getuid() != 0:
            return
        self.ssh_tool.clenSshResultFiles()
        self.changeUser()
        self.ssh_tool = SshTool(self.xml_cluster_info.getClusterNodeNames())
        self.logger.log("Success to change user to [{0}]".format(self.user))

    def send_xml(self):
        """
        Send XML file to new node.
        """
        xml_dir = os.path.dirname(self.context.xmlFile)
        create_dir_cmd = g_file.SHELL_CMD_DICT["createDir"] % (xml_dir, xml_dir,
                                                               DefaultValue.MAX_DIRECTORY_MODE)
        create_dir_cmd += " && chown {0}:{1} {2}".format(self.user, self.group, xml_dir)
        self.ssh_tool.executeCommand(create_dir_cmd)
        self.ssh_tool.scpFiles(self.context.xmlFile, self.context.xmlFile,
                               hostList=self.get_node_names(self.new_nodes))
        self.logger.log("Success to send XML to new nodes")

    def preinstall_run(self):
        """
        preinstall layout
        """
        self.logger.log("Start to perform perinstall on nodes: "
                        "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))
        pre_install_path = os.path.realpath(os.path.join(self.context.packagepath,
                                                         "script", "gs_preinstall"))
        sep_env_file = "--sep-env-file={0}".format(EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH")) \
            if EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH") else ""
        cmd = "{0} -U {1} -G {2} -X {3} -L {4} " \
              "--non-interactive 2>&1".format(pre_install_path,
                                              self.user,
                                              self.group,
                                              self.context.xmlFile,
                                              sep_env_file)
        self.logger.log("Preinstall command is: {0}".format(cmd))
        result_map, output = \
            self.ssh_tool.getSshStatusOutput(cmd,
                                             ExpansionImplWithCm.get_node_names(self.new_nodes))

        self.logger.debug("Preinstall result: {0}".format(result_map))
        self.logger.debug("Preinstall output: {0}".format(output))

    def install_app(self):
        """
        Install app on new nodes
        """
        self.logger.log("Installing applications on all new nodes.")
        # Installing applications
        cmd = "source %s;" % self.envFile
        cmd += "%s -t %s -U %s -X %s -R %s -c %s -l %s" % (
            OMCommand.getLocalScript("Local_Install"),
            ACTION_INSTALL_CLUSTER,
            self.user + ":" + self.group,
            self.context.xmlFile,
            self.static_cluster_info.appPath,
            self.static_cluster_info.name,
            self.context.localLog)
        self.context.logger.debug(
            "Command for installing application: %s" % cmd)

        # exec the cmd for install application on all nodes
        result_map, output = \
            self.ssh_tool.getSshStatusOutput(cmd,
                                             ExpansionImplWithCm.get_node_names(self.new_nodes))
        self.logger.log("Install on new node output: {0}".format(output))
        if "Failure" in result_map.values():
            self.logger.debug(ErrorCode.GAUSS_527["GAUSS_52707"] %
                              [key for key in result_map.keys() if result_map[key] == "Failure"])
            raise Exception(ErrorCode.GAUSS_527["GAUSS_52707"] %
                              [key for key in result_map.keys() if result_map[key] == "Failure"])
        self.logger.log("Successfully installed APP on nodes "
                        "{0}.".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))

    def send_all_ca_file(self):
        """
        Send CM ca file to new nodes
        """
        ca_file_dir = os.path.realpath(os.path.join(self.static_cluster_info.appPath,
                                                    "share", "sslcert"))
        if not os.path.isdir(ca_file_dir):
            self.logger.log("Not exists CA directory [{0}].".format(ca_file_dir))
            return

        self.ssh_tool.scpFiles(ca_file_dir,
                               os.path.dirname(ca_file_dir),
                               ExpansionImplWithCm.get_node_names(self.new_nodes))
        self.logger.log("success to send all CA file.")

    def _get_local_cm_agent_dir(self):
        """
        Get cm_agent directory
        """
        local_node = [node for node in self.static_cluster_info.dbNodes
                      if node.name == NetUtil.GetHostIpOrName()][0]
        return local_node.cmDataDir

    def _create_cm_component_dir(self):
        """
        Create CM agnet directory
        """
        self.logger.debug("Create CM directory on remote node.")
        cmd = g_file.SHELL_CMD_DICT["createDir"] % (self._get_local_cm_agent_dir(),
                                                    self._get_local_cm_agent_dir(),
                                                    DefaultValue.MAX_DIRECTORY_MODE)
        cmd += " && chown -R {0}:{1} {2}".format(self.user, self.group,
                                                 self._get_local_cm_agent_dir())
        self.ssh_tool.getSshStatusOutput(cmd, ExpansionImplWithCm.get_node_names(self.new_nodes))
        self.logger.debug("Success to create CM directory on nodes "
                          "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))

    def _set_om_monitor_cron(self):
        """
        Set om_monitor crontab
        """
        self.logger.debug("Set om_monitor crontab on remote node.")
        cmd = "source %s;" % self.envFile
        cmd += "source {0};" \
               "{1} -U {2} -l {3}".format(self.envFile,
                                          OMCommand.getLocalScript("Local_Check_Config"),
                                          self.context.user, self.context.localLog)
        self.context.logger.debug(
            "Command for set node crontab: %s." % cmd)
        CmdExecutor.execCommandWithMode(
            cmd, self.ssh_tool,
            host_list=ExpansionImplWithCm.get_node_names(self.new_nodes))

        self.logger.debug("Success to set om_monitor crontab on nodes "
                          "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))

    def _init_instance(self):
        """
        Initial instance
        """
        self.logger.debug("Start initial instance.")
        cmd = "source {0}; " \
              "{1} -U {2} -l {3}".format(self.envFile,
                                         OMCommand.getLocalScript("Local_Init_Instance"),
                                         self.context.user, self.context.localLog)
        if self.xml_cluster_info.enable_dcf == "on":
            cmd += " --paxos_mode"
        self.context.logger.debug(
            "Command for initializing instances: %s" % cmd)
        CmdExecutor.execCommandWithMode(
            cmd, self.ssh_tool,
            host_list=ExpansionImplWithCm.get_node_names(self.new_nodes))
        self.logger.log("Success to init instance on nodes "
                        "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))

    def _backup_static_file(self):
        """
        Start backup static config file.
        """
        self.logger.debug("Start to backup static config file.")
        src_file = os.path.realpath(os.path.join(self.static_cluster_info.appPath,
                                                 "bin", "cluster_static_config"))
        dest_file = os.path.realpath(os.path.join(self.static_cluster_info.appPath,
                                                  "bin", "cluster_static_config_backup"))
        cmd = "cp {0} {1}".format(src_file, dest_file)
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool)
        self.logger.debug("Success to backup static config file.")

    def _get_pgxc_node_name_for_single_inst(self):
        """
        Get value of pgxc_node_name
        """
        all_dn_inst_id = [inst.instanceId for node in self.xml_cluster_info.dbNodes
                          for inst in node.datanodes]
        all_dn_inst_id = sorted(all_dn_inst_id)
        all_dn_inst_id = [str(inst_id) for inst_id in all_dn_inst_id]
        return "dn_{0}".format("_".join(all_dn_inst_id))

    def set_guc_for_datanode(self, para_list):
        """
        Set guc parameter.
        """
        node_name, inst_dir, para_name, para_value = para_list
        guc_path = os.path.join(os.path.realpath(self.static_cluster_info.appPath),
                                "bin", "gs_guc")
        para_str = " -c \"{0}='{1}'\" ".format(para_name, para_value)
        cmd = "{0} set -D {1} {2}".format(guc_path, inst_dir, para_str)
        self.logger.debug("Set guc parameter command: {0}".format(cmd))
        self.guc_executor(self.ssh_tool, cmd, node_name)
        self.logger.debug("Successfully set guc param [{0}] "
                          "on node [{1}]".format(para_name, node_name))

    def _set_other_guc_para(self):
        """
        Set pgxc_node_name on old nodes
        """
        self.logger.debug("Start to set other guc parameters.")

        # set port|application_name|log_directory|audit_directory on new nodes
        app_names = self.getIncreaseAppNames(len(self.new_nodes))
        log_path = ClusterDir.getUserLogDirWithUser(self.user)
        new_nodes_para_list = []
        for node,appname in zip(self.new_nodes, app_names):
            if node.datanodes:
                datains = node.datanodes[0]
                log_dir = "%s/pg_log/dn_%d" % (log_path, appname)
                audit_dir = "%s/pg_audit/dn_%d" % (log_path, appname)
                new_nodes_para_list.extend([
                    (node.name, datains.datadir, "port", datains.port),
                    (node.name, datains.datadir, "application_name", "dn_%s" % appname),
                    (node.name, datains.datadir, "log_directory", "%s" % log_dir),
                    (node.name, datains.datadir, "audit_directory", "%s" % audit_dir)
                ])

        for new_node_para in new_nodes_para_list:
            self.set_guc_for_datanode(new_node_para)
        # set dcf parameter on all nodes
        if self.xml_cluster_info.enable_dcf == "on":
            cmd_param = "*==SYMBOL==*-D*==SYMBOL==*%s" % (
                        "enable_dcf=" + self.xml_cluster_info.enable_dcf)
            cmd_param += "*==SYMBOL==*-S*==SYMBOL==*%s" % (
                         "enable_dcf=" + self.xml_cluster_info.enable_dcf)
            cmd_param += "*==SYMBOL==*-D*==SYMBOL==*%s" % (
                         "dcf_config=" + self.xml_cluster_info.dcf_config.replace('"', '\\"'))
            para_line = "*==SYMBOL==*-U*==SYMBOL==*%s%s" % (self.user, cmd_param)
            new_node_line = para_line + "*==SYMBOL==*-X*==SYMBOL==*%s" % self.context.xmlFile
            cmd = "source {0}; " \
                  "{1} {2}".format(self.envFile,
                                   OMCommand.getLocalScript("Local_Config_Instance"),
                                   DefaultValue.encodeParaline(new_node_line,
                                                               DefaultValue.BASE_ENCODE))
            self.logger.debug("Command for set dcf_config is : {0}."
                              "Parameter is: {1}".format(cmd, new_node_line))

            CmdExecutor.execCommandWithMode(cmd, self.ssh_tool,
                                            host_list=self.get_node_names(self.new_nodes))
            self.logger.log("Update dcf config on new nodes successfully.")
            old_node_cmd = "source {0}; " \
                  "{1} {2}".format(self.envFile,
                                   OMCommand.getLocalScript("Local_Config_Instance"),
                                   DefaultValue.encodeParaline(para_line,
                                                               DefaultValue.BASE_ENCODE))

            CmdExecutor.execCommandWithMode(old_node_cmd, self.ssh_tool,
                         host_list=self.get_node_names(self.static_cluster_info.dbNodes))
            self.logger.log("Update dcf config on old nodes successfully.")
        self.logger.debug("Set other guc parameters successfully.")

    def _set_pgxc_node_name(self):
        # 1.set pgxc_node_name on old nodes
        gauss_home = os.path.realpath(self.static_cluster_info.appPath)
        guc_path = os.path.join(gauss_home, "bin", "gs_guc")
        export_str = "export LD_LIBRARY_PATH={0}:" \
                     "$LD_LIBRARY_PATH".format(os.path.join(gauss_home, "lib"))
        cmd = "%s;%s set -N all -I all -c " \
              "\\\"%s='%s'\\\"" % (export_str, guc_path,
                                   "pgxc_node_name",
                                   self._get_pgxc_node_name_for_single_inst())
        su_cmd = """su - {0} -c "{1}" """.format(self.user, cmd)
        self.logger.debug("Set guc parameter command: {0}".format(su_cmd))
        self.guc_executor(self.ssh_tool, su_cmd, socket.gethostname())

    def _get_new_node_by_back_ip(self, back_ip):
        """
        Get inst from back IP
        """
        dest_nodes = [node for node in self.xml_cluster_info.dbNodes if back_ip in node.backIps]
        if dest_nodes:
            self.logger.debug("From back IP [{0}] find node [{1}]".format(back_ip, dest_nodes))
            return dest_nodes[0]
        self.logger.debug("Not find node from back IP [{0}]".format(back_ip))
        return None

    def _config_new_node_hba(self, host_ip):
        """
        Config pg_hba.conf on new nodes
        """
        new_node = self._get_new_node_by_back_ip(host_ip)
        new_inst = new_node.datanodes[0]
        cmd = "source {0};gs_guc set -D {1}".format(self.envFile, new_inst.datadir)
        cmd += " -h 'host    all    %s    %s/32    trust'" % (self.user, host_ip)
        cmd += " -h 'host    all    all    %s/32    sha256'" % host_ip
        self.logger.log("Ready to perform command on node [{0}]. "
                        "Command is : {1}".format(new_node.name, cmd))
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool, host_list=[new_node.name])

    def _config_pg_hba(self):
        """
        Config pg_hba.conf
        """
        self.addTrust()
        for node in self.context.newHostList:
            self._config_new_node_hba(node)
        self.logger.log("Successfully set hba on all nodes.")

    def _config_instance(self):
        """
        Config instance
        """
        self.logger.debug("Start config instance.")
        self.generateClusterStaticFile()
        self.setGucConfig()
        self._set_other_guc_para()
        self._config_pg_hba()
        self.distributeCipherFile()

    def _set_expansion_success(self):
        """
        Set expansionSuccess
        """
        for node in self.new_nodes:
            for back_ip in node.backIps:
                if back_ip in self.expansionSuccess.keys():
                    self.expansionSuccess[back_ip] = True

    def expansion_check(self):
        """
        Check cluster for expansion
        """
        self.checkUserAndGroupExists()
        self.checkXmlFileAccessToUser()
        self.checkClusterStatus()
        self.validNodeInStandbyList()

    def do_preinstall(self):
        """
        check preinstall on new node
        """
        if self.context.standbyLocalMode:
            self.logger.log("No need to do preinstall on local mode.")
            self.sendSoftToHosts(send_pkg=False)
            self.send_xml()
            return
        self.sendSoftToHosts()
        self.send_xml()
        self.preinstall_run()
        self._create_cm_component_dir()
        self._set_expansion_success()
        self.logger.log("Success to perform perinstall on nodes "
                        "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))

    def do_install(self, p_value):
        """
        Install app and instance
        """
        self._change_user_without_root()
        self.install_app()
        self.distributeCipherFile()
        if DefaultValue.is_create_grpc(self.logger,
                                       self.static_cluster_info.appPath):
            self.generateGRPCCert()
        self.send_all_ca_file()
        p_value.value = 1

    def do_config(self, p_value):
        """
        Config instance on new nodes
        """
        self._change_user_without_root()
        self._set_om_monitor_cron()
        self._init_instance()
        self._config_instance()
        p_value.value = 1

    def do_start(self, p_value):
        """
        Start cluster
        """
        self.logger.debug("Ready to restart cluster.")
        self._change_user_without_root()
        cm_component = CM_OLAP()
        cm_component.logger = self.logger
        cm_component.binPath = "%s/bin" % self.static_cluster_info.appPath
        cm_component.stop_cluster((0, "", 0, "", ""))
        DefaultValue.remove_metadata_and_dynamic_config_file(self.user,
                                                             self.ssh_tool, self.logger)
        if self.xml_cluster_info.enable_dcf == "on":
            cm_component.startCluster(self.user, isSwitchOver=False,
                                      timeout=DefaultValue.TIMEOUT_EXPANSION_SWITCH)
        else:
            cm_component.startCluster(self.user, timeout=DefaultValue.TIMEOUT_EXPANSION_SWITCH)
        p_value.value = 1

    def run(self):
        """
        This is class enter.
        """
        self.expansion_check()
        self.do_preinstall()
        self.logger.debug("[preinstall end] new nodes success: %s" % self.expansionSuccess)
        change_user_executor(self.do_install)
        change_user_executor(self.do_config)
        self._set_pgxc_node_name()
        change_user_executor(self.do_start)
        self.check_new_node_state(True)

