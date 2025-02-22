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
import re
import sys
import subprocess
import socket
import collections
import json

from multiprocessing import Process, Value
from time import sleep

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
from gspylib.component.DSS.dss_checker import DssConfig
from gspylib.component.DSS.dss_comp import DssInst


# Action type
ACTION_INSTALL_CLUSTER = "install_cluster"
ACTION_EXPAND_NODE ="expansion_node"


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
        self.old_nodes = list()
        self.app_names = list()
        self.node_name_map = collections.defaultdict(str)
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

        self.old_nodes = list(set(self.xml_cluster_info.dbNodes).difference(set(self.new_nodes)))

        back_ips = self.xml_cluster_info.getClusterBackIps()
        for i, ip in enumerate(back_ips):
            host = self.xml_cluster_info.getNodeNameByBackIp(ip)
            self.node_name_map[host] = (i, ip)

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
        self.ssh_tool.clen_ssh_result_files()
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
        self.ssh_tool.scpFiles(self.context.xmlFile, self.context.xmlFile)
        cmd = "chown %s:%s %s" % (self.user, self.group, self.context.xmlFile)
        self.ssh_tool.executeCommand(cmd)
        self.logger.log("Success to send XML to new nodes")

    def preinstall_run(self):
        """
        preinstall layout
        """
        self.logger.log("Start to perform perinstall on nodes: "
                        "{0}".format(ExpansionImplWithCm.get_node_names(self.new_nodes)))
        pre_install_path = os.path.realpath(os.path.join(self.remote_pkg_dir,
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

        failed_preinstall_hosts = []
        for host in ExpansionImplWithCm.get_node_names(self.new_nodes):
            sshTool = SshTool([host], timeout=300)
            result_map, output = sshTool.getSshStatusOutput(cmd, [])
            self.logger.debug(result_map)
            self.logger.debug(output)
            if result_map[host] == DefaultValue.SUCCESS:
                self.logger.log("Preinstall %s success" % host)
            else:
                failed_preinstall_hosts.append(host)
            self.cleanSshToolFile(sshTool)
        if failed_preinstall_hosts:
            self.logger.log("Failed to preinstall on: \n%s" % ", ".join(failed_preinstall_hosts))
        self.logger.log("End to preinstall database step.")

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

    def _reghl_new_nodes(self, is_reghl=False):
        """
        register dss for new nodes
        """
        if self.xml_cluster_info.enable_dss != 'on':
            return

        cmd = f"source {self.envFile};"
        if is_reghl:
            cmd += "dsscmd reghl;"
            self.logger.log(f"Command for reg dss is: {cmd}")
        else:
            cmd += "dsscmd unreghl;"
            self.logger.log(f"Command for unreg dss is: {cmd}")
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool,
                                        host_list=ExpansionImplWithCm.get_node_names(self.new_nodes))
        self.logger.log("Success to register dss on new nodes.")

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

        if self.xml_cluster_info.enable_dss == "on":
            dss_config = DssConfig.get_value_b64_handler(
                **{
                    'dss_nodes_list': self.context.clusterInfo.dss_config,
                    'share_disk_path': self.context.clusterInfo.cm_share_disk,
                    'voting_disk_path': self.context.clusterInfo.cm_vote_disk
                })
            cmd += f" --dss_mode --dss_config={dss_config}"

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
        log_path = ClusterDir.getUserLogDirWithUser(self.user)
        new_nodes_para_list = []
        for node,appname in zip(self.new_nodes, self.app_names):
            if node.datanodes:
                datains = node.datanodes[0]
                log_dir = "%s/pg_log/dn_%d" % (log_path, appname)
                audit_dir = "%s/pg_audit/dn_%d" % (log_path, appname)
                if "127.0.0.1" in datains.listenIps:
                    listen_ips = "%s" % ",".join(datains.listenIps)
                else:
                    listen_ips = "localhost,%s" % ",".join(datains.listenIps)
                new_nodes_para_list.extend([
                    (node.name, datains.datadir, "port", datains.port),
                    (node.name, datains.datadir, "application_name", "dn_%s" % appname),
                    (node.name, datains.datadir, "log_directory", "%s" % log_dir),
                    (node.name, datains.datadir, "audit_directory", "%s" % audit_dir),
                    (node.name, datains.datadir, "listen_addresses", listen_ips)
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
        cmd = "source %s; %s set -N all -I all -c " \
              "\\\"%s='%s'\\\"" % (self.envFile, guc_path,
                                   "pgxc_node_name",
                                   self._get_pgxc_node_name_for_single_inst())
        if self.context.current_root_user:
            su_cmd = """su - {0} -c "{1}" """.format(self.user, cmd)
        else:
            su_cmd = cmd
        self.logger.debug("Set guc parameter command: {0}".format(su_cmd))
        status, output = subprocess.getstatusoutput(su_cmd)
        if status == 0:
            self.logger.debug("Set pgxc_node_name successfully.")
        else:
            self.logger.debug("Set pgxc_node_name failed. "
                              "result is : {0}".format(output))
            raise Exception(ErrorCode.GAUSS_535["GAUSS_53507"] % su_cmd)

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
        submask_length = NetUtil.get_submask_len(host_ip)
        cmd += " -h 'host    all    %s    %s/%s    trust'" % (self.user, host_ip, submask_length)
        cmd += " -h 'host    all    all    %s/%s    sha256'" % (host_ip, submask_length)
        if self.xml_cluster_info.enable_dss == 'on':
            node_ips = [node.backIps[0] for node in self.old_nodes]
            for ip in node_ips:
                cmd += " -h 'host    all    all    %s/%s    sha256'" % (ip, submask_length)
        if self.xml_cluster_info.float_ips:
            submask_length = NetUtil.get_submask_len(self.xml_cluster_info.float_ips[new_inst.float_ips[0]])
            cmd += " -h 'host    all    all    %s/%s    sha256'" % \
                   (self.xml_cluster_info.float_ips[new_inst.float_ips[0]], submask_length)
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

    def _update_cm_res_json(self):
        """
        Update cm resource json file.
        """
        if not self.xml_cluster_info.float_ips:
            self.logger.log("The current cluster does not support VIP.")
            return
        self.logger.log("Updating cm resource file on all nodes.")
        cmd = "source %s; " % self.envFile
        cmd += "%s -t %s -U %s -X '%s' -l '%s' " % (
               OMCommand.getLocalScript("Local_Config_CM_Res"), ACTION_EXPAND_NODE,
               self.context.user, self.context.xmlFile, self.context.localLog)
        self.logger.debug("Command for updating cm resource file: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool)
        self.logger.log("Successfully updated cm resource file.")

    def update_guc_param(self):
        """
        Keep ss_interconnect_channel_count same with origin node.
        """
        port = EnvUtil.getEnv("PGPORT")
        get_cmd = "gsql -d postgres -p %s -A -t -c 'show ss_interconnect_channel_count;'" % port
        sta, out = subprocess.getstatusoutput(get_cmd)
        channel_count = int(out)
        set_cmd = ""
        for node in self.new_nodes:
            ssh_tool = SshTool([node.name], timeout=300)
            pgdata_path = node.datanodes[0].datadir
            set_cmd = "gs_guc set -D %s -c 'ss_interconnect_channel_count = %d'" % (pgdata_path, channel_count)
            self.logger.debug("Command for update guc param: %s" % set_cmd)
            result_map, _ = ssh_tool.getSshStatusOutput(set_cmd, [])
            if result_map[node.name] == DefaultValue.SUCCESS:
                self.logger.log("Update ss_interconnect_channel_count on %s success." % node.name)
            else:
                self.logger.log("Update ss_interconnect_channel_count on %s failed." % node.name)
                raise Exception("Update ss_interconnect_channel_count on %s failed." % node.name)

    def _config_instance(self):
        """
        Config instance
        """
        self.logger.debug("Start config instance.")
        self.check_cm_enable_availablezone()
        self.generateClusterStaticFile()
        self.setGucConfig()
        self._set_other_guc_para()
        self._update_cm_res_json()
        self._config_pg_hba()
        self.distributeCipherFile()
        self.update_guc_param()

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

    def get_env(self, env):
        """
        Get dss_home when current user is root.
        """
        cmd = f"cat {self.envFile} | grep {env} | grep /"
        if os.getuid() == 0:
            cmd = f"su - {self.user} -c '{cmd}'"
        sta, out = subprocess.getstatusoutput(cmd)
        value = out.split('=')[-1]
        return value

    def get_nodes_list(self, port, hosts):
        """
        Check dss_nodes_list and change it if invalied.
        """
        cur_lists = list()
        for host in hosts:
            cur_lists.append(str(self.node_name_map[host][0]) + ":" + self.node_name_map[host][1] + ":" + port)
        cur_list = ','.join(cur_lists)
        return cur_list

    def update_dss_inst(self, old_hosts, hosts):
        """
        Update dss_nodes_list on old nodes.
        """
        dss_home = self.get_env("DSS_HOME")
        dss_inst = dss_home + '/cfg/dss_inst.ini'
        if os.getuid() == 0:
            get_list_cmd = f"su - {self.user} -c 'cat {dss_inst} | grep DSS_NODES_LIST'"
        else:
            get_list_cmd = f'cat {dss_inst} | grep DSS_NODES_LIST'
        status, output = subprocess.getstatusoutput(get_list_cmd)
        if status != 0:
            self.logger.debug("Failed to get old DSS_NODES_LIST.")
            raise Exception("Failed to get old DSS_NODES_LIST.")
        port = output.split(":")[-1]
        new_list = 'DSS_NODES_LIST=' + self.get_nodes_list(port, hosts)
        update_list_cmd = "sed -i 's/^.*DSS_NODES_LIST.*$/%s/' %s" % (new_list, dss_inst)
        if os.getuid() == 0:
            update_list_cmd = f"su - {self.user} -c '{update_list_cmd}'"
        self.logger.debug("Command for update dss_inst: %s" % update_list_cmd)
        for host in old_hosts:
            sshTool = SshTool([host], timeout=300)
            result_map, _ = sshTool.getSshStatusOutput(update_list_cmd, [])
            if result_map[host] == DefaultValue.SUCCESS:
                self.logger.log("Update dss_inst.ini on %s success." % host)
            else:
                self.logger.debug("Failed to update dss_inst.ini on %s" % host)
                raise Exception("Failed to update dss_inst.ini on %s" % host)
        self.logger.log("Successfully update dss_inst.ini on old nodes.")

        return new_list

    def update_guc_url(self, node_list):
        """
        Update ss_interconnect_url on old nodes.
        """
        pgdata_path = self.get_env("PGDATA")
        conf_file = pgdata_path + os.sep + 'postgresql.conf'
        get_url_cmd = "grep -n 'ss_interconnect_url' %s" % conf_file
        sta, out = subprocess.getstatusoutput(get_url_cmd)
        url = eval(out.split('=')[-1].strip())
        url_port = (url.split(',')[0]).split(':')[-1]
        dss_port = (node_list.split(',')[0]).split(':')[-1]
        new_url = node_list.replace(dss_port, url_port)

        guc_cmd = "grep -n 'ss_interconnect_url' %s | cut -f1 -d: | xargs -I {} sed -i {}\'s/%s/%s/g' %s" % (
                  conf_file, url, new_url, conf_file)
        self.logger.debug("Command for update ss_interconnect_url: %s" % guc_cmd)
        for node in self.old_nodes:
            ssh_tool = SshTool([node.name], timeout=300)
            pgdata_file = node.datanodes[0].datadir + os.sep + 'postgresql.conf'
            guc_cmd = "grep -n 'ss_interconnect_url' %s | cut -f1 -d: | xargs -I {} sed -i {}\'s/%s/%s/g' %s" % (
                  pgdata_file, url, new_url, pgdata_file)
            self.logger.debug("host %s Command for update ss_interconnect_url: %s" % (node.name, guc_cmd))
            result_map, _ = ssh_tool.getSshStatusOutput(guc_cmd, [])
            if result_map[node.name] == DefaultValue.SUCCESS:
                self.logger.log("Update ss_interconnect_url on %s success." % node.name)
            else:
                self.logger.debug("Failed to update ss_interconnect_url on %s" % node.name)
                raise Exception("Failed to update ss_interconnect_url on %s" % node.name)
        self.logger.log("Successfully update ss_interconnect_url on old nodes.")

    def update_old_cm_res(self):
        """
        Update cm_resource.json on old nodes.
        """
        get_last_cmd = "cm_ctl res --list --res_name='dss' --list_inst | awk 'END{print $5, $7, $9, $10}'"
        (status, output) = subprocess.getstatusoutput(get_last_cmd)
        node_id, inst_id, dss_home, dn_home = output.split(' ')
        res_args = dss_home + ' ' + dn_home

        update_cmd = ''
        for i in range(len(self.new_nodes)):
            inst_info = "node_id=%d,res_instance_id=%d,res_args=%s" % (int(node_id)+i+1, int(inst_id)+i+1, res_args)
            update_cmd += "cm_ctl res --edit --res_name='dss' --add_inst='%s'" % inst_info
            if i < len(self.new_nodes) - 1:
                update_cmd += " && "
        self.logger.debug("Command for update cm_resource.json: %s" % update_cmd)
        for host in ExpansionImplWithCm.get_node_names(self.old_nodes):
            sshTool = SshTool([host], timeout=300)
            result_map, _ = sshTool.getSshStatusOutput(update_cmd, [])
            if result_map[host] == DefaultValue.SUCCESS:
                self.logger.log("Update cm_resource.json on %s success" % host)
            else:
                self.logger.debug("Failed to update cm_resource.json on %s" % host)
                raise Exception("Failed to update cm_resource.json on %s" % host)
        self.logger.log("Successfully update cm_resource.json on old nodes.")

    def update_old_dss_info(self):
        """
        Update new node's dss on old nodes.
        """
        if self.xml_cluster_info.enable_dss != 'on':
            return

        old_hosts = [node.name for node in self.old_nodes]
        new_hosts = [node.name for node in self.new_nodes]
        node_list = self.update_dss_inst(old_hosts, old_hosts + new_hosts)
        self.update_guc_url(node_list.split('=')[-1])

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
        self._reghl_new_nodes(is_reghl=True)
        self._init_instance()
        self._config_instance()
        self._reghl_new_nodes(is_reghl=False)
        p_value.value = 1

    def do_restart(self, p_value):
        """
        Restart cluster when enable_dss to sync params on new standby.
        """
        if self.xml_cluster_info.enable_dss != 'on':
            return
        self.logger.debug("Ready to restart cluster.")
        self._change_user_without_root()
        self.ss_restart_cluster()
        p_value.value = 1

    def do_start(self, p_value):
        """
        Start cluster
        """
        self.logger.debug("Ready to restart cm_server cluster.")
        self._change_user_without_root()
        if self.xml_cluster_info.enable_dss == 'on':
            self.update_old_cm_res()
            self.check_processes()
            DefaultValue.remove_metadata_and_dynamic_config_file(self.user, self.ssh_tool, self.logger)
            self.ss_restart_cluster()
            p_value.value = 1
            return
        # stop CM processes in existed nodes
        clusterInfo = dbClusterInfo()
        clusterInfo.initFromStaticConfig(self.user)
        stopCMProcessesCmd = "pkill -9 om_monitor -U {user}; pkill -9 cm_agent -U {user}; " \
            "pkill -9 cm_server -U {user};".format(user=self.user)
        self.logger.debug("stopCMProcessesCmd: " + stopCMProcessesCmd)
        hostList = [node.name for node in clusterInfo.dbNodes]
        newNodesList = [node.name for node in self.new_nodes]
        existingHosts = [host for host in hostList if host not in newNodesList]
        gaussHome = EnvUtil.getEnv("GAUSSHOME")
        gaussLog = EnvUtil.getEnv("GAUSSLOG")
        CmdExecutor.execCommandWithMode(stopCMProcessesCmd, self.ssh_tool, host_list=existingHosts)
        DefaultValue.remove_metadata_and_dynamic_config_file(self.user, self.ssh_tool, self.logger)
        # execute gs_guc reload
        self._gsctlReload()
        # start CM processes on old and new nodes
        startCMProcessesCmd = "source %s; nohup %s/bin/om_monitor -L %s/cm/om_monitor >> /dev/null 2>&1 & \n" \
            "rm %s/bin/cluster_manual_start -rf" % (self.envFile, gaussHome, gaussLog, gaussHome)
        self.logger.debug("startCMProcessesCmd: " + startCMProcessesCmd)
        CmdExecutor.execCommandWithMode(startCMProcessesCmd, self.ssh_tool, host_list=hostList)
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
                "All steps of expansion have finished, but failed to wait cluster to be normal in 600s!\n"
                "HINT: Maybe the cluster is continually being started in the background.\n"
                "You can wait for a while and check whether the cluster starts.")
        p_value.value = 1

    def _gsctlReload(self):
        # execute gs_ctl reload
        ctlPath = os.path.join(os.path.realpath(self.static_cluster_info.appPath), "bin", "gs_ctl")
        nodeDict = self.context.clusterInfoDict
        localHost = socket.gethostname()
        dataPath = nodeDict[localHost]["dataNode"]
        ctlReloadCmd = "source %s; %s reload -N all -D %s" % (self.envFile, ctlPath, dataPath)
        self.logger.debug("ctlReloadCmd: " + ctlReloadCmd)
        CmdExecutor.execCommandWithMode(ctlReloadCmd, self.ssh_tool, host_list=[localHost])

    def recover_old_dss_info(self, old_hosts):
        """
        Recover old nodes dss info when expansion failed.
        """
        node_list = self.update_dss_inst(old_hosts, old_hosts)
        self.update_guc_url(node_list.split('=')[-1])
        self.logger.debug("Successfully recover dss_nodes_list and ss_interconnect_url on old nodes.")

    def recover_new_nodes(self):
        """
        Uninstall app on new nodes when expansion failed.
        """
        new_hosts = [node.name for node in self.new_nodes]
        cmd = f"source {self.envFile}; gs_uninstall --delete-data -L"
        if os.getuid() == 0:
            cmd = f"su - {self.user} -c '{cmd}'"
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool, host_list=new_hosts)
        self.logger.debug("Successfully uninstall app on new nodes.")

    def recover_old_cm_res(self, old_hosts):
        """
        Recover cm_resource.json on old nodes.
        """
        cm_component = CM_OLAP()
        cm_component.binPath = os.path.realpath(os.path.join(
            self.context.clusterInfo.appPath, "bin"))
        local_node = [node for node in self.context.clusterInfo.dbNodes
                      if NetUtil.GetHostIpOrName() == node.name][0]
        local_name = NetUtil.getHostName()
        cm_component.instInfo = local_node.cmagents[0]
        cm_res_file = os.path.realpath(
                      os.path.join(cm_component.instInfo.datadir, "cm_resource.json"))
        
        with open(cm_res_file, "r") as f:
            data = json.load(f)
        insts_list = data["resources"][1]["instances"]
        for i, _ in enumerate(self.new_nodes):
            insts_list.pop()
        with open(cm_res_file, "w") as f:
            json.dump(data, f, indent=4)
        for host in old_hosts:
            if host == local_name:
                continue
            host_ssh = SshTool([host])
            host_ssh.scpFiles(cm_res_file, cm_res_file)

        self.logger.debug("Successfully recover cm_resource.json on old nodes.")

    def recover_static_conf(self):
        """
        Recover the cluster static conf and save it.
        """
        master_instance = 0
        local_name = NetUtil.GetHostIpOrName()
        self.logger.log("Begin to recover the cluster static conf.")
        tmp_dir = EnvUtil.getEnvironmentParameterValue("PGHOST", self.user, self.envFile)
        config_path = "%s/bin/cluster_static_config" % self.static_cluster_info.appPath
        for node in self.new_nodes:
            dn_loop = self.context.clusterInfo.getDbNodeByName(node.name)
            self.context.clusterInfo.dbNodes.remove(dn_loop)
        for node in self.old_nodes:
            if node.name == local_name:
                if len(node.datanodes) > 0:
                    node.datanodes[0].instanceType = master_instance
                    break
        for node in self.old_nodes:
            if node.name == local_name:
                self.context.clusterInfo.saveToStaticConfig(config_path, node.id)
                continue
            config_path_dn = "%s/cluster_static_config_%s" % (tmp_dir, node.name)
            self.context.clusterInfo.saveToStaticConfig(config_path_dn, node.id)

        cmd = "source %s; gs_om -t refreshconf" % self.envFile
        subprocess.getstatusoutput(cmd)
        old_hosts = [node.name for node in self.old_nodes]
        for host in old_hosts:
            host_ssh = SshTool([host])
            if host != local_name:
                config_name = "%s/cluster_static_config_%s" % (tmp_dir, host)
                host_ssh.scpFiles(config_name, config_path, [host], self.envFile)
                try:
                    os.unlink(config_name)
                except FileNotFoundError:
                    pass
        self.logger.log("End of recover the cluster static conf.")

    def get_normal_host(self):
        """
        Get host status normal.
        """
        cmd = "cm_ctl query -Cv | awk 'END{print}'"
        status, output = subprocess.getstatusoutput(cmd)
        nodes_list = list(filter(None, output.split('|')))
        for node in nodes_list:
            status = list(filter(None, node.split(' ')))[-1]
            node_name = list(filter(None, node.split(' ')))[1]
            if status == "Normal":
                return node_name
        return None

    def clean_disk(self):
        """
        Delete new_node pg_xlog and pg_doublewrite. 
        """
        vg_name = EnvUtil.getEnv("VGNAME")
        dss_home = self.get_env("DSS_HOME")
        dss_inst = dss_home + '/cfg/dss_inst.ini'
        get_list_cmd = "cat %s | grep DSS_NODES_LIST" % dss_inst
        status, output = subprocess.getstatusoutput(get_list_cmd)
        lists = (output.split('=')[-1]).split(',')
        res_ids = set()
        for item in lists:
            res_ids.add(int(item[0]))

        normal_host = self.get_normal_host()
        if not normal_host:
            self.logger.debug("No normal node in cluster now, please clean dss dir before next expansion.")
            return

        get_xlog_cmd = "dsscmd ls -p +%s | grep pg_xlog | awk '{print $6}'" % vg_name
        host_ssh = SshTool([normal_host])
        result_map, output = host_ssh.getSshStatusOutput(get_xlog_cmd, [normal_host], self.envFile)
        out_lines = output.split('\n')
        xlog_list = list()
        for out_line in out_lines:
            xlog_list.append(re.findall(r"pg_xlog[0-9]", out_line))
        xlog_list = list(filter(None, xlog_list))
        del_cmd = ""
        for xlog_n in xlog_list:
            if int(xlog_n[0][-1]) not in res_ids:
                dw_path = 'pg_doublewrite' + xlog_n[0][-1]
                pri_vgname = DssInst.get_private_vgname_by_ini(dss_home, int(xlog_n[0][-1]))
                del_cmd += "dsscmd unlink -p +%s/%s; dsscmd rmdir -p +%s/%s -r; dsscmd rmdir -p +%s/%s -r;" % (
                    vg_name, xlog_n[0], pri_vgname, xlog_n[0], vg_name, dw_path)
        result_map, _ = host_ssh.getSshStatusOutput(del_cmd, [normal_host])
        if "Success" not in result_map.values():
            self.logger.debug("Failed to delete xlog of new hosts.")
            raise Exception("Failed to delete xlog of new hosts.")
        self.logger.debug("Successfully delete xlog of new hosts.")

    def recover_cluster(self):
        """
        Recover cluster when expansion failed.
        """
        self.logger.log("Begin to recover cluster.")
        if self.xml_cluster_info.enable_dss == "on":
            old_nodes = [node.name for node in self.old_nodes]
            self.recover_old_dss_info(old_nodes)
            self.recover_old_cm_res(old_nodes)
            self.clean_disk()
        self.recover_new_nodes()
        self.recover_static_conf()
        DefaultValue.remove_metadata_and_dynamic_config_file(self.user, self.ssh_tool, self.logger)
        self.logger.log("Successfully recover cluster.")
        self.check_new_node_state(False)
        sys.exit(1)

    def check_processes(self):
        """
        Check processes exist or not before restart cluster.
        """
        check_cmd = ""
        processes = {"om_monitor", "cm_agent", "dssserver"}
        old_nodes = [node.name for node in self.old_nodes]
        for process in processes:
            check_cmd = f"ps ux | grep {process} | grep -v grep | wc -l"
            for node in old_nodes:
                ssh_tool = SshTool([node])
                result_map, output_map = ssh_tool.getSshStatusOutput(check_cmd, [])
                if result_map[node] != DefaultValue.SUCCESS:
                    self.logger.debug(f"Failed to check process on node {node}.")
                    raise Exception(f"Failed to check process on node {node}.")
                proc_num = int(output_map.split('\n')[1])
                if proc_num < 1:
                    self.logger.log(f"No {process} on {node}, need to expand again.")
                    self.recover_cluster()
        self.logger.log("Successfully check processes on cluster nodes.")

    def ss_restart_cluster(self):
        """
        Restart cluster on dss_mode.
        """
        if self.xml_cluster_info.enable_dss != "on":
            return
        restart_cmd = f"source {self.envFile}; cm_ctl stop; cm_ctl start;"
        status, _ = subprocess.getstatusoutput(restart_cmd)
        if status != 0:
            self.logger.debug("Failed to restart cluster when dss enabled.")
            raise Exception("Failed to restart cluster when dss enabled.")
        self.logger.log("Successfully restart cluster when dss enabled.")

    def run(self):
        """
        This is class enter.
        """
        self.expansion_check()
        self.update_old_dss_info()
        self.do_preinstall()
        self.logger.debug("[preinstall end] new nodes success: %s" % self.expansionSuccess)
        self.app_names = self.getIncreaseAppNames(len(self.new_nodes))
        self.logger.debug("get increase application names %s" % self.app_names)
        change_user_executor(self.do_install)
        change_user_executor(self.do_config)
        change_user_executor(self.do_start)
        change_user_executor(self.do_restart)
        change_user_executor(self.check_tblspc_directory)
        self.check_new_node_state(True)
