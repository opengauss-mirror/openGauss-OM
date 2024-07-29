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
import json

sys.path.append(sys.path[0] + "/../../../../")
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil
from base_utils.executor.cmd_executor import CmdExecutor
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.component.CM.CM_OLAP.CM_OLAP import CM_OLAP
from gspylib.threads.SshTool import SshTool
from gspylib.os.gsfile import g_file
from impl.dropnode.DropnodeImpl import DropnodeImpl
from base_utils.os.file_util import FileUtil
from gspylib.component.DSS.dss_comp import Dss, DssInst


# Action type
ACTION_DROP_NODE = "drop_node"


class DropNodeWithCmImpl(DropnodeImpl):
    def __init__(self, drop_node):
        super(DropNodeWithCmImpl, self).__init__(drop_node)
        self.drop_nodes = list()
        self.stoped_nodes = list()
        self.cm_component = None
        self.ssh_tool = None
        self.dss_mode = False

    def check_dss_mode(self):
        """
        Check if on dss_mode.
        """
        if EnvUtil.getEnv("DSS_HOME"):
            self.dss_mode = True

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

    def backup_cm_res_json(self):
        """
        Backup cm resource json on primary node
        """
        cm_resource = os.path.realpath(
                      os.path.join(self.cm_component.instInfo.datadir, "cm_resource.json"))
        backup_cm_res = os.path.realpath(
                        os.path.join(self.pghostPath, "cm_resource_bak.json"))
        if not os.path.isfile(backup_cm_res):
            FileUtil.cpFile(cm_resource, backup_cm_res)

    def get_del_res_info(self, nodeId):
        """
        Get res info through nodeId.
        """
        cm_res_file = os.path.join(self.instInfo.datadir, "cm_resource.json")
        with open(cm_res_file, "r") as f:
            data = json.load(f)
        
        res_info = ''
        instances = data["resources"][-1]["instances"]
        for ins in instances:
            if ins["node_id"] == nodeId:
                res_info = "node_id=%d,res_instance_id=%s,res_args=%s" % (
                            nodeId, ins["res_instance_id"], ins["res_args"])
                break
        return res_info

    def get_update_res_cmd(self, hostName):
        """
        Get update cm_resource.json cmd for del host.
        """
        get_id_cmd = "cm_ctl query -Cv | grep %s | awk 'NR=1{print $1}'" % hostName
        status, output = subprocess.getstatusoutput(get_id_cmd)
        node_id = int(output)
        res_info = self.get_del_res_info(node_id)
        update_cmd = "cm_ctl res --edit --res_name='dss' --del_inst='%s'" % res_info
        return update_cmd

    def update_cm_res_json(self):
        """
        Update cm resource json file.
        """
        if self.dss_mode:
            self.update_old_cm_res()
            return
        
        if not self.commonOper.check_is_vip_mode():
            self.logger.log("The current cluster does not support VIP.")
            return

        self.backup_cm_res_json()
        self.logger.log("Updating cm resource file on exist nodes.")
        del_hosts = ",".join(self.context.hostMapForDel.keys())
        cmd = "source %s; " % self.userProfile
        cmd += "%s -t %s -U %s -H %s -l '%s' " % (
                OMCommand.getLocalScript("Local_Config_CM_Res"),
                ACTION_DROP_NODE, self.user, del_hosts, self.context.localLog)
        self.logger.debug("Command for updating cm resource file: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd, self.ssh_tool,
                                        host_list=self.context.hostMapForExist.keys())
        self.logger.log("Successfully updated cm resource file.")

    def update_dss_inst(self):
        """
        Update dss_inst.ini.
        """
        dss_home = EnvUtil.get_dss_home()
        dss_inst = dss_home + '/cfg/dss_inst.ini'
        get_list_cmd = "cat %s | grep DSS_NODES_LIST" % dss_inst
        status, output = subprocess.getstatusoutput(get_list_cmd)
        old_list = output.split('=')[1]
        old_nodes = old_list.split(',')
        del_hosts = [self.context.hostMapForDel[hostName]["ipaddr"] for hostName in self.context.hostMapForDel.keys()]
        for host in del_hosts:
            for node in old_nodes:
                if host in node:
                    old_nodes.remove(node)
                    break
        new_list = ",".join(old_nodes)

        update_cmd = "sed -i 's/%s/%s/g' %s" % (old_list, new_list, dss_inst)
        self.logger.debug("Command for update dss_inst.ini: %s" % update_cmd)
        CmdExecutor.execCommandWithMode(update_cmd, self.ssh_tool, host_list=self.context.hostMapForExist.keys())
        self.logger.log("Successfully update dss_inst.ini on old nodes.")

        return new_list

    def update_ss_url(self, node_list):
        """
        Update ss_interconnect_url on old nodes.
        """
        pg_port = EnvUtil.getEnv("PGPORT")
        get_url_cmd = f"gsql -d postgres -p {pg_port} -c 'show ss_interconnect_url;'"
        sta, out = subprocess.getstatusoutput(get_url_cmd)
        url = out.split('\n')[2]
        url_port = (url.split(',')[0]).split(':')[-1]
        dss_port = (node_list.split(',')[0]).split(':')[-1]
        new_url = "ss_interconnect_url='%s'" % node_list.replace(dss_port, url_port)

        update_cmd = 'gs_guc set -N all -I all -c "%s"' % new_url
        self.logger.debug("Command for update ss_interconnect_url: %s" % update_cmd)
        CmdExecutor.execCommandLocally(update_cmd)
        self.logger.log("Successfully reset ss_interconnect_url.")

    def update_dss_info(self):
        """
        Delete dss info on existing nodes.
        """
        if not self.dss_mode:
            return

        node_list = self.update_dss_inst()
        self.update_ss_url(node_list)

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
        if self.dss_mode:
            self.ss_restart_cluster()

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

    def restore_cm_res_json(self):
        """
        Restore cm resource json on primary node
        """
        cm_resource = os.path.realpath(
                      os.path.join(self.cm_component.instInfo.datadir, "cm_resource.json"))
        backup_cm_res = os.path.realpath(
                        os.path.join(self.pghostPath, "cm_resource_bak.json"))
        if os.path.isfile(backup_cm_res):
            FileUtil.cpFile(backup_cm_res, cm_resource)

    def clean_del_dss(self):
        """
        Clean del_hosts on dss disk.
        """
        if not self.dss_mode:
            return

        vg_name = EnvUtil.getEnv("VGNAME")
        dss_home = EnvUtil.get_dss_home()
        dss_inst = dss_home + '/cfg/dss_inst.ini'
        get_list_cmd = "cat %s | grep DSS_NODES_LIST" % dss_inst
        status, output = subprocess.getstatusoutput(get_list_cmd)
        lists = (output.split('=')[-1]).split(',')
        res_ids = set()
        for item in lists:
            res_ids.add(int(item[0]))

        getXLog_cmd = "dsscmd ls -p +%s | grep pg_xlog | awk '{print $6}'" % vg_name
        sta, out = subprocess.getstatusoutput(getXLog_cmd)
        xlog_list = out.split('\n')
        del_cmd = ""
        for xlog_n in xlog_list:
            if int(xlog_n[-1]) not in res_ids:
                dw_path = 'pg_doublewrite' + xlog_n[-1]
                pri_vgname = DssInst.get_private_vgname_by_ini(dss_home, int(xlog_n[-1]))
                del_cmd += "dsscmd unlink -p +%s/%s; dsscmd rmdir -p +%s/%s -r; dsscmd rmdir -p +%s/%s -r;" % (
                    vg_name, xlog_n, pri_vgname, xlog_n, vg_name, dw_path)
        del_sta, del_out = subprocess.getstatusoutput(del_cmd)
        if del_sta != 0:
            self.logger.debug("Failed to delete xlog of del hosts.")
            raise Exception("Failed to delete xlog of del hosts.")
        self.logger.debug("Successfully delete xlog of del hosts.")

    def get_res_info(self, nodeId):
        """
        Get del id res info.
        """
        cm_cmd = "cm_ctl res --list --res_name='dss' --list_inst"
        _, output = subprocess.getstatusoutput(cm_cmd)
        cm_res = output.split('\n')
        if len(cm_res) <= 5:
            self.logger.debug("cm_res info invalid.")
            raise Exception("cm_res info invalid.")

        res_id = -1
        res_args = ""
        for i in range(5, len(cm_res)):
            infos = cm_res[i].split('|')
            if int(infos[2]) == nodeId:
                res_id, res_args = int(infos[3]), infos[4]
                break
        res_info = "node_id=%d,res_instance_id=%d,res_args=%s" % (nodeId, res_id, res_args)
        return res_info

    def get_del_cm_res(self):
        """
        Get cm_res info for del nodes.
        """
        res_infos = list()
        node_ids = list()
        for node in self.context.hostMapForDel.keys():
            cmd = "cm_ctl query -Cv | grep %s | awk 'NR==1{print $1}'" % node
            _, output = subprocess.getstatusoutput(cmd)
            node_ids.append(int(output))

        for id in node_ids:
            res_info = self.get_res_info(id)
            res_infos.append(res_info)
        return res_infos

    def update_old_cm_res(self):
        """
        Update cm res info on old nodes.
        """
        res_infos = self.get_del_cm_res()
        del_cmd = ""
        for info in res_infos:
            del_cmd += "cm_ctl res --edit --res_name='dss' --del_inst='%s';" % info
        self.logger.log("Command for del cm_res on old nodes: %s" % del_cmd)
        CmdExecutor.execCommandWithMode(del_cmd, self.ssh_tool, host_list=self.context.hostMapForExist.keys())
        self.logger.log("Successfully del cm_res on old nodes.")

    def ss_restart_cluster(self):
        """
        Restart new cluster.
        """
        if not self.dss_mode:
            return
        restart_cmd = "cm_ctl stop; cm_ctl start;"
        status, _ = subprocess.getstatusoutput(restart_cmd)
        if status != 0:
            self.logger.debug("Failed to restart cluster when dss enabled.")
            raise Exception("Failed to restart cluster when dss enabled.")
        self.logger.log("Successfully restart cluster.")

    def remove_cm_res_backup(self):
        """
        Remove cm resource backup on primary node
        """
        backup_cm_res = os.path.realpath(
                        os.path.join(self.pghostPath, "cm_resource_bak.json"))
        if os.path.isfile(backup_cm_res):
            os.remove(backup_cm_res)
            self.logger.log("Successfully remove cm resource backup file")

    def run(self):
        """
        start dropnode
        """
        self.logger.log("Drop node with CM node is running.")
        self.check_dss_mode()
        self.init_global_value()
        self.check_drop_cm_node()
        self.change_user()
        self.logger.log("[gs_dropnode]Start to drop nodes of the cluster.")
        self.restore_cm_res_json()
        self.checkAllStandbyState()
        self.dropNodeOnAllHosts()
        self.operationOnlyOnPrimary()
        self.update_cm_res_json()
        self.update_dss_info()
        self._stop_drop_node()
        self._generate_flag_file_on_drop_nodes()
        self.modifyStaticConf()
        self.clean_del_dss()
        self.restart_new_cluster()
        self.remove_cm_res_backup()
        self.logger.log("[gs_dropnode] Success to drop the target nodes.")