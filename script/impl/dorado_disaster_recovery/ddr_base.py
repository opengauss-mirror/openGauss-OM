#!/usr/bin/env python3
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
# Description  : ddr_base.py is a base module for dorado disaster recovery.
#############################################################################
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from datetime import timedelta

from domain_utils.cluster_file.version_info import VersionInfo
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.Common import DefaultValue, ClusterInstanceConfig
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.threads.SshTool import SshTool
from gspylib.threads.parallelTool import parallelTool
from gspylib.os.gsfile import g_file
from base_utils.os.cmd_util import CmdUtil, FastPopen
from base_utils.os.env_util import EnvUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.user_util import UserUtil
from base_utils.security.sensitive_mask import SensitiveMask
from base_utils.common.constantsbase import ConstantsBase
from impl.streaming_disaster_recovery.streaming_base import StreamingBase
from impl.dorado_disaster_recovery.ddr_constants import DoradoDisasterRecoveryConstants

class DoradoDisasterRecoveryBase(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dorado_file_dir = os.path.join(self.pg_host, DoradoDisasterRecoveryConstants.DDR_FILES_DIR)
        self.dorado_xml = os.path.join(self.dorado_file_dir, DoradoDisasterRecoveryConstants.DDR_CONFIG_XML)
        self.streaming_file_dir = self.dorado_file_dir
        self.dss_home_dir = self.cluster_info.dss_home
        self.init_step_file_path()

    def init_step_file_path(self):
        """
        Init step file path
        """
        if self.params.task == DoradoDisasterRecoveryConstants.ACTION_START:
            if self.params.mode == "primary":
                step_file_name = DoradoDisasterRecoveryConstants.DDR_STEP_FILES["start_primary"]
            elif self.params.mode == "disaster_standby":
                step_file_name = DoradoDisasterRecoveryConstants.DDR_STEP_FILES["start_standby"]
            else:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "init step file path")
        elif self.params.task == DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
            if self.params.mode == "primary":
                step_file_name = DoradoDisasterRecoveryConstants.DDR_STEP_FILES["switchover_primary"]
            elif self.params.mode == "disaster_standby":
                step_file_name = DoradoDisasterRecoveryConstants.DDR_STEP_FILES["switchover_standby"]
            else:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "init step file path")
        else:
            step_file_name = DoradoDisasterRecoveryConstants.DDR_STEP_FILES[self.params.task]
        self.step_file_path = os.path.join(self.dorado_file_dir, step_file_name)
        self.logger.debug("Init step file:%s." % self.step_file_path)

    def create_disaster_recovery_dir(self, dir_path):
        """
        Create dorado disaster recovery files dir.
        """
        self.create_streaming_dir(dir_path)

    def handle_lock_file(self, trace_id, action):
        """
        Create lock file for other dorado process.
        """
        if self.params.task not in DoradoDisasterRecoveryConstants.TASK_EXIST_CHECK:
            return
        file_name = DoradoDisasterRecoveryConstants.PROCESS_LOCK_FILE + trace_id
        file_path = os.path.join(self.pg_host, file_name)
        self.logger.debug("Start %s lock file:%s." % (action, file_path))
        if action == 'create':
            FileUtil.createFile(file_path, DefaultValue.KEY_FILE_MODE)
        elif action == 'remove':
            if os.path.isfile(file_path):
                FileUtil.removeFile(file_path, DefaultValue.KEY_FILE_MODE)
            else:
                self.logger.warn("Not found:%s." % file_path)
        self.logger.debug("Successfully %s lock file:%s." % (action, file_path))

    def check_parallel_process_is_running(self):
        """
        Check dorado process is running
        """
        hostnames = ' -H '.join(self.cluster_node_names)
        file_path = os.path.join(self.pg_host, DoradoDisasterRecoveryConstants.PROCESS_LOCK_FILE)
        cmd = 'source %s && pssh -t 10 -H %s "ls %s*"' % (self.mpp_file, hostnames, file_path)
        # waiting for check
        time.sleep(DoradoDisasterRecoveryConstants.CHECK_PROCESS_WAIT_TIME)
        _, output = CmdUtil.retryGetstatusoutput(cmd, retry_time=0)
        host_file_str_list = re.findall(r'.* ?: *%s[^\*^\s]+' % file_path, output)
        process_list = []
        for item in host_file_str_list:
            hostname = item.split(':')[0].strip()
            file_name = item.split(':')[1].strip()
            uuid = os.path.basename(file_name).split('_')[-1]
            if uuid != self.trace_id:
                process_list.append([hostname, file_name])
        if process_list:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % 'check dorado disaster recovery process, please execute after other ' \
                    'process exited, if you ensure no other process is running, ' \
                    'remove the lock file [%s] on node [%s], and try again' \
                  % (process_list[0][-1], process_list[0][0])
            self.logger.error(msg)
            raise Exception(msg)

    # remove_streaming_dir 可替换
    def remove_dorado_dir(self, dir_path):
        """
        Remove dorado files dir
        """
        cmd = "if [ -d %s ]; then rm %s -rf;fi" % (dir_path, self.dorado_file_dir)
        self.ssh_tool.executeCommand(cmd)
        self.logger.debug("Successfully remove dir [%s] on all nodes." % dir_path)

    def query_dorado_step(self):
        """
        write dorado step
        :return: NA
        """
        return self.query_streaming_step()

    def write_dorado_step(self, step):
        """
        write dorado step
        :return: NA
        """
        self.write_streaming_step(step)

    def init_cluster_status(self):
        """
        Generate cluster status file
        """
        if not os.path.exists(self.dorado_file_dir):
            self.logger.log("Dorado disaster recover tmp dir [%s] not exist." % self.dorado_file_dir)
            self.create_streaming_dir(self.dorado_file_dir)

        tmp_file = os.path.join(self.dorado_file_dir,
                                DoradoDisasterRecoveryConstants.DDR_CLUSTER_STATUS_TMP_FILE)
        cmd = ClusterCommand.getQueryStatusCmd("", tmp_file)
        self.logger.debug("Command for checking cluster state: %s" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                  % "check cluster state, status:%s, output:%s" % (status, output)
            self.logger.debug(msg)
            raise Exception(msg)
        self.logger.debug("Successfully init cluster status.")

    def wait_cluster_status(self, cluster_normal_status, timeout=30):
        """
        wait cluster status until in cluster_normal_status
        """
        end_time = datetime.now() + timedelta(seconds=timeout)
        while True:
            time.sleep(2)
            self.logger.log('Waiting cluster normal.')
            check_ret = self.check_cluster_status(cluster_normal_status, only_check=True,
                                                  check_current=True, is_log=False)
            if check_ret:
                self.logger.log("Successfully started datanode instances.")
                break
            if datetime.now() >= end_time:
                query_result = self.query_cluster()
                self.logger.log("Timeout. Failed to start the cluster in (%s)s." % timeout)
                self.logger.log("Current cluster status (%s)." % query_result)
                self.logger.log("It will continue to start in the background.")
                break

    def check_dn_instance_params(self):
        """set_dn_instance_params"""
        check_dick = {"ha_module_debug ": "off"}
        dn_insts = [dn_inst for db_node in self.cluster_info.dbNodes
                    for dn_inst in db_node.datanodes]
        primary_dn_insts = [inst for inst in dn_insts if inst.instanceId in self.primary_dn_ids]
        if not primary_dn_insts:
            self.logger.debug("The primary dn not exist, do not need check dn inst params.")
            return
        execute_dn = primary_dn_insts[0]
        param_list = []
        guc_backup_file = os.path.join(self.dorado_file_dir, DoradoDisasterRecoveryConstants.GUC_BACKUP_FILE)
        if not os.path.isfile(guc_backup_file):
            FileUtil.createFileInSafeMode(guc_backup_file, DefaultValue.KEY_FILE_MODE_IN_OS)
        for peer_check, idx in list(check_dick.items()):
            param_list.append((execute_dn, {peer_check: idx}))
        ret = parallelTool.parallelExecute(self._check_dn_inst_param, param_list)
        self.ssh_tool.scpFiles(guc_backup_file, self.dorado_file_dir, self.cluster_node_names)
        if any(ret):
            self.logger.logExit('\n'.join(filter(bool, ret)))
        self.logger.debug("Successfully check dn inst default value.")

    def _check_dn_inst_param(self, param):
        """check_dn_inst_param"""
        self.logger.debug("Check dn inst params: %s." % param[1])
        if len(param) != 2:
            error_msg = ErrorCode.GAUSS_521["GAUSS_52102"] % param
            return error_msg
        guc_backup_file = os.path.join(self.dorado_file_dir, DoradoDisasterRecoveryConstants.GUC_BACKUP_FILE)
        for sql_key, value in list(param[1].items()):
            sql = "show %s;" % sql_key
            (status, output) = ClusterCommand.remoteSQLCommand(sql,
                                                               self.user, param[0].hostname,
                                                               str(param[0].port))
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % sql, "\nError:%s" % output)
            if output.strip() != value:
                if sql_key in DoradoDisasterRecoveryConstants.GUC_CHANGE_MAP.keys():
                    content = "%s,%s,%s" % (sql_key, output.strip(), self.trace_id)
                    FileUtil.write_add_file(guc_backup_file, content,
                                            DefaultValue.KEY_FILE_MODE_IN_OS)
                    self.set_datanode_guc(sql_key, DoradoDisasterRecoveryConstants.GUC_CHANGE_MAP[sql_key], "reload")
                    return
                error_msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                            % "check [%s], Actual value: [%s], expect value: [%s]" \
                            % (sql, output, value)
                return error_msg
        self.logger.debug("Successfully check and rectify dn inst value:%s." % param[1])

    def restore_guc_params(self):
        """
        Restore guc params in .dorado_guc_backup
        """
        self.logger.debug("Start restore guc params.")
        guc_backup_file = os.path.join(self.dorado_file_dir, DoradoDisasterRecoveryConstants.GUC_BACKUP_FILE)
        if not os.path.isfile(guc_backup_file):
            self.logger.debug("Not found guc backup file, no need restore guc params.")
        params_record = DefaultValue.obtain_file_content(guc_backup_file)
        params_record.reverse()
        restored_keys = []
        for param in params_record:
            guc_key, guc_value, trace_id = param.split(",")
            self.logger.debug("Got guc param:%s, value:%s, trace id:%s in guc backup file."
                              % (guc_key, guc_value, trace_id))
            if guc_key not in DoradoDisasterRecoveryConstants.GUC_CHANGE_MAP.keys():
                continue
            # When the number of dns <=2, ensure that the maximum available mode is always on.
            dn_insts = [dn_inst for db_node in self.cluster_info.dbNodes
                        for dn_inst in db_node.datanodes]
            if guc_key in restored_keys or len(dn_insts) <= 2 \
                    and guc_key in ["most_available_sync"]:
                continue
            guc_value = "off" if guc_value not in ["on", "off"] else guc_value
            self.set_datanode_guc(guc_key, guc_value, "reload")
            restored_keys.append(guc_key)

    def __set_app_name_each_inst(self, params_list):
        """
        Set xlog_lock_file_path value in each dn
        """
        (inst, opt_type, value, mpprc_file) = params_list
        self.logger.debug("Start [%s] shardNum [%s] node [%s] application_name value [%s]."
                          % (opt_type, inst.mirrorId, inst.hostname, value))
        cmd = "source %s; pssh -H %s \"source %s ; gs_guc %s " \
              "-Z datanode -D %s -c \\\"application_name = '%s'\\\"\"" % \
              (mpprc_file, inst.hostname, mpprc_file, opt_type, inst.datadir, value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Options:%s, Error: \n%s "
                            % ("set application_name for inst:%s" % inst.instanceId, str(output)))
        self.logger.debug("Successfully [%s] shardNum [%s] node [%s] application_name "
                          "value [%s]." % (opt_type, inst.mirrorId, inst.hostname, value))

    def set_application_name(self):
        """
        guc set application_name value 
        """
        self.logger.log("Starting set application_name param")
        app_name_prefix = "dn_master" if self.params.mode == "primary" \
            else "dn_standby"
        params_list = []
        for dbnode in self.cluster_info.dbNodes:
            for inst in dbnode.datanodes:
                app_name = "%s_%s" % (app_name_prefix, inst.instanceId)
                params_list.append((inst, "set", app_name, self.mpp_file))

        if not params_list:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain param list for set application_name")

        parallelTool.parallelExecute(self.__set_app_name_each_inst, params_list)
        self.logger.log("Successfully set application_name param.")

    def set_ha_module_mode(self):
        """
        guc set ha_module_debug value 
        """
        self.set_datanode_guc("ha_module_debug", "off", "set")

    def get_all_connection_node_name(self, action_flag="", no_update=True):
        """
        get all connection node name
        """
        if self.connected_nodes and no_update:
            self.logger.debug("Got connected nodes:%s for action:%s"
                              % (self.connected_nodes, action_flag))
            return self.connected_nodes
        rets = parallelTool.parallelExecute(DefaultValue.fast_ping, self.cluster_node_names)
        self.logger.debug("Check connect for action:%s, result:%s" % (action_flag, str(rets)))
        connected_hosts = [ret[0] for ret in rets if ret[-1]]
        self.connected_nodes = connected_hosts
        return self.connected_nodes

    def set_ss_disaster_mode(self):
        """
        guc set ss_disaster_mode value
        :ss_disaster_mode:  stream(streaming replication dual-cluster), 
                            dorado(dorado replication dual-cluster, default value)
        :return:NA
        """
        self.logger.log("Start set ss_disaster_mode")
        self.set_datanode_guc("ss_disaster_mode", self.params.disaster_type, "set")

    def judge_ss_cluster_role(self):
        """
        function: determine the role of the current cluster
        input: NA
        output: "single","disaster_standby","primary"
        """
        cluster_current_role = "single"
        cmd = "source %s; cm_ctl view | grep cmDataPath | awk -F [:] '{print $2}' | head -n 1" % EnvUtil.getMpprcFile()
        stdout = DefaultValue.execute_command(cmd)
        cm_agent_conf_file = stdout + "/cm_agent/cm_agent.conf"

        content = DefaultValue.get_cm_agent_conf_content(self.cluster_info, cm_agent_conf_file)
        ret_standby = re.findall(r'ss_double_cluster_mode *= *2', content)
        ret_primary = re.findall(r'ss_double_cluster_mode *= *1', content)

        if ret_standby:
            return "disaster_standby"
        elif ret_primary:
            return "primary"
        return cluster_current_role

    def update_pg_hba(self):
        """
        update pg_hba.conf, read config_param.json file and set other cluster ip
        :return:NA
        """
        self.logger.log("Start update pg_hba config.")
        remote_ips = self.__get_remote_ips()

        for remote_ip in remote_ips:
            submask_length = NetUtil.get_submask_len(remote_ip)
            cmd = "source %s ; gs_guc set -Z datanode -N all -I all -h " \
                  "\"host   all   all   %s/%s   trust\"" \
                  % (self.mpp_file, remote_ip, submask_length)
            self.logger.debug("Update pg_hba.conf with cmd: %s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)
            self.logger.debug("Successfully update pg_hba config with remote datanode ip:%s."
                              % remote_ips)

    def __get_remote_ips(self):
        """
        Get remote dn data ip
        """
        remote_cluster_info = self.params.remoteClusterConf
        shards = remote_cluster_info["shards"]
        indx = 1
        remote_ips = []
        for shard in shards:
            for node in shard:
                ip = node["ip"]
                data_ip = node["dataIp"]
                remote_ips.append(data_ip)

        return remote_ips

    def __config_one_dn_instance(self, params):
        """
        Config cross_cluster_replconninfo for one dn instance
        """
        inst, opt_mode = params
        local_dn_ip = inst.listenIps[0]
        local_port = inst.port
        remote_port = self.params.remoteClusterConf['port']
        remote_data_ips = self.__get_remote_ips()

        idx = 1
        for remote_ip in remote_data_ips:
            set_cmd = "source %s ; gs_guc set -N %s -D %s -c " \
                      "\"cross_cluster_replconninfo%s = 'localhost=%s localport=%s " \
                      "remotehost=%s remoteport=%s '\"" \
                      % (self.mpp_file, inst.hostname, inst.datadir, idx,
                         local_dn_ip, local_port, remote_ip, remote_port)
            self.logger.debug("Set dn cross cluster replinfos with cmd:%s" % set_cmd)
            idx += 1
            status, output = CmdUtil.retryGetstatusoutput(set_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % set_cmd +
                                " Error: \n%s " % output)
            self.logger.debug("Successfully rectify original repl infos for instance:%s."
                              % inst.instanceId)

    def config_cross_cluster_repl_info(self):
        """
        update postgresql.conf for cross_cluster_replconninfo
        """
        self.logger.debug("set all datanode guc param in postgres conf for cross_cluster_replconninfo.")

        opt_mode = "set"
        config_repl_params = []
        datanode_instance = [inst for node in self.cluster_info.dbNodes for inst in node.datanodes]

        for inst in datanode_instance:
            config_repl_params.append((inst, opt_mode))
        rets = parallelTool.parallelExecute(self.__config_one_dn_instance, config_repl_params)

        self.logger.debug(
            "Successfully set all datanode guc param in postgres conf for cross_cluster_replconninfo.")

    def set_datanode_guc(self, guc_parameter, guc_value, guc_type, only_mode=None):
        """
        set datanode guc param
        :return: NA
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set datanode guc [%s] to [%s] not for mode:%s."
                              % (guc_parameter, guc_value, self.params.mode))
            return
        cmd = "gs_guc %s -Z datanode -N all -I all -c \"%s=%s\" " % \
              (guc_type, guc_parameter, guc_value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "set datanode guc [%s] to [%s], output:%s" \
                  % (guc_parameter, guc_value, output)
            self.logger.debug(msg)

    def set_cmserver_guc(self, guc_parameter, guc_value, guc_type, only_mode=None):
        """
        set cmserver guc param
        :return: NA
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set cms guc [%s] to [%s] not for mode:%s."
                              % (guc_parameter, guc_value, self.params.mode))
            return
        cmd = "source %s; cm_ctl %s --param --server -k \"%s=%s\" " % \
              (self.mpp_file, guc_type, guc_parameter, guc_value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "set cm server guc [%s] to [%s], output:%s" \
                  % (guc_parameter, guc_value, output)
            self.logger.debug(msg)

    def set_cmagent_guc(self, guc_parameter, guc_value, guc_type, only_mode=None):
        """
        set cmagent guc param
        :return: NA
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set cma guc [%s] to [%s] not for mode:%s."
                              % (guc_parameter, guc_value, self.params.mode))
            return
        cmd = "source %s; cm_ctl %s --param --agent -k \"%s=%s\" " % \
              (self.mpp_file, guc_type, guc_parameter, guc_value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "set cm agent guc [%s] to [%s], output:%s" \
                  % (guc_parameter, guc_value, output)
            self.logger.debug(msg)

    def reload_cm_guc(self):
        """
        reload  cmagent and cm_server param on all node
        :return: NA
        """
        self.logger.log("Start reload cm_agent and cm_server param.")
        cmd = "source %s; cm_ctl reload --param --agent"  % self.mpp_file
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "cm_ctl reload agent param failed, output:%s" \
                  % (output)
            self.logger.debug(msg)
        
        cmd = "source %s; cm_ctl reload --param --server"  % self.mpp_file
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "cm_ctl reload server param failed, output:%s" \
                  % (output)
            self.logger.debug(msg)
        self.logger.log("Successfully reload cm guc param on all nodes.")

    def start_dss_instance(self, only_mode=None):
        """
        Start dssserver process 
        """
        self.logger.log("Start dssserver in main standby node.")
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Start dssserver step is not for mode:%s." % self.params.mode)
            return
        primary_dn = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                      db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        main_standby_inst = primary_dn[0]

        if self.local_host == main_standby_inst.hostname:
            cmd = 'sh -c "source {}; export DSS_MAINTAIN=TRUE && nohup dssserver -D $DSS_HOME >/dev/null 2>&1 & "'.format(
                self.mpp_file)
        else:
            cmd = "source %s; pssh -s -t 5 -H %s \"source %s; export DSS_MAINTAIN=TRUE && " \
                  "nohup dssserver -D $DSS_HOME >/dev/null 2>&1 & \"" \
                  % (self.mpp_file, main_standby_inst.hostname)

        self.logger.debug("Start dssserver on node [%s],cmd: %s." % (main_standby_inst.hostname, cmd))
        proc = FastPopen(cmd)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] +
                            'Start dssserver on node [{}] Error: {}'.format(main_standby_inst.hostname,
                                                                            str(err + out).strip()))

        self.logger.log("Successfully Start dssserver on node [%s] " % main_standby_inst.hostname)

    def build_main_standby_datanode(self, only_mode=None):
        """
        Build Main standby datanode 
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Build Main standby step is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start build main standby datanode in disaster standby cluster.")
        primary_dn = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                      db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        main_standby_inst = primary_dn[0]

        if self.local_host == main_standby_inst.hostname:
            build_cmd = "source %s; gs_ctl build -D %s -b cross_cluster_full -q " \
                        % (self.mpp_file, main_standby_inst.datadir)
        else:
            build_cmd = "source %s; pssh -s -t %s -H %s \"source %s;" \
                        " gs_ctl build -D %s -b cross_cluster_full -q \"" \
                        % (self.mpp_file, DoradoDisasterRecoveryConstants.MAX_BUILD_TIMEOUT,
                           main_standby_inst.hostname,
                           self.mpp_file, main_standby_inst.datadir)
        self.logger.debug("Build Main standby datanode on node [%s],cmd: %s." % (main_standby_inst.hostname, build_cmd))
        status, output = CmdUtil.retry_util_timeout(build_cmd, self.params.waitingTimeout)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % build_cmd +
                            "Options:%s, Error: \n%s "
                            % ("build main_standby on node :%s" % main_standby_inst.hostname, str(output)))
        self.logger.log(
            "Successfully build main standby in disaster standby cluster on node [%s] " % main_standby_inst.hostname)

    def stop_dss_instance(self, only_mode=None):
        """
        Stop dssserver process 
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Stop dssserver process step is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Stop dssserver instance on main standby node.")
        primary_dn = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                      db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        main_standby_inst = primary_dn[0]

        if self.local_host == main_standby_inst.hostname:
            kill_cmd = "source %s; dsscmd stopdss" % (self.mpp_file)
        else:
            kill_cmd = "source %s; pssh -s -t 3 -H %s \"source %s; dsscmd stopdss\"" \
                       % (self.mpp_file, main_standby_inst.hostname, self.mpp_file)
        self.logger.debug("Stop dssserver on node [%s],cmd: %s." % (main_standby_inst.hostname, kill_cmd))
        sts, out = CmdUtil.getstatusoutput_by_fast_popen(kill_cmd)
        if sts not in [0, 1]:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "Stop dssserver before start cluster on node:" + main_standby_inst.hostname +
                            ", output:" + str(out).strip())
        self.logger.log("Successfully stop dssserver before start cluster on node [%s] " % main_standby_inst.hostname)
      
    def set_dss_cluster_run_mode(self, mode='cluster_standby', only_mode=None):
        """
        Set dss cluster_run_mode in dss cfg 
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set dssserver cluster_run_mode step is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start set all dss instance CLUSTER_RUN_MODE.")
        dss_home = EnvUtil.getEnv('DSS_HOME')
        cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')

        cmd = r"grep -q '^\s*CLUSTER_RUN_MODE\s*=' %s" % cfg
        (status, output) = subprocess.getstatusoutput(cmd)
        self.logger.debug("grep dss cfg CLUSTER_RUN_MODE cmd: %s" % cmd)
        if status != 0:
            cmd_param = r"echo 'CLUSTER_RUN_MODE = %s' >> %s" % (mode, cfg)
        else:
            cmd_param = r"sed -i 's/^\s*CLUSTER_RUN_MODE\s*=.*/CLUSTER_RUN_MODE = %s/' %s" % (mode, cfg)

        params_list = [(inst, cmd_param) for db_node in
                       self.cluster_info.dbNodes for inst in db_node.datanodes]

        rets = parallelTool.parallelExecute(self.__config_dss_para, params_list)
        self.logger.log(
            "Successfully set dss cfg CLUSTER_RUN_MODE to %s." % mode)

    def __config_dss_para(self, params_list):
        """
        Set dss para in dss cfg(dss_init.ini)
        """
        inst, cmd = params_list

        if self.local_host != inst.hostname:
            cmd = "source %s; pssh -s -t 5 -H %s \"%s\"" % \
                    (self.mpp_file, inst.hostname, cmd)
        self.logger.debug("config dss cfg cmd: %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Options:%s, Error: \n%s "
                            % ("config dss_init.ini for inst:%s" % inst.instanceId, str(output)))

    def set_dss_storage_mode(self, mode='CLUSTER_RAID'):
        """
        Set dss storage mode in dss cfg
        this step, P, S cluster both needs 
        """
        self.logger.log("Start set all dss instance STORAGE_MODE.")
        dss_home = EnvUtil.getEnv('DSS_HOME')
        cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')

        cmd = r"grep -q '^\s*STORAGE_MODE\s*=' %s" % cfg
        (status, output) = subprocess.getstatusoutput(cmd)
        self.logger.debug("grep dss cfg STORAGE_MODE cmd: %s" % cmd)
        if status != 0:
            cmd_param = r"echo 'STORAGE_MODE = %s' >> %s" % (mode, cfg)
        else:
            cmd_param = r"sed -i 's/^\s*STORAGE_MODE\s*=.*/STORAGE_MODE = %s/' %s" % (mode, cfg)

        params_list = [(inst, cmd_param) for db_node in
                    self.cluster_info.dbNodes for inst in db_node.datanodes]

        rets = parallelTool.parallelExecute(self.__config_dss_para, params_list)
        self.logger.log("Successfully set dss cfg STORAGE_MODE to %s." % mode)

    def __check_one_main_standby_connection(self, param_list):
        """
        concurrent check main standby is connected primary dn
        """
        (dn_inst, sql_check) = param_list
        self.logger.debug("Node %s primary dn instanceId [%s] Check main standby is connected "
                          "with cmd:%s." % (dn_inst.hostname, dn_inst.instanceId, sql_check))
        status, output = ClusterCommand.remoteSQLCommand(
            sql_check, self.user, dn_inst.hostname, dn_inst.port)
        if status == 0 and output.strip():
            self.logger.debug("Successfully check main standby connected "
                              "primary dn on inst:[%s]." % dn_inst.instanceId)
            return True
        self.logger.debug("Retry check main standby connected on inst:[%s]." % dn_inst.instanceId)

    def check_main_standby_connection_primary_dn(self, p_inst_list):
        """
        check connection main_standby connected primary dn
        """
        if not p_inst_list:
            self.logger.debug("The primary dn does not exist on current cluster.")
            return
        self.primary_dn_ids = p_inst_list
        sql_check_dorado = "select 1 from pg_catalog.pg_stat_get_wal_senders() where " \
                    "sync_state='Async' and peer_role='StandbyCluster_Standby' and peer_state='Normal';"
        sql_check_stream = "select 1 from pg_catalog.pg_stat_get_wal_senders() where " \
                    "peer_role='Standby' and peer_state='Normal';"
        sql_check = sql_check_dorado if self.params.disaster_type == "dorado" else sql_check_stream
        param_list = [(dn_inst, sql_check) for db_node in self.cluster_info.dbNodes
                      for dn_inst in db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]

        if not param_list:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain param list for check main standby connection on primary dn")
        self.logger.debug("Start check main standby connection with sql:%s." % sql_check)
        results = parallelTool.parallelExecute(self.__check_one_main_standby_connection,
                                               param_list)

        return all(results)

    def check_action_and_mode(self):
        """
        Check action and mode if step file exist.
        if any dorado options not finished(step file exist),
        not allowed doing any other dorado options except query.
        """
        self.logger.debug("Checking action and mode.")
        exist_step_file_names = []
        for file_name in DoradoDisasterRecoveryConstants.DDR_STEP_FILES.values():
            step_file_path = os.path.join(self.dorado_file_dir, file_name)
            if os.path.isfile(step_file_path) and file_name != ".ddr_query.step":
                exist_step_file_names.append(file_name)
        if exist_step_file_names and set(exist_step_file_names) ^ {os.path.basename(
                self.step_file_path)}:
            exist_action = [key for key, value in DoradoDisasterRecoveryConstants.DDR_STEP_FILES.items()
                            if value in exist_step_file_names]
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "check action and mode, the step files %s already exist, "
                                  "please ensure the action %s is finished before "
                                  "doing current options" % (exist_step_file_names, exist_action))
        self.logger.debug("clean_global_configSuccessfully checked action and mode.")

    def __remove_cross_cluster_replinfo(self, params):
        """
        Remove cross_cluster_replinfo from single dn instances.
        """
        dn_inst, guc_mode, dn_num = params
        self.logger.debug("Start remove cross_cluster_replinfo for instance:%s" % dn_inst.instanceId)

        for idx in range(1, dn_num + 1):
            cmd = "source %s ; gs_guc %s -N %s -D %s -c " \
                  "\"cross_cluster_replconninfo%s\"" \
                  % (self.mpp_file, guc_mode, dn_inst.hostname, dn_inst.datadir, idx)
            self.logger.debug("Remove dn cross_cluster_replconninfo with cmd:%s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)
            self.logger.debug("Successfully remove cross_cluster_replconninfo with cmd:%s."
                              % cmd)

        self.logger.debug("Successfully removed replconninfo for instance:%s" % dn_inst.instanceId)

    def remove_cross_cluster_replinfos(self, guc_mode="set"):
        """
        Remove cross_cluster_replinfos from all instances
        """
        params = []
        dn_instances = [inst for node in self.cluster_info.dbNodes
                        for inst in node.datanodes]
        cluster_conf = os.path.join(self.dorado_file_dir,
                                    DoradoDisasterRecoveryConstants.DDR_CLUSTER_CONF_RECORD)
        dn_num = DefaultValue.get_all_dn_num_for_dr(cluster_conf, dn_instances[0],
                                                    self.cluster_info, self.logger)
        for inst in dn_instances:
            if inst.instanceId not in self.normal_dn_ids:
                self.logger.error("Ignore rectify repl info of dn:%s" % inst.instanceId)
                continue
            params.append((inst, guc_mode, dn_num))
        if params:
            self.logger.log("Starting remove all node dn instances repl infos.")
            parallelTool.parallelExecute(self.__remove_cross_cluster_replinfo, params)
            self.logger.log("Successfully remove all node dn instances repl infos.")

    def update_dorado_info(self, key, value, only_mode=None):
        """
        Update info for dorado status
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Update query status [%s] to [%s] "
                              "not for mode:%s." % (key, value, self.params.mode))
            return
        self.logger.debug("Update query [%s] to [%s]." % (key, value))
        try:
            if key == "cluster":
                key_stat = DoradoDisasterRecoveryConstants.DDR_CLUSTER_STAT
            elif key == DoradoDisasterRecoveryConstants.ACTION_FAILOVER:
                key_stat = DoradoDisasterRecoveryConstants.DDR_FAILOVER_STAT
            elif key == DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
                key_stat = DoradoDisasterRecoveryConstants.DDR_SWITCHOVER_STAT
            elif key == DoradoDisasterRecoveryConstants.ACTION_ESTABLISH:
                key_stat = DoradoDisasterRecoveryConstants.DDR_ESTABLISH_STAT
            else:
                self.logger.debug("key error.")
                return
            file_path = os.path.realpath(os.path.join(self.dorado_file_dir, key_stat))
            with os.fdopen(os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                   DefaultValue.KEY_FILE_MODE_IN_OS), "w") as fp_write:
                fp_write.write(value)
            host_names = self.get_all_connection_node_name(
                action_flag="update_dorado_info", no_update=True)
            self.ssh_tool.scpFiles(file_path, self.dorado_file_dir, host_names)
        except Exception as error:
            self.logger.debug("Failed write info, key:%s, value:%s, "
                              "error:%s." % (key, value, error))

    def check_datanode_query_info(self, params):
        """
        check datanode info by "gs_ctl query" command.
        """
        state, dest_ip, datadir = params
        mpprc_file = self.mpp_file
        if dest_ip == self.local_host:
            cmd = "source %s && gs_ctl query -D %s" % (mpprc_file, datadir)
        else:
            cmd = "pssh -H %s \"source %s && gs_ctl query -D %s \"" % (dest_ip,
                                                                       mpprc_file,
                                                                       datadir)
        (status, output) = subprocess.getstatusoutput(cmd)
        db_state = re.findall(r"db_state.*: (.*?)\n", output)
        local_role = re.findall(r"local_role.*: (.*?)\n", output)
        peer_role = re.findall(r"peer_role.*: (.*?)\n", output)
        peer_state = re.findall(r"peer_state.*: (.*?)\n", output)
        channel = re.findall(r"channel.*: (.*?)\n", output)
        if status == 0:
            check_ok = 0
            if state == "Primary":
                if (len(db_state) != 1 or db_state[0] != "Normal") or \
                        (len(local_role) != 2 or local_role[0] != "Primary" or local_role[1] != "Primary") or \
                        (len(peer_role) != 1 or peer_role[0] != "StandbyCluster_Standby") or \
                        (len(peer_state) != 1 or peer_state[0] != "Normal") or \
                        (len(channel) != 1 or "-->" not in channel[0] or len(channel[0]) <= 30):
                    check_ok = -1
            elif state == "Main Standby":
                if (len(db_state) != 1 or db_state[0] != "Normal") or \
                        (len(local_role) != 2 or local_role[0] != "Main Standby" or local_role[1] != "Standby") or \
                        (len(peer_role) != 1 or peer_role[0] != "Primary") or \
                        (len(peer_state) != 1 or peer_state[0] != "Normal") or \
                        (len(channel) != 1 or "<--" not in channel[0] or len(channel[0]) <= 30):
                    check_ok = -1
            elif state == "Standby":
                if (len(db_state) != 1 or db_state[0] != "Normal") or \
                        (len(local_role) != 1 or local_role[0] != "Standby"):
                    check_ok = -1
            else:
                raise Exception(ErrorCode.GAUSS_521["F"] % state)
        else:
            check_ok = status

        return check_ok, output, dest_ip

    def check_dorado_datanode_query_info(self, timeout=DefaultValue.TIMEOUT_CLUSTER_START,
                                         dorado_switchover=None):
        """
        check gs_ctl query info
        """
        self.logger.debug("Waiting for gs_ctl query status being satisfied.")
        end_time = None if timeout <= 0 else datetime.now() + timedelta(seconds=timeout)

        self.init_cluster_status()
        self.parse_cluster_status()
        host_names = self.get_all_connection_node_name()
        if len(host_names) != len(self.cluster_node_names):
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50623"] % host_names)
        check_params = []
        all_instances = [(db_node.name, dn_inst) for db_node in self.status_info.dbNodes
                         for dn_inst in db_node.datanodes]
        for host_name, dn_inst in all_instances:
            check_params.append([dn_inst.status, host_name, dn_inst.datadir])
        if len(check_params) <= 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51620"] % "cluster")
        while True:
            check_status = 0
            time.sleep(10)
            if end_time is not None and datetime.now() >= end_time:
                check_status = 1
                self.logger.debug("Timeout. The gs_ctl query command cannot obtain the expected status.")
                break
            results = parallelTool.parallelExecute(
                self.check_datanode_query_info, check_params)
            for ret in results:
                if ret[0] != 0:
                    self.logger.log("Failed to check node[%s] info using \"gs_ctl query\" command "
                                      "with status[%s], output[%s]" % (ret[-1], ret[0], ret[1]))
                    check_status = 1
            if check_status == 0:
                break
        if check_status != 0:
            if dorado_switchover == "disaster_switchover":
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51602"])
            self.logger.logExit(
                ErrorCode.GAUSS_516["GAUSS_51602"])
        self.logger.debug("Successfully wait for gs_ctl query status become Normal.", "constant")

    def check_input(self, msg_print):
        flag = input(msg_print)
        count_f = 2
        while count_f:
            if (
                    flag.upper() != "YES"
                    and flag.upper() != "NO"
                    and flag.upper() != "Y" and flag.upper() != "N"):
                count_f -= 1
                flag = input("Please type 'yes' or 'no': ")
                continue
            break
        if flag.upper() != "YES" and flag.upper() != "Y":
            self.logger.exitWithError(
                ErrorCode.GAUSS_358["GAUSS_35805"] % flag.upper())

    def dorado_failover_single_inst(self, dorado_disaster_step, action_flag=None):
        """
        dorado disaster recovery failover for single_inst cluster
        """
        if action_flag != DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
            self.update_dorado_info("cluster", "promote")
        # 0. check cluster status and get normal instance list
        if self.params.stage is None or int(self.params.stage) == 1:
            if dorado_disaster_step < 0:
                if action_flag == DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
                    self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "10%")
                else:
                    self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_FAILOVER, "10%")
                self.init_cluster_status()
                self.parse_cluster_status()
                if self.params.restart:
                    self.stop_cluster()
                self.write_dorado_step("0_dorado_disaster_stop_cluster_for_failover")
            self.logger.log("Successfully do_first_stage_for_switchover.")
        if self.params.stage is None or int(self.params.stage) == 2:
            if dorado_disaster_step < 1:
                if self.params.disaster_type == "dorado":
                    self.check_input(DoradoDisasterRecoveryConstants.PRIMARY_MSG)
                self.write_dorado_step("1_set_remote_replication_pairs_for_failover")
            self._failover_config_step(dorado_disaster_step, action_flag)
            self._failover_start_step(dorado_disaster_step, action_flag)

    def _failover_start_step(self, dorado_disaster_step, action_flag):
        """
        Failover step 5 & 6
        """
        if dorado_disaster_step < 3:
            if action_flag == DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "80%")
            else:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_FAILOVER, "80%")
            if self.params.restart:
                self.start_cluster()
            else:
                self.failover_standby_dn()
            self.write_dorado_step("3_start_cluster_done")
        if dorado_disaster_step < 4:
            cluster_normal_status = [DefaultValue.CLUSTER_STATUS_NORMAL]
            self.wait_cluster_status(cluster_normal_status)
            if action_flag != DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_FAILOVER, "100%")
                self.update_dorado_info("cluster", "normal")
            else:
                self.wait_main_standby_connection()
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "100%")
                self.update_dorado_info("cluster", "archive")

    def failover_standby_dn(self):
        """
        failover Main standby datanode 
        """
        self.logger.log("Start failover main standby datanode in disaster standby cluster.")
        primary_dn = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                      db_node.datanodes if dn_inst.instanceId in self.main_standby_ids]
        main_standby_inst = primary_dn[0]

        if self.local_host == main_standby_inst.hostname:
            cmd = "source %s; gs_ctl failover -D %s " \
                        % (self.mpp_file, main_standby_inst.datadir)
        else:
            cmd = "source %s; pssh -s -H %s \"source %s;" \
                        " gs_ctl failover -D %s \"" \
                        % (self.mpp_file, main_standby_inst.hostname,
                           self.mpp_file, main_standby_inst.datadir)
        self.logger.debug("Failover Main standby datanode on node [%s],cmd: %s." % (main_standby_inst.hostname, cmd))
        status, output = CmdUtil.retry_util_timeout(cmd, self.params.waitingTimeout)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Options:%s, Error: \n%s "
                            % ("failover main_standby on node :%s" % main_standby_inst.hostname, str(output)))
        self.logger.log(
            "Successfully Failover main standby in disaster standby cluster on node [%s] " % main_standby_inst.hostname)

    def _failover_config_step(self, dorado_disaster_step, action_flag):
        """
        Failover step 2 - 4
        """
        if dorado_disaster_step < 2:
            if action_flag == DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "30%")
            else:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_FAILOVER, "30%")
            self.set_cmagent_guc("ss_double_cluster_mode", "1", "set")
            self.set_cmserver_guc("ss_double_cluster_mode", "1", "set")
            if not self.params.restart:
                self.reload_cm_guc()
            self.set_dss_cluster_run_mode("cluster_primary")
            self.write_dorado_step("2_set_cluster_guc_for_failover_done")