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
# Description  : streaming_base.py is a base module for streaming disaster recovery.
#############################################################################
import json
import os
import re
import time
from datetime import datetime
from datetime import timedelta
import subprocess

from domain_utils.cluster_file.version_info import VersionInfo
from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants
from impl.streaming_disaster_recovery.params_handler import check_local_cluster_conf
from impl.streaming_disaster_recovery.params_handler import check_remote_cluster_conf
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.Common import DefaultValue, ClusterInstanceConfig
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.threads.SshTool import SshTool
from gspylib.threads.parallelTool import parallelTool
from gspylib.os.gsfile import g_file
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.user_util import UserUtil
from base_utils.security.sensitive_mask import SensitiveMask
from base_utils.common.constantsbase import ConstantsBase


class StreamingBase(object):
    def __init__(self, params, user, logger, trace_id, log_file=None):
        self.user = user
        self.params = params
        self.logger = logger
        self.trace_id = trace_id
        self.log_file = log_file
        self.cluster_info = None
        self.gp_home = None
        self.pg_host = None
        self.gauss_home = None
        self.bin_path = None
        self.local_host = None
        self.local_ip = None
        self.is_single_inst = None
        self.streaming_file_dir = None
        self.streaming_xml = None
        self.cluster_node_names = None
        self.normal_cm_ips = []
        self.normal_node_list = []
        self.ssh_tool = None
        self.mpp_file = None
        self.status_info = None
        self.step_file_path = ""
        self.cluster_status = ''
        self.normal_dn_ids = []
        self.normal_cn_ids = []
        self.normal_etcd_ids = []
        self.normal_gtm_ids = []
        self.normal_cm_ids = []
        self.normal_instances = []
        self.primary_dn_ids = []
        self.main_standby_ids = []
        self.cascade_standby_ids = []
        self.connected_nodes = []
        self.__init_globals()
        self.backup_open_key = StreamingConstants.BACKUP_OPEN % user

    def __init_globals(self):
        self.cluster_info = dbClusterInfo()
        self.cluster_info.initFromStaticConfig(self.user)
        self.gp_home = EnvUtil.getEnvironmentParameterValue("GPHOME", self.user)
        self.pg_host = EnvUtil.getEnvironmentParameterValue("PGHOST", self.user)
        self.gauss_home = EnvUtil.getEnvironmentParameterValue("GAUSSHOME", self.user)
        self.bin_path = os.path.join(os.path.realpath(self.gauss_home), 'bin')
        self.local_host = NetUtil.GetHostIpOrName()
        self.local_ip = DefaultValue.getIpByHostName()
        self.is_single_inst = True if self.cluster_info.isSingleInstCluster() else None
        self.cluster_node_names = self.cluster_info.getClusterNodeNames()
        self.streaming_file_dir = os.path.join(self.pg_host, StreamingConstants.STREAMING_FILES_DIR)
        self.streaming_xml = os.path.join(self.streaming_file_dir,
                                          StreamingConstants.STREAMING_CONFIG_XML)
        self.ssh_tool = SshTool(self.cluster_node_names, self.log_file)
        self.mpp_file = EnvUtil.getMpprcFile()
        self._init_step_file_path()

    def init_cluster_conf(self):
        """
        Init cluster conf from file
        """
        if (not hasattr(self.params, "localClusterConf")) \
                or (not hasattr(self.params, "remoteClusterConf")):
            self.logger.log("Parse cluster conf from file.")
            local_conf, remote_conf = self.read_cluster_conf_record()
            self.logger.debug("Start validte cluster conf info.")
            check_local_cluster_conf(local_conf)
            check_remote_cluster_conf(remote_conf)
            setattr(self.params, "localClusterConf", local_conf)
            setattr(self.params, "remoteClusterConf", remote_conf)
            self.logger.log("Successfully parse cluster conf from file.")

    def _init_step_file_path(self):
        """
        Init step file path
        """
        if self.params.task == StreamingConstants.ACTION_START:
            if self.params.mode == "primary":
                step_file_name = StreamingConstants.STREAMING_STEP_FILES["start_primary"]
            elif self.params.mode == "disaster_standby":
                step_file_name = StreamingConstants.STREAMING_STEP_FILES["start_standby"]
            else:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "init step file path")
        elif self.params.task == StreamingConstants.ACTION_SWITCHOVER:
            if self.params.mode == "primary":
                step_file_name = StreamingConstants.STREAMING_STEP_FILES["switchover_primary"]
            elif self.params.mode == "disaster_standby":
                step_file_name = StreamingConstants.STREAMING_STEP_FILES["switchover_standby"]
            else:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "init step file path")
        else:
            step_file_name = StreamingConstants.STREAMING_STEP_FILES[self.params.task]
        self.step_file_path = os.path.join(self.streaming_file_dir, step_file_name)
        self.logger.debug("Init step file:%s." % self.step_file_path)

    def read_cluster_conf_record(self, check_file_exist=True):
        """
        Read cluster conf from file
        """
        cluster_conf_record = os.path.join(self.streaming_file_dir,
                                           StreamingConstants.STREAMING_CLUSTER_CONF_RECORD)
        if not os.path.isfile(cluster_conf_record):
            if check_file_exist:
                raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                                % "check cluster conf, cluster_conf_record is lost")
            else:
                self.logger.log("Not found file cluster_conf_record.")
                return '', ''
        content = DefaultValue.obtain_file_content(cluster_conf_record, is_list=False)
        json_content = json.loads(content)
        local_conf = json_content["localClusterConf"]
        remote_conf = json_content["remoteClusterConf"]
        return local_conf, remote_conf

    def handle_lock_file(self, trace_id, action):
        """
        Create lock file for other streaming process.
        """
        if self.params.task not in StreamingConstants.TASK_EXIST_CHECK:
            return
        file_name = StreamingConstants.PROCESS_LOCK_FILE + trace_id
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

    def check_streaming_process_is_running(self):
        """
        Check streaming process is running
        """
        hostnames = ' -H '.join(self.cluster_node_names)
        file_path = os.path.join(self.pg_host, StreamingConstants.PROCESS_LOCK_FILE)
        cmd = 'source %s && pssh -t 10 -H %s "ls %s*"' % (self.mpp_file, hostnames, file_path)
        # waiting for check
        time.sleep(StreamingConstants.CHECK_PROCESS_WAIT_TIME)
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
                  % 'check streaming process, please execute streaming options after other ' \
                    'process exited, if you ensure no other process is running, ' \
                    'remove the lock file [%s] on node [%s], and try again' \
                  % (process_list[0][-1], process_list[0][0])
            self.logger.error(msg)
            raise Exception(msg)

    def create_streaming_dir(self, dir_path):
        """
        Create streaming files dir
        """
        cmd = g_file.SHELL_CMD_DICT["createDir"] % (
            dir_path, dir_path, DefaultValue.MAX_DIRECTORY_MODE)
        self.ssh_tool.executeCommand(cmd)
        self.logger.debug("Successfully create dir [%s] on all nodes." % dir_path)

    def check_hadr_pwd(self, only_mode=None):
        """
        Check hadr pwd is correct or not
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Checking hadr user is not for mode:%s." % self.params.mode)
            return
        self.logger.debug("Start checking disaster user password.")
        sql = "select 1;"
        primary_dns = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                       db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        if not primary_dns:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                            % "obtain primary dn when check disaster user")
        status, output = ClusterCommand.remoteSQLCommand(
            sql, self.user, primary_dns[0].hostname, primary_dns[0].port, False,
            user_name=self.params.hadrUserName, user_pwd=self.params.hadrUserPassword)
        if status != 0:
            if "Invalid username/password" in output:
                self.logger.debug("Logging denied, please check your password.")
            self.logger.logExit(ErrorCode.GAUSS_516['GAUSS_51632']
                                % "check disaster user password")
        self.logger.debug("Successfully check disaster user password.")

    def check_hadr_user(self, only_mode=None):
        """
        Check hadr user is exist
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Checking hadr user is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start checking disaster recovery user.")
        sql = "select usename, userepl from pg_user;"
        primary_dns = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                       db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        if not primary_dns:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                            % "obtain primary dn when check disaster user")
        status, output = ClusterCommand.remoteSQLCommand(
            sql, self.user, primary_dns[0].hostname, primary_dns[0].port, True)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                            % "execute sql for checking disaster user.")
        user_dict = {user_info.split('|')[0].strip(): user_info.split('|')[-1].strip()
                     for user_info in output.strip().split('\n')}
        for user_name, repl in user_dict.items():
            if user_name == self.params.hadrUserName and repl == 't':
                self.logger.log("Successfully check disaster recovery user.")
                return
        msg = ErrorCode.GAUSS_516['GAUSS_51632'] % 'checking disaster user, please confirm ' \
                                                   'disaster user is exist and with ' \
                                                   'replication role'
        self.logger.logExit(msg + "Users:%s" % user_dict)

    def __copy_hadr_user_key(self, secure_dir_path, update=False):
        """
        Copy hadr.key.cipher and hadr.key.rand
        """
        self.logger.log("Start copy hadr user key files.")
        hadr_cipher_path = os.path.join(self.bin_path, "hadr.key.cipher")
        hadr_rand_path = os.path.join(self.bin_path, "hadr.key.rand")
        secure_cipher_path = os.path.join(secure_dir_path, "hadr.key.cipher")
        secure_rand_path = os.path.join(secure_dir_path, "hadr.key.rand")
        if not update:
            if (not os.path.isfile(hadr_cipher_path)) or (not os.path.isfile(hadr_rand_path)):
                self.logger.debug("Not found hadr user key, no need to copy.")
                return
            FileUtil.cpFile(hadr_cipher_path, secure_cipher_path, cmd_type="shell")
            FileUtil.cpFile(hadr_rand_path, secure_rand_path, cmd_type="shell")
            self.logger.debug("Successfully copy hadr key files into temp secure dir.")
        else:
            if (not os.path.isfile(secure_cipher_path)) or (not os.path.isfile(secure_rand_path)):
                self.logger.debug("Not found hadr user key, no need to update.")
                return
            host_names = self.get_all_connection_node_name("update_hadr_key")
            self.ssh_tool.scpFiles(secure_cipher_path, self.bin_path, hostList=host_names)
            self.ssh_tool.scpFiles(secure_rand_path, self.bin_path, hostList=host_names)
            FileUtil.removeFile(secure_cipher_path)
            FileUtil.removeFile(secure_rand_path)
            self.logger.debug("Finished copy hadr key files to nodes:%s." % host_names)

    def remove_secure_dir(self, dir_path, host_name):
        """
        Remove gs_secure_files dir in PGDATA
        """
        secure_dir_path = os.path.join(dir_path, StreamingConstants.GS_SECURE_FILES)
        cmd = "echo \"if [ -d '%s' ];then rm -rf '%s';fi\" | pssh -s -H %s" % \
              (secure_dir_path, secure_dir_path, host_name)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        self.logger.debug("Remove gs_secure_files cmd:%s" % cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s " % output)

    def __stream_copy_file_to_all_dn(self, temp_secure_dir_path):
        """
        copy key file dir to all dn dir
        """
        dn_infos = DefaultValue.get_dn_info(self.cluster_info)
        self.logger.debug("Got dns:%s" % dn_infos)
        copy_succeed = 0
        host_names = self.get_all_connection_node_name("copy gs_secure_files to dns")
        for dn_info in dn_infos:
            if dn_info["host_name"] not in host_names:
                continue
            self.logger.debug("Copy disaster recovery secure files to inst[%s][%s][%s]." %
                              (dn_info['id'], dn_info['data_dir'], dn_info['host_name']))
            try:
                self.remove_secure_dir(dn_info['data_dir'], dn_info['host_name'])
                self.ssh_tool.scpFiles(
                    temp_secure_dir_path, dn_info['data_dir'], [dn_info['host_name']])
                copy_succeed += 1
            except Exception as error:
                self.logger.debug("Failed copy secure files to inst[%s][%s][%s],error:%s." %
                                  (dn_info['id'], dn_info['data_dir'], dn_info['host_name'],
                                   str(error)))
        if copy_succeed == 0:
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "copy secure dir to all dn data dir")
        self.logger.log("Successfully copy secure files.")

    def __prepare_cluster_user_record(self, temp_secure_dir_path):
        """
        Save cluster user record
        """
        cluster_user_record = os.path.join(temp_secure_dir_path,
                                           StreamingConstants.CLUSTER_USER_RECORD)
        DefaultValue.write_content_on_file(cluster_user_record, self.user)
        self.logger.debug("Record current cluster user:%s." % self.user)

    def prepare_gs_secure_files(self, only_mode=None):
        """
        Prepare gs_secure_files on primary cluster
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Prepare gs_secure_files is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start prepare secure files.")
        secure_dir_name = StreamingConstants.GS_SECURE_FILES
        temp_secure_dir_path = os.path.realpath(
            os.path.join(self.streaming_file_dir, secure_dir_name))
        if os.path.isdir(temp_secure_dir_path):
            self.logger.debug("Secure file dir exist, cleaning...")
            FileUtil.removeDirectory(temp_secure_dir_path)
        FileUtil.createDirectory(temp_secure_dir_path, True, DefaultValue.KEY_DIRECTORY_MODE)
        if os.path.isdir(temp_secure_dir_path):
            self.logger.debug("Successfully create secure file dir.")
        version_file_path = os.path.realpath(os.path.join(self.gp_home, "version.cfg"))
        FileUtil.cpFile(version_file_path, temp_secure_dir_path)
        self.__prepare_cluster_user_record(temp_secure_dir_path)
        self.__copy_hadr_user_key(temp_secure_dir_path, update=False)
        self.__stream_copy_file_to_all_dn(temp_secure_dir_path)
        FileUtil.removeDirectory(temp_secure_dir_path)

    def stream_clean_gs_secure(self, params):
        """
        clean gs secure dir
        """
        inst, file_path = params
        self.logger.debug("Starting clean instance %s gs secure dir." % inst.instanceId)
        cmd = "source %s && pssh -s -H %s 'if [ -d %s ]; then rm -rf %s; fi'" \
              % (self.mpp_file, inst.hostname, file_path, file_path)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            self.logger.debug("Clean gs secure dir for instance [%s] result:%s." %
                              (inst.instanceId, output))
        self.logger.debug("Successfully clean instance %s gs secure dir." % inst.instanceId)

    def clean_gs_secure_dir(self, only_mode=None):
        """
        Clean gs secure dir if exist
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Clean gs_secure_files is not for mode:%s." % self.params.mode)
            return
        self.logger.debug("Start clean gs secure dir.")
        params = []
        for node in self.cluster_info.dbNodes:
            for inst in node.datanodes:
                if inst.hostname not in self.connected_nodes:
                    continue
                file_path = os.path.realpath(os.path.join(
                    inst.datadir, StreamingConstants.GS_SECURE_FILES))
                params.append((inst, file_path))
        if params:
            parallelTool.parallelExecute(self.stream_clean_gs_secure, params)
        self.logger.debug("Finished clean gs secure dir.")

    def remove_streaming_dir(self, dir_path):
        """
        Remove streaming files dir
        """
        cmd = "if [ -d %s ]; then rm %s -rf;fi" % (dir_path, self.streaming_file_dir)
        self.ssh_tool.executeCommand(cmd)
        self.logger.debug("Successfully remove dir [%s] on all nodes." % dir_path)

    def query_streaming_step(self):
        """
        Streaming step
        """
        step = -1
        if os.path.isfile(self.step_file_path):
            step_list = FileUtil.readFile(self.step_file_path)
            if step_list:
                step = int(step_list[0].split("_")[0])
        if step == -1:
            self.logger.log("Got the step for action:[%s]." % self.params.task)
        else:
            self.logger.log("Got the continue step:[%s] for action:[%s]." %
                            (step, self.params.task))
        return step

    def write_streaming_step(self, step):
        """
        write streaming step
        :return: NA
        """
        self.logger.debug("Streaming action:[%s] record current step:[%s]"
                          % (self.params.task, step))
        with os.fdopen(os.open(self.step_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                               DefaultValue.KEY_FILE_MODE_IN_OS), "w") as fp_write:
            fp_write.write(step)

    def init_cluster_status(self):
        """
        Generate cluster status file
        """
        tmp_file = os.path.join(self.streaming_file_dir,
                                StreamingConstants.STREAMING_CLUSTER_STATUS_TMP_FILE)
        cmd = ClusterCommand.getQueryStatusCmd("", tmp_file)
        self.logger.debug("Command for checking cluster state: %s" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                  % "check cluster state, status:%s, output:%s" % (status, output)
            self.logger.debug(msg)
            raise Exception(msg)
        self.logger.debug("Successfully init cluster status.")

    def query_cluster_info(self, cm_check=False):
        """
        Query cluster info
        """
        cmd = ClusterCommand.getQueryStatusCmd()
        if cm_check:
            cmd = "source %s; cm_ctl query -Cv" % self.mpp_file
        self.logger.debug("Command for checking cluster state: %s" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0 or not output.strip():
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                  % "check cluster state, status:%s, output:%s" % (status, output)
            self.logger.debug(msg)
            return ""
        return output.strip()

    def __clean_cluster_status(self):
        """
        Clean status
        """
        self.normal_cm_ids = []
        self.normal_gtm_ids = []
        self.normal_cn_ids = []
        self.primary_dn_ids = []
        self.main_standby_ids = []
        self.cascade_standby_ids = []
        self.normal_dn_ids = []
        self.normal_etcd_ids = []
        self.normal_instances = []

    def __parse_instance_status(self):
        """
        Parse instance status
        """
        abnormal_insts = []
        for db_node in self.status_info.dbNodes:
            for cms_inst in db_node.cmservers:
                if cms_inst.status in ["Primary", "Standby"]:
                    self.normal_cm_ids.append(cms_inst.instanceId)
                    self.normal_instances.append(cms_inst)
                else:
                    abnormal_insts.append({cms_inst.instanceId: cms_inst.status})
            for gtm_inst in db_node.gtms:
                if gtm_inst.status in ["Primary", "Standby"] and gtm_inst.isInstanceHealthy():
                    self.normal_gtm_ids.append(gtm_inst.instanceId)
                    self.normal_instances.append(gtm_inst)
                else:
                    abnormal_insts.append({gtm_inst.instanceId: gtm_inst.status})
            for coo_inst in db_node.coordinators:
                if coo_inst.status == "Normal":
                    self.normal_cn_ids.append(coo_inst.instanceId)
                    self.normal_instances.append(coo_inst)
                else:
                    abnormal_insts.append({coo_inst.instanceId: coo_inst.status})
            for data_inst in db_node.datanodes:
                if data_inst.status in ["Primary"]:
                    self.primary_dn_ids.append(data_inst.instanceId)
                if data_inst.status in ["Main Standby"]:
                    self.main_standby_ids.append(data_inst.instanceId)
                if data_inst.status in ["Cascade Standby"]:
                    self.cascade_standby_ids.append(data_inst.instanceId)
                if data_inst.status in ["Primary", "Standby", "Cascade Standby", "Main Standby"
                                        ] and data_inst.isInstanceHealthy():
                    self.normal_dn_ids.append(data_inst.instanceId)
                    self.normal_instances.append(data_inst)
                else:
                    abnormal_insts.append({data_inst.instanceId: data_inst.status})
            for etcd_inst in db_node.etcds:
                if etcd_inst.status in ["StateLeader", "StateFollower"] \
                        and etcd_inst.isInstanceHealthy():
                    self.normal_etcd_ids.append(etcd_inst.instanceId)
                    self.normal_instances.append(etcd_inst)
                else:
                    abnormal_insts.append({etcd_inst.instanceId: etcd_inst.status})
        return abnormal_insts

    def parse_cluster_status(self, current_status=None):
        """
        Parse cluster status
        """
        tmp_file = os.path.join(self.streaming_file_dir,
                                StreamingConstants.STREAMING_CLUSTER_STATUS_TMP_FILE)
        if (not os.path.isfile(tmp_file)) and (not current_status):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                            % "cluster status file:%s" % tmp_file)
        self.status_info = DbClusterStatus()
        self.__clean_cluster_status()
        if current_status:
            self.status_info.init_from_content(current_status)
        else:
            self.status_info.initFromFile(tmp_file)
        self.cluster_status = self.status_info.clusterStatus
        self.logger.debug("Current cluster status is:%s." % self.cluster_status)
        # Parse instance status
        abnormal_insts = self.__parse_instance_status()
        # Get node names of normal nodes with nodeId
        for instance in self.normal_instances:
            self.normal_node_list.append(self.cluster_info.getDbNodeByID(int(instance.nodeId)).name)
        self.normal_node_list = list(set(self.normal_node_list))
        for node_id in list(set(self.normal_cm_ids)):
            self.normal_cm_ips.append(self.cluster_info.getDbNodeByID(int(node_id)).name)
        self.logger.debug("Parsed primary dns:%s" % self.primary_dn_ids)
        self.logger.debug("Parsed Main standby dns:%s" % self.main_standby_ids)
        if abnormal_insts:
            self.logger.debug("Abnormal instances:%s" % abnormal_insts)
        else:
            self.logger.debug("Checked all instances is normal:%s"
                              % set([inst.instanceId for inst in self.normal_instances]))

    def check_cluster_status(self, status_allowed, only_check=False,
                             check_current=False, is_log=True):
        """
        Stream disaster cluster switch to check cluster status
        """
        cluster_status = self.cluster_status
        if check_current:
            self.logger.debug("Starting check CLuster status")
            check_cmd = "source %s && cm_ctl query | grep cluster_state | awk '{print $NF}'"\
                        % self.mpp_file
            status, output = CmdUtil.retryGetstatusoutput(check_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51600"] +
                                "status(%d), output(%s)" % (status, output))
            cluster_status = output.strip()
            self.logger.debug("Checked cluster status is:%s" % cluster_status)
        if cluster_status not in status_allowed:
            if only_check is True:
                self.logger.debug("Current cluster status is %s" % cluster_status)
                return False
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "check cluster status")
        if is_log:
            self.logger.log("Successfully check cluster status is: %s." % cluster_status)
        else:
            self.logger.debug("Checked cluster status is: %s." % cluster_status)
        return True

    def check_is_under_upgrade(self):
        """
        Check is cluster is not doing upgrade
        """
        if DefaultValue.isUnderUpgrade(self.user):
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "check upgrade binary file, please ensure upgrade "
                                  "is finished and upgrade files has been cleaned")
        self.logger.debug("Successfully check cluster is not under upgrade opts.")

    def check_cluster_is_common(self):
        """
        Check no main standby and cascade standby
        """
        if self.main_standby_ids or self.cascade_standby_ids:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "check instance status, there are already main standby "
                                  "or cascade standby, main standby:%s, cascade stadnby:%s"
                                % (self.main_standby_ids, self.cascade_standby_ids))
        self.logger.log("Successfully check instance status.")

    def check_dn_instance_params(self):
        """set_dn_instance_params"""
        check_dick = {"enable_dcf": "off", "synchronous_commit": "on"}
        dn_insts = [dn_inst for db_node in self.cluster_info.dbNodes
                    for dn_inst in db_node.datanodes]
        if len(dn_insts) <= 2:
            self.logger.debug("Need set most available for current cluster.")
            check_dick.update({"most_available_sync": "on"})
        primary_dn_insts = [inst for inst in dn_insts if inst.instanceId in self.primary_dn_ids]
        if not primary_dn_insts:
            self.logger.debug("The primary dn not exist, do not need check dn inst params.")
            return
        execute_dn = primary_dn_insts[0]
        param_list = []
        guc_backup_file = os.path.join(self.streaming_file_dir, StreamingConstants.GUC_BACKUP_FILE)
        if not os.path.isfile(guc_backup_file):
            FileUtil.createFileInSafeMode(guc_backup_file, DefaultValue.KEY_FILE_MODE_IN_OS)
        for peer_check, idx in list(check_dick.items()):
            param_list.append((execute_dn, {peer_check: idx}))
        ret = parallelTool.parallelExecute(self._check_dn_inst_param, param_list)
        self.ssh_tool.scpFiles(guc_backup_file, self.streaming_file_dir, self.cluster_node_names)
        if any(ret):
            self.logger.logExit('\n'.join(filter(bool, ret)))
        self.logger.debug("Successfully check dn inst default value.")

    def _check_dn_inst_param(self, param):
        """check_dn_inst_param"""
        self.logger.debug("Check dn inst params: %s." % param[1])
        if len(param) != 2:
            error_msg = ErrorCode.GAUSS_521["GAUSS_52102"] % param
            return error_msg
        guc_backup_file = os.path.join(self.streaming_file_dir, StreamingConstants.GUC_BACKUP_FILE)
        for sql_key, value in list(param[1].items()):
            sql = "show %s;" % sql_key
            (status, output) = ClusterCommand.remoteSQLCommand(sql,
                                                               self.user, param[0].hostname,
                                                               str(param[0].port))
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % sql, "\nError:%s" % output)
            if output.strip() != value:
                if sql_key in StreamingConstants.GUC_CHANGE_MAP.keys():
                    content = "%s,%s,%s" % (sql_key, output.strip(), self.trace_id)
                    FileUtil.write_add_file(guc_backup_file, content,
                                            DefaultValue.KEY_FILE_MODE_IN_OS)
                    self.__set_guc_param(sql_key, StreamingConstants.GUC_CHANGE_MAP[sql_key],
                                         mode="reload", inst_type="dn", raise_error=True)
                    return
                error_msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                            % "check [%s], Actual value: [%s], expect value: [%s]" \
                            % (sql, output, value)
                return error_msg
        self.logger.debug("Successfully check and rectify dn inst value:%s." % param[1])

    def restore_guc_params(self):
        """
        Restore guc params in .streaming_guc_backup
        """
        self.logger.debug("Start restore guc params.")
        guc_backup_file = os.path.join(self.streaming_file_dir, StreamingConstants.GUC_BACKUP_FILE)
        if not os.path.isfile(guc_backup_file):
            self.logger.debug("Not found guc backup file, no need restore guc params.")
        params_record = DefaultValue.obtain_file_content(guc_backup_file)
        params_record.reverse()
        restored_keys = []
        for param in params_record:
            guc_key, guc_value, trace_id = param.split(",")
            self.logger.debug("Got guc param:%s, value:%s, trace id:%s in guc backup file."
                              % (guc_key, guc_value, trace_id))
            if guc_key not in StreamingConstants.GUC_CHANGE_MAP.keys():
                continue
            # When the number of dns <=2, ensure that the maximum available mode is always on.
            dn_insts = [dn_inst for db_node in self.cluster_info.dbNodes
                        for dn_inst in db_node.datanodes]
            if guc_key in restored_keys or len(dn_insts) <= 2 \
                    and guc_key in ["most_available_sync"]:
                continue
            guc_value = "off" if guc_value not in ["on", "off"] else guc_value
            self.__set_guc_param(guc_key, guc_value, mode="reload",
                                 inst_type="dn", raise_error=False)
            restored_keys.append(guc_key)

    def set_most_available(self, mode='set', inst_type='dn', raise_error=True):
        dn_insts = [dn_inst for db_node in self.cluster_info.dbNodes
                    for dn_inst in db_node.datanodes if int(dn_inst.mirrorId) == 1]
        if len(dn_insts) > 2:
            self.logger.debug("No need set most available for current cluster.")
            return
        self.__set_guc_param("most_available_sync", "on", mode=mode,
                             inst_type=inst_type, raise_error=raise_error)

        self.__set_guc_param("synchronous_commit", "on", mode=mode,
                             inst_type=inst_type, raise_error=raise_error)

    def __set_guc_param(self, key, value, mode='set', inst_type='dn', raise_error=True):
        """
        Set guc param
        """
        if inst_type == 'dn':
            instance = '-Z datanode'
        elif inst_type == 'cn':
            instance = '-Z coordinator'
        else:
            instance = "-Z datanode -Z coordinator"
        cmd = "source %s && gs_guc %s %s -N all -I all " \
              "-c \"%s=%s\"" \
              % (self.mpp_file, mode, instance, key, value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            if raise_error:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "Error:%s" % output)
            else:
                self.logger.debug(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "Error:%s" % output)
        else:
            self.logger.debug("Successfully change %s %s with mode %s." % (key, value, mode))

    def distribute_cluster_conf(self):
        """
        Record cluster conf in files
        """
        data = {"remoteClusterConf": self.params.remoteClusterConf,
                "localClusterConf": self.params.localClusterConf}
        file_path = os.path.join(self.streaming_file_dir,
                                 StreamingConstants.STREAMING_CLUSTER_CONF_RECORD)
        FileUtil.write_update_file(file_path, data, DefaultValue.KEY_FILE_MODE_IN_OS)
        self.ssh_tool.scpFiles(file_path, self.streaming_file_dir, self.cluster_node_names)

    def __record_wal_keep_segments(self, param_list):
        """
        record wal_keep_segments value to .wal_keep_segments_record
        """
        dn_inst, sql_check, wal_keep_segments = param_list
        self.logger.debug("Starting record wal_keep_segments default "
                          "value for isntance:%s." % dn_inst.instanceId)
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql_check, self.user, dn_inst.hostname, dn_inst.port, True)
        self.logger.debug("Got %s wal_keep_segments, status=%d, output: %s." %
                          (dn_inst.instanceId, status, SensitiveMask.mask_pwd(output)))
        if status == 0 and output.strip():
            value = output.strip()
            FileUtil.createFile(wal_keep_segments, True, DefaultValue.KEY_FILE_MODE)
            FileUtil.writeFile(wal_keep_segments, [str(dn_inst.instanceId) + ":" + str(value)])
            self.logger.debug("Successfully record %s wal_keep_segments default value:%s" %
                              (dn_inst.hostname, value))
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"]
                            % "wal_keep_segments default value of %s" % dn_inst.instanceId)

    def get_default_wal_keep_segments(self, only_mode=None):
        """
        get wal_keep_segments default value in primary dn
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Wal keep segment opts not for mode:%s." % self.params.mode)
            return
        self.logger.debug("Starting get wal_keep_segments default value.")
        wal_keep_segments = os.path.join(
            self.streaming_file_dir, StreamingConstants.WAL_KEEP_SEGMENTS)
        sql_check = "show wal_keep_segments;"
        param_list = [(dn_inst, sql_check, wal_keep_segments) for db_node in
                      self.cluster_info.dbNodes for dn_inst in db_node.datanodes
                      if dn_inst.instanceId in self.primary_dn_ids]
        if not param_list:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain param list for get wal_keep_segments")
        parallelTool.parallelExecute(self.__record_wal_keep_segments, param_list)
        self.logger.debug("Successfully get wal_keep_segments default value.")

    def __set_wal_keep_segments_each_inst(self, params_list):
        """
        Set wal_keep_segments value in primary dn
        """
        (inst, opt_type, value, mpprc_file) = params_list
        self.logger.debug("Start [%s] shardNum [%s] node [%s] wal_keep_segments value [%s]."
                          % (opt_type, inst.mirrorId, inst.hostname, value))
        cmd = "source %s; pssh -H %s \"source %s ; gs_guc %s " \
              "-Z datanode -D %s -c \\\"wal_keep_segments = '%s'\\\"\"" % \
              (mpprc_file, inst.hostname, mpprc_file, opt_type, inst.datadir, value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Options:%s, Error: \n%s "
                            % ("set wal_keep_segments for inst:%s" % inst.instanceId, str(output)))
        self.logger.debug("Successfully [%s] shardNum [%s] node [%s] wal_keep_segments "
                          "value [%s]." % (opt_type, inst.mirrorId, inst.hostname, value))

    def set_wal_keep_segments(self, opt_type, value, restore_flag=False, only_mode=None):
        """
        guc set wal_keep_segments value in primary dn
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set wal_keep_segments opts not for mode:%s." % self.params.mode)
            return
        self.logger.log("Starting %s wal_keep_segments value: %s." % (opt_type, value))
        if restore_flag and isinstance(value, dict):
            params_list = [(inst, opt_type, value.get(inst.instanceId, 128), self.mpp_file) for
                           node in self.cluster_info.dbNodes for inst in node.datanodes
                           if inst.instanceId in self.primary_dn_ids]
        else:
            params_list = [(inst, opt_type, value, self.mpp_file) for node in
                           self.cluster_info.dbNodes for inst in node.datanodes
                           if inst.instanceId in self.primary_dn_ids]
        if not params_list:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain param list for set wal_keep_segments")
        parallelTool.parallelExecute(self.__set_wal_keep_segments_each_inst, params_list)
        self.logger.log("Successfully %s wal_keep_segments value: %s." % (opt_type, value))

    def __stop_one_node(self, node_id):
        """
        Stop one node by node id
        """
        self.logger.debug("Start stop node:%s" % node_id)
        cmd = ClusterCommand.getStopCmd(int(node_id), "i", 1800)
        self.logger.debug("Streaming disaster calling cm_ctl to stop cluster, cmd=[%s]" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            self.logger.debug("Failed stop node:%s, error:%s" % (node_id, output))
        else:
            self.logger.debug("Successfully stop node:%s" % node_id)

    def stop_cluster_by_node(self, only_mode=None):
        """
        stop the cluster by node
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Stop cluster by node not for mode:%s." % self.params.mode)
            return
        self.logger.log("Stopping the cluster by node.")
        static_config = "%s/cluster_static_config" % self.bin_path
        cm_ctl_file = "%s/cm_ctl" % self.bin_path
        if not os.path.isfile(static_config) or not os.path.isfile(cm_ctl_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                            % (static_config + " or " + cm_ctl_file))
        node_id_list = list(set([instance.nodeId for instance in self.normal_instances]))
        parallelTool.parallelExecute(self.__stop_one_node, node_id_list)
        self.logger.log("Successfully stopped the cluster by node for streaming cluster.")

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

    def update_streaming_pg_hba(self, step):
        """
        update pg_hba.conf, read config_param.json file and set other cluster ip
        :return:NA
        """
        self.logger.log("Start update pg_hba config.")
        use_xml_action = False

        if self.params.json_path:
            self.logger.debug("[update_streaming_pg_hba] use json file.")
            cmd = "source %s; %s -U %s " % (
                self.mpp_file, OMCommand.getLocalScript(
                    "Local_Config_Hba"), self.user)
        elif self.params.xml_path and os.path.isfile(self.params.xml_path):
            self.logger.debug("[update_streaming_pg_hba] use xml file.")
            use_xml_action = True
            FileUtil.cpFile(self.params.xml_path, self.streaming_xml)
            cmd = "source %s; %s -U %s -X '%s' " % (
                self.mpp_file, OMCommand.getLocalScript(
                    "Local_Config_Hba"), self.user, self.streaming_xml)

        # The cluster may be stopped when re-entering after a failuer, then it can't be reloaded
        if step <= 5:
            cmd += " --try-reload"
        self.logger.debug("Command for changing instance pg_hba.conf file: %s" % cmd)
        self.get_all_connection_node_name("update_streaming_pg_hba")
        try:
            if use_xml_action:
                self.ssh_tool.scpFiles(self.streaming_xml, self.streaming_file_dir)
            self.ssh_tool.executeCommand(cmd, hostList=self.connected_nodes)
        except Exception as error:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "update streaming pg_hba with error:%s" % error
            self.logger.debug(msg)
            raise Exception(msg)
        self.logger.log("Successfully update pg_hba config.")

    def __get_repl_info_cmd(self, node_name, ret, dn_inst, opt_mode, idx):
        """
        get_repl_info_cmd
        """
        if node_name != self.local_host:
            set_cmd = "source %s; pssh -H %s \"source %s ; gs_guc %s " \
                      "-Z datanode -D %s -c " \
                      "\\\"replconninfo%s = 'localhost=%s localport=%s " \
                      "localheartbeatport=%s localservice=%s remotehost=%s " \
                      "remoteport=%s remoteheartbeatport=%s " \
                      "remoteservice=%s iscascade=%s iscrossregion=%s'\\\"\""
            set_cmd = set_cmd % (self.mpp_file, node_name,
                                 self.mpp_file, opt_mode,
                                 dn_inst.datadir, idx, ret.group(1),
                                 ret.group(2), ret.group(3), ret.group(4),
                                 ret.group(5), ret.group(6), ret.group(7),
                                 ret.group(8), "true", "false")
        else:
            set_cmd = "source %s ; gs_guc %s -Z datanode -D %s -c " \
                      "\"replconninfo%s = 'localhost=%s localport=%s " \
                      "localheartbeatport=%s localservice=%s remotehost=%s " \
                      "remoteport=%s remoteheartbeatport=%s " \
                      "remoteservice=%s iscascade=%s iscrossregion=%s'\""
            set_cmd = set_cmd % (self.mpp_file, opt_mode,
                                 dn_inst.datadir, idx, ret.group(1),
                                 ret.group(2), ret.group(3), ret.group(4),
                                 ret.group(5), ret.group(6), ret.group(7),
                                 ret.group(8), "true", "false")
        return set_cmd

    def __set_original_repl_info(self, dn_inst, node_name, opt_mode="set"):
        """
        Rectify original replconninfos
        """
        orignal_ports = None
        if not all([dn_inst, node_name]):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain dn infos")
        for idx in range(1, StreamingConstants.MAX_REPLICATION_NUMS + 1):
            if node_name == self.local_host:
                cmd = "source %s; gs_guc check -Z datanode -D %s " \
                      "-c 'replconninfo%s'" % (self.mpp_file, dn_inst.datadir, idx)
            else:
                cmd = "source %s; pssh -H %s 'source %s; gs_guc check " \
                      "-Z datanode -D %s -c \"replconninfo%s\"'" \
                      % (self.mpp_file, node_name, self.mpp_file, dn_inst.datadir, idx)
            self.logger.debug("Check original repl infos with cmd:%s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)
            if output.count("=NULL") > 2 or "iscrossregion=true" in output.lower():
                self.logger.debug("InstanceID:%s, Index:%s" % (dn_inst.instanceId, idx))
                return idx, orignal_ports
            if output.count(f"replconninfo{idx}=''") >= 2:
                continue
            ret = re.search(
                r"replconninfo%s='localhost=((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4})"
                r" localport=(\d{4,5}) localheartbeatport=(\d{4,5}) "
                r"localservice=(\d{4,5}) "
                r"replconninfo%s='localhost=((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4})"
                r"remoteport=(\d{4,5}) remoteheartbeatport=(\d{4,5}) "
                r"remoteservice=(\d{4,5})" % idx, output)
            if not ret:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "search repl infos")
            set_cmd = self.__get_repl_info_cmd(node_name, ret, dn_inst, opt_mode, idx)
            self.logger.debug("Set original repl infos with cmd:%s" % set_cmd)
            status, output = CmdUtil.retryGetstatusoutput(set_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % set_cmd +
                                " Error: \n%s " % output)
            orignal_ports = (ret.group(2), ret.group(3), ret.group(4))
            self.logger.debug("Successfully rectify original repl infos for instance:%s."
                              % dn_inst.instanceId)

    def __get_local_data_ip(self, inst_host):
        """
        Get local data ip
        """
        local_cluster_info = self.params.localClusterConf
        shards = local_cluster_info["shards"]
        inst_ips = DefaultValue.get_remote_ips(inst_host, self.mpp_file)
        for shard in shards:
            for node in shard:
                ip = node["ip"]
                data_ip = node["dataIp"]
                if ip in inst_ips:
                    self.logger.debug("Got ip[%s], dataIp[%s]." % (ip, data_ip))
                    return data_ip
        raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                        % "obtain shards from local cluster info")

    def __config_one_dn_instance(self, params):
        """
        Config replconninfo for one dn instance
        """
        inst, opt_mode, remote_cluster_info = params
        local_data_ip = self.__get_local_data_ip(inst.hostname)
        base_dn_port = self.params.remoteClusterConf['port']
        self.logger.debug("Start config instance:[%s], got dataIp:[%s], port:[%s]."
                          % (inst.instanceId, local_data_ip, base_dn_port))
        if not all([local_data_ip, base_dn_port]):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"]
                            % "dn port or dataIp for config instance")
        inst_index, original_ports = self.__set_original_repl_info(
            inst, inst.hostname, opt_mode=opt_mode)
        repl_params = []
        shards = remote_cluster_info.get("shards")
        for shard in shards:
            for node_info in shard:
                data_ip = node_info.get("dataIp")
                shard_num = node_info.get("shardNum", '1')
                if str(inst.mirrorId) == str(shard_num):
                    repl_params.append((
                        shard_num, inst.hostname, local_data_ip,
                        inst.datadir, data_ip, inst_index,
                        original_ports, base_dn_port, opt_mode))
                    inst_index += 1
        return repl_params

    def __do_config_dn_repl_info(self, params):
        """
        function:config postgres conf
        :return:NA
        """
        shard_num, host, local_data_ip, data_dir, data_ip, index, \
        original_ports, base_port, opt_mode = params
        local_port, local_heartbeat, local_service = original_ports
        remote_base = int(base_port)
        self.logger.debug("shard num %s base port is %s" % (shard_num, remote_base))
        remote_port = remote_base + 1
        remote_heartbeat = remote_base + 5
        remote_service = remote_base + 4
        is_cascade = "false"
        if self.local_host == host:
            guc_cmd = "source %s ; gs_guc %s -Z datanode -D %s " \
                      "-c \"replconninfo%s = 'localhost=%s localport=%s " \
                      "localheartbeatport=%s localservice=%s remotehost=%s " \
                      "remoteport=%s remoteheartbeatport=%s remoteservice=%s " \
                      "iscascade=%s iscrossregion=true'\"" \
                      % (self.mpp_file, opt_mode, data_dir, index, local_data_ip, local_port,
                         local_heartbeat, local_service, data_ip, remote_port,
                         remote_heartbeat, remote_service, is_cascade)
            self.logger.debug("Set datanode postgres file for streaming "
                              "disaster cluster with cmd:%s" % guc_cmd)
        else:
            guc_cmd = "source %s; pssh -s -H %s \"source %s ; gs_guc %s -Z datanode -D %s " \
                      "-c \\\"replconninfo%s = 'localhost=%s localport=%s " \
                      "localheartbeatport=%s localservice=%s remotehost=%s " \
                      "remoteport=%s remoteheartbeatport=%s remoteservice=%s " \
                      "iscascade=%s iscrossregion=true'\\\"\"" \
                      % (self.mpp_file, host,
                         self.mpp_file, opt_mode, data_dir, index,
                         local_data_ip, local_port, local_heartbeat,
                         local_service, data_ip, remote_port,
                         remote_heartbeat, remote_service, is_cascade)
            self.logger.debug("Set datanode postgres file for streaming "
                              "disaster cluster with cmd:%s" % guc_cmd)
        status, output = CmdUtil.retryGetstatusoutput(guc_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % guc_cmd +
                            " Error: \n%s " % output)

    def config_streaming_repl_info(self):
        """
        update postgresql.conf for replconninfo
        """
        self.logger.debug("set all datanode guc param in postgres conf for streaming cluster.")
        repl_params = []
        opt_mode = "reload" if self.params.mode == "primary" else "set"
        config_repl_params = []
        datanode_instance = [inst for node in self.cluster_info.dbNodes for inst in node.datanodes]

        for inst in datanode_instance:
            config_repl_params.append((inst, opt_mode, self.params.remoteClusterConf))
        rets = parallelTool.parallelExecute(self.__config_one_dn_instance, config_repl_params)
        for param in rets:
            repl_params += param
        self.logger.debug("Got repl params:%s" % str(repl_params))
        parallelTool.parallelExecute(self.__do_config_dn_repl_info, repl_params)
        self.logger.debug(
            "Successfully set all datanode guc param in postgres conf for streaming cluster.")

    def set_cmserver_guc(self, guc_parameter, guc_value, guc_type, only_mode=None):
        """
        set cmserver guc param
        :return: NA
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Set cms guc [%s] to [%s] not for mode:%s."
                              % (guc_parameter, guc_value, self.params.mode))
            return
        cmd = "gs_guc %s -Z cmserver -N all -I all -c \"%s=%s\" " % \
              (guc_type, guc_parameter, guc_value)
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
        cmd = "gs_guc %s -Z cmagent -N all -I all -c \"%s=%s\" " % \
              (guc_type, guc_parameter, guc_value)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            msg = ErrorCode.GAUSS_516['GAUSS_51632'] \
                  % "set cm agent guc [%s] to [%s], output:%s" \
                  % (guc_parameter, guc_value, output)
            self.logger.debug(msg)

    def __check_datanode_data_ip_connection(self, inst):
        """
        Check remote data ip can connect or not
        """
        any_connected = False
        node_infos = [node_info for shard in self.params.remoteClusterConf.get("shards", [])
                      for node_info in shard]
        local_data_ip = self.__get_local_data_ip(inst.hostname)
        for node_info in node_infos:
            data_ip = node_info.get("dataIp")
            shard_num = node_info.get("shardNum", '1')
            if str(shard_num) != str(inst.mirrorId):
                continue
            _, ret = DefaultValue.fast_ping_on_node(inst.hostname, local_data_ip,
                                                    data_ip, self.logger)
            if ret:
                any_connected = True
                break
        if not any_connected:
            self.logger.error("Failed check data ip connection for inst:%s." % inst.instanceId)
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "check data ip connection")
        self.logger.debug("Successfully check main standby data ip connection.")

    def __pghba_backup_handler(self, node_name, dir_name, inst_id, mode="backup"):
        """
        Backup or restore pg_hba file.
        """
        file_path = os.path.join(dir_name, "pg_hba.conf")
        old_file_path = os.path.join(dir_name, "pg_hba.conf.old")
        dest_file = os.path.join(self.streaming_file_dir, "%s_pg_hba.conf" % inst_id)
        if self.local_host == node_name:
            if mode == "backup" and not os.path.isfile(dest_file):
                if os.path.isfile(file_path):
                    self.logger.debug("Backup file from[%s] to[%s]." % (
                        file_path, dest_file))
                    FileUtil.cpFile(file_path, dest_file)
                else:
                    self.logger.debug("Backup file from[%s] to[%s]." % (
                        old_file_path, dest_file))
                    FileUtil.cpFile(old_file_path, dest_file)
            if mode == "restore":
                self.logger.debug("Restore file from[%s] to[%s]." % (
                    dest_file, file_path))
                FileUtil.cpFile(dest_file, file_path)
                FileUtil.removeFile(dest_file)
        else:
            if mode == "backup":
                cmd = "source %s; pssh -s -H %s \"if [ ! -f '%s' ];then if [ -f '%s' ];" \
                      "then cp '%s' '%s';else cp '%s' '%s';fi;fi\"" \
                      % (self.mpp_file, node_name, dest_file, file_path, file_path,
                         dest_file, old_file_path, dest_file)
                self.logger.debug("Backup file on node[%s] with cmd [%s]." % (
                    node_name, cmd))
            else:
                cmd = "source %s; pssh -s -H %s \"cp %s %s && rm -f %s\"" % (
                    self.mpp_file, node_name, dest_file, file_path, dest_file)
                self.logger.debug("Restore file on node[%s] from[%s] to[%s]." % (
                    node_name, file_path, dest_file))
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)

    def __pg_ident_backup_handler(self, node_name, dir_name, inst_id, mode="backup"):
        """
        Backup or restore pg_ident file.
        """
        file_path = os.path.join(dir_name, "pg_ident.conf")
        dest_file = os.path.join(self.streaming_file_dir, "%s_pg_ident.conf" % inst_id)
        if self.local_host == node_name:
            if mode == "backup" and not os.path.isfile(dest_file):
                if os.path.isfile(file_path):
                    self.logger.debug("Backup file from[%s] to[%s]." % (
                        file_path, dest_file))
                    FileUtil.cpFile(file_path, dest_file)

            if mode == "restore" and os.path.isfile(dest_file):
                self.logger.debug("Restore file from[%s] to[%s]." % (
                    dest_file, file_path))
                FileUtil.cpFile(dest_file, file_path)
                FileUtil.removeFile(dest_file)
        else:
            if mode == "backup":
                cmd = "source %s; pssh -s -H %s \"if [ ! -f '%s' ];then if [ -f '%s' ];" \
                      "then cp '%s' '%s';fi;fi\"" \
                      % (self.mpp_file, node_name, dest_file, file_path, file_path, dest_file)
                self.logger.debug("Backup file on node[%s] with cmd [%s]." % (
                    node_name, cmd))
            else:
                cmd = "source %s; pssh -s -H %s \"if [ -f '%s' ];then cp '%s' '%s' && " \
                      "rm -f '%s';fi\"" % (self.mpp_file, node_name, dest_file, dest_file,
                                           file_path, dest_file)
                self.logger.debug("Restore file on node[%s] from[%s] to[%s]." % (
                    node_name, file_path, dest_file))
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)

    def __start_main_standby_dn(self, start_params):
        """
        Start single main standby dn
        """
        local_ip, inst, bin_path, distribute_arg, build_timeout = start_params
        self.logger.log("Starting single main standby dn:%s" % inst.instanceId)
        if local_ip == inst.hostname:
            cmd_start = "source %s; %s/gs_ctl start -D %s -M hadr_main_standby%s" % (
                self.mpp_file, bin_path, inst.datadir, distribute_arg)
        else:
            cmd_start = "source %s; pssh -s -t %s -H %s \"source %s; %s/gs_ctl start -D %s " \
                        "-M hadr_main_standby%s\"" \
                        % (self.mpp_file, StreamingConstants.MAX_BUILD_TIMEOUT + 10, inst.hostname,
                           self.mpp_file, bin_path, inst.datadir, distribute_arg)
        self.logger.debug("Start dn with cmd:%s." % cmd_start)
        status, output = CmdUtil.retry_util_timeout(cmd_start, build_timeout)
        if status != 0:
            raise Exception(
                ErrorCode.GAUSS_514[
                    "GAUSS_51400"] % cmd_start + " Error: \n%s " % output)
        self.logger.log("Successfully start single main standby dn:%s" % inst.instanceId)

    def __check_build_state(self, host, is_local, datadir):
        """
        check build state:
            Build failed
            Building
            Build completed
        """
        check_build_state_cmd = "source %s; gs_ctl querybuild -D %s" % (self.mpp_file, datadir)
        if not is_local:
            check_build_state_cmd = "pssh -s -H %s \"%s\"" % (host, check_build_state_cmd)
        status, output = subprocess.getstatusoutput(check_build_state_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % check_build_state_cmd +
                            "status: %s\n" % status + " output: \n%s " % output)
        build_states = re.findall(r'db_state *: *(.*)', output)
        if len(build_states) < 1:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % check_build_state_cmd +
                            "\nstatus: %s\n" % status + " output: \n%s " % output)
        return build_states[0]

    def __build_main_standby_dn(self, params):
        """
        Build single main standby dn
        """
        inst, build_timeout, local_ip, bin_path, distribute_arg, rds_backup, backup_pwd = params
        self.logger.log("Start build main standby dn:%s" % inst.instanceId)
        self.__check_datanode_data_ip_connection(inst)
        self.__pghba_backup_handler(inst.hostname, inst.datadir, inst.instanceId, mode="backup")
        self.__pg_ident_backup_handler(inst.hostname, inst.datadir, inst.instanceId, mode="backup")
        # -t 1209600 means default value 14 days
        if local_ip == inst.hostname:
            cmd = "source %s; nohup %s/gs_ctl build -D %s -M hadr_main_standby -r 7200 -q%s -Q " \
                  "force_copy_from_local -U %s -P '%s' -t %s &" \
                  % (self.mpp_file, bin_path, inst.datadir, distribute_arg, rds_backup, backup_pwd,
                     StreamingConstants.MAX_BUILD_TIMEOUT)
        else:
            cmd = "echo \"source %s; nohup %s/gs_ctl build -D %s -M hadr_main_standby -r 7200 -q%s " \
                  "-Q force_copy_from_local -U %s -P '%s' -t %s &\" | pssh -s -t %s -H %s" \
                  % (self.mpp_file, bin_path, inst.datadir, distribute_arg, rds_backup,
                     backup_pwd, StreamingConstants.MAX_BUILD_TIMEOUT,
                     StreamingConstants.MAX_BUILD_TIMEOUT + 10, inst.hostname)
        cmd_log = cmd.replace(backup_pwd, '***')
        self.logger.debug("Building with cmd:%s." % cmd_log)

        max_try_times = 3
        try_time = 0
        while try_time < max_try_times:
            status, output = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.debug("Building failed with cmd:%s, output:%s." % (cmd_log, output))
                try_time += 1
                continue

            while True:
                output = self.__check_build_state(inst.hostname, local_ip == inst.hostname, inst.datadir)
                if output != "Building":
                    break
                time.sleep(5)
            if output == "Build completed":
                self.logger.log("Successfully build main standby dn:%s" % inst.instanceId)
                break
            else:
                self.logger.debug("building process of main standby interupted abnormally!")
                self.logger.log("Failed to build main standby dn:%s. Try next time." % inst.instanceId)
                try_time += 1

        if try_time == max_try_times:
            self.logger.log("Failed to build main standby more than three times.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "full build from remote cluster")

        self.__pghba_backup_handler(inst.hostname, inst.datadir, inst.instanceId, mode="restore")
        self.__pg_ident_backup_handler(inst.hostname, inst.datadir, inst.instanceId, mode="restore")
        start_params = (local_ip, inst, bin_path, distribute_arg, build_timeout)
        self.__start_main_standby_dn(start_params)

    def __build_cascade_standby_dn(self, params):
        """
        Build single cascade standby dn
        """
        inst, build_timeout, local_ip, bin_path, distribute_arg = params
        self.logger.log("Start build cascade standby dn:%s" % inst.instanceId)
        # -t 1209600 means default value 14 days
        if local_ip == inst.hostname:
            cmd = "source %s; nohup %s/gs_ctl build -D %s -M cascade_standby " \
                  "-b standby_full -r 7200%s -t %s &" \
                  % (self.mpp_file, bin_path, inst.datadir, distribute_arg,
                     StreamingConstants.MAX_BUILD_TIMEOUT)
        else:
            cmd = "echo \"source %s; nohup %s/gs_ctl build -D %s -M cascade_standby -b standby_full " \
                  "-r 7200%s -t %s & \" | pssh -s -t %s -H %s" \
                  % (self.mpp_file, bin_path, inst.datadir, distribute_arg,
                     StreamingConstants.MAX_BUILD_TIMEOUT,
                     StreamingConstants.MAX_BUILD_TIMEOUT + 10, inst.hostname)
        self.logger.debug("Building with cmd:%s." % cmd)

        max_try_times = 3
        try_time = 0
        while try_time < max_try_times:
            status, output = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.debug("Building failed with cmd:%s, output:%s." % (cmd, output))
                try_time += 1
                continue

            while True:
                output = self.__check_build_state(inst.hostname, local_ip == inst.hostname, inst.datadir)
                if output != "Building":
                    break
                time.sleep(5)
            if output == "Build completed":
                break
            else:
                self.logger.debug("building process of cascade standby interupted abnormally!")
                self.logger.log("Failed to build cascade standby dn:%s. Try next time." % inst.instanceId)
                try_time += 1

        if try_time == max_try_times:
            self.logger.log("Failed to build cascade standby more than three times.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "full build from remote cluster")

        self.logger.log("Successfully build cascade standby dn:%s" % inst.instanceId)

    def build_dn_instance(self, only_mode=None):
        """
        Build dn instance
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Build dn step is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start building process.")
        distribute_arg = "" if self.cluster_info.isSingleInstCluster() else " -Z datanode"
        main_params = []
        cascade_params = []
        datanode_instance = [inst for node in self.cluster_info.dbNodes
                             for inst in node.datanodes]
        for inst in datanode_instance:
            if inst.instanceId in self.main_standby_ids + self.primary_dn_ids:
                main_params.append((inst, self.params.waitingTimeout, self.local_host,
                                    self.bin_path, distribute_arg, self.params.hadrUserName,
                                    self.params.hadrUserPassword))
            else:
                cascade_params.append((inst, self.params.waitingTimeout, self.local_host,
                                       self.bin_path, distribute_arg))
        if main_params:
            parallelTool.parallelExecute(self.__build_main_standby_dn, main_params)
            self.logger.log("Finished build main standby dns.")
        if cascade_params:
            parallelTool.parallelExecute(self.__build_cascade_standby_dn, cascade_params)
            self.logger.log("Finished build cascade standby dns.")
        del self.params.hadrUserPassword

    def query_cluster(self):
        """
        query cluster
        :return: output
        """
        cmd = "source %s; cm_ctl query -v -C -s -i -d" % self.mpp_file
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            self.logger.error(ErrorCode.GAUSS_516["GAUSS_51600"] +
                              "status(%d), output(%s)" % (status, output))
        return output

    def start_cluster(self, cm_timeout=None, only_mode=None):
        """
        start the cluster
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Start cluster is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Starting the cluster.")
        cm_timeout = cm_timeout or 300
        user, group = UserUtil.getPathOwner(self.gp_home)
        if user == "" or group == "":
            raise Exception("Failed to obtain the owner of application.")
        end_time = datetime.now() + timedelta(seconds=cm_timeout)
        cmd = ClusterCommand.getStartCmd(0, cm_timeout)
        self.logger.debug("Calling cm_ctl to start cluster, cmd=[%s]" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd, retry_time=0)
        if status != 0:
            error_str = ErrorCode.GAUSS_516["GAUSS_51607"] % "the cluster" + \
                          " Error:\n%s." % output
            self.logger.debug(error_str)
            self.logger.log("Warning: the cluster is not normal, please check cluster status!")
        else:
            self.logger.log("Successfully started primary instance. "
                            "Please wait for standby instances.")

        cluster_normal_status = [DefaultValue.CLUSTER_STATUS_NORMAL,
                                 DefaultValue.CLUSTER_STATUS_DEGRADED]
        while True:
            time.sleep(5)
            self.logger.log('Waiting cluster normal.')
            check_ret = self.check_cluster_status(cluster_normal_status, only_check=True,
                                                  check_current=True, is_log=False)
            if check_ret:
                self.logger.log("Successfully started standby instances.")
                break
            if datetime.now() >= end_time:
                query_result = self.query_cluster()
                self.logger.log("Timeout. Failed to start the cluster in (%s)s." % cm_timeout)
                self.logger.log("Current cluster status (%s)." % query_result)
                self.logger.log("It will continue to start in the background.")
                break

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
        sql_check = "select 1 from pg_catalog.gs_hadr_local_rto_and_rpo_stat();"
        sql_check_2 = "select 1 from pg_catalog.pg_stat_get_wal_senders() where " \
                      "sync_state='Async' and peer_role='Standby' and peer_state='Normal';"
        param_list = [(dn_inst, sql_check) for db_node in self.cluster_info.dbNodes
                      for dn_inst in db_node.datanodes
                      if dn_inst.instanceId in self.primary_dn_ids]
        param_list_2 = [(dn_inst, sql_check_2) for db_node in self.cluster_info.dbNodes
                        for dn_inst in db_node.datanodes if dn_inst.instanceId
                        in self.primary_dn_ids]
        if not param_list:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain param list for check main standby connection on primary dn")
        self.logger.debug("Start check main standby connection with sql:%s." % sql_check)
        results = parallelTool.parallelExecute(self.__check_one_main_standby_connection,
                                               param_list)
        self.logger.debug("Start check main standby connection with sql:%s." % sql_check_2)
        results_2 = parallelTool.parallelExecute(self.__check_one_main_standby_connection,
                                                 param_list_2)

        return all(results+results_2)

    def wait_main_standby_connection(self, only_mode=None):
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Start cluster is not for mode:%s." % self.params.mode)
            return
        self.logger.log("Waiting for the main standby connection.")
        end_time = datetime.now() + timedelta(seconds=self.params.waitingTimeout)
        while True:
            p_inst_list = [int(i) for i in DefaultValue.get_primary_dn_instance_id("Primary",
                                                                                   ignore=True)]
            if self.check_main_standby_connection_primary_dn(p_inst_list):
                break
            if datetime.now() >= end_time:
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51632"] % "check main standby connection" +
                    " Because Waiting timeout: %ss" % str(self.params.waitingTimeout))
            time.sleep(5)
        self.logger.log("Main standby already connected.")

    def hadr_key_generator(self, key_name):
        """
        Generate key_name.key.cipher & key_name.key.rand
        """
        self.logger.log("Start generate hadr key files.")
        if not os.path.exists(self.bin_path):
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain bin path."
            self.logger.debug(msg)
            raise Exception(msg)
        if not os.path.exists(self.gp_home):
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain env GPHOME"
            self.logger.debug(msg)
            raise Exception(msg)
        key_cipher = os.path.join(self.bin_path, "%s.key.cipher" % key_name)
        key_rand = os.path.join(self.bin_path, "%s.key.rand" % key_name)
        cmd = "export LD_LIBRARY_PATH=%s/script/gspylib/clib && source %s " \
              "&& gs_guc generate -S default -o %s -D '%s' && %s && %s" \
              % (self.gp_home, self.mpp_file, key_name, self.bin_path,
                 CmdUtil.getChmodCmd(str(ConstantsBase.KEY_FILE_MODE), key_cipher),
                 CmdUtil.getChmodCmd(str(ConstantsBase.KEY_FILE_MODE), key_rand))
        if (not os.path.isfile(key_cipher)) or (not os.path.isfile(key_rand)):
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0 or (not os.path.isfile(key_cipher)) \
                    or (not os.path.isfile(key_rand)):
                msg = ErrorCode.GAUSS_516["GAUSS_51632"] \
                      % "generate hadr key files" + "Error:%s" % output
                self.logger.error(msg)
                raise Exception(msg)
        else:
            self.logger.log("Streaming key files already exist.")

        self.ssh_tool.scpFiles(key_cipher, self.bin_path)
        self.ssh_tool.scpFiles(key_rand, self.bin_path)
        self.logger.log("Finished generate and distribute hadr key files.")

    def encrypt_hadr_user_info(self, key_name, hadr_user, hadr_pwd):
        """
        Encrypt hadr user info.
        """
        self.logger.log("Start encrypt hadr user info.")
        cmd = "source %s && gs_encrypt -f %s \"%s|%s\"" \
              % (self.mpp_file, key_name, hadr_user, hadr_pwd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0 or not output:
            msg = ErrorCode.GAUSS_516["GAUSS_51632"] % "encrypt hadr user info"
            self.logger.error(msg)
            raise Exception(msg)
        self.logger.log("Successfully encrypt hadr user info.")
        return output

    def keep_hadr_user_info(self, info_str, retry=5):
        """
        Keep hadr user info into GLOBAL CONFIGURATION
        """
        self.logger.log("Start save hadr user info into database.")
        sql = "ALTER GLOBAL CONFIGURATION with(hadr_user_info ='%s');" % info_str
        primary_dns = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                       db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        primary_dns = primary_dns * retry
        output = "None"
        for dn_inst in primary_dns:
            status, output = ClusterCommand.remoteSQLCommand(
                sql, self.user, dn_inst.hostname, dn_inst.port, True)
            if status == 0:
                self.logger.log("Successfully save hadr user info into database.")
                return
        msg = ErrorCode.GAUSS_516['GAUSS_51632'] % "save hadr user info into database"
        self.logger.error(msg + "Error:%s" % SensitiveMask.mask_pwd(output))
        raise Exception(msg)

    def restore_wal_keep_segments(self, only_mode=None):
        """
        restore wal_keep_segments default value
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Restore wal_keep_segments not for mode:%s." % self.params.mode)
            return
        self.logger.debug("Starting restore wal_keep_segments default value.")
        default_value_dict = {}
        wal_keep_segments = os.path.join(self.streaming_file_dir,
                                         StreamingConstants.WAL_KEEP_SEGMENTS)
        if not os.path.isfile(wal_keep_segments):
            self.logger.debug("Not found wal keep segments record file, no need restore.")
            return
        wal_keep_segments_list = FileUtil.readFile(wal_keep_segments)
        if not wal_keep_segments_list:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632'] % "obtain record wal_keep_segments")
        for each_dn in wal_keep_segments_list:
            DefaultValue.checkGuc(each_dn.split(":")[1].strip())
            default_value_dict[each_dn.split(":")[0].strip()] = each_dn.split(":")[1].strip()
        self.set_wal_keep_segments("reload", default_value_dict, True)
        self.logger.debug("Successfully restore wal_keep_segments default value.")

    def __clean_streaming_files_on_local_node(self, file_name_list):
        file_name_list = [file_name_list] \
            if not isinstance(file_name_list, list) else file_name_list
        for file_name in file_name_list:
            file_path = os.path.join(self.streaming_file_dir, file_name)
            if os.path.isfile(file_path):
                FileUtil.removeFile(file_path)
                self.logger.debug("Successfully removed file:[%s]" % file_path)

    def clean_step_file(self):
        """
        Clean step file for each action
        """
        step_file = os.path.basename(self.step_file_path)
        self.__clean_streaming_files_on_local_node(step_file)
        self.logger.log("Successfully removed step file.")

    def check_action_and_mode(self):
        """
        Check action and mode if step file exist.
        if any streaming options not finished(step file exist),
        not allowed doing any other streaming options except query.
        """
        self.logger.debug("Checking action and mode.")
        exist_step_file_names = []
        for file_name in StreamingConstants.STREAMING_STEP_FILES.values():
            step_file_path = os.path.join(self.streaming_file_dir, file_name)
            if os.path.isfile(step_file_path) and file_name != ".streaming_query.step":
                exist_step_file_names.append(file_name)
        if exist_step_file_names and set(exist_step_file_names) ^ {os.path.basename(
                self.step_file_path)}:
            exist_action = [key for key, value in StreamingConstants.STREAMING_STEP_FILES.items()
                            if value in exist_step_file_names]
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "check action and mode, the step files %s already exist, "
                                  "please ensure the action %s is finished before "
                                  "doing current options" % (exist_step_file_names, exist_action))
        self.logger.debug("Successfully checked action and mode.")

    def clean_streaming_dir(self):
        """
        Clean streaming dir when stop or failover
        """
        self.logger.debug("Start clean streaming dir:%s." % self.streaming_file_dir)
        cmd = g_file.SHELL_CMD_DICT["deleteDir"] % (self.streaming_file_dir,
                                                    self.streaming_file_dir)
        try:
            self.ssh_tool.executeCommand(cmd, hostList=self.cluster_info.getClusterSshIps()[0])
        except Exception as error:
            self.logger.debug(
                "Failed to remove streaming dir with error:%s" % error)
        self.logger.log("Finished remove streaming dir.")

    def clean_global_config(self):
        """
        Clean global config
        """
        self.logger.log("Clean hadr user info.")
        sql = "DROP GLOBAL CONFIGURATION hadr_user_info;"
        primary_dns = [dn_inst for db_node in self.cluster_info.dbNodes for dn_inst in
                       db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        output = "None"
        for dn_inst in primary_dns:
            status, output = ClusterCommand.remoteSQLCommand(
                sql, self.user, dn_inst.hostname, dn_inst.port, True)
            if status == 0:
                self.logger.log("Successfully clean hadr user info from database.")
                return
        msg = ErrorCode.GAUSS_516['GAUSS_51632'] % "clean hadr user info from database"
        self.logger.debug(msg + "Error:%s" % SensitiveMask.mask_pwd(output))

    def get_build_info(self):
        """
        Assemble build infos
        """
        # 1. Get local primary dn inst dir, host
        self.logger.debug("Start assemble build info")
        dn_inst_info = []
        dn_instances = [dn_inst for db_node in self.cluster_info.dbNodes
                        for dn_inst in db_node.datanodes if int(dn_inst.mirrorId) == 1]
        for dn_inst in dn_instances:
            dn_info = dict()
            dn_info["port"] = dn_inst.port + 1
            dn_info["data_dir"] = dn_inst.datadir
            dn_info["host_name"] = dn_inst.hostname
            dn_info["listen_ip"] = self.__get_local_data_ip(dn_inst.hostname)
            self.logger.debug("Got build listen ips:%s, ip:%s selected."
                              % (str(dn_inst.listenIps), dn_info["listen_ip"]))
            dn_inst_info.append(dn_info)

        # 2. Get remote dn ip and port
        remote_ip_port = []
        shards = self.params.remoteClusterConf["shards"]
        remote_port = int(self.params.remoteClusterConf["port"]) + 1
        shard_info = [info for shard in shards for info in shard
                      if info.get("shardNum", "1") == "1"]
        for node_info in shard_info:
            remote_ip = node_info.get("dataIp")
            remote_ip_port.append((remote_ip, remote_port))
        if (not dn_inst_info) or (not remote_ip_port):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain dn info")
        self.logger.debug("Successfully get remote dn info:%s." % remote_ip_port)
        return dn_inst_info, remote_ip_port

    def build_file_from_remote(self):
        """
        Build files from remote cluster
        """
        local_dn_info, remote_ip_port = self.get_build_info()
        cmd_local = 'source %s; %s/gs_ctl build -D %s -M standby -b copy_secure_files -Z datanode' \
                    ' -U %s -P "%s" -C "localhost=%s localport=%s remotehost=%s remoteport=%s"'
        cmd_remote = "echo \"source %s; %s/gs_ctl build -D %s -M standby -b copy_secure_files -Z " \
                     "datanode -U %s -P '%s' -C 'localhost=%s localport=%s " \
                     "remotehost=%s remoteport=%s'\"" \
                     " | pssh -s -H %s"

        end_time = datetime.now() + timedelta(seconds=self.params.waitingTimeout)
        self.logger.debug("Retry Building with timeout:%ss." % self.params.waitingTimeout)
        succeed = False
        while datetime.now() < end_time:
            for local_primary in local_dn_info:
                for remote_ip, remote_port in remote_ip_port:
                    if local_primary["host_name"] == NetUtil.GetHostIpOrName():
                        cmd = cmd_local % (self.mpp_file, "%s/bin" % self.gauss_home,
                                           local_primary["data_dir"],
                                           self.params.hadrUserName, self.params.hadrUserPassword,
                                           local_primary["listen_ip"], local_primary["port"],
                                           remote_ip, remote_port)
                    else:
                        cmd = cmd_remote % (self.mpp_file, "%s/bin" % self.gauss_home,
                                            local_primary["data_dir"],
                                            self.params.hadrUserName, self.params.hadrUserPassword,
                                            local_primary["listen_ip"], local_primary["port"],
                                            remote_ip, remote_port, local_primary["host_name"])
                    result = DefaultValue.fast_ping_on_node(local_primary["host_name"],
                                                            local_primary["listen_ip"],
                                                            remote_ip, self.logger)
                    if not result[-1]:
                        self.logger.debug("Ignore build from %s, ping result:%s"
                                          % (remote_ip, result[-1]))
                        continue
                    if self.cluster_info.isSingleInstCluster():
                        cmd = cmd.replace(" -Z datanode", "")
                    self.logger.debug("Building with cmd:%s."
                                      % cmd.replace(self.params.hadrUserPassword, "***"))
                    status, output = CmdUtil.getstatusoutput_by_fast_popen(cmd)
                    if status == 0:
                        succeed = True
                        self.logger.debug("Successfully Building with cmd:%s."
                                          % cmd.replace(self.params.hadrUserPassword, "***"))
                        return succeed
                    else:
                        self.logger.debug("Building result:%s." % SensitiveMask.mask_pwd(output))
                time.sleep(1)
        return succeed

    def __copy_secure_dir_from_dn_dir(self):
        """
        Find and copy key file dir from all dn dir
        """
        local_temp_secure_path = os.path.join(
            self.streaming_file_dir, StreamingConstants.GS_SECURE_FILES)
        if os.path.isdir(local_temp_secure_path):
            FileUtil.removeDirectory(local_temp_secure_path)
        rand_path = os.path.join(local_temp_secure_path, StreamingConstants.HADR_KEY_RAND)
        cipher_path = os.path.join(local_temp_secure_path, StreamingConstants.HADR_KEY_CIPHER)
        cmd_tep = "echo \"if [ -d '%s' ];then source %s && pscp --trace-id %s -H %s '%s' '%s' " \
                  "&& rm -rf '%s';fi\" | pssh -s -H %s"
        succeed = False
        for db_node in self.cluster_info.dbNodes:
            for dn_inst in db_node.datanodes:
                if int(dn_inst.mirrorId) == 1:
                    key_file_path = os.path.realpath(os.path.join(
                        dn_inst.datadir, StreamingConstants.GS_SECURE_FILES))
                    cmd_copy_dir = cmd_tep % (key_file_path, self.mpp_file, self.trace_id,
                                              self.local_host, key_file_path,
                                              self.streaming_file_dir,
                                              key_file_path, dn_inst.hostname)
                    status, output = CmdUtil.getstatusoutput_by_fast_popen(cmd_copy_dir)
                    self.logger.debug("Copy cmd:%s" % cmd_copy_dir)
                    if status != 0:
                        self.logger.debug("Try copy secure dir from:[%s][%s], error:%s" % (
                            dn_inst.hostname, key_file_path, output))
                    if os.path.isdir(local_temp_secure_path) and os.path.isfile(rand_path) \
                            and os.path.isfile(cipher_path):
                        succeed = True
        if not succeed:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "copy secure file dir")
        self.logger.debug("Successfully copy secure dir, file list:%s." %
                          os.listdir(local_temp_secure_path))

    def build_and_distribute_key_files(self, only_mode=None):
        """
        Distribute key files
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Wal keep segment opts not for mode:%s." % self.params.mode)
            return
        self.logger.log("Start build key files from remote cluster.")
        # build file
        if not self.build_file_from_remote():
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632'] % "build files from cluster")
        # copy file from data dir to streaming dir
        self.__copy_secure_dir_from_dn_dir()
        # check version consistency
        self.__check_version_file()
        # check cluster user consistency
        self.__check_cluster_user()
        # distribute key files to all node
        secure_dir_path = os.path.join(self.streaming_file_dir, StreamingConstants.GS_SECURE_FILES)
        self.__copy_hadr_user_key(secure_dir_path, update=True)
        FileUtil.removeDirectory(secure_dir_path)
        self.logger.log("Successfully build and distribute key files to all nodes.")

    def __check_version_file(self):
        """
        function: Check whether the version numbers of the host
        cluster and the disaster recovery cluster are the same
        """
        gs_secure_version = os.path.realpath(os.path.join(self.streaming_file_dir,
                                                          "gs_secure_files/version.cfg"))
        master_commit_id = VersionInfo.get_version_info(gs_secure_version)[-1]
        local_version_file = VersionInfo.get_version_file()
        local_commit_id = VersionInfo.get_version_info(local_version_file)[-1]
        self.logger.debug("The committed of the host cluster is %s, "
                          "and the committed of the disaster recovery cluster is %s" %
                          (master_commit_id, local_commit_id))
        if local_commit_id != master_commit_id:
            raise ValueError(ErrorCode.GAUSS_516["GAUSS_51632"] %
                             "check version. Different version of cluster and disaster recovery")

    def __check_cluster_user(self):
        """
        function: Check whether the version numbers of the host
        cluster and the disaster recovery cluster are the same
        """
        user_file = os.path.realpath(os.path.join(self.streaming_file_dir,
                                                  StreamingConstants.GS_SECURE_FILES,
                                                  StreamingConstants.CLUSTER_USER_RECORD))
        remote_user = DefaultValue.obtain_file_content(user_file, is_list=False)
        if remote_user.strip() != self.user:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "check cluster user consistency, remote:%s, local:%s"
                                % (remote_user, self.user))
        self.logger.debug("Successfully checked cluster user consistency.")

    def check_cluster_type(self, allowed_type):
        """
        Check cluster type is allowed type or not
        """
        if allowed_type == 'primary' and self.main_standby_ids:
            self.logger.logExit(ErrorCode.GAUSS_516['GAUSS_51632']
                                % "check cluster type, standby cluster is not supported for %s"
                                % self.params.task)
        elif allowed_type == 'standby' and self.primary_dn_ids:
            self.logger.logExit(ErrorCode.GAUSS_516['GAUSS_51632']
                                % "check cluster type, primary cluster is not supported for %s"
                                % self.params.task)
        else:
            self.logger.log("Check cluster type succeed.")

    def __remove_streaming_repl_info(self, params):
        """
        Remove streaming repl info from single dn instances.
        """
        dn_inst, guc_mode, dn_num = params
        self.logger.debug("Start remove replconninfo for instance:%s" % dn_inst.instanceId)
        for idx in range(1, dn_num + 1):
            if dn_inst.hostname == self.local_host:
                cmd = "source %s; gs_guc check -Z datanode -D %s " \
                      "-c 'replconninfo%s'" % (self.mpp_file, dn_inst.datadir, idx)
            else:
                cmd = "source %s; pssh -H %s 'source %s; gs_guc check " \
                      "-Z datanode -D %s -c \"replconninfo%s\"'" \
                      % (self.mpp_file, dn_inst.hostname, self.mpp_file, dn_inst.datadir, idx)
            self.logger.debug("Check original repl infos with cmd:%s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)
            if output.count("=NULL") > 2:
                continue
            elif "iscrossregion=false" in output.lower():
                ret = re.search(
                    r"replconninfo%s='localhost=((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4})"
                    r" localport=(\d{4,5}) localheartbeatport=(\d{4,5}) "
                    r"localservice=(\d{4,5}) "
                    r"replconninfo%s='localhost=((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4})"
                    r"remoteport=(\d{4,5}) remoteheartbeatport=(\d{4,5}) "
                    r"remoteservice=(\d{4,5})" % idx, output)
                if not ret:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "search repl infos")
                if dn_inst.hostname != NetUtil.GetHostIpOrName():
                    set_cmd = "source %s; pssh -H %s \"source %s ; gs_guc %s " \
                              "-Z datanode -D %s -c " \
                              "\\\"replconninfo%s = 'localhost=%s localport=%s " \
                              "localheartbeatport=%s localservice=%s remotehost=%s " \
                              "remoteport=%s remoteheartbeatport=%s " \
                              "remoteservice=%s'\\\"\""
                    set_cmd = set_cmd % (self.mpp_file, dn_inst.hostname,
                                         self.mpp_file, guc_mode,
                                         dn_inst.datadir, idx, ret.group(1),
                                         ret.group(2), ret.group(3), ret.group(4),
                                         ret.group(5), ret.group(6), ret.group(7),
                                         ret.group(8))
                else:
                    set_cmd = "source %s ; gs_guc %s -Z datanode -D %s -c " \
                              "\"replconninfo%s = 'localhost=%s localport=%s " \
                              "localheartbeatport=%s localservice=%s remotehost=%s " \
                              "remoteport=%s remoteheartbeatport=%s " \
                              "remoteservice=%s'\""
                    set_cmd = set_cmd % (self.mpp_file, guc_mode,
                                         dn_inst.datadir, idx, ret.group(1),
                                         ret.group(2), ret.group(3), ret.group(4),
                                         ret.group(5), ret.group(6), ret.group(7),
                                         ret.group(8))
                self.logger.debug("Set original repl infos with cmd:%s" % set_cmd)
                status, output = CmdUtil.retryGetstatusoutput(set_cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % set_cmd +
                                    " Error: \n%s " % output)
                self.logger.debug("Successfully remove original repl infos with cmd:%s."
                                  % set_cmd)
            elif "iscrossregion=true" in output.lower():
                if dn_inst.hostname != self.local_host:
                    set_cmd = "source %s; pssh -H %s \"source %s ; gs_guc %s " \
                              "-Z datanode -D %s -c \\\"replconninfo%s\\\"\""
                    set_cmd = set_cmd % (self.mpp_file, dn_inst.hostname,
                                         self.mpp_file, guc_mode,
                                         dn_inst.datadir, idx)
                else:
                    set_cmd = "source %s ; gs_guc %s -Z datanode -D %s -c " \
                              "\"replconninfo%s\""
                    set_cmd = set_cmd % (self.mpp_file, guc_mode,
                                         dn_inst.datadir, idx)
                self.logger.debug("Remove stream repl infos with cmd:%s" % set_cmd)
                status, output = CmdUtil.retryGetstatusoutput(set_cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % set_cmd +
                                    " Error: \n%s " % output)
                self.logger.debug("Successfully remove stream repl infos with cmd:%s."
                                  % set_cmd)
        self.logger.debug("Successfully removed replconninfo for instance:%s" % dn_inst.instanceId)

    def remove_all_stream_repl_infos(self, guc_mode="set"):
        """
        Remove retreaming disaster repl infos from all instances
        """
        params = []
        dn_instances = [inst for node in self.cluster_info.dbNodes
                        for inst in node.datanodes]
        cluster_conf = os.path.join(self.streaming_file_dir,
                                    StreamingConstants.STREAMING_CLUSTER_CONF_RECORD)
        dn_num = DefaultValue.get_all_dn_num_for_dr(cluster_conf, dn_instances[0],
                                                    self.cluster_info, self.logger)
        for inst in dn_instances:
            if inst.instanceId not in self.normal_dn_ids:
                self.logger.error("Ignore rectify repl info of dn:%s" % inst.instanceId)
                continue
            params.append((inst, guc_mode, dn_num))
        if params:
            self.logger.log("Starting remove all node dn instances repl infos.")
            parallelTool.parallelExecute(self.__remove_streaming_repl_info, params)
            self.logger.log("Successfully remove all node dn instances repl infos.")

    def remove_streaming_cluster_file(self):
        """
        function:  remove the parameter file for config pg_hba
        :return: NA
        """
        self.logger.log("Start remove cluster file.")
        cluster_info_file = os.path.join(self.streaming_file_dir,
                                         StreamingConstants.STREAMING_CLUSTER_CONF_RECORD)
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (cluster_info_file, cluster_info_file)
        try:
            self.ssh_tool.executeCommand(cmd, hostList=self.cluster_info.getClusterSshIps()[0])
        except Exception as error:
            self.logger.debug(
                "Failed to remove cluster file with error:%s" % error)
        self.logger.log("Finished remove cluster file.")

    def remove_streaming_pg_hba(self, ignore_error=False):
        """
        Remove remote ips from pg hba of streaming disaster
        """
        self.logger.log("Start remove pg_hba config.")
        remove_ips = []
        shards = self.params.remoteClusterConf["shards"]
        for shard in shards:
            for node_info in shard:
                data_ip = node_info.get("dataIp")
                remove_ips.append(data_ip)
        remove_ips = list(set(remove_ips))
        host_names = self.get_all_connection_node_name("remove_streaming_pg_hba")
        self.logger.debug("Remove ips:%s from pg_hba on nodes:%s" % (
            str(remove_ips), str(host_names)))
        cmd = "%s -U '%s' -l '%s'" % (OMCommand.getLocalScript("Local_Config_Hba"),
                                      self.user, self.log_file)
        remove_ips_str = ""
        for node_ip in remove_ips:
            remove_ips_str += " --remove-ip %s" % node_ip
        cmd += remove_ips_str
        self.logger.debug("Command for updating pg_hba:%s." % cmd)
        try:
            self.ssh_tool.executeCommand(cmd, DefaultValue.SUCCESS, host_names)
        except Exception as error:
            self.logger.debug("Failed updating pg_hba with error:%s." % error)
            if not ignore_error:
                raise error
        self.logger.log("Finished remove pg_hba config.")

    def streaming_drop_replication_slot(self, dn_inst, drop_slots):
        """
        Delete dn_xxx_hadr on all dn nodes if dn_xxx_hadr exists when the disaster tolerance
        relationship is lifted
        """
        if not drop_slots:
            self.logger.debug("WARNING:Not found dn_xxx_hadr on %s node, No need to "
                              "delete." % dn_inst.instanceId)
        else:
            for slot in drop_slots:
                self.logger.debug("starting drop inst %s %s" % (dn_inst.instanceId, slot.strip()))
                sql = "select * from pg_catalog.pg_drop_replication_slot('%s');" % slot.strip()
                status_dr, output_dr = ClusterCommand.remoteSQLCommand(
                    sql, self.user, dn_inst.hostname, dn_inst.port, maintenance_mode=True)
                self.logger.debug("get %s need drop replication_slots, status=%d, "
                                  "output: %s." % (dn_inst.hostname, status_dr,
                                                   SensitiveMask.mask_pwd(output_dr)))
                if status_dr != 0:
                    self.logger.debug("Failed to remove inst %s %s with error: %s" % (
                        dn_inst.instanceId, slot.strip(), output_dr))
                self.logger.debug(
                    "Successfully drop node %s %s" % (dn_inst.instanceId, slot.strip()))

    def concurrent_drop_slot(self, dn_inst):
        """
        concurrent drop all dn replication slots
        """
        sql_check = "select * from pg_catalog.pg_get_replication_slots();"
        self.logger.debug("Starting concurrent drop node %s instance [%s] replication slots" %
                          (dn_inst.hostname, dn_inst.instanceId))
        status, output = ClusterCommand.remoteSQLCommand(
            sql_check, self.user, dn_inst.hostname, dn_inst.port, maintenance_mode=True)
        self.logger.debug("get %s all replication slots, status=%d, output: %s." %
                          (dn_inst.instanceId, status, SensitiveMask.mask_pwd(output)))
        if status == 0 and output.strip():
            drop_slots = []
            if str(dn_inst.instanceId).startswith("6"):
                drop_slots = re.findall(r"dn_\d+_hadr", output.strip())
            if str(dn_inst.instanceId).startswith("5"):
                drop_slots = re.findall(r"cn_\d+_\d+\.\d+\.\d+\.\d+_\d+", output.strip())
            self.logger.debug("Waiting to delete instance [%s] replication slots is: %s" %
                              (dn_inst.instanceId, drop_slots))
            self.streaming_drop_replication_slot(dn_inst, drop_slots)
        else:
            self.logger.debug("Obtain all replication slot results:%s." % output)

    def streaming_clean_replication_slot(self):
        """
        Delete dn_xxx_hadr on all dn nodes if dn_xxx_hadr exists when the disaster tolerance
        relationship is lifted
        """
        self.logger.log("Starting drop all node replication slots")
        params = [dn_inst for db_node in self.cluster_info.dbNodes
                  for dn_inst in db_node.datanodes if dn_inst.instanceId in self.normal_dn_ids]
        self.logger.debug("need drop all node replication slots: %s" %
                          [inst.instanceId for inst in params])
        parallelTool.parallelExecute(self.concurrent_drop_slot, params)
        self.logger.log("Finished drop all node replication slots")

    def update_streaming_info(self, key, value, only_mode=None):
        """
        Update info for streaming status
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Update query status [%s] to [%s] "
                              "not for mode:%s." % (key, value, self.params.mode))
            return
        self.logger.debug("Update query [%s] to [%s]." % (key, value))
        try:
            if key == "cluster":
                key_stat = StreamingConstants.HADR_CLUSTER_STAT
            elif key == StreamingConstants.ACTION_FAILOVER:
                key_stat = StreamingConstants.HADR_FAILOVER_STAT
            elif key == StreamingConstants.ACTION_SWITCHOVER:
                key_stat = StreamingConstants.HADR_SWICHOVER_STAT
            elif key == StreamingConstants.ACTION_ESTABLISH:
                key_stat = StreamingConstants.HADR_ESTABLISH_STAT
            else:
                self.logger.debug("key error.")
                return
            file_path = os.path.realpath(os.path.join(self.streaming_file_dir, key_stat))
            with os.fdopen(os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                   DefaultValue.KEY_FILE_MODE_IN_OS), "w") as fp_write:
                fp_write.write(value)
            host_names = self.get_all_connection_node_name(
                action_flag="update_streaming_info", no_update=True)
            self.ssh_tool.scpFiles(file_path, self.streaming_file_dir, host_names)
        except Exception as error:
            self.logger.debug("Failed write info, key:%s, value:%s, "
                              "error:%s." % (key, value, error))

    def create_cluster_maintance_file(self, value):
        """
        add cluster_maintance file for streaming failover and switchover disaster_standby
        """
        self.logger.debug("Start create cluster_maintance file.")
        try:
            cluster_maintance_file = os.path.realpath(os.path.join(self.gauss_home,
                                                                   "bin/cluster_maintance"))
            with os.fdopen(os.open(cluster_maintance_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                   DefaultValue.KEY_FILE_MODE_IN_OS), "w") as fp_write:
                fp_write.write(value)
            host_names = self.get_all_connection_node_name("create_cluster_maintance_file")
            self.ssh_tool.scpFiles(cluster_maintance_file,
                                   os.path.join(self.gauss_home, "bin"), host_names)
        except Exception as error:
            self.logger.debug("WARNING: Failed create cluster_maintance file, value:%s, "
                              "error:%s." % (value, str(error)))
        self.logger.debug("Successfully create cluster_maintance file.")

    def streaming_failover_single_inst(self, stream_disaster_step, action_flag=None):
        """
        streaming disaster recovery failover for single_inst cluster
        """
        self.create_cluster_maintance_file("streaming failover")
        if action_flag != StreamingConstants.ACTION_SWITCHOVER:
            self.update_streaming_info("cluster", "promote")
        # 0. check cluster status and get normal instance list
        if stream_disaster_step < 0:
            if action_flag == StreamingConstants.ACTION_SWITCHOVER:
                self.update_streaming_info(StreamingConstants.ACTION_SWITCHOVER, "10%")
            else:
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "10%")
            self.init_cluster_status()
            self.parse_cluster_status()
            self.write_streaming_step("0_check_cluster_status_done_for_failover")
        # 1.Specify max xid and max ter to start etcd
        max_term_record = os.path.join(self.streaming_file_dir, ".max_term_record")
        if stream_disaster_step < 1:
            max_term = self.get_term_info()
            term_key = "/%s/CMServer/status_key/term" % self.user
            para_dict = {term_key: max_term, self.backup_open_key: "0"}
            ClusterInstanceConfig.set_data_on_dcc(self.cluster_info,
                                                  self.logger, self.user, para_dict)
            DefaultValue.write_content_on_file(max_term_record, max_term)
            self.write_streaming_step("1_start_etcd_done_for_failover")
        self._failover_config_step(stream_disaster_step, action_flag)
        self._failover_start_step(stream_disaster_step, action_flag, max_term_record)

    def _failover_start_step(self, stream_disaster_step, action_flag, max_term_record):
        """
        Failover step 5 & 6
        """
        if stream_disaster_step < 5:
            if action_flag == StreamingConstants.ACTION_SWITCHOVER:
                self.update_streaming_info(StreamingConstants.ACTION_SWITCHOVER, "80%")
            else:
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "80%")
                if not os.path.isfile(max_term_record):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % max_term_record)
                _, dn_infos = self.get_specified_dn_infos(dn_status="Main Standby")
                max_term_list = DefaultValue.obtain_file_content(max_term_record)
                if not max_term_list:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "read max term")
                params = [(dn_info, max_term_list[0]) for dn_info in dn_infos]
                if params:
                    parallelTool.parallelExecute(self.start_primary_dn, params)
            self.write_streaming_step("5_start_primary_dn_done")
        if stream_disaster_step < 6:
            self.start_cluster()
            cluster_normal_status = [DefaultValue.CLUSTER_STATUS_NORMAL,
                                     DefaultValue.CLUSTER_STATUS_DEGRADED]
            self.check_cluster_status(cluster_normal_status, check_current=True)
            if action_flag == StreamingConstants.ACTION_SWITCHOVER:
                self.set_cluster_read_only_params({"default_transaction_read_only": "off"})
                self.revise_dn_readonly_status_in_switch_process("end")
            cluster_info = self.query_cluster_info()
            self.parse_cluster_status(current_status=cluster_info)
            if action_flag != StreamingConstants.ACTION_SWITCHOVER:
                self.clean_global_config()
                self.restore_guc_params()
            self.streaming_clean_archive_slot()
            if action_flag != StreamingConstants.ACTION_SWITCHOVER:
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "100%")
                self.update_streaming_info("cluster", "normal")
            else:
                self.update_streaming_info("cluster", "archive")

    def set_cluster_read_only_params(self, params_dict, guc_type="reload"):
        """
        set datanode params
        """
        if not params_dict:
            return

        cmd = ""
        for param_name, value in params_dict.items():
            cmd += " -c \"%s=%s\"" % (param_name, value)
        guc_cmd = "source %s; gs_guc %s -Z datanode -N all -I all %s" % (EnvUtil.getMpprcFile(), guc_type, cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(guc_cmd)
        self.logger.debug("The params dict %s %s status %s, output %s." % (params_dict, guc_type, status, output))

    def revise_dn_readonly_status_in_switch_process(self, action, guc_type="reload"):
        """
        revise dn readonly status in switch process
        """
        file_name = os.path.join(EnvUtil.getTmpDirFromEnv(), StreamingConstants.SWITCH_ENABLE_READ_ONLY_FILE)
        if action == "start":
            all_cms = [
                cm_inst for dbonde in self.cluster_info.dbNodes for cm_inst in dbonde.cmservers
                if cm_inst.hostname in self.normal_cm_ips
            ]
            for cm_inst in all_cms:
                cmd = "source %s; pssh -s -H %s \"grep enable_transaction_read_only " \
                      "%s/cm_server.conf\"" % (EnvUtil.getMpprcFile(), cm_inst.hostname, cm_inst.datadir)
                (status, output) = CmdUtil.retryGetstatusoutput(cmd)
                self.logger.debug("Check enable transaction read only status:%s, output:%s." % (status, output))
                if status != 0 or output.find("=") < -1:
                    continue
                params_dict = {"enable_transaction_read_only": output.split("=")[-1].strip()}
                with os.fdopen(os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                                       DefaultValue.KEY_FILE_MODE_IN_OS), "w") as fp_w:
                    json.dump(params_dict, fp_w)
                self.set_cmserver_guc("enable_transaction_read_only", "off", guc_type)
                self.logger.debug("The parameter enable_transaction_read_only is disabled.")
        else:
            if not os.path.isfile(file_name):
                self.logger.debug("The enable transaction read only file not exist.")
                return
            content = DefaultValue.obtain_file_content(file_name, is_list=False)
            loads_value = json.loads(content)
            param_value = loads_value.get("enable_transaction_read_only")
            value = param_value if param_value else "on"
            self.set_cmserver_guc("enable_transaction_read_only", value, guc_type)
            os.remove(file_name)
            self.logger.debug("The parameter enable_transaction_read_only is enabled.")

    def streaming_clean_archive_slot(self):
        """
        drop lot_type is physical and slot_name not contain (gs_roach_full, gs_roach_inc,
        cn_xxx，dn_xxx, dn_xxx_hadr) on all cn node and all primary dn node if the
        slot_name exists when the disaster cluster become primary cluster
        """
        self.logger.debug("Starting drop archive slots")
        params = [dn_inst for db_node in self.cluster_info.dbNodes
                  for dn_inst in db_node.datanodes if dn_inst.instanceId in self.primary_dn_ids]
        self.logger.debug("need drop all node archive slots: %s" %
                          [inst.instanceId for inst in params])
        parallelTool.parallelExecute(self.parallel_drop_archive_slot, params)
        self.logger.debug("Successfully drop all node archive slots")

    def parallel_drop_archive_slot(self, dn_inst):
        """
        concurrent drop all primary dn and all cn archive slots
        """
        sql_check = "select slot_name from pg_catalog.pg_get_replication_slots() " \
                    "where slot_type='physical' and slot_name not in " \
                    "('gs_roach_full', 'gs_roach_inc') and slot_name not like 'cn_%' and " \
                    "slot_name not like 'dn_%';"
        self.logger.debug("Starting concurrent drop node %s instance [%s] archive slots" %
                          (dn_inst.hostname, dn_inst.instanceId))
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql_check, self.user, dn_inst.hostname, dn_inst.port)
        self.logger.debug("get %s all archive slots, status=%d, output: %s." %
                          (dn_inst.instanceId, status, output))
        if status == 0 and output.strip():
            archive_slots = output.strip().split('\n')
            self.logger.debug("Waiting to delete instance [%s] archive slots is: %s" %
                              (dn_inst.instanceId, archive_slots))
            self.streaming_drop_replication_slot(dn_inst, archive_slots)

    def get_specified_dn_infos(self, update=False, dn_status="Primary"):

        """
        Get specified dn infos
        """
        tmp_file = os.path.join(self.streaming_file_dir, "cluster_state_tmp")
        if not os.path.isfile(tmp_file) or update:
            cmd = ClusterCommand.getQueryStatusCmd(self.user, 0, tmp_file)
            self.logger.debug("Update cluster state with cmd: %s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                                % "obtain primary dn infos" + "Error:%s" % output)
        cluster_info = DbClusterStatus()
        cluster_info.initFromFile(tmp_file)
        dn_infos = []
        dn_ids = []
        dn_instances = [(inst, db_node.name) for db_node in cluster_info.dbNodes
                        for inst in db_node.datanodes]
        for data_inst, db_node_name in dn_instances:
            if data_inst.status == dn_status:
                one_dn_info = dict()
                one_dn_info["node_ip"] = db_node_name
                one_dn_info["instance_id"] = data_inst.instanceId
                one_dn_info["data_dir"] = data_inst.datadir
                dn_ids.append(data_inst.instanceId)
                dn_infos.append(one_dn_info)
        self.logger.debug("Got %s dn infos: %s:%s" % (dn_status, dn_ids, dn_infos))
        return dn_ids, dn_infos

    def start_primary_dn(self, params):
        """
        Start main standby as primary dn in streaming failover.
        """
        dn_info, max_term = params
        opt_type = " -Z datanode" if not self.cluster_info.isSingleInstCluster() else ""
        self.logger.debug("Starting primary dn %s, max term:%s." %
                          (dn_info["instance_id"], max_term))
        bin_path = "%s/bin" % self.cluster_info.appPath
        instance_id = dn_info["instance_id"]
        hostname = dn_info["node_ip"]
        data_dir = dn_info["data_dir"]
        if self.local_ip == hostname:
            cmd_start = "source %s; %s/gs_ctl start%s -D %s -M pending -t 600" % \
                        (self.mpp_file, bin_path, opt_type, data_dir)
        else:
            cmd_start = "source %s; pssh -s -t 900 -H %s \"source %s; " \
                        "%s/gs_ctl start%s -D %s -M pending" \
                        " -t 600\"" % (self.mpp_file, hostname, self.mpp_file,
                                       bin_path, opt_type, data_dir)
        self.logger.debug("Start primary dn with cmd:%s" % cmd_start)
        status, output = CmdUtil.retryGetstatusoutput(cmd_start)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "start primary dn %s with error:%s"
                            % (instance_id, output))
        self.logger.debug("Successfully start primary dn %s" % instance_id)
        if self.local_ip == hostname:
            cmd_config = "source %s; %s/gs_ctl notify%s -D %s -M primary -T %s -t 600" \
                         % (self.mpp_file, bin_path, opt_type, data_dir, max_term)
        else:
            cmd_config = "source %s; pssh -s -t 900 -H %s \"source %s; %s/gs_ctl notify%s -D %s " \
                         "-M primary -T %s -t 600\""  % (self.mpp_file, hostname, self.mpp_file,
                                                         bin_path, opt_type, data_dir, max_term)
        self.logger.debug("Config primary dn with cmd:%s" % cmd_config)
        status, output = CmdUtil.retryGetstatusoutput(cmd_config)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "config primary dn %s with error:%s"
                            % (instance_id, output))
        self.logger.debug("Successfully start and config primary dn:%s" % instance_id)

    def stream_disaster_set_cmserver_guc(self, guc_parameter, guc_value, guc_type):
        """
        set cmserver guc param
        :param guc_parameter: guc param
        :param guc_value: value
        :param guc_type: init type
        :return: NA
        """
        self.logger.debug("Starting set cm server for streaming disaster.")
        cmd = "source %s && gs_guc %s -Z cmserver -D 'cm_instance_data_path' -c \"%s=%s\" " \
              % (self.mpp_file, guc_type, guc_parameter, guc_value)
        self.logger.debug("streaming disaster calling set cms, cmd=[%s]" % cmd)
        self.ssh_tool.executeCommand(cmd, hostList=self.normal_cm_ips)
        self.logger.debug("Successfully set cm server for streaming disaster.")

    def stream_disaster_set_cmagent_guc(self, guc_parameter, guc_value, guc_type):
        """
        set cmagent guc param
        :param guc_parameter: guc param
        :param guc_value: value
        :param guc_type: init type
        :return: NA
        """
        self.logger.debug("Starting set cm agent for streaming disaster.")
        cmd = "source %s && gs_guc %s -Z cmagent -D 'cm_instance_data_path' -c \"%s=%s\" " \
              % (self.mpp_file, guc_type, guc_parameter, guc_value)
        self.logger.debug("streaming disaster calling set cma, cmd=[%s]" % cmd)
        self.ssh_tool.executeCommand(cmd, hostList=self.normal_node_list)
        self.logger.debug("Successfully set cm agent for streaming disaster.")

    def _failover_config_step(self, stream_disaster_step, action_flag):
        """
        Failover step 2 - 4
        """
        # 2.Stop the cluster by node
        if stream_disaster_step < 2:
            if action_flag != StreamingConstants.ACTION_SWITCHOVER:
                self.streaming_clean_replication_slot()
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "30%")
            self.stop_cluster_by_node()
            self.write_streaming_step("2_stop_cluster_done_for_failover")
        # 3.Start the cluster in the main cluster mode
        if stream_disaster_step < 3:
            self.set_cmserver_guc("backup_open", "0", "set")
            self.stream_disaster_set_cmagent_guc("agent_backup_open", "0", "set")
            self.set_stream_cluster_run_mode_guc("set", fail_over=True)
            self.write_streaming_step("3_set_backup_open_for_failover")
            if action_flag == StreamingConstants.ACTION_SWITCHOVER:
                self.revise_dn_readonly_status_in_switch_process("start", guc_type="set")
                self.set_cluster_read_only_params({"default_transaction_read_only": "on"}, guc_type="set")
        # 4.Delete the relevant guc parameters and remove the disaster tolerance relationship
        # based on streaming disaster recovery cluster, No need to delete for switchover.
        if not action_flag:
            if stream_disaster_step < 4:
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "50%")
                self.remove_all_stream_repl_infos()
                self.remove_streaming_pg_hba(True)
                self.update_streaming_info(StreamingConstants.ACTION_FAILOVER, "70%")
                self.write_streaming_step("4_remove_hba_repl_done_for_failover")

    def get_term_info(self):
        """get_term_info"""
        # get max term from dns
        return self.get_term()

    def get_term(self, normal_dn=True):
        """
        get etcd term
        """
        max_term = 0
        sql_cmd = "select term from pg_last_xlog_replay_location();"
        params_list = [(inst, sql_cmd, max_term, normal_dn) for db_node in
                       self.cluster_info.dbNodes for inst in db_node.datanodes]
        if params_list:
            term_list = parallelTool.parallelExecute(self.get_max_term_by_compare, params_list)
            self.logger.debug("Get term list: %s." % term_list)
            if not term_list:
                max_term = 0
            else:
                max_term = int(max(term_list))
        if int(max_term) == 0:
            raise Exception("Failed get term")
        max_term = int(max_term) + 100
        self.logger.debug("Get max term %s in dns" % max_term)
        return max_term

    def streaming_switchover_roll_back_condition(self):
        """
        check need rollback or not by Main Standby dn status
        output: return True means need rollback
        """
        self.logger.debug("Starting check switchover rollback condition.")
        cluster_status = self.query_cluster_info(cm_check=True)
        if not cluster_status:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                            % "query cluster status when check rollback condition")

        rollback_check_list = ["Main Standby Need repair(Disconnected)",
                               "Main Standby Need repair(Connecting)"]
        need_rollback = False
        for check_status in rollback_check_list:
            if check_status in cluster_status:
                need_rollback = True
        self.logger.debug("Successfully check rollback condition: %s." % need_rollback)
        self.logger.debug("Cluster status: %s." % cluster_status)
        return need_rollback

    def get_max_term_by_compare(self, params):
        """
        get max term by compare
        """
        instance, sql_cmd, max_term, normal_dn = params
        if (normal_dn is True and instance.instanceId in self.normal_dn_ids) or \
                (normal_dn is False and instance.instanceType == DefaultValue.MASTER_INSTANCE):
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql_cmd, self.user, instance.hostname, instance.port, maintenance_mode=True)
            if status != 0 or self.find_error(output):
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] %
                                sql_cmd + "\nError: %s" % output)
            self.logger.debug("TERM %s, Instance %s" % (output, instance.instanceId))
            term = output.strip()
            if int(term) > int(max_term):
                max_term = term
        return int(max_term)

    def remove_cluster_maintance_file(self):
        """
        function:  remove the cluster_maintance file
        :return: NA
        """
        self.logger.debug("Start remove cluster_maintance file.")
        cluster_maintance_file = os.path.realpath(os.path.join(self.gauss_home,
                                                               "bin/cluster_maintance"))
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (cluster_maintance_file, cluster_maintance_file)
        host_names = self.get_all_connection_node_name("remove_cluster_maintance_file")
        try:
            self.ssh_tool.executeCommand(cmd, hostList=host_names)
        except Exception as error:
            self.logger.debug(
                "Failed to remove cluster_maintance file with error: %s" % str(error))
        self.logger.debug("Successfully remove %s cluster_maintance file." % host_names)

    def get_node_sship_from_nodeid(self, node_id):
        """
        get node sship from nodeid
        :param node_id: node id
        :return:
        """
        for nodename in self.cluster_info.dbNodes:
            if int(node_id) == int(nodename.id):
                return nodename.sshIps[0]

    def delivery_file_to_other_node(self, path_name, file_name, node_list=None):
        """delivery_file_to_other_node"""
        send_file = "%s/%s" % (path_name, file_name)
        send_file_bak = "%s/%s_bak" % (path_name, file_name)
        if not os.path.isfile(send_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % send_file)

        if node_list:
            p_node_list = " -H ".join(node_list)
        elif self.cluster_info.getClusterSshIps()[0]:
            p_node_list = " -H ".join(self.cluster_info.getClusterSshIps()[0])
        else:
            raise Exception("Failed to delivery file: %s, node information does not exits"
                            % file_name)
        pscp_cmd = "cp %s %s && source %s && pscp -t 60 -H %s %s %s && rm -f %s" % \
                   (send_file, send_file_bak, self.mpp_file, p_node_list,
                    send_file_bak, send_file, send_file_bak)
        status, output = CmdUtil.retryGetstatusoutput(pscp_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % pscp_cmd + " Error:\n%s" % output)
        else:
            self.logger.debug("Successfully send %s to all nodes" % send_file)

    @staticmethod
    def find_error(output):
        """
        error rule
        :param output: error info
        :return:bool
        """
        error_msg_flag = "(ERROR|FATAL|PANIC)"
        error_pattern = "^%s:.*" % error_msg_flag
        pattern = re.compile(error_pattern)
        for line in output.split("\n"):
            line = line.strip()
            result = pattern.match(line)
            if result is not None:
                return True
        return False

    def set_stream_cluster_run_mode_guc(self, guc_mode, fail_over=False):
        """
        function: set cluster run mode guc
        :return:
        """
        cluster_run_mode = "cluster_primary" if self.params.mode == "primary" \
            else "cluster_standby"
        if fail_over:
            cluster_run_mode = "cluster_primary"
        guc_cmd = "source %s && gs_guc %s -Z datanode -N all -I all -c " \
                  "\"stream_cluster_run_mode = '%s'\"" % \
                  (self.mpp_file, guc_mode, cluster_run_mode)
        host_names = self.cluster_info.getClusterNodeNames()
        ignore_node = [node for node in host_names if node not in self.normal_node_list]
        if ignore_node:
            self.logger.debug(
                "WARNING: cluster_run_mode for datanode ignore nodes:%s" % ignore_node)
            nodes = ",".join(ignore_node)
            guc_cmd = guc_cmd + " --ignore-node %s" % nodes
        self.logger.debug("Set dn stream_cluster_run_mode with cmd:%s" % guc_cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(guc_cmd)
        if status != 0:
            self.logger.debug("Warning: Failed %s dn stream_cluster_run_mode=%s, output: %s" %
                              (guc_mode, cluster_run_mode, str(output)))
        else:
            self.logger.debug("Successfully %s streaming cluster run mode for "
                              "datanode param %s" % (guc_mode, cluster_run_mode))

        guc_cmd_cn = "source %s && gs_guc %s -Z coordinator -N all -I all -c " \
                     "\"stream_cluster_run_mode = '%s'\"" % \
                     (self.mpp_file, guc_mode, cluster_run_mode)
        if ignore_node:
            self.logger.debug(
                "WARNING: cluster_run_mode for coordinator ignore nodes:%s" % ignore_node)
            nodes = ",".join(ignore_node)
            guc_cmd_cn = guc_cmd_cn + " --ignore-node %s" % nodes
        self.logger.debug("Set cn stream_cluster_run_mode with cmd:%s" % guc_cmd_cn)
        (status, output) = CmdUtil.retryGetstatusoutput(guc_cmd_cn)
        if status != 0:
            self.logger.debug("Warning: Failed %s cn stream_cluster_run_mode=%s, output: %s" %
                              (guc_mode, cluster_run_mode, str(output)))
        else:
            self.logger.debug("Successfully %s streaming cluster run mode for "
                              "coordinator param %s" % (guc_mode, cluster_run_mode))

    def set_data_in_dcc(self, key, value, only_mode=None):
        """
        Set data in dcc
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("set [%s][%s] not for mode:%s." % (key, value, self.params.mode))
            return
        self.logger.debug("Start set data: [%s][%s] in dcc." % (key, value))
        ClusterInstanceConfig.set_data_on_dcc(self.cluster_info,
                                              self.logger, self.user,
                                              {key: value})
        self.logger.log("Successfully set [%s][%s]." % (key, value))

    def stop_cluster(self, action=None):
        """
        stop the cluster
        """
        self.logger.log("Stopping the cluster.")
        static_config = "%s/bin/cluster_static_config" % self.cluster_info.appPath
        cm_ctl_file = "%s/bin/cm_ctl" % self.cluster_info.appPath
        if not os.path.isfile(static_config) or not os.path.isfile(cm_ctl_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            (static_config + " or " + cm_ctl_file))
        cmd = ClusterCommand.getStopCmd(0, "i", 1800)
        if action:
            cmd = ClusterCommand.getStopCmd(0, timeout=1800)
        self.logger.debug("disaster cluster calling cm_ctl to stop cluster, cmd=[%s]" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd, retry_time=0)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51610"] %
                            ("the cluster" + " Error:\n%s." % output))
        self.logger.log("Successfully stopped the cluster.")
