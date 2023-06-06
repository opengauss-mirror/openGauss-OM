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
# Description  : streaming_disaster_recovery_switchover.py is a utility for
# changing role between primary cluster and standby cluster.

import os
import time
from datetime import datetime, timedelta

from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from gspylib.common.Common import DefaultValue, ClusterCommand, ClusterInstanceConfig
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.parallelTool import parallelTool
from impl.streaming_disaster_recovery.streaming_base import StreamingBase
from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants


class StreamingSwitchoverHandler(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self):
        """
        streaming disaster recovery switchover
        """
        self.logger.log("Start streaming disaster switchover.")
        self.check_action_and_mode()
        self.check_switchover_workable()
        self.init_cluster_conf()
        self.check_dn_instance_params()
        self.check_is_under_upgrade()
        try:
            self.streaming_switchover_single_inst()
            self.clean_step_file()
        except Exception as error:
            if self.params.mode == "primary":
                self.update_streaming_info("cluster", "promote_fail")
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "switchover" + "Error:%s" % str(error))
        finally:
            self.remove_cluster_maintance_file_for_switchover()
            self.remove_cluster_maintance_file()
        self.logger.log("Successfully do streaming disaster recovery switchover.")

    def streaming_switchover_single_inst(self):
        """
        streaming disaster recovery switchover for single_inst cluster
        disaster_standby: expect primary cluster becomes standby
        primary: expect standby cluster becomes primary
        """
        self.create_cluster_maintance_file("streaming switchover")
        self.update_streaming_info("cluster", StreamingConstants.ACTION_SWITCHOVER)
        stream_disaster_step = self.query_streaming_step()
        if self.params.mode == "primary":
            end_time = datetime.now() + timedelta(seconds=self.params.waitingTimeout)
            self.logger.log("Waiting for switchover barrier.")
            while True:
                switchover_barrier_list = self.check_streaming_disaster_switchover_barrier()
                if len(switchover_barrier_list) == len(self.normal_dn_ids):
                    break
                if datetime.now() >= end_time:
                    self.restart_cluster()
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                                    "check switchover_barrier on all main standby dn" +
                                    " Because check timeout: %ss" %
                                    str(self.params.waitingTimeout))
                time.sleep(5)
            self.streaming_failover_single_inst(stream_disaster_step,
                                                StreamingConstants.ACTION_SWITCHOVER)
        else:
            self.add_cluster_maintance_file_for_switchover()
            try:
                if stream_disaster_step < 1:
                    self.update_streaming_info(StreamingConstants.ACTION_SWITCHOVER, "10%")
                    self.stop_cluster()
                    self.start_cluster()
                    self.streaming_disaster_set_master_cluster_in_switchover()
                    self.write_streaming_step("1_streaming_disaster_set_master_in_switchover")
                if stream_disaster_step < 2:
                    self.update_streaming_info(StreamingConstants.ACTION_SWITCHOVER, "30%")
                    ClusterInstanceConfig.set_data_on_dcc(self.cluster_info,
                                                          self.logger, self.user,
                                                          {self.backup_open_key: "2"})
                    self.stop_cluster()
                    self.write_streaming_step("2_stop_cluster_for_switchover")
                if stream_disaster_step < 3:
                    self.set_cmserver_guc("backup_open", "2", "set")
                    self.set_cmagent_guc("agent_backup_open", "2", "set")
                    self.write_streaming_step("3_set_backup_open_2_done")
                if stream_disaster_step < 4:
                    self.update_streaming_info(StreamingConstants.ACTION_SWITCHOVER, "50%")
                    self.remove_cluster_maintance_file_for_switchover()
                    self.remove_cluster_maintance_file()
                    self.start_cluster()
                    self.write_streaming_step("4_start_cluster_done")
                if stream_disaster_step < 5:
                    self.wait_for_normal(timeout=self.params.waitingTimeout,
                                         streaming_switchover="streaming_switchover")
                    self.streaming_clean_replication_slot()
                    self.update_streaming_info("cluster", "recovery")
            except Exception as error:
                self.logger.error("Failed to do streaming disaster cluster switchover, Error:"
                                  " \n%s" % str(error))
                rollback_step = self.query_streaming_step()
                self.logger.debug("Roll back switchover step:%s" % rollback_step)
                self.remove_cluster_maintance_file_for_switchover()
                self.remove_cluster_maintance_file()
                if rollback_step < 4 or (rollback_step >= 4 and
                                         self.streaming_switchover_roll_back_condition()):
                    self.streaming_switchover_roll_back(update_query=True)
                self.clean_step_file()
                raise Exception(error)
        self.remove_hadr_switchover_process_file()

    def remove_hadr_switchover_process_file(self):
        self.logger.debug("Remove hadr switchover process file for switchover.")
        process_file = os.path.realpath(os.path.join(self.streaming_file_dir,
                                                     ".hadr_switchover_stat"))
        cmd = "if [ -f {0} ]; then rm -rf {0}; fi".format(process_file)
        self.ssh_tool.executeCommand(cmd, hostList=self.connected_nodes)
        self.logger.debug("Successfully remove switchover process on all connected nodes.")

    @staticmethod
    def clean_file_on_node(params):
        """
        clean file on dest node with path
        """
        dest_ip, dest_path, timeout = params
        cmd = "source %s && pssh -s -t %s -H %s 'if [ -f %s ]; then rm -f %s; fi'" % (
            EnvUtil.getMpprcFile(), timeout, dest_ip, dest_path, dest_path)
        status, output = CmdUtil.getstatusoutput_by_fast_popen(cmd)
        return status, output, dest_ip

    def restart_cluster(self, restart_timeout=DefaultValue.TIMEOUT_CLUSTER_START):
        """
        Restart cluster
        """
        self.logger.log("Restart cluster.")
        static_config = "%s/bin/cluster_static_config" % self.bin_path
        cm_ctl_file = "%s/bin/cm_ctl" % self.bin_path
        if not os.path.isfile(static_config):
            self.logger.debug("Checked file %s lost." % static_config)
        if not os.path.isfile(cm_ctl_file):
            self.logger.debug("Checked file %s lost." % cm_ctl_file)
        stop_cmd = ClusterCommand.getStopCmd(0, timeout=restart_timeout)
        status, output = CmdUtil.retryGetstatusoutput(stop_cmd, retry_time=0)
        self.logger.debug("Stop cluster result:[%s][%s]." % (status, output))
        start_cmd = ClusterCommand.getStartCmd(0, timeout=restart_timeout)
        status, output = CmdUtil.retryGetstatusoutput(start_cmd, retry_time=0)
        self.logger.debug("Start cluster result:[%s][%s]." % (status, output))

    def remove_cluster_maintance_file_for_switchover(self):
        """
        function:  remove the cluster_maintance file
        :return: NA
        """
        self.logger.debug("Remove cluster_maintance file for switchover.")
        cluster_maintance_file = os.path.realpath(os.path.join(self.gauss_home,
                                                               "bin/cluster_maintance"))
        host_names = \
            self.get_all_connection_node_name("remove_cluster_maintance_file_for_switchover")
        try:
            pscp_params = []
            all_instances = [dn_inst for db_node in self.cluster_info.dbNodes
                             for dn_inst in db_node.datanodes]
            if not self.cluster_info.isSingleInstCluster():
                all_instances.extend([dn_inst for db_node in self.cluster_info.dbNodes
                                      for dn_inst in db_node.coordinators])
            for dn_inst in all_instances:
                if dn_inst.hostname in host_names:
                    pscp_params.append([dn_inst.hostname, os.path.join(
                        dn_inst.datadir, os.path.basename(cluster_maintance_file)), 10])
            if len(pscp_params) > 0:
                results = parallelTool.parallelExecute(self.clean_file_on_node, pscp_params)
                for ret in results:
                    if ret[0] != 0:
                        self.logger.debug("clean maintance file to node[%s] with status[%s], "
                                          "output[%s]" % (ret[-1], ret[0], ret[1]))
        except Exception as error:
            self.logger.debug(
                "Failed to remove cluster_maintance file for switchover with error: %s"
                % str(error))
        self.logger.debug("Successfully remove %s cluster_maintance file for switchover."
                          % host_names)

    def add_cluster_maintance_file_for_switchover(self):
        """
        add cluster_maintance file for streaming disaster switchover to disaster_standby
        """
        self.logger.debug("Start add cluster_maintance file for switchover.")
        try:
            cluster_maintance_file = os.path.realpath(os.path.join(self.gauss_home,
                                                                   "bin/cluster_maintance"))
            host_names = \
                self.get_all_connection_node_name("add_cluster_maintance_file_for_switchover", True)
            pscp_params = []
            all_instances = [dn_inst for db_node in self.cluster_info.dbNodes
                             for dn_inst in db_node.datanodes]
            for dn_inst in all_instances:
                if dn_inst.hostname in host_names:
                    pscp_params.append([dn_inst.hostname, cluster_maintance_file,
                                        os.path.join(dn_inst.datadir, "cluster_maintance"), 10])
            if len(pscp_params) > 0:
                results = parallelTool.parallelExecute(
                    DefaultValue.distribute_file_to_node, pscp_params)
                for ret in results:
                    if ret[0] != 0:
                        self.logger.debug("Distribute maintance file for switchover to node[%s] "
                                          "with status[%s], output[%s]" % (ret[-1], ret[0], ret[1]))
        except Exception as error:
            self.logger.debug("WARNING: Failed add cluster_maintance file for switchover, "
                              "error:%s." % (str(error)))
        self.logger.debug("Successfully add cluster_maintance file for switchover.")

    def streaming_disaster_set_master_cluster_in_switchover(self):
        """
        streaming disaster set master cluster in switchover
        """
        self.logger.debug("Starting set streaming master cluster in switchover.")
        primary_dns = [dn_inst for db_node in self.cluster_info.dbNodes
                       for dn_inst in db_node.datanodes if
                       dn_inst.instanceId in self.primary_dn_ids]
        if not primary_dns:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "obtain primary dns for switchover")
        if self.streaming_dr_in_switchover(primary_dns):
            if self.streaming_dr_service_truncation_check(primary_dns):
                self.logger.debug("Successfully set streaming master cluster in switchover.")

    def streaming_dr_service_truncation_check(self, primary_dns_list):
        """
        streaming dr service truncation check
        """
        self.logger.log("Waiting for truncation.")
        results = parallelTool.parallelExecute(self.concurrent_check_dr_service_truncation,
                                               primary_dns_list)
        return all(results)

    def concurrent_check_dr_service_truncation(self, dn_inst):
        """
        Wait for the log playback to complete.
        """
        self.logger.debug("Starting check node %s shardNum %s instance %s streaming service "
                          "truncation." % (dn_inst.hostname, dn_inst.mirrorId, dn_inst.instanceId))
        sql_check = "select * from gs_streaming_dr_service_truncation_check();"
        end_time = datetime.now() + timedelta(seconds=1200)
        succeed = False
        while datetime.now() < end_time:
            status, output = ClusterCommand.remoteSQLCommand(sql_check, self.user, dn_inst.hostname,
                                                             dn_inst.port)
            if status == 0 and output and output.strip() == "t":
                succeed = True
                break
            time.sleep(5)
            self.logger.debug("Retry truncation check shardNum %s in node %s instance %s." %
                              (dn_inst.mirrorId, dn_inst.hostname, dn_inst.instanceId))
        if not succeed:
            self.logger.error("Failed to execute the command: %s, Error:\n%s" % (sql_check, output))
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "check truncate service before switchover")
        self.logger.debug("Successfully check node %s shardNum %s instance %s streaming service "
                          "truncation." % (dn_inst.hostname, dn_inst.mirrorId, dn_inst.instanceId))
        return True

    def streaming_dr_in_switchover(self, primary_dns_list):
        """
        set steaming dr in switchover
        """
        results = parallelTool.parallelExecute(self.concurrent_set_dr_in_switchover,
                                               primary_dns_list)
        return all(results)

    def concurrent_set_dr_in_switchover(self, dn_inst):
        """
        Switchover requires log truncation first
        """
        self.logger.debug("Starting set shardNum %s node %s streaming dr in switchover." %
                          (dn_inst.mirrorId, dn_inst.hostname))
        sql_cmd = "select * from gs_streaming_dr_in_switchover();"
        # We need to use the normal port to transmit service truncation,
        # not the OM port.
        port = int(dn_inst.port) - 1
        (status, output) = ClusterCommand.remoteSQLCommand(sql_cmd,
                                                           self.user, dn_inst.hostname, str(port))
        self.logger.debug("check streaming in switchover, status=%d, output: %s."
                          % (status, output))
        if status != 0 or self.find_error(output) or output.strip() != "t":
            self.logger.error("Failed to execute the command: %s, Error:\n%s" % (sql_cmd, output))
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "generate switchover barrier before switchover")
        self.logger.debug("Successfully set shardNum %s node %s streaming dr in switchover." %
                          (dn_inst.mirrorId, dn_inst.hostname))
        return True

    def wait_for_normal(self, timeout=DefaultValue.TIMEOUT_CLUSTER_START,
                        streaming_switchover=None):
        """
        function:Wait the cluster become Normal or Degraded
        input:NA
        output:NA
        """
        self.logger.debug("Waiting for cluster status being satisfied.")
        end_time = None if timeout <= 0 else datetime.now() + timedelta(seconds=timeout)

        check_status = 0
        while True:
            time.sleep(10)
            if end_time is not None and datetime.now() >= end_time:
                check_status = 1
                self.logger.debug("Timeout. The cluster is not available.")
                break
            # View the cluster status
            status_file = "/home/%s/gauss_check_status_%d.dat" % (self.user, os.getpid())
            cmd = ClusterCommand.getQueryStatusCmd(outFile=status_file)
            (status, output) = CmdUtil.retryGetstatusoutput(cmd, retry_time=0)
            if status != 0:
                if os.path.exists(status_file):
                    os.remove(status_file)
                self.logger.debug("Failed to obtain the cluster status. Error: \n%s" % output)
                continue
            # Determine whether the cluster status is normal or degraded
            cluster_status = DbClusterStatus()
            cluster_status.initFromFile(status_file)
            if os.path.exists(status_file):
                os.remove(status_file)
            if cluster_status.clusterStatus == "Normal":
                self.logger.log("The cluster status is Normal.")
                break
            else:
                self.logger.debug("Cluster status is %s(%s)." % (
                cluster_status.clusterStatus, cluster_status.clusterStatusDetail))

        if check_status != 0:
            if streaming_switchover == "streaming_switchover":
                raise Exception(
                    ErrorCode.GAUSS_528["GAUSS_52800"] % (cluster_status.clusterStatus,
                                                          cluster_status.clusterStatusDetail))
            self.logger.logExit(ErrorCode.GAUSS_528["GAUSS_52800"] % (
                cluster_status.clusterStatus, cluster_status.clusterStatusDetail))
        self.logger.debug("Successfully wait for cluster status become Normal.", "constant")

    def set_auto_csn_barrier_guc(self, guc_mode, action_flag=False, roll_back=False):
        """
        auto_csn_barrier : 0 / 1
        """
        guc_value = 1 if self.params.mode == "primary" else 0
        if action_flag:
            guc_value = 0
        if roll_back:
            guc_value = 1
        self.logger.debug("Starting %s auto_csn_barrier is %s." % (guc_mode, guc_value))
        cmd = 'source %s && gs_guc %s -Z coordinator -N all -I all ' \
              '-c "auto_csn_barrier=%s"' % (self.mpp_file, guc_mode, guc_value)
        host_names = self.cluster_info.getClusterNodeNames()
        ignore_node = [node for node in host_names if node not in self.normal_node_list]
        if ignore_node:
            self.logger.debug(
                "WARNING: auto_csn_barrier need ignore host name is %s" % ignore_node)
            nodes = ",".join(ignore_node)
            cmd = cmd + " --ignore-node %s" % nodes
        self.logger.debug("Set auto_csn_barrier with cmd:%s" % cmd)
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                            % "set auto_csn_barrier" + "Error:%s" % output)
        self.logger.debug("Successfully %s auto_csn_barrier is %s." % (guc_mode, guc_value))

    def streaming_switchover_roll_back(self, update_query=False):
        """
        streaming disaster cluster roll back in switchover
        """
        self.logger.log("Roll back streaming disaster cluster switchover...")
        ClusterInstanceConfig.set_data_on_dcc(self.cluster_info,
                                              self.logger, self.user,
                                              {self.backup_open_key: "0"})
        self.stop_cluster()
        self.set_cmserver_guc("backup_open", "0", "set")
        self.set_cmagent_guc("agent_backup_open", "0", "set")
        self.logger.log("Successfully modify cma and cms parameters to start according to primary "
                        "cluster mode")
        if update_query:
            self.update_streaming_info("cluster", "archive")
        self.start_cluster()
        self.logger.log("Successfully Roll back streaming disaster cluster switchover.")

    def check_streaming_disaster_switchover_barrier(self):
        """
        check whether get switchover_barrier on all dn
        """
        self.logger.debug("check streaming disaster switchover barrier...")
        sql_cmd = "select * from gs_streaming_dr_get_switchover_barrier();"
        switchover_barrier_list = []
        for db_node in self.cluster_info.dbNodes:
            for dn_inst in db_node.datanodes:
                if dn_inst.instanceId not in self.normal_dn_ids:
                    self.logger.debug("Warning: Not check for abnormal instance %s %s" % (
                        dn_inst.instanceType, dn_inst.instanceId))
                    continue
                (status, output) = ClusterCommand.remoteSQLCommand(
                    sql_cmd, self.user, dn_inst.hostname, dn_inst.port, maintenance_mode=True)
                self.logger.debug("Check inst has switchover barrier, status=%d, "
                                  "output: %s." % (status, output))
                if status == 0 and output.strip() == "t":
                    self.logger.debug("Successfully check instance %s %s has switchover "
                                      "barrier." % (dn_inst.instanceType, dn_inst.instanceId))
                    switchover_barrier_list.append(dn_inst.instanceId)
        return switchover_barrier_list

    def check_switchover_workable(self):
        """
        Check switchover is workable
        """
        if not DefaultValue.is_disaster_cluster(self.cluster_info) \
                and self.params.mode == "primary":
            self.logger.debug("The primary dn exist, do nothing except record the result file.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "streaming disaster cluster switchover, Because the primary cluster "
                            "[drClusterMode] parameter must be disaster_standby")
        if DefaultValue.is_disaster_cluster(self.cluster_info) and \
                self.params.mode == "disaster_standby":
            self.logger.debug("The primary dn not exist, do nothing except record the result file.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "streaming disaster cluster switchover, Because the disaster_standby "
                            "cluster [drClusterMode] parameter must be primary")
        self.logger.log("Waiting for cluster and all instances normal.")
        if self.params.mode == "primary":
            end_time = datetime.now() + timedelta(seconds=600)
            while True:
                self.init_cluster_status()
                self.parse_cluster_status()
                if self.check_cluster_status(status_allowed=['Normal'], only_check=True,
                                     is_log=False) and self.check_instances_ready_for_switchover():
                    break
                if datetime.now() >= end_time:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"]
                                    % "check cluster and instances status"
                                      " with timeout: %ss" % str(600))
                time.sleep(5)
                self.logger.debug("Retry check stream disaster standby cluster status...")
        else:
            self.init_cluster_status()
            self.parse_cluster_status()
            if (not self.check_cluster_status(status_allowed=['Normal'], only_check=True,
                                              is_log=False)) \
                    or (not self.check_instances_ready_for_switchover()):
                raise Exception(ErrorCode.GAUSS_516['GAUSS_51632'] % "check cluster status")

    def check_instances_ready_for_switchover(self):
        """
        Check cns and dns is ready for switchover
        """
        dn_instances = [dn_inst.instanceId for db_node in self.cluster_info.dbNodes
                        for dn_inst in db_node.datanodes]
        if len(dn_instances) != len(self.normal_dn_ids):
            self.logger.debug("Not all dn instances is normal.")
            return False
        self.logger.debug("Successfully check cn and dn instances are normal.")
        return True
