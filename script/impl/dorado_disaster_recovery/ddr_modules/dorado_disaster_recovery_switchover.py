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
# Description  : dorado_disaster_recovery_switchover.py is a utility for
# changing role between primary cluster and standby cluster.
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta

from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from gspylib.common.Common import DefaultValue, ClusterCommand, ClusterInstanceConfig
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.parallelTool import parallelTool
from impl.dorado_disaster_recovery.ddr_base import DoradoDisasterRecoveryBase
from impl.dorado_disaster_recovery.ddr_constants import DoradoDisasterRecoveryConstants


class DisasterRecoverySwitchoverHandler(DoradoDisasterRecoveryBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self):
        """
        dorado disaster recovery switchover
        """
        if (self.params.stage is None or int(self.params.stage) == 1):
            self.logger.log(DoradoDisasterRecoveryConstants.TASK_START_MSG % 
                                (self.params.disaster_type, self.params.task))
            self.check_action_and_mode()
            self.init_cluster_conf()
            self.check_dn_instance_params()
            self.check_is_under_upgrade()
            cluster_current_role = self.judge_ss_cluster_role()
            if cluster_current_role == self.params.mode or cluster_current_role == "single":
                self.logger.log("Switchover operation for SS dual_cluster should be: \n"
                                "primary --demote--> disaster_standby & disaster_standby --promote--> primary, \n"
                                "please check your switchover cmd & make sure your cmd correct.")
                return
            self.params.disaster_type = DefaultValue.get_ss_disaster_mode()
            if self.params.disaster_type:
                self.logger.log("Successfully get the para disaster_type: %s." % self.params.disaster_type)
            self.logger.log("And now, on the %s cluster exectue the command: \ngs_ddr -t switchover -m %s" % (self.params.mode, cluster_current_role))
        try:
            self.dorado_switchover_single_inst()
            if (self.params.stage is None or int(self.params.stage) == 2):
                self.clean_step_file()
        except Exception as error:
            if self.params.mode == "primary":
                self.update_dorado_info("cluster", "promote_fail")
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "switchover" + "Error:%s" % str(error))
        
        if (self.params.stage is None or int(self.params.stage) == 2):
            self.logger.log(DoradoDisasterRecoveryConstants.TASK_FINISH_MSG % 
                                (self.params.disaster_type, self.params.task))

    def handle_standby_inst_cfg(self, dorado_disaster_step):
        if self.params.stage is None or int(self.params.stage) == 1:
            if dorado_disaster_step < 1:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "10%")
                self.stop_cluster()
                self.write_dorado_step("1_dorado_disaster_stop_cluster_for_switchover")
            self.logger.log("Successfully do_first_stage_for_switchover.")
        if self.params.stage is None or int(self.params.stage) == 2:
            if dorado_disaster_step < 2:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "30%")
                if self.params.disaster_type == "dorado":
                    self.check_input(DoradoDisasterRecoveryConstants.STANDBY_MSG)
                self.write_dorado_step("2_set_remote_replication_pairs_for_switchover")
            if dorado_disaster_step < 3:
                self.set_cmagent_guc("ss_double_cluster_mode", "2", "set")
                self.set_cmserver_guc("ss_double_cluster_mode", "2", "set")
                if self.params.disaster_type == "dorado":
                    self.set_dss_cluster_run_mode("cluster_standby", only_mode='disaster_standby')
                self.write_dorado_step("3_set_cluster_guc_done")
            if dorado_disaster_step < 4:
                self.update_dorado_info(DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER, "50%")
                self.start_cluster()
                self.write_dorado_step("4_start_cluster_done")
            if dorado_disaster_step < 5:
                self.wait_for_normal(timeout=self.params.waitingTimeout,
                                    dorado_switchover="disaster_switchover")
                self.check_dorado_datanode_query_info(timeout=self.params.waitingTimeout,
                                                    dorado_switchover="disaster_switchover")
                self.update_dorado_info("cluster", "recovery")

    def dorado_switchover_single_inst(self):
        """
        dorado disaster recovery switchover for single_inst cluster
        disaster_standby: expect primary cluster becomes standby
        primary: expect standby cluster becomes primary
        """
        if (self.params.stage is None or int(self.params.stage == 1)):
            self.update_dorado_info("cluster", DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER)
        dorado_disaster_step = self.query_dorado_step()
        if dorado_disaster_step < 1:
            self.check_switchover_workable()
        if self.params.mode == "primary":
            self.dorado_failover_single_inst(dorado_disaster_step,
                                             DoradoDisasterRecoveryConstants.ACTION_SWITCHOVER)
        else:
            try:
                self.handle_standby_inst_cfg(dorado_disaster_step)
            except Exception as error:
                self.logger.error("Failed to do dorado disaster cluster switchover, Error:"
                                  " \n%s" % str(error))
                raise Exception(error)
            
        if self.params.stage is None or int(self.params.stage) == 2:
            self.remove_ddr_switchover_process_file()

    def remove_ddr_switchover_process_file(self):
        self.logger.debug("Remove ddr switchover process file for switchover.")
        process_file = os.path.realpath(os.path.join(self.dorado_file_dir,
                                                     DoradoDisasterRecoveryConstants.DDR_SWITCHOVER_STAT))
        cmd = "if [ -f {0} ]; then rm -rf {0}; fi".format(process_file)
        self.ssh_tool.executeCommand(cmd, hostList=self.connected_nodes)
        self.logger.debug("Successfully remove switchover process on all connected nodes.")

    def wait_for_normal(self, timeout=DefaultValue.TIMEOUT_CLUSTER_START,
                        dorado_switchover=None):
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
            if dorado_switchover == "disaster_switchover":
                raise Exception(
                    ErrorCode.GAUSS_528["GAUSS_52800"] % (cluster_status.clusterStatus,
                                                          cluster_status.clusterStatusDetail))
            self.logger.logExit(ErrorCode.GAUSS_528["GAUSS_52800"] % (
                cluster_status.clusterStatus, cluster_status.clusterStatusDetail))
        self.logger.debug("Successfully wait for cluster status become Normal.", "constant")

    def dorado_switchover_roll_back(self, update_query=False):
        """
        dorado disaster cluster roll back in switchover
        """
        self.logger.log("Roll back dorado disaster cluster switchover...")
        self.stop_cluster()
        if self.params.mode == "primary":
            self.set_cmagent_guc("ss_double_cluster_mode", "2", "set")
            self.set_cmserver_guc("ss_double_cluster_mode", "2", "set")
            if self.params.disaster_type == "dorado":
                self.set_dss_cluster_run_mode("cluster_standby")
        else:
            self.set_cmagent_guc("ss_double_cluster_mode", "1", "set")
            self.set_cmserver_guc("ss_double_cluster_mode", "1", "set")
            if self.params.disaster_type == "dorado":
                self.set_dss_cluster_run_mode("cluster_primary")
        self.logger.log("Successfully modify cma and cms parameters to start according to original "
                        "cluster mode")
        if update_query:
            self.update_dorado_info("cluster", "archive")
        if self.params.disaster_type == "dorado":
            self.logger.log(DoradoDisasterRecoveryConstants.SWITCHOVER_MSG) 
        self.logger.log("Successfully Roll back dorado disaster cluster switchover.")

    def check_switchover_workable(self):
        """
        Check switchover is workable
        """
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
