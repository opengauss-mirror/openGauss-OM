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
# Description  : dorado_disaster_recovery_start.py is utility for creating
# relationship between primary cluster and standby cluster.

import os

from base_utils.security.sensitive_mask import SensitiveMask
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue, ClusterCommand
from impl.dorado_disaster_recovery.ddr_base import DoradoDisasterRecoveryBase
from impl.dorado_disaster_recovery.ddr_constants import DoradoDisasterRecoveryConstants


class DisasterRecoveryStartHandler(DoradoDisasterRecoveryBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def first_step_create_ddr_dir(self, step):
        """
        First step for ddr start
        """
        if step >= 2:
            return
        self.logger.debug("Start first step of DisasterRecovery start.")
        self.create_disaster_recovery_dir(self.dorado_file_dir)
        self.check_action_and_mode()
        self.init_cluster_status()

    def second_step_check_cluster_status(self, step):
        """
        Second step for ddr start
        """
        if step >= 2:
            return
        self.logger.debug("Start second step of ddr start.")
        self.check_cluster_status(status_allowed=['Normal'])
        self.check_cluster_is_common()
        cm_exist = DefaultValue.check_is_cm_cluster(self.logger)
        if not cm_exist:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"] %
                                "check cm_ctl is available for current cluster")
        self.check_is_under_upgrade()
        self.check_dn_instance_params()
        self.write_dorado_step("2_check_cluster_step")

    def common_step_for_ddr_start(self):
        """
        Common step for ddr start between step 1 and 2
        """
        self.logger.debug("Start common config step of ddr start.")
        self.distribute_cluster_conf()
        

    def third_step_set_guc_param(self, step):
        """
        Third step for ddr start: set DN para(postgresql.conf & pg_hba.conf)
        """
        if step >= 3:
            return
        self.logger.debug("Start third step of ddr start.")
        self.set_ss_disaster_mode()
        self.update_pg_hba()
        self.config_cross_cluster_repl_info()
        self.set_application_name()
        self.set_ha_module_mode()
        self.write_dorado_step("3_set_datanode_guc_step")

    def fourth_step_stop_cluster(self, step):
        """
        Fourth step for ddr start
        """
        if step >= 4:
            return
        self.logger.debug("Start fourth step of ddr start.")
        self.stop_cluster()
        self.write_dorado_step("4_stop_cluster_step")

    def fifth_step_start_cluster(self, step):
        """
        Fifth step for ddr start: set primary cluster CM para
        """
        if step >= 5:
            return
        self.logger.debug("Start fifth step of ddr start.")
        self.set_cmagent_guc("ss_double_cluster_mode", "1", "set", only_mode='primary')
        self.set_cmserver_guc("ss_double_cluster_mode", "1", "set", only_mode='primary')
        if self.params.disaster_type == "dorado":
            self.set_dss_storage_mode("CLUSTER_RAID")
        self.start_cluster(only_mode="primary")
        self.write_dorado_step("5_start_primary_cluster_step")
        self.logger.log("Successfully set ss_double_cluster_mode")

    def sixth_step_build_main_standby(self, step):
        """
        Sixth step for ddr start
        """
        if step >= 6 or self.params.mode == "primary":
            return
        self.logger.debug("Start sixth step of ddr start.")
        self.update_dorado_info("cluster", "restore", only_mode='disaster_standby')
        try:
            self.start_dss_instance(only_mode='disaster_standby')
            self.build_main_standby_datanode(only_mode='disaster_standby')
        except Exception as error:
            self.update_dorado_info("cluster", "restore_fail", only_mode='disaster_standby')
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "build dns" + "Error:%s" % error)
        finally:
            self.stop_dss_instance(only_mode='disaster_standby')
        self.write_dorado_step("6_build_dn_instance_step")
        

    def seventh_step_set_cm_guc(self, step):
        """
        Seventh step for ddr start: set disaster_standby CM para
        """
        if step >= 7 or self.params.mode == "primary":
            return
        self.logger.debug("Start seventh step of ddr start.")
        self.set_cmagent_guc("ss_double_cluster_mode", "2", "set", only_mode='disaster_standby')
        self.set_cmserver_guc("ss_double_cluster_mode", "2", "set", only_mode='disaster_standby')
        if self.params.disaster_type == "dorado":
            self.set_dss_storage_mode("CLUSTER_RAID")
            self.set_dss_cluster_run_mode("cluster_standby", only_mode='disaster_standby')
        self.write_dorado_step("7_set_cm_guc_step")
        

    def eighth_step_wait_main_standby(self, step):
        """
        Eighth step for ddr start
        """
        if step >= 8:
            return
        self.logger.debug("Start eighth step of ddr start.")
        if self.params.disaster_type == "dorado":
            self.check_input(DoradoDisasterRecoveryConstants.START_MSG)
        self.start_cluster(cm_timeout=DoradoDisasterRecoveryConstants.STANDBY_START_TIMEOUT,
                           only_mode='disaster_standby')
        self.update_dorado_info("cluster", "full_backup", only_mode='primary')
        try:
            self.wait_main_standby_connection(only_mode='primary')
        except Exception as error:
            self.update_dorado_info("cluster", "backup_fail", only_mode='primary')
            raise Exception(str(error))
        ret = self.check_cluster_status(status_allowed=['Normal'],
                                        only_check=True, check_current=True)
        query_status = "recovery" if ret else "recovery_fail"
        self.update_dorado_info("cluster", query_status, only_mode='disaster_standby')
        self.update_dorado_info("cluster", "archive", only_mode='primary')
        self.write_dorado_step("8_start_cluster_step")

    def ninth_step_clean(self, step):
        """
        ninth step for ddr start
        """
        if step >= 9:
            return
        self.logger.debug("Start ninth step of ddr start.")
        self.clean_step_file()

    def run(self):
        self.logger.log("Start create dorado storage disaster relationship.")
        self.logger.log("param.stage = %s." % self.params.stage)
        step = self.query_dorado_step()
        if self.params.stage is None or int(self.params.stage) == 1:
            self.first_step_create_ddr_dir(step)
            self.parse_cluster_status()
            self.second_step_check_cluster_status(step)
            self.common_step_for_ddr_start()
            self.third_step_set_guc_param(step)
            self.fourth_step_stop_cluster(step)
            self.fifth_step_start_cluster(step)
            self.sixth_step_build_main_standby(step)
            self.seventh_step_set_cm_guc(step)
            self.logger.log("Successfully set cm_guc.")
        if self.params.stage is None or int(self.params.stage) == 2:
            self.eighth_step_wait_main_standby(step)
            self.ninth_step_clean(step)
            self.logger.log("Successfully do dorado disaster recovery start.")
 
