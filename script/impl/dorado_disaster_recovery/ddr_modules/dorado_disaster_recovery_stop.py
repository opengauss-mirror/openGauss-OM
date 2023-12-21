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
# Description  : dorado_disaster_recovery_stop.py is a utility for stopping
# dorado disaster recovery on primary cluster.

from impl.dorado_disaster_recovery.ddr_base import DoradoDisasterRecoveryBase


class DisasterRecoveryStopHandler(DoradoDisasterRecoveryBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def first_step_init_and_check(self, step):
        """
        First step for ddr stop
        """
        if step >= 2:
            return
        self.logger.debug("Start first step of dorado disaster recovery stop.")
        self.init_cluster_status()
        self.check_action_and_mode()

    def second_step_check_cluster_status(self, step):
        """
        Second step for ddr stop
        """
        if step >= 2:
            return
        self.logger.debug("Start second step of dorado disaster recovery stop.")
        self.check_cluster_status(status_allowed=['Normal'])
        self.check_cluster_type(allowed_type='primary')
        self.check_is_under_upgrade()
        self.write_dorado_step("2_check_cluster_step")

    def third_step_remove_ddr_config(self, step):
        """
        Third step for ddr stop
        """
        if step >= 3:
            return
        self.logger.debug("Start third step of dorado disaster recovery stop.")
        self.remove_cross_cluster_replinfos(guc_mode="reload")
        self.remove_streaming_pg_hba()
        self.remove_streaming_cluster_file()
        self.write_dorado_step("3_remove_config_step")

    def fourth_step_clean_dir(self, step):
        """
        Fourth step for ddr stop
        """
        if step >= 5:
            return
        self.logger.debug("Start fourth step of dorado disaster recovery stop.")
        self.check_cluster_status(['Normal'])
        self.update_dorado_info("cluster", "normal")
        self.clean_streaming_dir()

    def run(self):
        self.logger.log("Start remove dorado disaster recovery relationship.")
        step = self.query_dorado_step()
        self.first_step_init_and_check(step)
        self.parse_cluster_status()
        self.second_step_check_cluster_status(step)
        self.third_step_remove_ddr_config(step)
        self.fourth_step_clean_dir(step)
        self.logger.log("Successfully do dorado disaster recovery stop.")
