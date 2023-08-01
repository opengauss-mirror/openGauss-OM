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

    def _first_step_for_ddr_stop(self, step):
        """
        First step for ddr stop
        """
        if step >= 2:
            return
        self.logger.debug("Start first step of dorado disaster recovery stop.")
        self.init_cluster_status()
        self.check_action_and_mode()

    def _second_step_for_ddr_stop(self, step):
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

    def _third_step_for_ddr_stop(self, step):
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

    def _fourth_step_for_ddr_stop(self, step):
        """
        Fourth step for ddr stop
        """
        if step >= 4:
            return
        self.logger.debug("Start fourth step of dorado disaster recovery stop.")
        #self.restore_guc_params()
        self.write_dorado_step("4_remove_pg_hba_step")

    def _fifth_step_for_ddr_stop(self, step):
        """
        Fifth step for ddr stop
        """
        if step >= 5:
            return
        self.logger.debug("Start fifth step of dorado disaster recovery start.")
        self.check_cluster_status(['Normal'])
        self.update_dorado_info("cluster", "normal")
        self.clean_streaming_dir()

    def run(self):
        self.logger.log("Start remove dorado disaster recovery relationship.")
        step = self.query_dorado_step()
        self._first_step_for_ddr_stop(step)
        self.parse_cluster_status()
        self._second_step_for_ddr_stop(step)
        self._third_step_for_ddr_stop(step)
        self._fourth_step_for_ddr_stop(step)
        self._fifth_step_for_ddr_stop(step)
        self.logger.log("Successfully do dorado disaster recovery stop.")
