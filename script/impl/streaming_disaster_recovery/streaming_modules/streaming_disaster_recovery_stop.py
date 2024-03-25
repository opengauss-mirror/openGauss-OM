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
# Description  : streaming_disaster_recovery_stop.py is a utility for stopping
# streaming disaster recovery on primary cluster.

import os

from impl.streaming_disaster_recovery.streaming_base import StreamingBase


class StreamingStopHandler(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _first_step_for_streaming_stop(self, step):
        """
        First step for streaming stop
        """
        if step >= 2:
            return
        if step == -1 and not os.path.exists(self.streaming_file_dir):
            self.logger.logExit("No need to stop because the cluster is not a disaster cluster.")
        self.logger.debug("Start first step of streaming stop.")
        self.init_cluster_status()
        self.check_action_and_mode()

    def _second_step_for_streaming_stop(self, step):
        """
        Second step for streaming stop
        """
        if step >= 2:
            return
        self.logger.debug("Start second step of streaming start.")
        self.check_cluster_status(status_allowed=['Normal'])
        self.check_cluster_type(allowed_type='primary')
        self.check_is_under_upgrade()
        self.write_streaming_step("2_check_cluster_step")

    def _third_step_for_streaming_stop(self, step):
        """
        Third step for streaming stop
        """
        if step >= 3:
            return
        self.logger.debug("Start third step of streaming stop.")
        self.remove_all_stream_repl_infos(guc_mode="reload")
        self.remove_streaming_cluster_file()
        self.write_streaming_step("3_remove_config_step")

    def _fourth_step_for_streaming_stop(self, step):
        """
        Fourth step for streaming stop
        """
        if step >= 4:
            return
        self.logger.debug("Start fourth step of streaming stop.")
        self.remove_streaming_pg_hba()
        self.restore_guc_params()
        self.write_streaming_step("4_remove_pg_hba_step")

    def _fifth_step_for_streaming_stop(self, step):
        """
        Fifth step for streaming stop
        """
        if step >= 5:
            return
        self.logger.debug("Start fifth step of streaming start.")
        self.streaming_clean_replication_slot()
        self.write_streaming_step("5_update_config_step")

    def _sixth_step_for_streaming_stop(self, step):
        """
        Sixth step for streaming stop
        """
        if step >= 6:
            return
        self.logger.debug("Start sixth step of streaming stop.")
        self.check_cluster_status(['Normal'])
        self.clean_global_config()
        self.update_streaming_info("cluster", "normal")
        self.clean_streaming_dir()

    def run(self):
        self.logger.log("Start remove streaming disaster relationship.")
        step = self.query_streaming_step()
        self._first_step_for_streaming_stop(step)
        self.parse_cluster_status()
        self._second_step_for_streaming_stop(step)
        self._third_step_for_streaming_stop(step)
        self._fourth_step_for_streaming_stop(step)
        self._fifth_step_for_streaming_stop(step)
        self._sixth_step_for_streaming_stop(step)
        self.logger.log("Successfully do streaming disaster recovery stop.")
