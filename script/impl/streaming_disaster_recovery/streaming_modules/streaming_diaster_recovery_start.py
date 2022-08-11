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
# Description  : streaming_disaster_recovery_start.py is utility for creating
# relationship between primary cluster and standby cluster.

import os

from base_utils.security.sensitive_mask import SensitiveMask
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue, ClusterCommand
from impl.streaming_disaster_recovery.streaming_base import StreamingBase
from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants


class StreamingStartHandler(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _first_step_for_streaming_start(self, step):
        """
        First step for streaming start
        """
        if step >= 2:
            return
        self.logger.debug("Start first step of streaming start.")
        self.create_streaming_dir(self.streaming_file_dir)
        self.check_action_and_mode()
        self.init_cluster_status()

    def _second_step_for_streaming_start(self, step):
        """
        Second step for streaming start
        """
        if step >= 2:
            return
        self.logger.debug("Start second step of streaming start.")
        self.check_cluster_status(status_allowed=['Normal'])
        self.check_cluster_is_common()
        cm_exist = DefaultValue.check_is_cm_cluster(self.logger)
        if not cm_exist:
            self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51632"] %
                                "check cm_ctl is available for current cluster")
        self.check_is_under_upgrade()
        self.check_dn_instance_params()
        self.write_streaming_step("2_check_cluster_step")

    def _third_step_for_streaming_start(self, step):
        """
        Third step for streaming start
        """
        if step >= 3:
            return
        self.logger.debug("Start third step of streaming start.")
        self.drop_replication_slot_on_dr_cluster(only_mode="disaster_standby")
        self.prepare_gs_secure_files(only_mode='primary')
        self.build_and_distribute_key_files(only_mode='disaster_standby')
        self.get_default_wal_keep_segments(only_mode='primary')
        self.write_streaming_step("3_set_wal_segments_step")

    def drop_replication_slot_on_dr_cluster(self, only_mode=None):
        """
        Drop replication slot on dr cluster
        """
        if only_mode and self.params.mode != only_mode:
            self.logger.debug("Drop replication slot opts not for mode:%s." % self.params.mode)
            return
        sql_check = "select slot_name from pg_get_replication_slots() where slot_type='logical'"
        primary_dns = DefaultValue.get_primary_dn_instance_id("Primary", ignore=True)
        if not primary_dns:
            return
        primary_insts = [inst for node in self.cluster_info.dbNodes
                         for inst in node.datanodes if str(inst.instanceId) in primary_dns]
        dn_inst = primary_insts[0]
        self.logger.debug("Start drop node %s [%s] slots" % (dn_inst.hostname, dn_inst.instanceId))
        status, output = ClusterCommand.remoteSQLCommand(
            sql_check, self.user, dn_inst.hostname, dn_inst.port)
        self.logger.debug("Get %s all replication slots, status=%d, output: %s." %
                          (dn_inst.instanceId, status, SensitiveMask.mask_pwd(output)))
        if status == 0 and output.strip():
            drop_slots = output.strip().split('\n')
            for slot in drop_slots:
                self.logger.debug("Starting drop node %s %s" % (dn_inst.instanceId, slot.strip()))
                sql = "select * from pg_drop_replication_slot('%s');" % slot.strip()
                status_dr, output_dr = ClusterCommand.remoteSQLCommand(
                    sql, self.user, dn_inst.hostname, dn_inst.port)
                if status_dr != 0:
                    self.logger.debug("Failed to remove node %s %s with error: %s" % (
                        dn_inst.hostname, slot.strip(), SensitiveMask.mask_pwd(output_dr)))
                self.logger.debug(
                    "Successfully drop node %s %s" % (dn_inst.instanceId, slot.strip()))

    def _fourth_step_for_streaming_start(self, step):
        """
        Fourth step for streaming start
        """
        if step >= 4:
            return
        self.logger.debug("Start fourth step of streaming start.")
        self.set_wal_keep_segments(
            "reload", StreamingConstants.MAX_WAL_KEEP_SEGMENTS, only_mode='primary')
        self.write_streaming_step("4_set_wal_segments_step")

    def _fifth_step_for_streaming_start(self, step):
        """
        Fifth step for streaming start
        """
        if step >= 5:
            return
        self.logger.debug("Start fifth step of streaming start.")
        self.set_data_in_dcc(self.backup_open_key, "0", only_mode='primary')
        self.set_data_in_dcc(self.backup_open_key, "2", only_mode='disaster_standby')
        self.stop_cluster_by_node(only_mode='disaster_standby')
        self.write_streaming_step("5_set_wal_segments_step")

    def common_step_for_streaming_start(self):
        """
        Common step for streaming start between step 1 and 2
        """
        self.logger.debug("Start common config step of streaming start.")
        self.distribute_cluster_conf()
        self.update_streaming_pg_hba()
        self.config_streaming_repl_info()

    def _sixth_step_for_streaming_start(self, step):
        """
        Sixth step for streaming start
        """
        if step >= 6:
            return
        self.logger.debug("Start sixth step of streaming start.")
        self.set_cmserver_guc("backup_open", "2", "set", only_mode='disaster_standby')
        self.set_cmagent_guc("agent_backup_open", "2", "set", only_mode='disaster_standby')
        self.write_streaming_step("6_set_guc_step")

    def _seventh_step_for_streaming_start(self, step):
        """
        Seventh step for streaming start
        """
        if step >= 7:
            return
        self.logger.debug("Start seventh step of streaming start.")
        self.update_streaming_info("cluster", "restore", only_mode='disaster_standby')
        try:
            self.build_dn_instance(only_mode='disaster_standby')
        except Exception as error:
            self.update_streaming_info("cluster", "restore_fail", only_mode='disaster_standby')
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "build dns" + "Error:%s" % error)
        self.write_streaming_step("7_build_dn_instance_step")

    def _eighth_step_for_streaming_start(self, step):
        """
        Eighth step for streaming start
        """
        if step >= 8:
            return
        self.logger.debug("Start eighth step of streaming start.")
        self.start_cluster(cm_timeout=StreamingConstants.STANDBY_START_TIMEOUT,
                           only_mode='disaster_standby')
        self.update_streaming_info("cluster", "full_backup", only_mode='primary')
        try:
            self.wait_main_standby_connection(only_mode='primary')
        except Exception as error:
            self.update_streaming_info("cluster", "backup_fail", only_mode='primary')
            raise Exception(str(error))
        ret = self.check_cluster_status(status_allowed=['Normal'],
                                        only_check=True, check_current=True)
        query_status = "recovery" if ret else "recovery_fail"
        self.update_streaming_info("cluster", query_status, only_mode='disaster_standby')
        self.update_streaming_info("cluster", "archive", only_mode='primary')
        self.write_streaming_step("8_start_cluster_step")

    def _ninth_step_for_streaming_start(self, step):
        """
        ninth step for streaming start
        """
        if step >= 9:
            return
        self.logger.debug("Start ninth step of streaming start.")
        self.restore_wal_keep_segments(only_mode='primary')
        self.clean_gs_secure_dir()
        self.clean_step_file()

    def _check_and_refresh_disaster_user_permission(self):
        """check and refresh disaster user permission"""
        if self.params.mode != "primary":
            return
        self.check_hadr_user(only_mode='primary')
        self.check_hadr_pwd(only_mode='primary')
        self.logger.debug("Encrypt hadr user info to database not "
                          "for mode:%s." % self.params.mode)
        hadr_cipher_path = os.path.join(self.bin_path, "hadr.key.cipher")
        hadr_rand_path = os.path.join(self.bin_path, "hadr.key.rand")
        if not os.path.isfile(hadr_cipher_path) or not os.path.isfile(hadr_rand_path):
            self.hadr_key_generator('hadr')
        user_info = DefaultValue.obtain_hadr_user_encrypt_str(self.cluster_info, self.user,
                                                              self.logger, False, True)
        if user_info:
            self.clean_global_config()
        pass_str = self.encrypt_hadr_user_info(
            'hadr', self.params.hadrUserName, self.params.hadrUserPassword)
        self.keep_hadr_user_info(pass_str)

    def run(self):
        self.logger.log("Start create streaming disaster relationship.")
        step = self.query_streaming_step()
        self._first_step_for_streaming_start(step)
        self.parse_cluster_status()
        self._check_and_refresh_disaster_user_permission()
        self._second_step_for_streaming_start(step)
        self.common_step_for_streaming_start()
        self._third_step_for_streaming_start(step)
        self._fourth_step_for_streaming_start(step)
        self._fifth_step_for_streaming_start(step)
        self._sixth_step_for_streaming_start(step)
        self._seventh_step_for_streaming_start(step)
        self._eighth_step_for_streaming_start(step)
        self._ninth_step_for_streaming_start(step)
        self.logger.log("Successfully do streaming disaster recovery start.")
