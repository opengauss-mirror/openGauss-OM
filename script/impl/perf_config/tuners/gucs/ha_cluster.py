#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
# Description  : gs_perfconfg is a utility to optimize system and database configure about openGauss
#############################################################################

from impl.perf_config.basic.guc import GucMap, GUCTuneGroup


class SenderServerGUC(GUCTuneGroup):
    def __init__(self):
        super(SenderServerGUC, self).__init__()
        self.max_wal_senders = self.bind('max_wal_senders')
        self.wal_keep_segments = self.bind('wal_keep_segments')
        self.wal_sender_timeout = self.bind('wal_sender_timeout')
        self.logical_sender_timeout = self.bind('logical_sender_timeout')
        self.max_replication_slots = self.bind('max_replication_slots')
        self.enable_slot_log = self.bind('enable_slot_log')
        self.max_changes_in_memory = self.bind('max_changes_in_memory')
        self.max_cached_tuplebufs = self.bind('max_cached_tuplebufs')
        self.enable_wal_shipping_compression = self.bind('enable_wal_shipping_compression')
        self.repl_auth_mode = self.bind('repl_auth_mode')
        self.repl_uuid = self.bind('repl_uuid')
        self.replconninfo1 = self.bind('replconninfo1')
        self.replconninfo2 = self.bind('replconninfo2')
        self.replconninfo3 = self.bind('replconninfo3')
        self.replconninfo4 = self.bind('replconninfo4')
        self.replconninfo5 = self.bind('replconninfo5')
        self.replconninfo6 = self.bind('replconninfo6')
        self.replconninfo7 = self.bind('replconninfo7')
        self.replconninfo8 = self.bind('replconninfo8')
        self.cross_cluster_replconninfo1 = self.bind('cross_cluster_replconninfo1')
        self.cross_cluster_replconninfo2 = self.bind('cross_cluster_replconninfo2')
        self.cross_cluster_replconninfo3 = self.bind('cross_cluster_replconninfo3')
        self.cross_cluster_replconninfo4 = self.bind('cross_cluster_replconninfo4')
        self.cross_cluster_replconninfo5 = self.bind('cross_cluster_replconninfo5')
        self.cross_cluster_replconninfo6 = self.bind('cross_cluster_replconninfo6')
        self.cross_cluster_replconninfo7 = self.bind('cross_cluster_replconninfo7')
        self.cross_cluster_replconninfo8 = self.bind('cross_cluster_replconninfo8')
        self.available_zone = self.bind('available_zone')
        self.max_keep_log_seg = self.bind('max_keep_log_seg')
        self.cluster_run_mode = self.bind('cluster_run_mode')

    def calculate(self):
        pass


class PrimaryServerGUC(GUCTuneGroup):
    def __init__(self):
        super(PrimaryServerGUC, self).__init__()
        self.synchronous_standby_names = self.bind('synchronous_standby_names')
        self.most_available_sync = self.bind('most_available_sync')
        self.keep_sync_window = self.bind('keep_sync_window')
        self.enable_stream_replication = self.bind('enable_stream_replication')
        self.enable_mix_replication = self.bind('enable_mix_replication')
        self.vacuum_defer_cleanup_age = self.bind('vacuum_defer_cleanup_age')
        self.data_replicate_buffer_size = self.bind('data_replicate_buffer_size')
        self.walsender_max_send_size = self.bind('walsender_max_send_size')
        self.enable_data_replicate = self.bind('enable_data_replicate')
        self.ha_module_debug = self.bind('ha_module_debug')
        self.enable_incremental_catchup = self.bind('enable_incremental_catchup')
        self.wait_dummy_time = self.bind('wait_dummy_time')
        self.catchup2normal_wait_time = self.bind('catchup2normal_wait_time')
        self.sync_config_strategy = self.bind('sync_config_strategy')
        self.enable_save_confirmed_lsn = self.bind('enable_save_confirmed_lsn')
        self.hadr_recovery_time_target = self.bind('hadr_recovery_time_target')
        self.hadr_recovery_point_target = self.bind('hadr_recovery_point_target')
        self.hadr_super_user_record_path = self.bind('hadr_super_user_record_path')
        self.ignore_standby_lsn_window = self.bind('ignore_standby_lsn_window')
        self.ignore_feedback_xmin_window = self.bind('ignore_feedback_xmin_window')

    def calculate(self):
        pass


class StandbyServerGUC(GUCTuneGroup):
    def __init__(self):
        super(StandbyServerGUC, self).__init__()
        self.hot_standby = self.bind('hot_standby')
        self.max_standby_archive_delay = self.bind('max_standby_archive_delay')
        self.max_standby_streaming_delay = self.bind('max_standby_streaming_delay')
        self.wal_receiver_status_interval = self.bind('wal_receiver_status_interval')
        self.hot_standby_feedback = self.bind('hot_standby_feedback')
        self.wal_receiver_timeout = self.bind('wal_receiver_timeout')
        self.wal_receiver_connect_timeout = self.bind('wal_receiver_connect_timeout')
        self.wal_receiver_connect_retries = self.bind('wal_receiver_connect_retries')
        self.wal_receiver_buffer_size = self.bind('wal_receiver_buffer_size')
        self.primary_slotname = self.bind('primary_slotname')
        self.max_logical_replication_workers = self.bind('max_logical_replication_workers')
        self.max_sync_workers_per_subscription = self.bind('max_sync_workers_per_subscription')

    def calculate(self):
        pass

