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

import math
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.guc import GucMap, GUCTuneGroup
from impl.perf_config.probes.business import BsScenario


class VacuumGUC(GUCTuneGroup):
    def __init__(self):
        super(VacuumGUC, self).__init__()
        # vacuum
        self.vacuum_cost_delay = self.bind('vacuum_cost_delay')
        self.vacuum_cost_page_hit = self.bind('vacuum_cost_page_hit')
        self.vacuum_cost_page_miss = self.bind('vacuum_cost_page_miss')
        self.vacuum_cost_page_dirty = self.bind('vacuum_cost_page_dirty')
        self.vacuum_cost_limit = self.bind('vacuum_cost_limit')
        self.vacuum_freeze_min_age = self.bind('vacuum_freeze_min_age')
        self.vacuum_freeze_table_age = self.bind('vacuum_freeze_table_age')
        self.vacuum_defer_cleanup_age = self.bind('vacuum_defer_cleanup_age')
        # auto vacuum
        self.autovacuum = self.bind('autovacuum')
        self.autovacuum_mode = self.bind('autovacuum_mode')
        self.autovacuum_io_limits = self.bind('autovacuum_io_limits')
        self.autovacuum_max_workers = self.bind('autovacuum_max_workers')
        self.autovacuum_naptime = self.bind('autovacuum_naptime')
        self.autovacuum_vacuum_threshold = self.bind('autovacuum_vacuum_threshold')
        self.autovacuum_analyze_threshold = self.bind('autovacuum_analyze_threshold')
        self.autovacuum_vacuum_scale_factor = self.bind('autovacuum_vacuum_scale_factor')
        self.autovacuum_analyze_scale_factor = self.bind('autovacuum_analyze_scale_factor')
        self.autovacuum_freeze_max_age = self.bind('autovacuum_freeze_max_age')
        self.autovacuum_vacuum_cost_delay = self.bind('autovacuum_vacuum_cost_delay')
        self.autovacuum_vacuum_cost_limit = self.bind('autovacuum_vacuum_cost_limit')
        # auto analyze
        self.autoanalyze = self.bind('autoanalyze')
        self.enable_analyze_check = self.bind('enable_analyze_check')
        self.autoanalyze_timeout = self.bind('autoanalyze_timeout')
        # others
        self.defer_csn_cleanup_time = self.bind('defer_csn_cleanup_time')
        self.log_autovacuum_min_duration = self.bind('log_autovacuum_min_duration')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.vacuum_cost_limit.set(10000)

        if BsScenario.isOLTPScenario(infos.business.scenario):
            self.autovacuum.turn_on()
            self.autovacuum_mode.set('vacuum')

            autovacuum_max_workers = min(max(math.floor(infos.cpu.count() * 0.15), 1), 20)
            self.autovacuum_max_workers.set(str(autovacuum_max_workers))

            autovacuum_naptime = 5
            self.autovacuum_naptime.set(f'{autovacuum_naptime}s')

            self.autovacuum_vacuum_cost_delay.set('10')
            self.autovacuum_vacuum_scale_factor.set('0.1')
            self.autovacuum_analyze_scale_factor.set('0.02')


class CheckpointGUC(GUCTuneGroup):
    def __init__(self):
        super(CheckpointGUC, self).__init__()
        self.checkpoint_segments = self.bind('checkpoint_segments')
        self.checkpoint_timeout = self.bind('checkpoint_timeout')
        self.checkpoint_completion_target = self.bind('checkpoint_completion_target')
        self.checkpoint_warning = self.bind('checkpoint_warning')
        self.checkpoint_wait_timeout = self.bind('checkpoint_wait_timeout')

        self.enable_incremental_checkpoint = self.bind('enable_incremental_checkpoint')
        self.incremental_checkpoint_timeout = self.bind('incremental_checkpoint_timeout')

        self.enable_xlog_prune = self.bind('enable_xlog_prune')
        self.max_redo_log_size = self.bind('max_redo_log_size')
        self.max_size_for_xlog_prune = self.bind('max_size_for_xlog_prune')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if BsScenario.isOLTPScenario(infos.business.scenario):
            self.enable_incremental_checkpoint.turn_on()

        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.checkpoint_segments.set(3000)
            self.checkpoint_timeout.set('15min')
            self.incremental_checkpoint_timeout.set('5min')
            self.enable_xlog_prune.turn_off()
            self.max_redo_log_size.set('400GB')


class BackendWriteThreadGUC(GUCTuneGroup):
    def __init__(self):
        super(BackendWriteThreadGUC, self).__init__()
        self.candidate_buf_percent_target = self.bind('candidate_buf_percent_target')
        self.bgwriter_delay = self.bind('bgwriter_delay')
        self.bgwriter_lru_maxpages = self.bind('bgwriter_lru_maxpages')
        self.bgwriter_lru_multiplier = self.bind('bgwriter_lru_multiplier')
        self.bgwriter_flush_after = self.bind('bgwriter_flush_after')
        self.dirty_page_percent_max = self.bind('dirty_page_percent_max')
        self.pagewriter_thread_num = self.bind('pagewriter_thread_num')
        self.pagewriter_sleep = self.bind('pagewriter_sleep')
        self.max_io_capacity = self.bind('max_io_capacity')
        self.enable_consider_usecount = self.bind('enable_consider_usecount')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.candidate_buf_percent_target.set('0.7')
            self.bgwriter_delay.set('5s')
            self.bgwriter_flush_after.set('32')

            self.pagewriter_thread_num.set(2)
            self.pagewriter_sleep.set(100)
            self.max_io_capacity.set('2GB')


class DoubleWriteGUC(GUCTuneGroup):
    def __init__(self):
        super(DoubleWriteGUC, self).__init__()
        self.enable_double_write = self.bind('enable_double_write')
        self.dw_file_num = self.bind('dw_file_num')
        self.dw_file_size = self.bind('dw_file_size')

    def calculate(self):
        self.enable_double_write.turn_on()


class AsyncIoGUC(GUCTuneGroup):
    def __init__(self):
        super(AsyncIoGUC, self).__init__()
        self.enable_adio_debug = self.bind('enable_adio_debug')
        self.enable_adio_function = self.bind('enable_adio_function')
        self.enable_fast_allocate = self.bind('enable_fast_allocate')
        self.prefetch_quantity = self.bind('prefetch_quantity')
        self.backwrite_quantity = self.bind('backwrite_quantity')
        self.cstore_prefetch_quantity = self.bind('cstore_prefetch_quantity')
        self.cstore_backwrite_quantity = self.bind('cstore_backwrite_quantity')
        self.cstore_backwrite_max_threshold = self.bind('cstore_backwrite_max_threshold')
        self.fast_extend_file_size = self.bind('fast_extend_file_size')
        self.effective_io_concurrency = self.bind('effective_io_concurrency')
        self.checkpoint_flush_after = self.bind('checkpoint_flush_after')
        self.backend_flush_after = self.bind('backend_flush_after')

    def calculate(self):
        pass


class WalGUC(GUCTuneGroup):
    def __init__(self):
        super(WalGUC, self).__init__()
        self.wal_level = self.bind('wal_level')
        self.fsync = self.bind('fsync')
        self.synchronous_commit = self.bind('synchronous_commit')
        self.full_page_writes = self.bind('full_page_writes')
        self.wal_sync_method = self.bind('wal_sync_method')
        self.wal_log_hints = self.bind('wal_log_hints')
        self.wal_buffers = self.bind('wal_buffers')
        self.wal_writer_delay = self.bind('wal_writer_delay')
        self.commit_delay = self.bind('commit_delay')
        self.commit_siblings = self.bind('commit_siblings')
        self.wal_block_size = self.bind('wal_block_size')
        self.wal_segment_size = self.bind('wal_segment_size')
        self.walwriter_cpu_bind = self.bind('walwriter_cpu_bind')
        self.walwriter_sleep_threshold = self.bind('walwriter_sleep_threshold')
        self.wal_file_init_num = self.bind('wal_file_init_num')
        self.xlog_file_path = self.bind('xlog_file_path')
        self.xlog_file_size = self.bind('xlog_file_size')
        self.xlog_lock_file_path = self.bind('xlog_lock_file_path')
        self.force_promote = self.bind('force_promote')
        self.wal_flush_timeout = self.bind('wal_flush_timeout')
        self.wal_flush_delay = self.bind('wal_flush_delay')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        self.full_page_writes.turn_off()
        self._calc_walwriter_cpu_bind(infos)

        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.wal_level.set('archive')
            self.wal_buffers.set('1GB')
            self.wal_log_hints.turn_off()
            self.walwriter_sleep_threshold.set(50000)
            self.wal_file_init_num.set(1000)


    def _calc_walwriter_cpu_bind(self, infos):
        # we're already calculated the res when we adjust the network, cpu and thread pool GUC.
        numa_bind_info = infos.cpu.notebook.read('numa_bind_info')
        if numa_bind_info['use']:
            self.walwriter_cpu_bind.set(0)


class RecoveryGUC(GUCTuneGroup):
    def __init__(self):
        super(RecoveryGUC, self).__init__()
        self.recovery_time_target = self.bind('recovery_time_target')
        self.recovery_max_workers = self.bind('recovery_max_workers')
        self.recovery_parse_workers = self.bind('recovery_parse_workers')
        self.recovery_redo_workers = self.bind('recovery_redo_workers')
        self.recovery_parallelism = self.bind('recovery_parallelism')
        self.recovery_min_apply_delay = self.bind('recovery_min_apply_delay')
        self.redo_bind_cpu_attr = self.bind('redo_bind_cpu_attr')
        self.enable_page_lsn_check = self.bind('enable_page_lsn_check')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_page_lsn_check.turn_off()


class BackoutRecoveryGUC(GUCTuneGroup):
    def __init__(self):
        super(BackoutRecoveryGUC, self).__init__()
        self.operation_mode = self.bind('operation_mode')
        self.enable_cbm_tracking = self.bind('enable_cbm_tracking')
        self.hadr_max_size_for_xlog_receiver = self.bind('hadr_max_size_for_xlog_receiver')

    def calculate(self):
        pass


class ArchiveGUC(GUCTuneGroup):
    def __init__(self):
        super(ArchiveGUC, self).__init__()
        self.archive_mode = self.bind('archive_mode')
        self.archive_command = self.bind('archive_command')
        self.archive_dest = self.bind('archive_dest')
        self.archive_timeout = self.bind('archive_timeout')
        self.archive_interval = self.bind('archive_interval')

    def calculate(self):
        pass


class LockManagerGUC(GUCTuneGroup):
    def __init__(self):
        super(LockManagerGUC, self).__init__()
        self.deadlock_timeout = self.bind('deadlock_timeout')
        self.lockwait_timeout = self.bind('lockwait_timeout')
        self.update_lockwait_timeout = self.bind('update_lockwait_timeout')
        self.max_locks_per_transaction = self.bind('max_locks_per_transaction')
        self.max_pred_locks_per_transaction = self.bind('max_pred_locks_per_transaction')
        self.gs_clean_timeout = self.bind('gs_clean_timeout')
        self.partition_lock_upgrade_timeout = self.bind('partition_lock_upgrade_timeout')
        self.fault_mon_timeout = self.bind('fault_mon_timeout')
        self.enable_online_ddl_waitlock = self.bind('enable_online_ddl_waitlock')
        self.xloginsert_locks = self.bind('xloginsert_locks')
        self.num_internal_lock_partitions = self.bind('num_internal_lock_partitions')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.update_lockwait_timeout.set('20min')
            self.gs_clean_timeout.set(0)


class TransactionGUC(GUCTuneGroup):
    def __init__(self):
        super(TransactionGUC, self).__init__()
        self.default_transaction_isolation = self.bind('default_transaction_isolation')
        self.default_transaction_read_only = self.bind('default_transaction_read_only')
        self.default_transaction_deferrable = self.bind('default_transaction_deferrable')
        self.transaction_isolation = self.bind('transaction_isolation')
        self.transaction_read_only = self.bind('transaction_read_only')
        self.transaction_deferrable = self.bind('transaction_deferrable')

        self.autocommit = self.bind('autocommit')
        self.xc_maintenance_mode = self.bind('xc_maintenance_mode')
        self.allow_concurrent_tuple_update = self.bind('allow_concurrent_tuple_update')
        self.max_prepared_transactions = self.bind('max_prepared_transactions')
        self.enable_show_any_tuples = self.bind('enable_show_any_tuples')
        self.replication_type = self.bind('replication_type')
        self.enable_defer_calculate_snapshot = self.bind('enable_defer_calculate_snapshot')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        max_prepared_transactions = infos.business.parallel * 10
        self.max_prepared_transactions.set(max_prepared_transactions)


class UstoreGUC(GUCTuneGroup):
    def __init__(self):
        super(UstoreGUC, self).__init__()
        self.enable_ustore = self.bind('enable_ustore')
        self.enable_default_ustore_table = self.bind('enable_default_ustore_table')
        self.ustore_attr = self.bind('ustore_attr')

    def calculate(self):
        pass


class SharedStorageGUC(GUCTuneGroup):
    def __init__(self):
        super(SharedStorageGUC, self).__init__()
        self.ss_enable_dss = self.bind('ss_enable_dss')
        self.ss_enable_dms = self.bind('ss_enable_dms')
        self.ss_enable_ssl = self.bind('ss_enable_ssl')
        self.ss_enable_catalog_centralized = self.bind('ss_enable_catalog_centralized')
        self.ss_instance_id = self.bind('ss_instance_id')
        self.ss_dss_vg_name = self.bind('ss_dss_vg_name')
        self.ss_dss_conn_path = self.bind('ss_dss_conn_path')
        self.ss_interconnect_channel_count = self.bind('ss_interconnect_channel_count')
        self.ss_work_thread_count = self.bind('ss_work_thread_count')
        self.ss_recv_msg_pool_size = self.bind('ss_recv_msg_pool_size')
        self.ss_interconnect_type = self.bind('ss_interconnect_type')
        self.ss_interconnect_url = self.bind('ss_interconnect_url')
        self.ss_rdma_work_config = self.bind('ss_rdma_work_config')
        self.ss_ock_log_path = self.bind('ss_ock_log_path')
        self.ss_enable_scrlock = self.bind('ss_enable_scrlock ')
        self.ss_enable_scrlock_sleep_mode = self.bind('ss_enable_scrlock_sleep_mode ')
        self.ss_scrlock_server_port = self.bind('ss_scrlock_server_port ')
        self.ss_scrlock_worker_count = self.bind('ss_scrlock_worker_count ')
        self.ss_scrlock_worker_bind_core = self.bind('ss_scrlock_worker_bind_core  ')
        self.ss_scrlock_server_bind_core = self.bind('ss_scrlock_server_bind_core  ')
        self.ss_log_level = self.bind('ss_log_level')
        self.ss_log_backup_file_count = self.bind('ss_log_backup_file_count')
        self.ss_log_max_file_size = self.bind('ss_log_max_file_size')
        self.ss_enable_aio = self.bind('ss_enable_aio')
        self.ss_enable_verify_page = self.bind('ss_enable_verify_page')
        self.ss_enable_reform = self.bind('ss_enable_reform')
        self.ss_parallel_thread_count = self.bind('ss_parallel_thread_count')
        self.ss_enable_ondemand_recovery = self.bind('ss_enable_ondemand_recovery')
        self.ss_ondemand_recovery_mem_size = self.bind('ss_ondemand_recovery_mem_size')
        self.ss_enable_bcast_snapshot = self.bind('ss_enable_bcast_snapshot')

    def calculate(self):
        pass
