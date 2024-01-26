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


class DoubleDbReplicationGUC(GUCTuneGroup):
    def __init__(self):
        super(DoubleDbReplicationGUC, self).__init__()
        self.RepOriginId = self.bind('RepOriginId')

    def calculate(self):
        pass

class AiGUC(GUCTuneGroup):
    def __init__(self):
        super(AiGUC, self).__init__()
        self.db4ai_snapshot_mode = self.bind('db4ai_snapshot_mode')
        self.db4ai_snapshot_version_delimiter = self.bind('db4ai_snapshot_version_delimiter')
        self.db4ai_snapshot_version_separator = self.bind('db4ai_snapshot_version_separator')
        self.enable_ai_stats = self.bind('enable_ai_stats')
        self.enable_cachedplan_mgr = self.bind('enable_cachedplan_mgr')

    def calculate(self):
        pass


class DcfGUC(GUCTuneGroup):
    def __init__(self):
        super(DcfGUC, self).__init__()
        self.enable_dcf = self.bind('enable_dcf')
        self.dcf_ssl = self.bind('dcf_ssl')
        self.dcf_config = self.bind('dcf_config')
        self.dcf_data_path = self.bind('dcf_data_path')
        self.dcf_log_path = self.bind('dcf_log_path')
        self.dcf_node_id = self.bind('dcf_node_id')
        self.dcf_max_workers = self.bind('dcf_max_workers')
        self.dcf_truncate_threshold = self.bind('dcf_truncate_threshold')
        self.dcf_election_timeout = self.bind('dcf_election_timeout')
        self.dcf_enable_auto_election_priority = self.bind('dcf_enable_auto_election_priority')
        self.dcf_election_switch_threshold = self.bind('dcf_election_switch_threshold')
        self.dcf_run_mode = self.bind('dcf_run_mode')
        self.dcf_log_level = self.bind('dcf_log_level')
        self.dcf_log_backup_file_count = self.bind('dcf_log_backup_file_count')
        self.dcf_max_log_file_size = self.bind('dcf_max_log_file_size')
        self.dcf_socket_timeout = self.bind('dcf_socket_timeout')
        self.dcf_connect_timeout = self.bind('dcf_connect_timeout')
        self.dcf_mec_fragment_size = self.bind('dcf_mec_fragment_size')
        self.dcf_stg_pool_max_size = self.bind('dcf_stg_pool_max_size')
        self.dcf_stg_pool_init_size = self.bind('dcf_stg_pool_init_size')
        self.dcf_mec_pool_max_size = self.bind('dcf_mec_pool_max_size')
        self.dcf_flow_control_disk_rawait_threshold = self.bind('dcf_flow_control_disk_rawait_threshold')
        self.dcf_flow_control_net_queue_message_num_threshold = self.bind('dcf_flow_control_net_queue_message_num_threshold')
        self.dcf_flow_control_cpu_threshold = self.bind('dcf_flow_control_cpu_threshold')
        self.dcf_mec_batch_size = self.bind('dcf_mec_batch_size')
        self.dcf_mem_pool_max_size = self.bind('dcf_mem_pool_max_size')
        self.dcf_mem_pool_init_size = self.bind('dcf_mem_pool_init_size')
        self.dcf_compress_algorithm = self.bind('dcf_compress_algorithm')
        self.dcf_compress_level = self.bind('dcf_compress_level')
        self.dcf_mec_channel_num = self.bind('dcf_mec_channel_num')
        self.dcf_rep_append_thread_num = self.bind('dcf_rep_append_thread_num')
        self.dcf_mec_agent_thread_num = self.bind('dcf_mec_agent_thread_num')
        self.dcf_mec_reactor_thread_num = self.bind('dcf_mec_reactor_thread_num')
        self.dcf_log_file_permission = self.bind('dcf_log_file_permission')
        self.dcf_log_path_permission = self.bind('dcf_log_path_permission')
        self.dcf_majority_groups = self.bind('dcf_majority_groups')

    def calculate(self):
        self.enable_dcf.turn_off()


class NvmGUC(GUCTuneGroup):
    def __init__(self):
        super(NvmGUC, self).__init__()
        self.enable_nvm = self.bind('enable_nvm')
        self.nvm_buffers = self.bind('nvm_buffers')
        self.nvm_file_path = self.bind('nvm_file_path')
        self.bypass_nvm = self.bind('bypass_nvm')
        self.bypass_dram = self.bind('bypass_dram')

    def calculate(self):
        self.enable_nvm.turn_off()


class FaultToleranceGUC(GUCTuneGroup):
    def __init__(self):
        super(FaultToleranceGUC, self).__init__()
        self.exit_on_error = self.bind('exit_on_error')
        self.restart_after_crash = self.bind('restart_after_crash')
        self.omit_encoding_error = self.bind('omit_encoding_error')
        self.cn_send_buffer_size = self.bind('cn_send_buffer_size')
        self.max_cn_temp_file_size = self.bind('max_cn_temp_file_size')
        self.retry_ecode_list = self.bind('retry_ecode_list')
        self.data_sync_retry = self.bind('data_sync_retry')
        self.remote_read_mode = self.bind('remote_read_mode')

    def calculate(self):
        pass


class HyperLogLogGUC(GUCTuneGroup):
    def __init__(self):
        super(HyperLogLogGUC, self).__init__()
        self.hll_default_log2m = self.bind('hll_default_log2m')
        self.hll_default_log2explicit = self.bind('hll_default_log2explicit')
        self.hll_default_log2sparse = self.bind('hll_default_log2sparse')
        self.hll_duplicate_check = self.bind('hll_duplicate_check')

    def calculate(self):
        pass


class StandbyIUDGuc(GUCTuneGroup):
    def __init__(self):
        super(StandbyIUDGuc, self).__init__()
        self.enable_remote_excute = self.bind('enable_remote_excute')

    def calculate(self):
        pass


class DevelopOptionGUC(GUCTuneGroup):
    def __init__(self):
        super(DevelopOptionGUC, self).__init__()
        self.allow_system_table_mods = self.bind('allow_system_table_mods')
        self.debug_assertions = self.bind('debug_assertions')
        self.ignore_checksum_failure = self.bind('ignore_checksum_failure')
        self.ignore_system_indexes = self.bind('ignore_system_indexes')
        self.post_auth_delay = self.bind('post_auth_delay')
        self.pre_auth_delay = self.bind('pre_auth_delay')
        self.trace_notify = self.bind('trace_notify')
        self.trace_recovery_messages = self.bind('trace_recovery_messages')
        self.trace_sort = self.bind('trace_sort')
        self.zero_damaged_pages = self.bind('zero_damaged_pages')
        self.remotetype = self.bind('remotetype')
        self.max_user_defined_exception = self.bind('max_user_defined_exception')
        self.enable_fast_numeric = self.bind('enable_fast_numeric')
        self.enable_compress_spill = self.bind('enable_compress_spill')
        self.resource_track_log = self.bind('resource_track_log')
        self.show_acce_estimate_detail = self.bind('show_acce_estimate_detail')
        self.support_batch_bind = self.bind('support_batch_bind')
        self.log_pagewriter = self.bind('log_pagewriter')
        self.enable_csqual_pushdown = self.bind('enable_csqual_pushdown')
        self.string_hash_compatible = self.bind('string_hash_compatible')
        self.pldebugger_timeout = self.bind('pldebugger_timeout')
        self.plsql_show_all_error = self.bind('plsql_show_all_error')

    def calculate(self):
        pass


class UndoGUC(GUCTuneGroup):
    def __init__(self):
        super(UndoGUC, self).__init__()
        self.undo_space_limit_size = self.bind('undo_space_limit_size')
        self.undo_limit_size_per_transaction = self.bind('undo_limit_size_per_transaction')
        self.max_undo_workers = self.bind('max_undo_workers')

        self.enable_recyclebin = self.bind('enable_recyclebin')
        self.recyclebin_retention_time = self.bind('recyclebin_retention_time')
        self.version_retention_age = self.bind('version_retention_age')
        self.undo_retention_time = self.bind('undo_retention_time')

    def calculate(self):
        pass


class OtherDefaultGUC(GUCTuneGroup):
    def __init__(self):
        super(OtherDefaultGUC, self).__init__()
        self.dynamic_library_path = self.bind('dynamic_library_path')
        self.gin_fuzzy_search_limit = self.bind('gin_fuzzy_search_limit')
        self.local_preload_libraries = self.bind('local_preload_libraries')

    def calculate(self):
        pass


class OtherOptionsGUC(GUCTuneGroup):
    def __init__(self):
        super(OtherOptionsGUC, self).__init__()
        self.reserve_space_for_nullable_atts = self.bind('reserve_space_for_nullable_atts')
        self.server_version = self.bind('server_version')
        self.server_version_num = self.bind('server_version_num')
        self.block_size = self.bind('block_size')
        self.segment_size = self.bind('segment_size')
        self.max_index_keys = self.bind('max_index_keys')
        self.integer_datetimes = self.bind('integer_datetimes')
        self.max_identifier_length = self.bind('max_identifier_length')
        self.server_encoding = self.bind('server_encoding')
        self.enable_upgrade_merge_lock_mode = self.bind('enable_upgrade_merge_lock_mode')
        self.transparent_encrypted_string = self.bind('transparent_encrypted_string')
        self.transparent_encrypt_kms_url = self.bind('transparent_encrypt_kms_url')
        self.transparent_encrypt_kms_region = self.bind('transparent_encrypt_kms_region')
        self.basebackup_timeout = self.bind('basebackup_timeout')
        self.datanode_heartbeat_interval = self.bind('datanode_heartbeat_interval')
        self.max_concurrent_autonomous_transactions = self.bind('max_concurrent_autonomous_transactions')
        self.sql_ignore_strategy = self.bind('sql_ignore_strategy')

    def calculate(self):
        pass

