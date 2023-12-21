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

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.tuner import Tuner, TunerGroup
from impl.perf_config.basic.guc import GucMap, GUCTuneGroup
from impl.perf_config.probes.business import BsScenario


class StatisticCollectGUC(GUCTuneGroup):
    def __init__(self):
        super(StatisticCollectGUC, self).__init__()
        self.track_activities = self.bind('track_activities')
        self.track_counts = self.bind('track_counts')
        self.track_io_timing = self.bind('track_io_timing')
        self.track_functions = self.bind('track_functions')
        self.track_activity_query_size = self.bind('track_activity_query_size')
        self.stats_temp_directory = self.bind('stats_temp_directory')
        self.track_thread_wait_status_interval = self.bind('track_thread_wait_status_interval')
        self.enable_save_datachanged_timestamp = self.bind('enable_save_datachanged_timestamp')
        self.track_sql_count = self.bind('track_sql_count')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.track_activities.turn_off()
            self.track_sql_count.turn_off()
            self.enable_save_datachanged_timestamp.turn_off()


class WorkloadManagerGUC(GUCTuneGroup):
    def __init__(self):
        super(WorkloadManagerGUC, self).__init__()
        self.use_workload_manager = self.bind('use_workload_manager')

        self.memory_tracking_mode = self.bind('memory_tracking_mode')
        self.memory_detail_tracking = self.bind('memory_detail_tracking')
        self.memory_fault_percent = self.bind('memory_fault_percent')
        self.disable_memory_protect = self.bind('disable_memory_protect')
        self.session_history_memory = self.bind('session_history_memory')

        self.enable_resource_track = self.bind('enable_resource_track')
        self.enable_resource_record = self.bind('enable_resource_record')
        self.resource_track_level = self.bind('resource_track_level')
        self.resource_track_cost = self.bind('resource_track_cost')
        self.resource_track_duration = self.bind('resource_track_duration')

        self.enable_logical_io_statistics = self.bind('enable_logical_io_statistics')
        self.enable_user_metric_persistent = self.bind('enable_user_metric_persistent')
        self.user_metric_retention_time = self.bind('user_metric_retention_time')
        self.enable_instance_metric_persistent = self.bind('enable_instance_metric_persistent')
        self.instance_metric_retention_time = self.bind('instance_metric_retention_time')

        self.enable_bbox_dump = self.bind('enable_bbox_dump')
        self.bbox_dump_count = self.bind('bbox_dump_count')
        self.bbox_dump_path = self.bind('bbox_dump_path')
        self.bbox_blanklist_items = self.bind('bbox_blanklist_items')

        self.io_limits = self.bind('io_limits')
        self.io_priority = self.bind('io_priority')
        self.io_control_unit = self.bind('io_control_unit')
        self.session_respool = self.bind('session_respool')
        self.session_statistics_memory = self.bind('session_statistics_memory')
        self.topsql_retention_time = self.bind('topsql_retention_time')
        self.transaction_pending_time = self.bind('transaction_pending_time')
        self.current_logic_cluster = self.bind('current_logic_cluster')
        self.enable_ffic_log = self.bind('enable_ffic_log')
        self.cgroup_name = self.bind('cgroup_name')
        self.cpu_collect_timer = self.bind('cpu_collect_timer')
        self.query_band = self.bind('query_band')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.use_workload_manager.turn_off()
            self.enable_logical_io_statistics.turn_off()
            self.enable_user_metric_persistent.turn_off()
            self.enable_instance_metric_persistent.turn_off()
            self.enable_ffic_log.turn_off()
            self.enable_bbox_dump.turn_off()
            self.enable_resource_track.turn_off()


class TrackStmtGUC(GUCTuneGroup):
    def __init__(self):
        super(TrackStmtGUC, self).__init__()
        self.instr_unique_sql_count = self.bind('instr_unique_sql_count')
        self.instr_unique_sql_track_type = self.bind('instr_unique_sql_track_type')
        self.enable_auto_clean_unique_sql = self.bind('enable_auto_clean_unique_sql')

        self.percentile = self.bind('percentile')
        self.enable_instr_cpu_timer = self.bind('enable_instr_cpu_timer')
        self.enable_instr_track_wait = self.bind('enable_instr_track_wait')
        self.enable_instr_rt_percentile = self.bind('enable_instr_rt_percentile')
        self.instr_rt_percentile_interval = self.bind('instr_rt_percentile_interval')

        self.enable_stmt_track = self.bind('enable_stmt_track')
        self.track_stmt_session_slot = self.bind('track_stmt_session_slot')
        self.track_stmt_details_size = self.bind('track_stmt_details_size')
        self.track_stmt_retention_time = self.bind('track_stmt_retention_time')
        self.track_stmt_stat_level = self.bind('track_stmt_stat_level')
        self.track_stmt_standby_chain_size = self.bind('track_stmt_standby_chain_size')
        self.log_min_duration_statement = self.bind('log_min_duration_statement')

        self.time_record_level = self.bind('time_record_level')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_stmt_track.turn_off()
            self.instr_unique_sql_count.set('0')
            self.time_record_level.set('1')
            self.enable_instr_cpu_timer.turn_off()
            self.enable_instr_track_wait.turn_off()
            self.enable_instr_rt_percentile.turn_off()


class WdrAspGUC(GUCTuneGroup):
    def __init__(self):
        super(WdrAspGUC, self).__init__()
        self.enable_wdr_snapshot = self.bind('enable_wdr_snapshot')
        self.wdr_snapshot_retention_days = self.bind('wdr_snapshot_retention_days')
        self.wdr_snapshot_query_timeout = self.bind('wdr_snapshot_query_timeout')
        self.wdr_snapshot_interval = self.bind('wdr_snapshot_interval')

        self.enable_asp = self.bind('enable_asp')
        self.asp_flush_mode = self.bind('asp_flush_mode')
        self.asp_flush_rate = self.bind('asp_flush_rate')
        self.asp_log_filename = self.bind('asp_log_filename')
        self.asp_retention_days = self.bind('asp_retention_days')
        self.asp_sample_interval = self.bind('asp_sample_interval')
        self.asp_sample_num = self.bind('asp_sample_num')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_wdr_snapshot.turn_off()
            self.enable_asp.turn_off()


class LogGUC(GUCTuneGroup):
    def __init__(self):
        super(LogGUC, self).__init__()
        self.debug_print_parse = self.bind('debug_print_parse')
        self.debug_print_rewritten = self.bind('debug_print_rewritten')
        self.debug_print_plan = self.bind('debug_print_plan')
        self.debug_pretty_print = self.bind('debug_pretty_print')

        self.log_parser_stats = self.bind('log_parser_stats')
        self.log_planner_stats = self.bind('log_planner_stats')
        self.log_executor_stats = self.bind('log_executor_stats')
        self.log_statement_stats = self.bind('log_statement_stats')
        self.log_destination = self.bind('log_destination')
        self.log_directory = self.bind('log_directory')
        self.log_filename = self.bind('log_filename')
        self.log_file_mode = self.bind('log_file_mode')
        self.log_truncate_on_rotation = self.bind('log_truncate_on_rotation')
        self.log_rotation_age = self.bind('log_rotation_age')
        self.log_rotation_size = self.bind('log_rotation_size')
        self.log_checkpoints = self.bind('log_checkpoints')
        self.log_connections = self.bind('log_connections')
        self.log_disconnections = self.bind('log_disconnections')
        self.log_duration = self.bind('log_duration')
        self.log_error_verbosity = self.bind('log_error_verbosity')
        self.log_hostname = self.bind('log_hostname')
        self.log_line_prefix = self.bind('log_line_prefix')
        self.log_lock_waits = self.bind('log_lock_waits')
        self.log_statement = self.bind('log_statement')
        self.log_temp_files = self.bind('log_temp_files')
        self.log_timezone = self.bind('log_timezone')
        self.logging_collector = self.bind('logging_collector')
        self.logging_module = self.bind('logging_module')
        self.log_min_error_statement = self.bind('log_min_error_statement')
        self.log_min_messages = self.bind('log_min_messages')
        self.client_min_messages = self.bind('client_min_messages')

        self.event_source = self.bind('event_source')
        self.enable_debug_vacuum = self.bind('enable_debug_vacuum')
        self.backtrace_min_messages = self.bind('backtrace_min_messages')
        self.plog_merge_age = self.bind('plog_merge_age')
        self.syslog_facility = self.bind('syslog_facility')
        self.syslog_ident = self.bind('syslog_ident')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.log_min_messages.set('FATAL')
            self.client_min_messages.set('ERROR')
            self.log_duration.turn_off()


