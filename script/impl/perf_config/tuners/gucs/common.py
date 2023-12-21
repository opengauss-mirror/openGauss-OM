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

from base_utils.os.cpu_util import CpuArchitecture, CpuUtil

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.tuner import Tuner, TunerGroup
from impl.perf_config.basic.guc import GucMap, GUCTuneGroup
from impl.perf_config.probes.business import BsScenario, TblKind
from impl.perf_config.tuners.os import CPUTuner

class CommonGUC(GUCTuneGroup):
    def __init__(self):
        super(CommonGUC, self).__init__()
        self.pgxc_node_name = self.bind('pgxc_node_name')
        self.application_name = self.bind('application_name')

    def calculate(self):
        pass


class FileLocationGUC(GUCTuneGroup):
    def __init__(self):
        super(FileLocationGUC, self).__init__()
        self.data_directory = self.bind('data_directory')
        self.config_file = self.bind('config_file')
        self.hba_file = self.bind('hba_file')
        self.ident_file = self.bind('ident_file')
        self.external_pid_file = self.bind('external_pid_file')
        self.enable_default_cfunc_libpath = self.bind('enable_default_cfunc_libpath')

    def calculate(self):
        pass


class KernelResourceGUC(GUCTuneGroup):
    def __init__(self):
        super(KernelResourceGUC, self).__init__()
        self.max_files_per_process = self.bind('max_files_per_process')
        self.shared_preload_libraries = self.bind('shared_preload_libraries')
        self.sql_use_spacelimit = self.bind('sql_use_spacelimit')
        self.temp_file_limit = self.bind('temp_file_limit')

    def calculate(self):
        pass


class MemoryGUC(GUCTuneGroup):
    def __init__(self):
        super(MemoryGUC, self).__init__()
        # memory pool
        self.memorypool_enable = self.bind('memorypool_enable')
        self.memorypool_size = self.bind('memorypool_size')
        # memory seciruty
        self.enable_memory_limit = self.bind('enable_memory_limit')
        self.enable_memory_context_control = self.bind('enable_memory_context_control')
        self.uncontrolled_memory_context = self.bind('uncontrolled_memory_context')
        # size, buffer and work mem
        self.max_process_memory = self.bind('max_process_memory')
        self.shared_buffers = self.bind('shared_buffers')
        self.cstore_buffers = self.bind('cstore_buffers')
        self.segment_buffers = self.bind('segment_buffers')
        self.temp_buffers = self.bind('temp_buffers')
        self.work_mem = self.bind('work_mem')
        self.query_mem = self.bind('query_mem')
        self.query_max_mem = self.bind('query_max_mem')
        self.psort_work_mem = self.bind('psort_work_mem')
        self.maintenance_work_mem = self.bind('maintenance_work_mem')
        # huge pages
        self.enable_huge_pages = self.bind('enable_huge_pages')
        self.huge_page_size = self.bind('huge_page_size')
        # others
        self.bulk_write_ring_size = self.bind('bulk_write_ring_size')
        self.max_loaded_cudesc = self.bind('max_loaded_cudesc')
        self.max_stack_depth = self.bind('max_stack_depth')
        self.bulk_read_ring_size = self.bind('bulk_read_ring_size')
        self.enable_early_free = self.bind('enable_early_free')
        self.resilience_memory_reject_percent = self.bind('resilience_memory_reject_percent')
        self.pca_shared_buffers = self.bind('pca_shared_buffers')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        self._calc_memorypool(infos)
        self._calc_memory_security(infos)
        self._calc_memory_size(infos)
        self._calc_memory_others(infos)

    def _calc_memorypool(self, infos):
        self.memorypool_enable.turn_off()

    def _calc_memory_security(self, infos):
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_memory_limit.turn_off()
            self.enable_memory_context_control.turn_off()

    def _calc_memory_size(self, infos):
        max_process_memory_rate = 0.55
        shared_buffers_rate = 0.4
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            max_process_memory_rate = 0.6
            shared_buffers_rate = 0.45
        elif infos.business.scenario == BsScenario.AP:
            max_process_memory_rate = 0.65
            shared_buffers_rate = 0.5

        max_process_memory = int(infos.memory.total_size() * max_process_memory_rate / 1024)
        if max_process_memory == 0:
            Project.fatat('Your machine memory is too small to support configuration.')
        self.max_process_memory.set('{}MB'.format(max_process_memory))

        shared_buffers = int(infos.memory.total_size() * shared_buffers_rate / 1024)
        if self.shared_buffers == 0:
            Project.fatat('Your machine memory is too small to support configuration.')
        self.shared_buffers.set('{}MB'.format(shared_buffers))

        cstore_buffers = 16
        if TblKind.haveColumnTbl(infos.business.rel_kind):
            cstore_buffers = 512
        self.cstore_buffers.set('{}MB'.format(cstore_buffers))

        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.work_mem.set('1MB')
            self.maintenance_work_mem.set('2GB')

    def _calc_memory_others(self, infos):
        if infos.business.scenario == BsScenario.AP:
            self.enable_early_free.turn_on()


class SysCacheGUC(GUCTuneGroup):
    def __init__(self):
        super(SysCacheGUC, self).__init__()
        self.enable_global_syscache = self.bind('enable_global_syscache')
        self.local_syscache_threshold = self.bind('local_syscache_threshold')
        self.global_syscache_threshold = self.bind('global_syscache_threshold')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_global_syscache.turn_off()
            self.local_syscache_threshold.set('16MB')


class AlarmGUC(GUCTuneGroup):
    def __init__(self):
        super(AlarmGUC, self).__init__()
        self.enable_alarm = self.bind('enable_alarm')
        self.connection_alarm_rate = self.bind('connection_alarm_rate')
        self.alarm_report_interval = self.bind('alarm_report_interval')
        self.alarm_component = self.bind('alarm_component')
        self.table_skewness_warning_threshold = self.bind('table_skewness_warning_threshold')
        self.table_skewness_warning_rows = self.bind('table_skewness_warning_rows')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.enable_alarm.turn_off()


class RegionFormatGUC(GUCTuneGroup):
    def __init__(self):
        super(RegionFormatGUC, self).__init__()
        self.DateStyle = self.bind('DateStyle')
        self.IntervalStyle = self.bind('IntervalStyle')
        self.TimeZone = self.bind('TimeZone')
        self.timezone_abbreviations = self.bind('timezone_abbreviations')
        self.extra_float_digits = self.bind('extra_float_digits')
        self.client_encoding = self.bind('client_encoding')
        self.lc_messages = self.bind('lc_messages')
        self.lc_monetary = self.bind('lc_monetary')
        self.lc_numeric = self.bind('lc_numeric')
        self.lc_time = self.bind('lc_time')
        self.lc_collate = self.bind('lc_collate')
        self.lc_ctype = self.bind('lc_ctype')
        self.default_text_search_config = self.bind('default_text_search_config')

    def calculate(self):
        self.lc_messages.set('C')
        self.lc_monetary.set('C')
        self.lc_numeric.set('C')
        self.lc_time.set('C')


class ThreadPoolGUC(GUCTuneGroup):
    def __init__(self):
        super(ThreadPoolGUC, self).__init__()
        self.enable_thread_pool = self.bind('enable_thread_pool')
        self.thread_pool_attr = self.bind('thread_pool_attr')
        self.thread_pool_stream_attr = self.bind('thread_pool_stream_attr')
        self.resilience_threadpool_reject_cond = self.bind('resilience_threadpool_reject_cond')
        self.numa_distribute_mode = self.bind('numa_distribute_mode')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        numa_bind_info = infos.cpu.notebook.read('numa_bind_info')
        if numa_bind_info is None:
            numa_bind_info = CPUTuner.calculate_numa_bind()
            infos.cpu.notebook.write('numa_bind_info', numa_bind_info)
        if not numa_bind_info['use']:
            self.enable_thread_pool.turn_off()
            return

        self.enable_thread_pool.turn_on()
        self.numa_distribute_mode.set('all')

        for sug in numa_bind_info['suggestions']:
            Project.report.suggest(sug)

        numa_group_count = len(infos.cpu.numa())
        thread_count = self._calc_thread_count(infos, numa_bind_info)
        cpubind = 'cpubind:{}'.format(CpuUtil.cpuListToCpuRangeStr(numa_bind_info['threadpool'])) \
            if len(numa_bind_info['threadpool']) != infos.cpu.count() else 'allbind'

        thread_pool_attr = '{0},{1},({2})'.format(thread_count, numa_group_count, cpubind)
        self.thread_pool_attr.set(thread_pool_attr)
        
    def _calc_thread_count(self, infos, numa_bind_info):
        max_count = len(numa_bind_info['threadpool']) * 7.25
        min_count = len(numa_bind_info['threadpool'])
        value = infos.business.parallel / (1.2 if infos.business.scenario == BsScenario.TP_PERFORMANCE else 2)
        
        res = math.floor(max(min(max_count, value), min_count))
        return res


class UpgradeGUC(GUCTuneGroup):
    def __init__(self):
        super(UpgradeGUC, self).__init__()
        self.IsInplaceUpgrade = self.bind('IsInplaceUpgrade')
        self.inplace_upgrade_next_system_object_oids = self.bind('inplace_upgrade_next_system_object_oids')
        self.upgrade_mode = self.bind('upgrade_mode')

    def calculate(self):
        pass


class MotGUC(GUCTuneGroup):
    def __init__(self):
        super(MotGUC, self).__init__()
        self.enable_codegen_mot = self.bind('enable_codegen_mot')
        self.force_pseudo_codegen_mot = self.bind('force_pseudo_codegen_mot')
        self.enable_codegen_mot_print = self.bind('enable_codegen_mot_print')
        self.codegen_mot_limit = self.bind('codegen_mot_limit')
        self.mot_allow_index_on_nullable_column = self.bind('mot_allow_index_on_nullable_column')
        self.mot_config_file = self.bind('mot_config_file')

    def calculate(self):
        pass


class GlobalTempTableGUC(GUCTuneGroup):
    def __init__(self):
        super(GlobalTempTableGUC, self).__init__()
        self.max_active_global_temporary_table = self.bind('max_active_global_temporary_table')
        self.vacuum_gtt_defer_check_age = self.bind('vacuum_gtt_defer_check_age')
        self.enable_gtt_concurrent_truncate = self.bind('enable_gtt_concurrent_truncate')

    def calculate(self):
        pass


class UserDefineFuncGUC(GUCTuneGroup):
    def __init__(self):
        super(UserDefineFuncGUC, self).__init__()
        self.udf_memory_limit = self.bind('udf_memory_limit')
        self.FencedUDFMemoryLimit = self.bind('FencedUDFMemoryLimit')
        self.UDFWorkerMemHardLimit = self.bind('UDFWorkerMemHardLimit')
        self.pljava_vmoptions = self.bind('pljava_vmoptions')

    def calculate(self):
        pass


class JobScheduleGUC(GUCTuneGroup):
    def __init__(self):
        super(JobScheduleGUC, self).__init__()
        self.job_queue_processes = self.bind('job_queue_processes')
        self.enable_prevent_job_task_startup = self.bind('enable_prevent_job_task_startup')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.job_queue_processes.set('0')
