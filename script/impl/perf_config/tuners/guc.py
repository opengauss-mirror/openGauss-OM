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


import os
import json
import shutil

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.anti import AntiLog
from impl.perf_config.basic.tuner import Tuner, TunerGroup
from impl.perf_config.basic.guc import GucRootTuner
from impl.perf_config.tuners.gucs.common import CommonGUC, FileLocationGUC, KernelResourceGUC, MemoryGUC, SysCacheGUC, \
     AlarmGUC, RegionFormatGUC, ThreadPoolGUC, UpgradeGUC, MotGUC, GlobalTempTableGUC, UserDefineFuncGUC, JobScheduleGUC
from impl.perf_config.tuners.gucs.connection import ConnectionGUC, PoolerGUC
from impl.perf_config.tuners.gucs.execute import StmtBehaviorGUC, VersionCompatibilityGUC, EnvCompatibilityGUC
from impl.perf_config.tuners.gucs.ha_cluster import SenderServerGUC, PrimaryServerGUC, StandbyServerGUC, ReplConnInfoGUC
from impl.perf_config.tuners.gucs.ops import StatisticCollectGUC, WorkloadManagerGUC, TrackStmtGUC, WdrAspGUC, LogGUC
from impl.perf_config.tuners.gucs.optimizer import OptNodeCostGUC, OptRewriteGUC, OptPartTableGUC, OptGeqoGUC, \
    OptCodeGenGUC, OptBypassGUC, OptExplainGUC, OptSmpGUC, OptNgrmGUC, OptPbeGUC, OptGlobalPlanCacheGUC, OptOtherGUC
from impl.perf_config.tuners.gucs.other import DoubleDbReplicationGUC, AiGUC, DcfGUC, NvmGUC, FaultToleranceGUC, \
    HyperLogLogGUC, StandbyIUDGuc, DevelopOptionGUC, UndoGUC, OtherDefaultGUC, OtherOptionsGUC
from impl.perf_config.tuners.gucs.security import SecurityGUC, AuditGUC
from impl.perf_config.tuners.gucs.storage import VacuumGUC, CheckpointGUC, BackendWriteThreadGUC, DoubleWriteGUC, \
    AsyncIoGUC, WalGUC, RecoveryGUC, BackoutRecoveryGUC, ArchiveGUC, LockManagerGUC, TransactionGUC, SharedStorageGUC


class GucTuner(GucRootTuner):
    def __init__(self):
        super(GucTuner, self).__init__()
        ###########################################################################################
        # Register each GUC tune group. Theoretically, the adjustment strategy of different
        # guc groups should be independent of each other, but it is inevitable that there
        # are special cases. So, we still need to pay attention to the order.
        ###########################################################################################
        # common
        self.common = self.add(CommonGUC())
        self.file_location = self.add(FileLocationGUC())
        self.kernel_resource = self.add(KernelResourceGUC())
        self.memory = self.add(MemoryGUC())
        self.syscache = self.add(SysCacheGUC())
        self.alarm = self.add(AlarmGUC())
        self.region_format = self.add(RegionFormatGUC())
        self.thread_pool = self.add(ThreadPoolGUC())
        self.upgrade = self.add(UpgradeGUC())
        self.mot = self.add(MotGUC())
        self.gtt = self.add(GlobalTempTableGUC())
        self.udf = self.add(UserDefineFuncGUC())
        self.job = self.add(JobScheduleGUC())

        # security
        self.security = self.add(SecurityGUC())
        self.audit = self.add(AuditGUC())

        # connection
        self.connection = self.add(ConnectionGUC())
        self.pooler = self.add(PoolerGUC())

        # optmizer
        self.opt_nodecost = self.add(OptNodeCostGUC())
        self.opt_rewrite = self.add(OptRewriteGUC())
        self.opt_partition = self.add(OptPartTableGUC())
        self.opt_geqo = self.add(OptGeqoGUC())
        self.opt_codegen = self.add(OptCodeGenGUC())
        self.opt_bypass = self.add(OptBypassGUC())
        self.opt_explain = self.add(OptExplainGUC())
        self.opt_smp = self.add(OptSmpGUC())
        self.opt_ngrm = self.add(OptNgrmGUC())
        self.opt_pbe = self.add(OptPbeGUC())
        self.opt_gpc = self.add(OptGlobalPlanCacheGUC())
        self.opt_other = self.add(OptOtherGUC())

        # execute
        self.stmt_behavior = self.add(StmtBehaviorGUC())
        self.version_compa = self.add(VersionCompatibilityGUC())
        self.env_compa = self.add(EnvCompatibilityGUC())

        # storage
        self.vacuum = self.add(VacuumGUC())
        self.checkpoint = self.add(CheckpointGUC())
        self.bgwrite = self.add(BackendWriteThreadGUC())
        self.dw = self.add(DoubleWriteGUC())
        self.async_io = self.add(AsyncIoGUC())
        self.wal = self.add(WalGUC())
        self.recovery = self.add(RecoveryGUC())
        self.backout_recovery = self.add(BackoutRecoveryGUC())
        self.archive = self.add(ArchiveGUC())
        self.lock_mgr = self.add(LockManagerGUC())
        self.transaction = self.add(TransactionGUC())
        self.shared_storage = self.add(SharedStorageGUC())

        # ha
        self.repl_conn_info = self.add(ReplConnInfoGUC())
        self.sender_server = self.add(SenderServerGUC())
        self.primary_server = self.add(PrimaryServerGUC())
        self.standby_server = self.add(StandbyServerGUC())

        # ops
        self.statistic = self.add(StatisticCollectGUC())
        self.wlm = self.add(WorkloadManagerGUC())
        self.track_stmt = self.add(TrackStmtGUC())
        self.wdr_asp = self.add(WdrAspGUC())
        self.log = self.add(LogGUC())

        # other
        self.dbrep = self.add(DoubleDbReplicationGUC())
        self.ai = self.add(AiGUC())
        self.dcf = self.add(DcfGUC())
        self.nvm = self.add(NvmGUC())
        self.fault_tolerance = self.add(FaultToleranceGUC())
        self.hll = self.add(HyperLogLogGUC())
        self.standby_iud = self.add(StandbyIUDGuc())
        self.dev_options = self.add(DevelopOptionGUC())
        self.undo = self.add(UndoGUC())
        self.other_default = self.add(OtherDefaultGUC())
        self.other_options = self.add(OtherOptionsGUC())

