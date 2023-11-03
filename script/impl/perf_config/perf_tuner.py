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
# Description  : perf_probe.py setup a information set for configure
#############################################################################

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.anti import AntiLog
from impl.perf_config.basic.tuner import Tuner, TunerGroup, ShellTunePoint
from impl.perf_config.tuners.os import OSTuner
from impl.perf_config.tuners.setup import SetupTuner
from impl.perf_config.tuners.guc import GucTuner


class PerfTuneTarget(object):
    def __init__(self, argc, apply):
        self._tune_target = []
        self._apply = apply

        all_module = ['os', 'setup', 'guc', 'suggest']
        argv = argc.split(',')

        for arg in argv:
            if arg == 'all':
                self._tune_target = all_module
            elif arg == 'os':
                if 'os' not in self._tune_target:
                    self._tune_target.append('os')
            elif arg == 'setup':
                if 'setup' not in self._tune_target:
                    self._tune_target.append('setup')
            elif arg == 'guc':
                if 'guc' not in self._tune_target:
                    self._tune_target.append('guc')
            elif arg == 'suggest':
                if 'suggest' not in self._tune_target:
                    self._tune_target.append('suggest')
            else:
                Project.fatal('unknown param {}.'.format(arg))
                exit(1)

        if not Project.haveRootPrivilege() and self.hasOS():
            Project.warning('no root privilege, ignore os.')
            self._tune_target.remove('os')

    def apply(self):
        return self._apply

    def noTarget(self):
        return len(self._tune_target) == 0

    def hasOS(self):
        return 'os' in self._tune_target

    def hasSetUp(self):
        return 'setup' in self._tune_target

    def hasGuc(self):
        return 'guc' in self._tune_target

    def hasSuggest(self):
        return 'suggest' in self._tune_target


class PerfTuner(TunerGroup):
    def __init__(self):
        super(PerfTuner, self).__init__()
        tt = Project.getTask().tune_target
        self.os = self.add(OSTuner()) if tt.hasOS() else None
        self.setup = self.add(SetupTuner()) if tt.hasSetUp() else None
        self.guc = self.add(GucTuner()) if tt.hasGuc() else None

    @staticmethod
    def rollback(alog):
        AntiLog.register(ShellTunePoint)
        AntiLog.register(GucTuner)

        AntiLog.rollback()

