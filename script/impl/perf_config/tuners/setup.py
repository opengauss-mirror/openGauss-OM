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

import os
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.tuner import Tuner, TunerGroup, ShellTunePoint
from impl.perf_config.probes.db import DBInfo
from impl.perf_config.probes.business import BusinessProbe


class SetupTuner(TunerGroup):
    def __init__(self):
        super(SetupTuner, self).__init__()

    def calculate(self):
        self._calculate_isolated_xlog()

    def _calculate_isolated_xlog(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.isolated_xlog is None:
            return

        script = Project.environ.get_builtin_script('isolated_xlog.sh')
        old_path = os.path.join(infos.db.gauss_data, 'pg_xlog')
        new_path = os.path.join(infos.business.isolated_xlog, 'pg_xlog')

        cmd = f'sh {script} isolated {old_path} {new_path}'
        anti = f'sh {script} recover {old_path} {new_path}'
        desc = 'Storing wal on a separate disk.'

        self.add(ShellTunePoint(cmd, anti, desc))

