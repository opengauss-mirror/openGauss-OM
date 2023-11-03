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


from impl.perf_config.basic.probe import Probe, ProbeGroup
from impl.perf_config.probes.business import BusinessProbe
from impl.perf_config.probes.cpu import CPUInfo
from impl.perf_config.probes.db import DBInfo
from impl.perf_config.probes.disk import DiskInfo
from impl.perf_config.probes.memory import MemoryInfo
from impl.perf_config.probes.network import NetworkInfo
from impl.perf_config.probes.os import OSInfo
from impl.perf_config.probes.user import UserInfo


class PerfProbe(ProbeGroup):
    def __init__(self):
        super(PerfProbe, self).__init__()
        self.user = self.add(UserInfo())
        self.cpu = self.add(CPUInfo())
        self.memory = self.add(MemoryInfo())
        self.disk = self.add(DiskInfo())
        self.network = self.add(NetworkInfo())
        self.os = self.add(OSInfo())
        self.db = self.add(DBInfo())
        self.business = self.add(BusinessProbe())

