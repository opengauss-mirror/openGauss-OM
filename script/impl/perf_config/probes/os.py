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

from base_utils.os.cmd_util import CmdUtil

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe, ProbeGroup


class BiosInfo(Probe):
    def __init__(self):
        super(BiosInfo).__init__()
        self.support_smmu = None
        self.cpu_prefetching = None
        self.die_interleaving = None

    def detect(self):
        # We can't detect it yet, so we're assuming it's all open.
        self.support_smmu = 'Enable'
        self.cpu_prefetching = 'Enable'
        self.die_interleaving = 'Enable'


class OSBaseInfo(Probe):
    def __init__(self):
        super(OSBaseInfo).__init__()
        self.is_virtual = False

    def detect(self):
        pass


class OSServiceInfo(Probe):
    def __init__(self):
        super(OSServiceInfo).__init__()
        self.sysmonitor = None
        self.irqbalance = None

    @staticmethod
    def is_running(service):
        cmd = f'systemctl status {service} | grep "Active:"'
        try:
            output = CmdUtil.execCmd(cmd)
            if output.find('(running)') >= 0:
                return True
            return False
        except Exception:
            pass

    def detect(self):
        self.sysmonitor = self.is_running('sysmonitor')
        self.irqbalance = self.is_running('irqbalance')


class OSInfo(ProbeGroup):
    def __init__(self):
        super(OSInfo, self).__init__()
        self.bios = self.add(BiosInfo())
        self.base = self.add(OSBaseInfo())
        self.service = self.add(OSServiceInfo())
