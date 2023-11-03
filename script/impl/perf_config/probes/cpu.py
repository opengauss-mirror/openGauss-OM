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
from impl.perf_config.basic.probe import Probe
from base_utils.os.cpu_util import CpuArchitecture, CpuUtil
from base_utils.os.dmidecode_util import DmidecodeUtil, DMITypeCategory


class CPUInfo(Probe):
    def __init__(self):
        super(CPUInfo, self).__init__()
        self.architecture = lambda : CpuUtil.getCpuArchitecture()
        self.vendor = lambda : CpuUtil.getCpuVendor()
        self.count = lambda : CpuUtil.getCpuNum()
        self.numa = lambda : CpuUtil.getCpuNumaList()

        self.dmi_processor = None
        self.dmi_cache = None

    def detect(self):
        if Project.haveRootPrivilege():
            self.dmi_processor = DmidecodeUtil.getDmidecodeTableByType(DMITypeCategory.PROCESSOR)
            self.dmi_cache = DmidecodeUtil.getDmidecodeTableByType(DMITypeCategory.CACHE)

