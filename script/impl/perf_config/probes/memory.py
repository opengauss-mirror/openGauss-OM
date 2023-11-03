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
# Description  : A probe for memory-related information.
#############################################################################

import re

from base_utils.os.cmd_util import CmdUtil
from base_utils.os.memory_util import MemoryUtil
from base_utils.os.dmidecode_util import DmidecodeUtil, DMIType, DMITypeCategory

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe


class MemoryInfo(Probe):
    def __init__(self):
        super(MemoryInfo, self).__init__()
        self.total_size = lambda : MemoryUtil.getPhysicalMemTotalSize()
        self.avail_size = lambda : MemoryUtil.getMemAvailableSize()
        self.page_size = lambda : CmdUtil.execCmd('getconf PAGE_SIZE')

        self.hugepage = None

        self.dmi_physical_mem_array = None
        self.dmi_all_devices = None
        self.dmi_use_devices = None

    def detect(self):
        self._detect_dmidecode()
        self._detect_hugepage()

    def _detect_dmidecode(self):
        if not Project.haveRootPrivilege():
            return
        self.dmi_physical_mem_array = DmidecodeUtil.getDmidecodeTableByType(DMIType.PHYSICAL_MEMORY_ARRAY)
        self.dmi_all_devices = DmidecodeUtil.getDmidecodeTableByType(DMIType.MEMORY_DEVICE)
        self.dmi_use_devices = []
        for device in self.dmi_all_devices:
            if device['Type'] != 'Unknown':
                self.dmi_use_devices.append(device)

    def _detect_hugepage(self):
        self.hugepage = {'enabled': '', 'defrag': ''}
        for key in self.hugepage:
            cmd = f'cat /sys/kernel/mm/transparent_hugepage/{key}'
            output = CmdUtil.execCmd(cmd)
            self.hugepage[key] = re.findall('\[(.*?)\]', output)[0]

