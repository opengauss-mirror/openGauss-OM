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

import math
from base_utils.os.cpu_util import CpuArchitecture, CpuUtil
from base_utils.os.disk_util import DiskUtil

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.anti import AntiLog
from impl.perf_config.basic.tuner import Tuner, TunerGroup, ShellTunePoint
from impl.perf_config.probes.business import BsScenario


################################################
# BIOS
# - BiosTuner
################################################
class BiosTuner(TunerGroup):
    def __init__(self):
        super(BiosTuner, self).__init__()

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.os.bios.support_smmu == 'Enable':
            sug = 'modify BIOS->Advances->MISC Config->Support Smmu to Disable.'
            Project.report.suggest(sug)
            Project.log('SUGGESTION: ' + sug)
        if infos.os.bios.cpu_prefetching == 'Enable':
            sug = 'modify BIOS->Advances->MISC Config->CPU Prefetching Configuration to Disable.'
            Project.report.suggest(sug)
            Project.log('SUGGESTION: ' + sug)
        if infos.os.bios.die_interleaving == 'Enable':
            sug = 'modify BIOS->Advances->MISC Config->Die Interleaving to Disable.'
            Project.report.suggest(sug)
            Project.log('SUGGESTION: ' + sug)


################################################
# CPU
# - CPUTuner
################################################
class CPUTuner(TunerGroup):
    def __init__(self):
        super(CPUTuner, self).__init__()

    @staticmethod
    def calculate_numa_bind():
        infos = Project.getGlobalPerfProbe()
        session_per_core = infos.business.parallel / infos.cpu.count()
        numa_bind = (infos.cpu.architecture() == CpuArchitecture.AARCH64 and
                     infos.cpu.count() >= 32 and
                     BsScenario.isOLTPScenario(infos.business.scenario) and
                     session_per_core > 1)

        numa_bind_info = {'use': False, 'threadpool': [], 'network': '', 'walwriter': '', 'suggestions': []}
        if numa_bind:
            numa_bind_info['use'] = True
            ratio_for_net = 0.1   # cpu num for irq-bind / all cpu, 0.1 is ref tpcc 2P 4P.
            threadpool = []
            network = []
            for cpu_list in infos.cpu.numa():
                cpu_count = len(cpu_list)
                count_for_net = max(math.floor(cpu_count * ratio_for_net), 1)
                threadpool += cpu_list[:cpu_count - count_for_net]
                network += cpu_list[cpu_count - count_for_net:]
            walwriter = [0]
            numactl_param = CpuUtil.cpuListToCpuRangeStr(threadpool)
            threadpool.remove(0)
            numa_bind_info['walwriter'] = CpuUtil.cpuListToCpuRangeStr(walwriter)
            numa_bind_info['threadpool'] = threadpool
            numa_bind_info['network'] = CpuUtil.cpuListToCpuRangeStr(network)

            suggestion = "If you use numactl for startup, you are advised to add param '-C {0}'{1}.".format(
                numactl_param,
                '' if infos.cpu.count() < 256 or len(infos.cpu.numa) < 4 else "and '--preferred=0'."
            )
            numa_bind_info['suggestions'].append(suggestion)

        return numa_bind_info

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        numa_bind_info = self.calculate_numa_bind()
        infos.cpu.notebook.write('numa_bind_info', numa_bind_info)

    def explain(self, apply=False):
        # tune threadpool in dbtuner and network in nerwork tuner
        pass


################################################
# MEMORY
# - MemoryTuner
#       - MemHugePageTuner
###############################################
class MemHugePageTuner(TunerGroup):
    def __init__(self):
        super(MemHugePageTuner, self).__init__()

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.memory.hugepage is None:
            return

        self._disable_huge_mem(infos)

    def _disable_huge_mem(self, infos):
        tune_enabled = (infos.memory.hugepage['enabled'] != 'never')
        if tune_enabled:
            cmd = "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled"
            anti = "echo '{}' > /sys/kernel/mm/transparent_hugepage/enabled".format(
                infos.memory.hugepage['enabled'])
            desc = 'Tune hugepage enabled to never, old value is {}'.format(infos.memory.hugepage['enabled'])
            self.add(ShellTunePoint(cmd, anti, desc))

        tune_defrag = (infos.memory.hugepage['defrag'] != 'never')
        if tune_defrag:
            cmd = "echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"
            anti = "echo '{}' > /sys/kernel/mm/transparent_hugepage/defrag".format(
                infos.memory.hugepage['enabled'])
            desc = 'Tune hugepage defrag to never, old value is {}'.format(infos.memory.hugepage['enabled'])
            self.add(ShellTunePoint(cmd, anti, desc))


class MemoryTuner(TunerGroup):
    def __init__(self):
        super(MemoryTuner, self).__init__()
        self.hugepage = self.add(MemHugePageTuner())


################################################
# DISK
# - DiskTuner
###############################################
class DiskTuner(TunerGroup):
    def __init__(self):
        super(DiskTuner, self).__init__()

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        gausshome_disk = DiskUtil.getMountPathByDataDir(infos.db.gauss_data)
        device = infos.disk.get(gausshome_disk)
        if device.fstype != 'xfs':
            sug = "Disk {0} is {1} format, you are advised to set the disk format to xfs ".format(
                device.device, device.fstype
            )
            Project.report.suggest(sug)
            Project.log('SUGGESTION: ' + sug)


################################################
# DISK
# - NetworkTuner
#       - NetworkIRQTuner
#       - EthtoolTuner
#       - NetConfigTuner
###############################################
class NetworkIRQTuner(TunerGroup):
    def __init__(self):
        super(NetworkIRQTuner, self).__init__()
        self.script = Project.environ.get_builtin_script('irq_operate.sh')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        numa_bind_info = infos.cpu.notebook.read('numa_bind_info')
        if numa_bind_info is None or not numa_bind_info.get('use'):
            return
        for ip in infos.db.ip:
            if ip == '*':
                continue
            gate = infos.network.get_gate(ip)
            if gate is None or gate.is_localhost() or gate.is_virbr():
                continue

            bind_list = CpuUtil.cpuRangeStrToCpuList(numa_bind_info.get('network'))
            roll_list = gate.irq_binds
            cmd = 'sh {0} bind "{1}"'.format(self.script, ' '.join([str(cpuid) for cpuid in bind_list]))
            anti = 'sh {0} bind "{1}"'.format(self.script, ' '.join([str(cpuid) for cpuid in roll_list]))
            desc = 'bind irq'
            self.add(ShellTunePoint(cmd, anti, desc))


class OffloadingTuner(TunerGroup):
    def __init__(self):
        super(OffloadingTuner, self).__init__()

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        for ip in infos.db.ip:
            if ip == '*':
                continue
            gate = infos.network.get_gate(ip)
            if gate is None or gate.is_localhost() or gate.is_virbr():
                continue

            tune_tso = (gate.tso == 'off')
            if tune_tso:
                cmd = 'ethtool -K {} tso on'.format(gate.name)
                anti = 'ethtool -K {} tso off'.format(gate.name)
                desc = 'open offloading tso'
                self.add(ShellTunePoint(cmd, anti, desc))

            tune_lro = (gate.lro == 'off')
            if tune_lro:
                cmd = 'ethtool -K {} lro on'.format(gate.name)
                anti = 'ethtool -K {} lro off'.format(gate.name)
                desc = 'open offloading lro'
                self.add(ShellTunePoint(cmd, anti, desc))


class NetConfigTuner(TunerGroup):
    def __init__(self):
        super(NetConfigTuner, self).__init__()

    def calculate(self):
        pass


class NetworkTuner(TunerGroup):
    def __init__(self):
        super(NetworkTuner, self).__init__()
        self.network_irq = self.add(NetworkIRQTuner())
        self.offloading = self.add(OffloadingTuner())
        self.net_config = self.add(NetConfigTuner())


################################################
# OS CONFIGURE AND SERVICE
# - OSServiceTuner
################################################
class OSServiceTuner(TunerGroup):
    def __init__(self):
        super(OSServiceTuner, self).__init__()

    def calculate(self):
        infos = Project.getGlobalPerfProbe()

        if infos.os.service.sysmonitor is not None and infos.os.service.sysmonitor:
            cmd = "service sysmonitor stop"
            anti = "service sysmonitor start"
            desc = "stop sysmonitor"
            self.add(ShellTunePoint(cmd, anti, desc))

        if infos.os.service.irqbalance is not None and infos.os.service.irqbalance:
            cmd = "service irqbalance stop"
            anti = "service irqbalance start"
            desc = "stop irqbalance"
            self.add(ShellTunePoint(cmd, anti, desc))


################################################
# OS TUNER
# - OSTuner
#       - BiosTuner
#       - CPUTuner
#       - MemoryTuner
#       - DiskTuner
#       - NetworkTuner
#       - OSServiceTuner
###############################################
class OSTuner(TunerGroup):
    def __init__(self):
        super(OSTuner, self).__init__()
        self.bios = self.add(BiosTuner())
        self.cpu = self.add(CPUTuner())
        self.memory = self.add(MemoryTuner())
        self.disk = self.add(DiskTuner())
        self.network = self.add(NetworkTuner())
        self.service = self.add(OSServiceTuner())
