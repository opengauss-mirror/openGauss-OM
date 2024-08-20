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
import ipaddress
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe, ProbeGroup
from base_utils.os.cmd_util import CmdUtil


class NetworkGateInfo(Probe):
    def __init__(self, ifconfig):
        super(NetworkGateInfo, self).__init__()
        self._ifconfig = ifconfig
        self.name = None
        self.ipv4 = None
        self.ipv6 = None
        self.mac = None

        self.irq_binds = None
        self.combined = None
        self.tso = None
        self.lro = None
        self.gro = None
        self.gso = None

    def detect(self):
        self._parse_ifconfig()

        if not self.is_enp_gate():
            return

        self._detect_irq_binds()
        self._detect_combined()
        self._detect_ethtool_k()

    def _parse_ifconfig(self):
        lines = self._ifconfig.split('\n')
        self.name = lines[0].split(':')[0].strip()
        for line in lines:
            line = line.strip()
            if line.startswith('inet6'):
                self.ipv6 = line.split(' ')[1]
            elif line.startswith('inet'):
                self.ipv4 = line.split(' ')[1]
                self.netmask = line.split(' ')[3]
            elif line.startswith('ether'):
                self.mac = line.split(' ')[1]

    def is_localhost(self):
        return self.name == 'lo'

    def is_virbr(self):
        return self.name.startswith('virbr')
        
    def is_enp_gate(self):
        return self.name.startswith('enp')

    def _detect_irq_binds(self):
        script = Project.environ.get_builtin_script('irq_operate.sh')
        cmd = f'sh {script} test {self.name}'
        output = CmdUtil.execCmd(cmd, noexcept=True)
        if output != 'ok':
            Project.log(output)
            return

        cmd = f'sh {script} check {self.name}'
        output = CmdUtil.execCmd(cmd)
        lines = output.split('\n')
        self.irq_binds = [int(num) for num in lines[2:]]
        Project.log(f'Irq binds of {self.name} is: ' + str(self.irq_binds))

    def _detect_combined(self):
        cmd = f'ethtool -l {self.name} | grep Combined'
        output = CmdUtil.execCmd(cmd)
        parts = output.split()
        self.combined = {'maximums': int(parts[1]),
                         'current': int(parts[3])}

    def _detect_ethtool_k(self):
        cmd = f'ethtool -k {self.name}'
        output = CmdUtil.execCmd(cmd)
        opt_map = {}
        for line in output.split('\n'):
            kv = line.split(':')
            opt_map[kv[0]] = kv[1].strip()

        self.tso = opt_map.get('tcp-segmentation-offload')
        self.lro = opt_map.get('large-receive-offload')


class NetworkInfo(ProbeGroup):
    def __init__(self):
        super(NetworkInfo, self).__init__()
        self._gates = []

    def detect(self):
        ifconfig = CmdUtil.execCmd('ifconfig')
        lines = ifconfig.split('\n')
        assert lines[-1].strip() == ''
        s = 0
        for i, line in enumerate(lines):
            if line.strip() == '':
                device = NetworkGateInfo('\n'.join(lines[s:i]))
                self._gates.append(device)
                self.add(device)
                s = i + 1

        super(NetworkInfo, self).detect()

    def get_gate(self, argc):
        """
        get device in device list
        :param argc: device name or ipv4 or mac
        :return:
        """
        # Handle localhost special case
        if argc in ['localhost', '127.0.0.1', '::1']:
            argc = '127.0.0.1' if argc == 'localhost' else argc
        try:
            ip = ipaddress.ip_address(argc)
            is_ip = True
        except ValueError:
            is_ip = False

        for gate in self._gates:
            if is_ip:
                if (ip.version == 4 and gate.ipv4 == argc) or (ip.version == 6 and gate.ipv6 == argc):
                    return gate
            else:
                if gate.name == argc or gate.mac == argc:
                    return gate
        return
