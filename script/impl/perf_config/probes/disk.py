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
import re
import psutil
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe
from base_utils.os.disk_util import DiskUtil
from base_utils.os.cmd_util import CmdUtil


class DiskDeviceInfo(Probe):
    def __init__(self, partition):
        super(DiskDeviceInfo, self).__init__()
        self._partition = partition
        self.device = self._partition.device
        self.mountpoint = self._partition.mountpoint
        self.fstype = self._partition.fstype
        self.total_size = lambda : DiskUtil.getTotalSize(self.device)
        self.avail_size = lambda : DiskUtil.getAvailSize(self.device)
        self.vendor = None
        self.r_speed = None
        self.w_speed = None
        self.opts = {}

    def detect(self):
        for opt in self._partition.opts.split(','):
            kv = opt.split('=')
            if len(kv) == 1:
                self.opts[kv[0]] = True
            else:
                assert len(kv) == 2
                self.opts[kv[0]] = kv[1]

        self._detect_io_speed()

    def simple_info(self):
        return 'device={0}, mountpoint={1}, fstype={2} size=(free {3}GB / total {4}GB)'.format(
            self.device, self.mountpoint, self.fstype, self.avail_size() / 1024, self.total_size() / 1024
        )

    def _detect_io_speed(self):
        self.r_speed = None
        self.w_speed = None

        if not CmdUtil.doesBinExist('fio'):
            Project.log('There is no fio.')
            return

        fio_file = os.path.join(self.mountpoint, '/gs_perfconfig_fio_test.fiofile')
        cmd = f'fio -filename={fio_file} -re=write -size=500M -direct=1 -ioengine=sync | grep WRITE'
        try:
            Project.log('detect io speed by fio: ' + cmd)
            output = CmdUtil.execCmd(cmd)

            CmdUtil.execCmd(f'rm {fio_file} -fr')
            Project.log('remove fio file: ' + fio_file)

            nums = re.findall(r'\d+', output)
            if len(nums) < 1:
                return
            self.w_speed = int(nums[0])

        except Exception:
            Project.log('remove fio file: ' + fio_file)
            CmdUtil.execCmd(f'rm {fio_file} -fr')
            pass

class DiskInfo(Probe):
    def __init__(self):
        super(DiskInfo, self).__init__()
        self._devices = []
        self._index = 0

    def get(self, item):
        if isinstance(item, int):
            if item > len(self._devices):
                return
            return self._devices[item]
        elif isinstance(item, str):
            for device in self._devices:
                if device.device == item or device.mountpoint == item:
                    return device
            return
        else:
            return

    def __iter__(self):
        self._index = 0
        return self

    def __next__(self):
        if self._index >= len(self._devices):
            raise StopIteration
        value = self._devices[self._index]
        self._index += 1
        return value

    def __len__(self):
        return len(self._devices)

    def detect(self):
        self._devices = []
        partitions = DiskUtil.getMountInfo()

        for partition in partitions:
            device = DiskDeviceInfo(partition)
            device.detect()
            self._devices.append(device)
