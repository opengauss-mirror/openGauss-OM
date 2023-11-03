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
# Description  : Provides a series of methods for parsing 'dmidecode'.
#############################################################################


import subprocess
from enum import Enum
from base_utils.os.cmd_util import CmdUtil
from gspylib.common.ErrorCode import ErrorCode


class DMIType(Enum):
    BIOS = 0
    SYSTEM = 1
    BASEBOARD = 2
    CHASSIS = 3
    PROCESSOR = 4
    MEMORY_CONTROLLER = 5
    MEMORY_MODULE = 6
    CACHE = 7
    PORT_CONNECTOR = 8
    SYSTEM_SLOTS = 9
    ON_BOARD_DEVICES = 10
    OEM_STRINGS = 11
    SYSTEM_CONFIGURATION_OPTIONS = 12
    BIOS_LANGUAGE = 13
    GROUP_ASSOCIATIONS = 14
    SYSTEM_EVENT_LOG = 15
    PHYSICAL_MEMORY_ARRAY = 16
    MEMORY_DEVICE = 17
    BIT_MEMORY_ERROR_32_BIT = 18
    MEMORY_ARRAY_MAPPED_ADDRESS = 19
    MEMORY_DEVICE_MAPPED_ADDRESS = 20
    BUILT_IN_POINTING_DEVICE = 21
    PORTABLE_BATTERY = 22
    SYSTEM_RESET = 23
    HARDWARE_SECURITY = 24
    SYSTEM_POWER_CONTROLS = 25
    VOLTAGE_PROBE = 26
    COOLING_DEVICE = 27
    TEMPERATURE_PROBE = 28
    ELECTRICAL_CURRENT_PROBE = 29
    OUT_OF_BAND_REMOTE_ACCESS = 30
    BOOT_INTEGRITY_SERVICES = 31
    SYSTEM_BOOT = 32
    MEMORY_ERROR_64_BIT = 33
    MANAGEMENT_DEVICE = 34
    MANAGEMENT_DEVICE_COMPONENT = 35
    MANAGEMENT_DEVICE_THRESHOLD_DATA = 36
    MEMORY_CHANNEL = 37
    IPMI_DEVICE = 38
    POWER_SUPPLY = 39
    ADDITIONAL_INFORMATION = 40
    ONBOARD_DEVICES_EXTENDED_INFORMATION = 41
    MANAGEMENT_CONTROLLER_HOST_INTERFACE = 42


class DMITypeCategory(Enum):
    BIOS = 'bios'
    SYSTEM = 'system'
    BASEBOARD = 'baseboard'
    CHASSIS = 'chassis'
    PROCESSOR = 'processor'
    MEMORY = 'memory'
    CACHE = 'cache'
    CONNECTOR = 'connector'
    SLOT = 'slot'


class DMIDevice(object):
    def __init__(self, src):
        self.src = src
        self.handle = 'Unknown'
        self.dmi_type = 'Unknown'
        self.name = 'Unknown'
        self.title = 'Unknown'
        self.attrs = {}
        self._key = None

        self._parse()

    def __str__(self):
        return self.src

    def __getitem__(self, item):
        return self.attrs.get(item)

    def _parse(self):
        def _get_level(_line):
            if _line.strip() == '':
                return -1
            _level = 0
            for i in range(0, len(_line)):
                if _line[i] == '\t':
                    _level += 1
                else:
                    break
            return _level

        lines = self.src.split('\n')
        for line in lines:
            level = _get_level(line)
            if level == -1:
                continue
            elif level == 1:
                self._parseAttr(line)
            elif level == 2:
                self._appendAttrVal(line)
            elif line.startswith('Handle'):
                self._parseHandle(line)
            elif line.find('Information'):
                self._parseTitle(line)
            elif line.find('Table at') or line.find('End Of Table'):
                pass
            else:
                print('ERROR, UNKNOWN DMIDECODE INFO:', line)
                assert False

    def _parseHandle(self, line):
        # Handle 0x0401, DMI type 4, 48 bytes
        assert line.startswith('Handle')
        parts = line[:-1].split(',')
        self.handle = parts[0].split(' ')[1]
        self.dmi_type = parts[1].split(' ')[2]

    def _parseTitle(self, line):
        self.title = line
        self.name = line[:-11]

    def _parseAttr(self, line):
        parts = line.split(':')
        key = parts[0].strip()
        value = ':'.join(parts[1:]).strip()
        self.attrs[key] = value
        self._key = key

    def _appendAttrVal(self, line):
        if not isinstance(self.attrs[self._key], list):
            self.attrs[self._key] = []
        self.attrs[self._key].append(line.strip())


class DmiDecodeTable(object):
    def __init__(self, src):
        self.src = src
        self.version = None
        self.devices = []
        self._iter = 0

        self._parse()

    def __iter__(self):
        self._idx = 0
        return self

    def __next__(self):
        if self._iter >= len(self.devices):
            self._iter = 0
            raise StopIteration
        res = self.devices[self._iter]
        self._iter += 1
        return res

    def _parse(self):
        lines = self.src.split('\n')

        is_first_part = True
        tmp = ''
        for line in lines:
            if line.strip() == '':
                if is_first_part:
                    is_first_part = False
                    pass  # ignore parse version
                else:
                    self.devices.append(DMIDevice(tmp))
                tmp = ''
                continue
            tmp += (line + '\n')

    def __str__(self):
        return self.src


class DmidecodeUtil(object):

    @staticmethod
    def getDmidecodeTableByType(dmitype=None):
        """
        execute dmidecode [-t type] and get the parsed result: DmiDecodeTable.
        :param dmitype: dmi type. None | int | str | DMIType | DMITypeCategory
        :return: DmiDecodeTable
        """
        if dmitype is None:
            cmd = CmdUtil.getDmidecodeCmd()
        elif isinstance(dmitype, DMIType) or isinstance(dmitype, DMITypeCategory):
            cmd = f'{CmdUtil.getDmidecodeCmd()} -t {dmitype.value} '
        elif isinstance(dmitype, int) or isinstance(dmitype, str):
            cmd = f'{CmdUtil.getDmidecodeCmd()} -t {dmitype} '
        else:
            assert False

        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % str(output))

        return DmiDecodeTable(output)

    @staticmethod
    def getDmidecodeTable():
        """
        execute dmidecode and get the parsed result: DmiDecodeTable.
        :return: DmiDecodeTable
        """
        return DmidecodeUtil.getDmidecodeTableByType()

    @staticmethod
    def getDmidecodeVersion():
        """
        execute dmidecode --version and get the result.
        :return: dmidecode --version
        """
        cmd = f'{CmdUtil.getDmidecodeCmd()} --version'
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % str(output))
        return output


if __name__ == '__main__':
    dmidecode = DmidecodeUtil.getDmidecodeTable()
    for item in dmidecode:
        print(item)
