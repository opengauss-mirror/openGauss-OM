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
# Description  : preset management. Including reading and resolving preset.
#############################################################################

import os
import re
import json
from enum import Enum
from impl.perf_config.basic.project import Project

"""
preset is a set of information about some business attributes. 
By writing a preset file, the preset configuration can be directly read during
the tool running, thus skipping the stage of business investigation.

preset contains Preset information about the service survey, and the configuration
parameters are related to the service survey. 

The preset file is actually a json file. This section describes how to set 
configuration items in key-value pairs.
In json, you can write in strings. However, different parameters have different 
parsing schemes, such as enumeration, ordinary string, etc., and some parsing rules
are needed to parse and determine whether the preset file is valid.

The built-in preset is stored in the tool code directory. 
Also, preset written by the user can be stored in the $GAUSSLOG/om/pg_perfconfig/preset. 
The difference between the two is that built-in files are automatically replaced when
the database is upgrade.

The preset name is a file name and needs to end with '.json'. 
If files with the same name exist in two directories, the internal directory takes 
precedence.
"""

class PsOptionType(Enum):
    INT = 'integer'
    STR = 'string'
    ENUM_VALUE = 'enum value'
    ENUM_LIST = 'list of enum'
    PATH = 'path'

class PsOptionRule(object):
    @staticmethod
    def transformIntValue(value, check_range):
        """
        transform an int value.
        :param value: origin value.
        :param check_range: function to check range. return T/F.
        :return: NA
        """
        if type(value) != int:
            value = int(value)

        if check_range is not None and not check_range(value):
            raise ValueError(f'value {value} not in range.')

        return value

    @staticmethod
    def transformStrValue(value, check_range):
        """
        transform a string value.
        :param value: origin value.
        :param check_range: function to check range. return T/F.
        :return: NA
        """
        if type(value) != str:
            value = str(value)

        if check_range is not None and not check_range(value):
            raise ValueError(f'value {value} not in range.')

        return value

    @staticmethod
    def transformEnumValue(value, value_list):
        """
        transform an enum value.
        :param value: origin value.
        :param value_list: enumrate list.
        :return: NA
        """
        if type(value) != str:
            value = str(value)

        value = value.strip()
        if value not in value_list:
            raise ValueError(f'value {value} not in range.')

        return value

    @staticmethod
    def transformEnumValueList(value, value_list):
        """
        transform an enum value list.
        :param value: origin value. The value can be a string separated
                      by commas or Spaces. It also could be a list.
        :param value_list: enumrate list.
        :return: NA
        """
        opts = value if type(value) == list else re.split(r'[, ]+', str(value))
        res = set()

        for opt in opts:
            if opt not in value_list:
                raise ValueError(f'option {opt} not in range.')
            res.add(opt)

        return list(res)

    @staticmethod
    def transformPath(value, check_exist):
        """
        transform a path.
        :param value: origin value.
        :param check_exist: Checks whether the path exists and is accessible.
        :return: NA
        """
        path = value if type(value) == str else str(value)
        if check_exist and not os.path.access(path, os.F_OK):
            raise ValueError(f'Could not access path Option path {path}.')
        return path

    def __init__(self, desc, option_type, default, range_info):
        self.desc = desc
        self.option_type = option_type
        self.default = default
        self.range_info = range_info

    def regulate(self, value):
        if value is None:
            return self.default
        try:
            if self.option_type == PsOptionType.INT:
                return PsOptionRule.transformIntValue(value, self.range_info)
            if self.option_type == PsOptionType.STR:
                return PsOptionRule.transformStrValue(value, self.range_info)
            elif self.option_type == PsOptionType.ENUM_VALUE:
                return PsOptionRule.transformEnumValue(value, self.range_info)
            elif self.option_type == PsOptionType.ENUM_LIST:
                return PsOptionRule.transformEnumValueList(value, self.range_info)
            elif self.option_type == PsOptionType.PATH:
                return PsOptionRule.transformPath(value, self.range_info)
            else:
                assert False
        except ValueError as e:
            Project.fatal('Preset error, ' + str(e))


class Preset(object):

    # options list.
    options = {
        'desc': PsOptionRule(
            'The description of preset',
            PsOptionType.STR,
            'no description',
            None
        ),
        'scenario': PsOptionRule(
            'Business scenario.',
            PsOptionType.ENUM_VALUE,
            'OLTP-performance',
            ['OLTP-produce', 'OLTP-performance']
        ),
        'rel_count': PsOptionRule(
            'How many tables do you have?',
            PsOptionType.INT,
            300,
            lambda x:x > 0
        ),
        'index_count': PsOptionRule(
            'How many indexs do you have?',
            PsOptionType.INT,
            600,
            lambda x:x > 0
        ),
        'rel_kind': PsOptionRule(
            'What kind of table do you used?',
            PsOptionType.ENUM_LIST,
            ['heap-table', 'partition-table'],
            ['heap-table', 'partition-table', 'column-table', 'column-partition-table']
        ),
        'part_count': PsOptionRule(
            'How many partitions do you have?',
            PsOptionType.INT,
            200,
            lambda x:x > 0
        ),
        'data_size': PsOptionRule(
            'How much data is there? unit is MB.',
            PsOptionType.INT,
            8192,
            lambda x:x > 0
        ),
        'parallel': PsOptionRule(
            'How much concurrency is there?',
            PsOptionType.INT,
            400,
            lambda x:x > 0
        ),
        'isolated_xlog': PsOptionRule(
            'Storing wal on a separate disk.',
            PsOptionType.PATH,
            None,
            True
        )
    }

    @staticmethod
    def usage():
        """
        how to write preset.
        """
        res = 'The preset configure is a file in JSON format that contains the following parameters:\n\n'
        for opt in Preset.options:
            res += f'Name: {opt}\n'
            res += f' Description: {Preset.options[opt].desc}\n'
            res += f' Type: {Preset.options[opt].option_type.value}\n'
            if Preset.options[opt].option_type in [PsOptionType.ENUM_VALUE, PsOptionType.ENUM_LIST]:
                res += f' Range: {str(Preset.options[opt].range_info)}\n'
            res += '\n'
        return res

    @staticmethod
    def get_preset_dir():
        dir1 = os.path.join(Project.environ.workspace1, 'preset')
        dir2 = os.path.join(Project.environ.workspace2, 'preset')
        return dir1, dir2

    @staticmethod
    def get_all_presets():
        def _read_preset_dir(_dir):
            """
            read all '.json' file in _dir.
            """
            if _dir is None:
                return []

            if not os.access(_dir, os.F_OK):
                Project.warning('Could not access ' + _dir)
                return []

            files = os.listdir(_dir)
            res = []
            for file in files:
                if file.endswith('.json'):
                    res.append(file[:-5])
            return res

        dir1, dir2 = Preset.get_preset_dir()

        builtins = _read_preset_dir(dir1)
        tmp_usersets = _read_preset_dir(dir2)
        # when duplicate name, builtin first.
        usersets = [x for x in tmp_usersets if x not in builtins]

        return builtins, usersets

    def __init__(self, preset_name):
        builtins, usersets = Preset.get_all_presets()
        dir1, dir2 = Preset.get_preset_dir()
        file = ''

        if preset_name in builtins:
            file = os.path.join(dir1, f'{preset_name}.json')
        elif preset_name in usersets:
            file = os.path.join(dir2, f'{preset_name}.json')
        else:
            Project.fatal('Could not find preset: ' + preset_name)

        self.name = preset_name
        with open(file, 'r') as f:
            config = json.load(f)
            for key in config:
                if not self.options.__contains__(key):
                    Project.warning(f'skip unknown option {key} in preset.')

        self.content = {}
        for key in self.options:
            val = config.get(key)
            self.content[key] = self.options[key].regulate(val)

    def __str__(self):
        res = f'Preset name: {self.name}\n'
        desc = self.content.get('desc')
        res += '  {}\n'.format(desc if desc is not None else 'no description')
        res += 'Detail:\n'
        for k in self.content:
            if k == 'desc':
                continue
            res += '    {0}: {1}\n'.format(k, self.content[k])

        return res

    def __getitem__(self, item):
        return self.content.get(item)
