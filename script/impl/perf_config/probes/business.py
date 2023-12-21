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
from enum import Enum
from base_utils.common.dialog import DialogUtil
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe
from impl.perf_config.preset.preset import Preset

"""
The business module is mainly used to investigate the user's business related information.

The business content will be investigated in the form of questions and answers.

You can also select a preset and read the configuration in it.
"""

class BsScenario(Enum):
    TP_PRODUCE = 0
    TP_PERFORMANCE = 1
    AP = 2                      # just beta or demo

    @staticmethod
    def isOLTPScenario(scenario):
        return scenario in [BsScenario.TP_PERFORMANCE, BsScenario.TP_PRODUCE]


class TblKind(Enum):
    COMMON_TBL = 0              # common heap table
    PARTITION_TBL = 1           # common heap partition table
    COLUMN_TBL = 2              # column table
    PART_COLUMN_TBL = 3         # column partition table

    @staticmethod
    def isCommonTbl(kind):
        return kind in [TblKind.COMMON_TBL]

    @staticmethod
    def isPartTbl(kind):
        return kind in [TblKind.PARTITION_TBL, TblKind.PART_COLUMN_TBL]

    @staticmethod
    def havePartTbl(kinds):
        for kind in kinds:
            if TblKind.isPartTbl(kind):
                return True
        return False

    @staticmethod
    def isColumnTbl(kind):
        return kind in [TblKind.COLUMN_TBL, TblKind.PART_COLUMN_TBL]

    @staticmethod
    def haveColumnTbl(kinds):
        for kind in kinds:
            if TblKind.isColumnTbl(kind):
                return True
        return False


class BusinessProbe(Probe):
    def __init__(self):
        super(BusinessProbe, self).__init__()
        self._preset = None

        self.scenario = BsScenario.TP_PRODUCE
        self.parallel = 200
        self.rel_count = 50
        self.rel_kind = [TblKind.COMMON_TBL, TblKind.PARTITION_TBL]
        self.part_count = 100
        self.index_count = 100
        self.data_size = 200 * 1024  # unit is MB
        self.isolated_xlog = None

    def __str__(self):
        return str({
            '_preset': self._preset,
            'scenario': self.scenario,
            'parallel': self.parallel,
            'rel_count': self.rel_count,
            'rel_kind': self.rel_kind,
            'part_count': self.part_count,
            'index_count': self.index_count,
            'data_size': self.data_size,
            'isolated_xlog': self.isolated_xlog
        })

    def relfilenode_count(self):
        """
        Estimate the number of relfilenodes.
        """
        rel_count = self.rel_count if self.rel_count is not None else 0
        part_count = self.part_count if self.part_count is not None else 0
        index_count = self.index_count if self.index_count is not None else 0
        return (rel_count + part_count + index_count) * 4

    def detect(self):
        """
        detect the user business by some research questions.
        """
        msg = 'Now we need to do some research to understand your business scenario.\n' \
              'Fields marked with "*" are required.'
        Project.msg(msg)

        question = 'What kind of way to choose？'
        options = [
            'Default case',
            'Preset',
            'Customization'
        ]
        check = DialogUtil.singleAnswerQuestion(question, options)
        Project.log('user choose: ' + options[check])

        if check == 0:
            self._load_preset('default')
        elif check == 1:
            self._load_preset()

        self._do_detect()

        Project.log('business detect res:' + self.__str__())

    def _load_preset(self, preset_name=None):
        if preset_name is None:
            question = 'Please select the desired preset.'
            builtins, usersets = Preset.get_all_presets()
            presets = builtins + usersets

            check = DialogUtil.singleAnswerQuestion(question, presets)
            preset_name = presets[check]

            Project.log('business detect research\nquestion: {0}\nanwser: {1}'.format(question, preset_name))

        self._preset = Preset(preset_name)

    def _do_detect(self):
        """
        do detect action. If we had load preset, just read it, otherwise do research.

        Pay attention to the order of detection, some different detection items are
        associated with each other. For example:
            - whether a partition table is used?
            - how many partitions you have.
            If you are not using a partition table, you do not need to survey the
            number of partitions.
        """

        self._detect_scenario()
        self._detect_parallel()
        self._detect_rel_count()
        self._detect_rel_kind()

        if TblKind.havePartTbl(self.rel_kind):
            self._detect_partition_count()
        else:
            self.part_count = 0

        self._detect_index_count()
        self._detect_data_size()
        self._detect_isolated_xlog()

    ###############
    # Below are survey questions or preset-load-functions for each option.
    ###############
    # load or research scenario
    def _load_scenario(self):
        scenario = self._preset['scenario']
        if scenario is None:
            pass
        elif scenario == 'OLTP-produce':
            self.scenario = BsScenario.TP_PRODUCE
        elif scenario == 'OLTP-performance':
            self.scenario = BsScenario.TP_PERFORMANCE
        else:
            assert False

    def _detect_scenario(self):
        if self._preset is not None:
            self._load_scenario()
            return

        question = 'What are the main scenarios for using databases?'
        options = [
            'OLTP performance first',
            'OLTP produce first',
        ]
        answer = [
            BsScenario.TP_PERFORMANCE,
            BsScenario.TP_PRODUCE
        ]
        check = DialogUtil.singleAnswerQuestion(question, options)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, options[check]))
        self.scenario = answer[check]

    # load or research parallel
    def _load_parallel(self):
        parallel = self._preset['parallel']
        self.parallel = parallel if parallel is not None else self.parallel

    def _detect_parallel(self):
        if self._preset is not None:
            self._load_parallel()
            return

        question = 'What is the average number of concurrent transactions?'
        num = DialogUtil.askANumber(question, lambda x:'Invalid number, please more than 0.' if x < 0 else None)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, num))
        self.parallel = num

    # load or research rel_count
    def _load_rel_count(self):
        rel_count = self._preset['rel_count']
        self.rel_count = rel_count if rel_count is not None else self.rel_count

    def _detect_rel_count(self):
        if self._preset is not None:
            self._load_rel_count()
            return

        question = 'Approximately how many tables you have?'
        num = DialogUtil.askANumber(question, lambda x:'Invalid number, please more than 0.' if x < 0 else None)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, num))
        self.rel_count = num

    # load or research rel_kind
    def _load_rel_kind(self):
        rel_kind = self._preset['rel_kind']
        if rel_kind is None:
            pass
        else:
            options = ['heap-table', 'partition-table', 'column-table', 'column-partition-table']
            checks = [False, False, False, False]
            res = [TblKind.COMMON_TBL, TblKind.PARTITION_TBL, TblKind.COLUMN_TBL, TblKind.PART_COLUMN_TBL]
            for kind in rel_kind:
                assert kind in options
                checks[options.index(kind)] = True
            self.rel_kind = [res[i] for i in range(0,4) if checks[i]]

    def _detect_rel_kind(self):
        if self._preset is not None:
            self._load_rel_kind()
            return

        question = 'What kind of table you used?'
        options = [
            'common heap table',
            'partition heap table',
            'column table',
            'partition column table'
        ]
        answer = [
            TblKind.COMMON_TBL,
            TblKind.PARTITION_TBL,
            TblKind.COLUMN_TBL,
            TblKind.PART_COLUMN_TBL
        ]

        checks = DialogUtil.multipleAnswerQuestion(question, options)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(
            question,
            str([options[check] for check in checks]))
        )
        self.rel_kind = [answer[check] for check in checks]

    # load or research part_count
    def _load_part_count(self):
        part_count = self._preset['part_count']
        self.part_count = part_count if part_count is not None else self.part_count

    def _detect_partition_count(self):
        if self._preset is not None:
            self._load_part_count()
            return

        question = 'Approximately how many partitions you have?'
        num = DialogUtil.askANumber(question, lambda x:'Invalid number, please more than 0.' if x < 0 else None)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, num))
        self.part_count = num

    # load or research index_count
    def _load_index_count(self):
        index_count = self._preset['index_count']
        self.index_count = index_count if index_count is not None else self.index_count

    def _detect_index_count(self):
        if self._preset is not None:
            self._load_index_count()
            return

        question = 'Approximately how many index you have?'
        num = DialogUtil.askANumber(question, lambda x:'Invalid number, please more than 0.' if x < 0 else None)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, num))
        self.index_count = num

    def _load_data_size(self):
        data_size = self._preset['data_size']
        self.data_size = data_size if data_size is not None else self.data_size

    def _detect_data_size(self):
        if self._preset is not None:
            self._load_data_size()
            return

        question = 'How much data is there, unit by MB?'
        num = DialogUtil.askANumber(question, lambda x:'Invalid number, please more than 0.' if x < 0 else None)
        Project.log('business detect research\nquestion:{0}\nanwser:{1}'.format(question, num))
        self.data_size = num

    def _load_isolated_xlog(self):
        isolated_xlog = self._preset['isolated_xlog']
        if isolated_xlog is None:
            self.isolated_xlog = None
            return

        if  not os.access(isolated_xlog, os.F_OK) or not os.path.isdir(isolated_xlog):
            Project.warning('Could not access ' + isolated_xlog + ' or it is not a dir.')
            self.isolated_xlog = None
            return

        self.isolated_xlog = isolated_xlog

    def _detect_isolated_xlog(self):
        if self._preset is not None:
            self._load_isolated_xlog()
            return

        question = 'Storing wal on a separate disk helps improve performance. Do you need to move them?\n' \
                   'Here is some disk information:\n'
        infos = Project.getGlobalPerfProbe()
        for device in infos.disk:
            question += f'  {device.simple_info()}\n'

        path = DialogUtil.askAPath(question, check_access=True, required=False)
        self.isolated_xlog = path


