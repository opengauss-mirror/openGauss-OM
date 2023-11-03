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
# Description  : Provides the abstract logic of the Tuner.
#############################################################################


import os
import sys
import json
from base_utils.os.cmd_util import CmdUtil
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.anti import AntiLog


class Tuner(object):
    """
    This is the basic class of tuner.
    """

    def __init__(self, tuner_name=''):
        assert not Project.getTask().tune_target.apply() or AntiLog.init_done, \
            'Must AntiLog.initAntiLog() first when apply is True.'
        assert Project.getGlobalPerfProbe() is not None, 'Must Project.setGlobalPerfProbe() first.'

        Project.log('Tuner construct <Class {0}> {1}'.format(self.__class__.__name__, tuner_name))

        self.tuner_name = tuner_name

    def calculate(self):
        """
        calculate the tune point
        :return:
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'.format(self.__class__.__name__, self.tuner_name)

    def explain(self, apply=False):
        """
        explain the tune points, generate a tune report. 
        If apply is True, we will really do the tune and write anti log.
        In addition, in this interface, you need to pay attention to the following:
            1. Implement the '_make_report' interface in advance and invoke the interface to
               generate a report.
            2. Record the content in logs.
            3. If the tune point is applied, record the anti log.
        :param apply:
        :return:
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'.format(self.__class__.__name__, self.tuner_name)

    def _make_report(self):
        """
        make a tune report.
        Called by self.explain(), the report content will be writed into project-report.
        :return: str
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'.format(self.__class__.__name__, self.tuner_name)

    def _make_alog(self):
        """
        make an anti log
        Called by self.explain(), the anti log content will be writed into AntiLog.
        :return: str
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'.format(self.__class__.__name__, self.tuner_name)

    @staticmethod
    def _parse_alog(alog):
        """
        parse an anti log, get information for rollback.
        Called by staticmethod rollback()
        :param alog: alog str
        :return: any data
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'

    @staticmethod
    def rollback(alog):
        """
        when exception or recover, rollback the tune point already be applied.
        :param alog:
        :return:
        """
        assert False, 'Incomplete function: <{0} {1}>.calculate().'


class ShellTunePoint(Tuner):
    """
    This is a common tune class for execute shell.
    """

    def __init__(self, cmd, anti, desc=''):
        """
        :param cmd: sh command
        :param anti: anti-command, to roll back the tune point
        :param desc: description
        """
        super(ShellTunePoint, self).__init__('command:' + cmd)
        self.cmd = cmd
        self.anti = anti
        self.desc = desc

    def __str__(self):
        return '<ShellTunePoint> {0}: {1}'.format(
            self.__class__.__name__, self._make_alog())

    def calculate(self):
        """
        ShellTunePoint does not need calculate.
        :return:
        """
        assert False

    def explain(self, apply=False):
        """
        :return:
        """
        Project.log('{0} {1}'.format('Apply' if apply else 'Explain', self.__str__()))
        if apply:
            AntiLog.write(self.__class__.__name__, self._make_alog())
            output = CmdUtil.execCmd(self.cmd)
            Project.log('Output: ' + output)

        Project.report.record(self._make_report())

    def _make_report(self):
        """
        make a tune report
        :return: str
        """
        report = '**shell tune point** \n' + \
                 '{}. \n'.format(self.desc) + \
                 'command: `{}`'.format(self.cmd)
        return report

    def _make_alog(self):
        """
        make an anti log.
        Use json format to record the relevant content.
        :return: json str
        """
        alog = {
            'cmd': self.cmd,
            'anti': self.anti,
            'desc': self.desc
        }
        return json.dumps(alog)

    @staticmethod
    def _parse_alog(alog):
        """
        parse an anti log.
        :return: dict
        """
        return json.loads(alog)

    @staticmethod
    def rollback(alog):
        commands = ShellTunePoint._parse_alog(alog)
        Project.notice('Rollback: ' + commands['anti'])
        output = CmdUtil.execCmd(commands['anti'])
        Project.log('Output: ' + output)


class TunerGroup(Tuner):
    """
    Indicates a tune group.

    Tuner is usually used to adjust a single point, but adjustments for a class of modules
    are often many points. Using a tuner group, you can manage multiple Tuners. The Tuners
    in the same group belong to the same module or level.

    Tuner group can also manage Tuner group, to form a tree of tune logic.

    Tune group only plays an administrative role and does not carry out actual adjustments,
    so it does not need to implement interfaces about alog, report, rollback and so on.
    """
    def __init__(self, tuner_name=''):
        super(TunerGroup, self).__init__(tuner_name)
        self._sub_tuner_groups = []

    def add(self, sub_tuner):
        """
        register a tuner or tuner group.
        :param sub_tuner: tuner or tuner group.
        :return: NA
        """
        self._sub_tuner_groups.append(sub_tuner)
        return sub_tuner

    def calculate(self):
        """
        Iterate sub tuner and calculate it in turn.
        :return: NA
        """
        for sub_tuner_group in self._sub_tuner_groups:
            sub_tuner_group.calculate()

    def explain(self, apply=False):
        """
        Iterate sub tuner and explain it in turn.
        :return: NA
        """
        for sub_tuner_group in self._sub_tuner_groups:
            sub_tuner_group.explain(apply)

