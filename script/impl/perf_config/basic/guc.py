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
# Description  : A series of adjustment methods for guc.
#############################################################################


import os
import json
import shutil

from base_utils.os.cmd_util import CmdUtil
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.anti import AntiLog
from impl.perf_config.basic.tuner import Tuner, TunerGroup


class GucMap(object):
    """
    GucMap is a non-instantiated class. The class variable globalGucDict stores all
    registered GUC parameters and operates these GUC parameters through a series
    of static interfaces.
    """
    _globalGucDict = {}
    tunePlan = []

    def __init__(self):
        assert False, 'class GucMap is set only as a series of global interfaces package.'

    @staticmethod
    def set(name, value):
        GucMap._globalGucDict[name].set(value)

    @staticmethod
    def show(name):
        return GucMap._globalGucDict[name].value

    @staticmethod
    def register(name):
        """
        :param name: name of a guc
        :return: GUCTunePoint
        """
        assert GucMap._globalGucDict.get(name) is None, '{} is duplicate.'.format(name)
        guc = GUCTunePoint(name)
        GucMap._globalGucDict[name] = guc
        return guc


class GUCTunePoint(Tuner):
    """
    Components for adjusting individual GUCs.

    The guc parameters are adjusted on a group basis, rather than individually.
    So there are special modules to do the calculations.

    All we need to do here is provide an interface to receive the value and
    make the value effective.

    However, we do not need to provide a rollback method, because there is a
    better solution: save the postgresql.conf in advance, and restore it directly
    when we need to recover. see: GucRootTuner
    """
    def __init__(self, name):
        super(GUCTunePoint, self).__init__(name)
        self.name = name
        self.value = None

    def set(self, value):
        self.value = value

    def turn_off(self):
        self.value = 'off'

    def turn_on(self):
        self.value = 'on'

    def calculate(self):
        """
        no calculate function. guc tuner group will do this.
        :return:
        """
        assert False, '<GucTunePoint {0}> should not be here (calculate).'.format(self.name)

    def explain(self, apply=False):
        """
        not need alog.
        :return:
        """
        if self.value is None:
            return

        infos = Project.getGlobalPerfProbe()
        Project.report.record(f'- set guc {self.name} to {self.value}')
        if apply:
            cmd = """gs_guc set -D {0} -c "{1}='{2}'" """.format(
                infos.db.gauss_data, self.name, self.value)
            GucMap.tunePlan.append(cmd)
            Project.log('prepare guc set cmd: ' + cmd)

    @staticmethod
    def rollback(alog):
        """
        no rollback function. guc tuner group will do this.
        :return:
        """
        assert False, '<GucTunePoint> should not be here (rollback).'


class GUCTuneGroup(Tuner):
    """
    The guc parameters are adjusted on a group basis, rather than individually.

    We group the guc according to different modules and logic, and each group is a GUCTuneGroup.

    """
    def __init__(self):
        super(GUCTuneGroup, self).__init__()
        self._guc_list = []

    def bind(self, name):
        """
        bind a guc on this group.
        :param name: tuner or tuner group.
        :return: NA
        """
        guc = GucMap.register(name)
        self._guc_list.append(guc)
        return guc

    def explain(self, apply=False):
        """
        Iterate sub tuner and explain it in turn.
        :return: NA
        """
        for guc in self._guc_list:
            guc.explain(apply)


class GucRootTuner(TunerGroup):
    """
    Root node of the guc tuning logical tree. It's also an entry point for tune.

    GucRootTuner manages different GUCTuneGroup and different GUCTuneGroup manage different GucTunePoint.

    Anti log records here.
    We save postgresql.conf in advance and record the save location in anti log,
    then calculate and tune guc parameters normally. When we need to roll back, read the anti log,
    get the location of the postgresql.conf backup and restore the it directly.
    """
    def __init__(self):
        super(GucRootTuner, self).__init__()
        self.postgresql_conf = None
        self.postgresql_conf_bak = None
        self.omm = None
        self.omm_uid = None
        self.omm_gid = None
        self.tmp_script = None

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        self.postgresql_conf = os.path.join(infos.db.gauss_data, 'postgresql.conf')
        self.postgresql_conf_bak = os.path.join(Project.environ.workspace2 or Project.environ.workspace1,
                                                'postgresql.conf.bak')
        self.omm = infos.db.omm
        self.omm_uid = infos.db.omm_uid
        self.omm_gid = infos.db.omm_gid

        self.tmp_script = os.path.join(Project.environ.workspace2 or Project.environ.workspace1,
                                       'guc_tune_plan.sh')

        super(GucRootTuner, self).calculate()

    def explain(self, apply=False):
        """
        explain the tune logic. if apply, save postgresql.conf in advance and record the save
        location in anti log
        """
        super(GucRootTuner, self).explain(apply)

        if apply:
            infos = Project.getGlobalPerfProbe()
            shutil.copy2(self.postgresql_conf, self.postgresql_conf_bak)
            Project.role.chown_to_user(self.postgresql_conf_bak)

            alog = self._make_alog()
            AntiLog.write(self.__class__.__name__, alog)

            tmp_script_content = ''
            if Project.environ.env is not None:
                tmp_script_content += f'source {Project.environ.env} \n'
            tmp_script_content += '\n'.join(GucMap.tunePlan)
            with open(self.tmp_script, 'w') as f:
                f.write(tmp_script_content)
            Project.role.chown_to_user(self.tmp_script)

            cmd = f"sh {self.tmp_script}" if not Project.haveRootPrivilege() else \
                  f'su - {self.omm} -c "sh {self.tmp_script}"'
            Project.log('Tune guc by command:' + cmd)
            Project.log('tmp guc tune script content:\n' + tmp_script_content)
            output = CmdUtil.execCmd(cmd)
            Project.log('Output: ' + output)


    def _make_alog(self):
        alog = {
            'postgresql_conf': self.postgresql_conf,
            'postgresql_conf_bak': self.postgresql_conf_bak,
            'omm_uid': self.omm_uid,
            'omm_gid': self.omm_gid
        }
        return json.dumps(alog)

    @staticmethod
    def _parse_alog(alog):
        return json.loads(alog)

    @staticmethod
    def rollback(alog):
        content = GucRootTuner._parse_alog(alog)
        shutil.copy2(content['postgresql_conf_bak'], content['postgresql_conf'])
        Project.notice('rollback GUC. cp {0} {1}'.format(
            content['postgresql_conf_bak'], content['postgresql_conf'])
        )
        os.chown(content['postgresql_conf'], content['omm_uid'], content['omm_gid'])

