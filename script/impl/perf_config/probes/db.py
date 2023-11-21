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
# Description  : gs_perfconfg is a utility to optimize system and database configure about openGauss
#############################################################################

import os
import pwd
from enum import Enum
from base_utils.os.cmd_util import CmdUtil
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe


class DBSeverMode(Enum):
    PRIMARY = 'primary'
    STANDBY = 'standby'


class DBInfo(Probe):
    def __init__(self):
        super(DBInfo, self).__init__()
        self.ip = None
        self.port = None
        self.omm = Project.role.user_name
        self.omm_uid = Project.role.user_uid
        self.omm_gid = Project.role.user_gid
        self.gauss_home = Project.environ.gauss_home
        self.gauss_data = Project.environ.gauss_data
        self.gauss_log = Project.environ.gauss_log
        self.postgresql_conf = os.path.join(self.gauss_data, 'postgresql.conf')

    def detect(self):
        self._detect_ip_port()

    def _detect_ip_port(self):
        listen_addresses = self._read_guc_in_postgresql_conf('listen_addresses')
        if listen_addresses is None:
            listen_addresses = '*'
        Project.log(f'detect database listen_addresses: {listen_addresses}')
        self.ip = [ip.strip() for ip in listen_addresses.split(',')]

        port = self._read_guc_in_postgresql_conf('port')
        if port is None:
            port = 5432
        Project.log(f'detect database port: {port}')
        self.port = port

    def _read_guc_in_postgresql_conf(self, guc):
        cmd = f'grep "{guc}" {self.postgresql_conf} -i'
        output = CmdUtil.execCmd(cmd, noexcept=True)
        if output == '':
            return
        res = None
        lines = output.split('\n')
        for line in lines:
            if line.strip().startswith('#'):
                continue
            if not line.lower().strip().startswith(guc.lower()):
                continue
            val = line.split('=')[1].strip()
            val = val.split('#')[0].strip()
            if val.startswith("'") or val.startswith('"'):
                val = val[1:-1]
            res = val
        return res



