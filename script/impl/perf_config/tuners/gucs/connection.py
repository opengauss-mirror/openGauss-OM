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

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.tuner import Tuner, TunerGroup
from impl.perf_config.basic.guc import GucMap, GUCTuneGroup


class ConnectionGUC(GUCTuneGroup):
    def __init__(self):
        super(ConnectionGUC, self).__init__()
        self.light_comm = self.bind('light_comm')
        self.listen_addresses = self.bind('listen_addresses')
        self.local_bind_address = self.bind('local_bind_address')
        self.port = self.bind('port')
        self.max_connections = self.bind('max_connections')
        self.max_inner_tool_connections = self.bind('max_inner_tool_connections')
        self.sysadmin_reserved_connections = self.bind('sysadmin_reserved_connections')
        self.unix_socket_directory = self.bind('unix_socket_directory')
        self.unix_socket_group = self.bind('unix_socket_group')
        self.unix_socket_permissions = self.bind('unix_socket_permissions')
        self.application_name = self.bind('application_name')
        self.connection_info = self.bind('connection_info')
        self.enable_dolphin_proto = self.bind('enable_dolphin_proto')
        self.dolphin_server_port = self.bind('dolphin_server_port')
        self.tcp_keepalives_idle = self.bind('tcp_keepalives_idle')
        self.tcp_keepalives_interval = self.bind('tcp_keepalives_interval')
        self.tcp_keepalives_count = self.bind('tcp_keepalives_count')
        self.tcp_user_timeout = self.bind('tcp_user_timeout')
        self.comm_proxy_attr = self.bind('comm_proxy_attr')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        self.light_comm.set('on')

        max_connections = int(infos.business.parallel) * 4
        self.max_connections.set(str(max_connections))


class PoolerGUC(GUCTuneGroup):
    def __init__(self):
        super(PoolerGUC, self).__init__()
        self.pooler_maximum_idle_time = self.bind('pooler_maximum_idle_time')
        self.minimum_pool_size = self.bind('minimum_pool_size')
        self.cache_connection = self.bind('cache_connection')

    def calculate(self):
        pass

