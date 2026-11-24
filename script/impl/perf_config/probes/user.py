#!/usr/bin/env python3
# Copyright (c) 2023 Huawei Technologies Co., Ltd.
# openGauss-OM is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import os
import getpass
from impl.perf_config.basic.project import Project
from impl.perf_config.basic.probe import Probe


class UserInfo(Probe):
    """
    Information about omm
    """
    def __init__(self):
        self.name = None
        self.uid = None
        self.gid = None

    def detect(self):
        self.name = Project.role.user_name
        self.uid = Project.role.user_uid
        self.gid = Project.role.user_gid
