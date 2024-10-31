#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
# Description  : Constants.py is a constant tool
#############################################################################
import os
import sys

local_dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(local_dir_path + "/../../")
from base_utils.common.constantsbase import ConstantsBase


class Constants(ConstantsBase):
    """common constants"""

    def __init__(self):
        pass

    __slots__ = ()

    _pid = os.getpid()
    SSH_PROTECT_PATH = "~/gaussdb_tmp/ssh_protect"
    TMP_HOSTS_FILE = "/tmp/tmp_hosts_%d"
    TMP_SSH_FILE = "/tmp/tmp_ssh_%d" % _pid
