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
# Description  : gs_upgradechk is a utility to check meta data in gaussdb after upgrade.
#############################################################################

"""
User define Exceptions
"""

class ParamParseException(Exception):
    """
    Exception when parse params
    """
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg

class ShellExecException(Exception):
    """
    Exception when execute a shell command
    """
    def __init__(self, cmd, stat, msg):
        self.cmd = cmd
        self.msg = msg
        self.stat = stat

    def __str__(self):
        return 'Command Execute Failed with err code {0}. \ncmd:\n{1}\nreason:\n{2}'.format(
            self.stat,
            self.cmd,
            self.msg
        )
