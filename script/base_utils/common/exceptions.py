#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
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
# Description  :
#############################################################################


# ------------------cmd util----------------------
class CommandNotFoundException(Exception):
    """
    """

    def __init__(self, cmd, paths):
        """
        function: constructor
        """
        self.cmd = cmd
        self.paths = paths

    def __str__(self):
        """
        function: str
        input  : NA
        output : str
        """
        return "Could not locate command: '%s' in this set of paths: %s" \
               % (self.cmd, repr(self.paths))
