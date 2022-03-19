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
# Description  : sql_result.py is a utility to store search result from database
#############################################################################
import os
import re
import sys
from ctypes import cdll, c_void_p, c_int, c_char_p, string_at

sys.path.append(sys.path[0] + "/../../")
from base_utils.os.env_util import EnvUtil


class SqlResult(object):
    """
    Class for storing search result from database
    """

    def __init__(self, result):
        """
        Constructor
        """
        self.resCount = 0
        self.resSet = []
        self.result = result

    def parseResult(self):
        """
        function : get resCount and resSet from result
        input:NA
        output:NA
        """
        libpath = os.path.join(EnvUtil.getEnv("GAUSSHOME"), "lib")
        sys.path.append(libpath)
        libc = cdll.LoadLibrary("libpq.so.5.5")
        libc.PQntuples.argtypes = [c_void_p]
        libc.PQntuples.restype = c_int
        libc.PQnfields.argtypes = [c_void_p]
        libc.PQnfields.restype = c_int
        libc.PQgetvalue.restype = c_char_p
        ntups = libc.PQntuples(self.result)
        nfields = libc.PQnfields(self.result)
        libc.PQgetvalue.argtypes = [c_void_p, c_int, c_int]
        self.resCount = ntups
        for i_index in range(ntups):
            tmp_string = []
            for j_index in range(nfields):
                paramValue = libc.PQgetvalue(self.result, i_index, j_index)
                if paramValue is not None:
                    tmp_string.append(string_at(paramValue))
                else:
                    tmp_string.append("")
            self.resSet.append(tmp_string)

    @staticmethod
    def findErrorInSql(output):
        """
        function : Find error in sql
        input : String
        output : boolean
        """
        # init flag
        ERROR_MSG_FLAG = "(ERROR|FATAL|PANIC)"
        ERROR_PATTERN = "^%s:.*" % ERROR_MSG_FLAG
        pattern = re.compile(ERROR_PATTERN)

        for line in output.split("\n"):
            line = line.strip()
            result = pattern.match(line)
            if result is not None:
                return True
        return False
