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
#############################################################################

import re


class SqlFile(object):
    @staticmethod
    def findErrorInSqlFile(sqlFile, output):
        """
        function : Find error in the sql file
        input : String,String
        output : String
        """
        GSQL_BIN_FILE = "gsql"
        # init flag
        ERROR_MSG_FLAG = "(ERROR|FATAL|PANIC)"
        GSQL_ERROR_PATTERN = "^%s:%s:(\d*): %s:.*" % (GSQL_BIN_FILE, sqlFile, ERROR_MSG_FLAG)
        pattern = re.compile(GSQL_ERROR_PATTERN)
        for line in output.split("\n"):
            line = line.strip()
            result = pattern.match(line)
            if result is not None:
                return True
        return False

    @staticmethod
    def findTupleErrorInSqlFile(output):
        """
        function : find tuple concurrently updated error in file
        input : sqlFile, output
        output : True, False
        """
        ERROR_TUPLE_PATTERN = "^gsql:(.*)tuple concurrently updated(.*)"
        pattern = re.compile(ERROR_TUPLE_PATTERN)
        for line in output.split("\n"):
            line = line.strip()
            result = pattern.match(line)
            if result is not None:
                return True
        return False
