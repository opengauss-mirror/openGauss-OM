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
import json
import os
import sys
from ctypes import cdll, c_char_p, c_void_p, c_int, string_at

from gspylib.common.ErrorCode import ErrorCode
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.sql_handler.sql_result import SqlResult

localDirPath = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, localDirPath + "/../../../lib")

from base_utils.executor.local_remote_cmd import LocalRemoteCmd
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.env_util import EnvUtil

class SqlExecutor(object):
    """
    exceute sql commands
    """
    @staticmethod
    def excuteSqlOnLocalhost(port, sql, database="postgres"):
        '''
        function: write output message
        input : sql
        output: NA
        '''
        tmpresult = None
        conn = None
        try:
            libpath = os.path.join(EnvUtil.getEnv("GAUSSHOME"), "lib")
            sys.path.append(libpath)
            libc = cdll.LoadLibrary("libpq.so.5.5")
            conn_opts = "dbname = '%s' application_name = 'OM' " \
                        "options='-c xc_maintenance_mode=on'  port = %s " % \
                        (database, port)
            conn_opts = conn_opts.encode(encoding='utf-8')
            err_output = ""
            libc.PQconnectdb.argtypes = [c_char_p]
            libc.PQconnectdb.restype = c_void_p
            libc.PQclear.argtypes = [c_void_p]
            libc.PQfinish.argtypes = [c_void_p]
            libc.PQerrorMessage.argtypes = [c_void_p]
            libc.PQerrorMessage.restype = c_char_p
            libc.PQresultStatus.argtypes = [c_void_p]
            libc.PQresultStatus.restype = c_int
            libc.PQexec.argtypes = [c_void_p, c_char_p]
            libc.PQexec.restype = c_void_p
            conn = libc.PQconnectdb(conn_opts)
            if not conn:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51310"]
                                % ("by options: %s." % conn_opts))
            sql = sql.encode(encoding='utf-8')
            libc.PQstatus.argtypes = [c_void_p]
            if libc.PQstatus(conn) != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51310"] % ".")
            tmpresult = libc.PQexec(conn, sql)
            if not tmpresult:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51309"] % sql)
            status = libc.PQresultStatus(tmpresult)

            resultObj = SqlResult(tmpresult)
            resultObj.parseResult()
            Error = libc.PQerrorMessage(conn)
            if Error:
                err_output = string_at(Error)
            result = resultObj.resSet
            libc.PQclear(tmpresult)
            libc.PQfinish(conn)
            return status, result, err_output
        except Exception as e:
            libc.PQclear.argtypes = [c_void_p]
            libc.PQfinish.argtypes = [c_void_p]
            if tmpresult:
                libc.PQclear(tmpresult)
            if conn:
                libc.PQfinish(conn)
            raise Exception(str(e))

    @staticmethod
    def getSQLResult(host_name, json_file):
        """
        function: get sql result from json_file
        input : host_name,json_file
        output: status, result, error_output
        """
        # copy json file from remote host
        tmp_dir = EnvUtil.getTmpDirFromEnv() + "/"
        filepath = os.path.join(tmp_dir, json_file)
        scp_cmd = LocalRemoteCmd.getRemoteCopyCmd(
            filepath, tmp_dir, host_name, False, "directory")
        CmdExecutor.execCommandLocally(scp_cmd)
        # parse json file
        status = ""
        result = []
        error_output = ""
        (ret, para) = SqlExecutor.check_input(filepath)
        if ret != 0:
            raise Exception("Error: can not load result data ")

        if "status" not in para:
            raise Exception("Error: can not get sql execute status")
        else:
            status = para["status"]

        if "result" not in para:
            raise Exception("Error: sql execute failed")
        else:
            result = para["result"]
        if "error_output" in para:
            error_output = para["error_output"]

        # remove json file from remote host and localhost
        FileUtil.removeDirectory(filepath)

        remote_cmd = CmdUtil.getSshCmd(host_name)
        cmd = "%s \"%s '%s'\"" % (remote_cmd, CmdUtil.getRemoveCmd("directory"), filepath)
        CmdExecutor.execCommandLocally(cmd)

        return status, result, error_output

    @staticmethod
    def check_input(json_file_path):
        """
        function: check the input, and load the backup JSON file.
        @param: N/A.
        @return: return [OK, para], if the backup JSON file is loaded
                successfully.
        """
        try:
            with open(json_file_path) as json_file:
                para = json.load(json_file)
            return [0, para]
        except TypeError as err:
            err_msg = "input para is not json_string. %s" % err
            return [1, err_msg]
