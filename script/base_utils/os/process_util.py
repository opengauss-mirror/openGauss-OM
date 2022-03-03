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

import os
import subprocess
import sys

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil

local_dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, local_dir_path + "/../../../lib")
import psutil



class ProcessUtil(object):
    """process util"""

    @staticmethod
    def getProcessIdByKeyWordsCmd(keywords):
        """
        function: get proecess id by keywords cmd
        input  : keywords
        output : str
        """
        ps_cmd = CmdUtil.findCmdInPath('ps')
        grep = CmdUtil.findCmdInPath('grep')
        awk = CmdUtil.findCmdInPath('awk')
        return "%s -ef| %s -F '%s' | %s -F -v 'grep'| %s '{print $2}'" % (
            ps_cmd, grep, keywords, grep, awk)

    @staticmethod
    def getProcess(process_keywords):
        """
        function : Get process id by keywords
        input  : process_keywords
        output : process_id
        """
        process_id = []
        cmd = ProcessUtil.getProcessIdByKeyWordsCmd(process_keywords)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0 and str(output.strip()) != "":
            # kill process
            process_id = output.strip().split("\n")
        return process_id

    @staticmethod
    def getProcPidList(proc_name):
        """
        function : Get process id by proc_name
        input  : proc_name
        output : pidList
        """
        pid_list = []
        for pid in psutil.pids():
            try:
                p = psutil.Process(pid)
                if proc_name == p.name():
                    pid_list.append(pid)
            except psutil.NoSuchProcess:
                pass
        return pid_list

    @staticmethod
    def killProcessByProcName(proc_name, kill_type=2):
        """
        function : Kill the process
        input : int, int
        output : boolean
        """
        try:
            pid_list = ProcessUtil.getProcPidList(proc_name)
            for pid in pid_list:
                os.kill(pid, kill_type)
            return True
        except Exception:
            return False

    @staticmethod
    def killallProcess(user_name, proc_name, kill_type='2'):
        """
        function : Kill all processes by user_name and proc_name.
        input : user_name, proc_name, kill_type
        output : boolean
        """
        cmd = "%s >/dev/null 2>&1" % CmdUtil.getKillallProcessCmd(kill_type,
                                                                  user_name,
                                                                  proc_name)
        status = subprocess.getstatusoutput(cmd)[0]
        if status != 0:
            return False
        return True

    @staticmethod
    def getPortProcessInfo(port):
        """
        function : get port occupation process
        input : port
        output : process info
        """
        try:
            process_info = ""
            cmd = "netstat -an | grep -w %s" % port
            output = subprocess.getstatusoutput(cmd)[1]
            process_info += "%s\n" % output
            return process_info
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error:\n%s" % str(excep))
