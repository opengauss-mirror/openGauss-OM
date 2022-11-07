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
# Description  : execute cmd.
#############################################################################

import os
import subprocess
from subprocess import PIPE

from base_utils.common.constantsbase import ConstantsBase
from gspylib.common.ErrorCode import ErrorCode
from base_utils.common.fast_popen import FastPopen
from base_utils.security.sensitive_mask import SensitiveMask


class CmdExecutor(object):
    """
    command executor.
    """
    def __init__(self):
        pass

    @staticmethod
    def execCommandLocally(cmd):
        """
        functino: exec only on local node
        input: cmd
        output: NA
        """
        # exec the cmd
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
        stdout, stderr = proc.communicate()
        output = stdout + stderr
        status = proc.returncode

        # if cmd failed, then raise
        if status != 0 and "[GAUSS-5" in str(output):
            raise Exception(str(output))
        elif status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                            % SensitiveMask.mask_pwd(str(cmd))
                            + " Error: \n%s" % str(output))

    @staticmethod
    def execCommandWithMode(cmd,
                            g_ssh_tool,
                            local_mode=False,
                            mpprc_file='',
                            host_list=None,
                            logger="",
                            timeout=0,
                            parallelism=True):
        """
        function: check the mode, if local mode, exec only on local node,
                  else exec on all nodes
        input: cmd, decript, g_sshTool, localMode, mpprcFile
        output: NA
        """
        if not host_list:
            host_list = []
        # check the localMode
        if local_mode:
            # localMode
            CmdExecutor.execCommandLocally(cmd)
        else:
            # Non-native mode
            if logger != "":
                g_ssh_tool.executeCommand(cmd, ConstantsBase.SUCCESS, host_list, mpprc_file,
                                          300, False, logger, timeout)
                return

            g_ssh_tool.executeCommand(cmd,
                                      ConstantsBase.SUCCESS,
                                      host_list,
                                      mpprc_file,
                                      parallelism=parallelism)

    @staticmethod
    def execCommandWithSubprocess(cmd, ignore_std_error=False):
        """
        Simply call the command, and get the standard output and standard error.

        :param cmd:             The command string.
        :param ignore_std_error:  Whether need to ignore the standard error message.
                                Sometimes adding standard error
                                 output results in unexpected errors.

        :type cmd:              str
        :type ignore_std_error:   bool

        :return:    Return the command execute result.
        :rtype:     (int, str, str | None)
        """
        if ignore_std_error:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdout=subprocess.PIPE,
                shell=True,
            )
        else:
            process = subprocess.Popen(
                cmd,
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            )

        # noinspection PyBroadException
        try:
            output, error = process.communicate()
        except IOError:
            process.kill()
            output, error = "", ""
        except Exception:
            process.kill()
            output, error = process.communicate()

        ret_code = process.poll()

        return ret_code, output, error
