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
import os

import subprocess
from subprocess import PIPE
from urllib.parse import urlparse
from upgrade_checker.utils.exception import ShellExecException
from base_utils.os.cmd_util import CmdUtil


class Shell(object):
    
    @staticmethod
    def run(cmd, check=False, print_desc=None):
        if print_desc is not None:
            print(print_desc, cmd)
            
        stat, res = subprocess.getstatusoutput(cmd)
        
        if check and stat != 0:
            raise ShellExecException(cmd, stat, res)
        return stat, res
        
    @staticmethod
    def communicate(progress, message, check=False):
        conn = subprocess.Popen(progress, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, encoding="utf-8",
                                universal_newlines=True)
        data, err = conn.communicate(message, 60)
        conn.terminate()
        
        if check and err is not None:
            raise ShellExecException('{0} < {1}'.format(progress, message), 1, err)
        return data, err
    
    @staticmethod
    def communicate_list(progress_list, message, check=False):
        conn = subprocess.Popen(progress_list, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE, encoding="utf-8",
                                universal_newlines=True)
        data, err = conn.communicate(message, 60)
        conn.terminate()
        
        if check and err is not None:
            raise ShellExecException('{0} < {1}'.format(' '.join(progress_list), message), 1, err)
        return data, err
        


class Download(object):

    @staticmethod
    def wget(url, output):
        """
        Download content from url to output using wget.
        Validate url and output with whitelist to prevent command injection.
        Only allowed to be called by installation user (user running this tool), no additional permission restrictions.
        """
        if not url:
            raise ValueError('url cannot be empty')
        
        if not output:
            raise ValueError('output path cannot be empty')
        
        # Only allow alphanumeric, underscore, dot, hyphen, slash, colon, question mark, equal sign, and ampersand
        if not all(c.isalnum() or c in '._-/?&=:@/' for c in url):
            raise ValueError('url contains invalid characters')

        # output only allows alphanumeric, underscore, dot, hyphen, slash
        if not all(c.isalnum() or c in '._-/' for c in output):
            raise ValueError('output path contains invalid characters')

        # Prohibit absolute path traversal, e.g., /etc/passwd
        real_output = os.path.realpath(output)
        if not real_output.startswith(os.getcwd()):
            raise ValueError('output path is not allowed to go beyond current working directory')

        # Use CmdUtil.quoteCmd to protect parameters
        cmd = 'wget {} -O {}'.format(CmdUtil.quoteCmd(url), CmdUtil.quoteCmd(output))
        try:
            Shell.run(cmd, check=True)
        except ShellExecException as e:
            Shell.run('rm -rf -- {}'.format(CmdUtil.quoteCmd(output)), check=False)
            raise e

