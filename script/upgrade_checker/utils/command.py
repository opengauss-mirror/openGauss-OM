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

import subprocess
from subprocess import PIPE
from upgrade_checker.utils.exception import ShellExecException


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
        


class Download(object):

    @staticmethod
    def wget(url, output):
        """
        download content of url by wget, and store it into output.
        """
        cmd = 'wget {0} -O {1}'.format(url, output)
        try:
            Shell.run(cmd, check=True)
        except ShellExecException as e:
            Shell.run('rm {0} -fr'.format(output), check=False)
            raise e


