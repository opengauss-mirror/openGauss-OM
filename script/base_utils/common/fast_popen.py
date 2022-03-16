# -*- coding:utf-8 -*-

"""
# Copyright (c): 2012-2020, Huawei Tech. Co., Ltd.
# FileName     : FastPopen
# Version      : GaussDB Kernel V500R001
# Date         : 2020-09-08
# Description  : FastPopen
"""

import subprocess


class FastPopen(subprocess.Popen):
    """
    optimization subprocess.Popen when close_fds=True,
    only close the currently opend file,
    reduce the execution time when ulimit is too large
    """

    def __init__(self, cmd, bufsize=0,
                 stdout=None, stderr=None,
                 preexec_fn=None, close_fds=False,
                 cwd=None, env=None, universal_newlines=True,
                 startupinfo=None, creationflags=0, logger=None):

        subprocess.Popen.logger = None
        subprocess.Popen.__init__(self, ["sh", "-"], bufsize=bufsize, executable=None,
                                  stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                  preexec_fn=preexec_fn, close_fds=close_fds, shell=None,
                                  cwd=cwd, env=env, universal_newlines=universal_newlines,
                                  startupinfo=startupinfo, creationflags=creationflags)
        self.logger = logger
        self.cmd = cmd

    def communicate(self, input_cmd=None, timeout=None):
        """
        Get data from stdout and stderr
        """
        if input_cmd:
            self.cmd = input_cmd

        if not isinstance(self.cmd, str):
            self.cmd = subprocess.list2cmdline(self.cmd)

        std_out, std_err = subprocess.Popen.communicate(self, self.cmd)
        return std_out, std_err
