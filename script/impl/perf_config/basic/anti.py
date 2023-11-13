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
# Description  : Provides logic for rolling back adjustments.
#############################################################################

import os
from impl.perf_config.basic.project import Project


class AntiLog(object):
    """
    Anti log describes the opposite logic for adjusting content.
    You can use anti log to roll back the tune information and
    restore the environment to its original state.

    Anti log is similar to the write-ahead logging of a database.
    Through the tuning log, we can learn about the adjustment details
    and how to roll back the adjustment, record the rollback function
    in anti log, so we can know how to rollback it.

    Anti log are stored in str format. Each line is a log. Therefore,
    the log cannot contain '\n'.

    The format of a typical anti log is as follows:

        "module-name -:|:- log-content"

        1, we can find a module in AntiLog._modules by module name.
        2, " -:|:- " is a separator.
        3, log-content are produced by the module, the module also needs
           to provide an interface to parse and execute the contents of
           the log-content.

    """
    init_done = False
    _file = None        # anti log file
    _records = []       # anti log content in memory. [alog1, alog2, ...]
    _modules = {}       # modules to exec anti log. { module1_name: module1, ...}

    def __init__(self):
        assert False, 'AntiLog is just a interface package.'

    @staticmethod
    def initAntiLog(file, reload=False):
        """
        init anti log
        :param file: anti log file
        :param reload: reload anti log from file or recreate a new empty anti log.
        :return: NA
        """
        AntiLog._file = file
        if reload:
            if not os.access(file, os.F_OK):
                Project.fatal('Could not access anti log: ' + file)
            with open(file, 'r') as f:
                AntiLog._records = f.readlines()
        else:
            with open(file, 'w') as f:
                pass
            Project.role.chown_to_user(file)
        AntiLog.init_done = True
        Project.notice('Anti Log ({0}) {1} done '.format(file, 'reload' if reload else 'init'))

    @staticmethod
    def destroyAntiLog():
        """
        destory anti log
        :return: NA
        """
        os.remove(AntiLog._file)
        AntiLog.init_done = False
        AntiLog._file = None
        AntiLog._records = []
        AntiLog._modules = {}

    @staticmethod
    def write(module_name, alog):
        """
        write an anti log in to memory and file.
        :param module_name: module to exec this log
        :param alog: log content
        :return:
        """
        assert isinstance(alog, str)
        assert alog.find('\n') < 0, 'Anti log can not contain "\\n".'

        record = '{0} -:|:- {1}\n'.format(module_name, alog)
        AntiLog._records.append(record)
        with open(AntiLog._file, 'a+') as f:
            f.write(record)
            f.flush()

    @staticmethod
    def register(module):
        """
        register a module.
        :param module: module to exec this log
        :return:
        """
        name = module.__name__
        if AntiLog._modules.get(name) is None:
            Project.log('AntiLog register module <class {0}>'.format(name))
            AntiLog._modules[name] = module

    @staticmethod
    def rollback():
        """
        Traverse the anti log in reverse order, invoke the corresponding module to rollback.
        """
        for alog in AntiLog._records[::-1]:
            parts = alog.split(' -:|:- ')
            module = AntiLog._modules.get(parts[0])
            assert module is not None, '{} is not registered.'.format(parts[0])
            module.rollback(parts[1])

