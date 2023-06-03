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
"""
日志模块
"""


import time
import sys
import traceback
from enum import Enum
from upgrade_checker.utils.singleton import singleton


class LogLevel(Enum):
    DEBUG = 0     # 不打印，或打印到日志
    LOG = 1       # 打印到日志
    INFO = 2      # 打印到日志和屏幕
    WARNING = 3   # 打印到日志和屏幕
    ERROR = 4     # 打印到日志和屏幕，并退出


@singleton
class Logger(object):

    def __init__(self):
        self._file = None
        self._debug = False            # debug模式
        self._in_process_bar = False   # 标记当前正在打印一个进度条

    def __del__(self):
        sys.stdout.flush()
        if self._file is not None:
            self._file.close()

    def set_file(self, file_path):
        if self._file is not None:
            sys.stdout.flush()
            self._file.close()

        try:
            self._file = open(file_path, 'a')
        except FileNotFoundError:
            print('无法打开文件', file_path)
            exit(1)

        self.log('Logger 日志文件设置成功： %s.' % file_path)

    def set_debug(self, state):
        self._debug = state

    def _format_content(self, log_level, content, hint):
        """
        将日志内容整理成带时间、等级等的格式，用于记录或者输出。
        :param log_level: 等级
        :param content: 内容
        :param hint: 提示
        :return:
        """
        s = time.strftime("%Y-%m-%d-%H_%M_%S", time.localtime()) + \
            " [{0}] ".format(log_level.name) + \
            content + \
            (("\n HINT: " + hint) if hint is not None else "") + \
            '\n'
        return s

    def _write_log(self, log_content):
        """
        日志写入文件
        :param log_content: 日志内容
        :return:
        """
        assert self._file is not None
        self._file.write(log_content)

    def _print_log(self, log_content):
        """
        日志打印到屏幕
        :param log_content: 日志内容
        :return:
        """
        if self._in_process_bar:
            print('')
            self._in_process_bar = False

        print(log_content, end='')

    def debug(self, content, hint=None):
        """
        定位信息，开启debug时写入文件。
        :param content: 内容
        :param hint: 提示
        :return:
        """
        if not self._debug:
            return
        res = self._format_content(LogLevel.DEBUG, content, hint)
        self._write_log(res)

    def log(self, content, hint=None):
        """
        日志信息，写入文件
        :param content: 内容
        :param hint: 提示
        :return:
        """
        res = self._format_content(LogLevel.LOG, content, hint)
        self._write_log(res)

    def info(self, content, hint=None):
        """
        普通信息。打印屏幕和写入文件
        :param content: 内容
        :param hint: 提示
        :return:
        """
        res = self._format_content(LogLevel.INFO, content, hint)
        self._write_log(res)
        self._print_log(res)

    def warning(self, content, hint=None):
        """
        警告信息，打印屏幕和写入文件
        :param content: 内容
        :param hint: 提示
        :return:
        """
        res = self._format_content(LogLevel.WARNING, content, hint)
        self._write_log(res)
        self._print_log(res)

    def err(self, content, hint=None):
        """
        错误信息，打印日志和写入文件，失败直接结束
        :param content: 内容
        :param hint: 提示
        :return:
        """
        bt = ''.join(traceback.format_stack()[0:-1])
        content = content + '\n' + 'Traceback (most recent call last):\n' + bt

        res = self._format_content(LogLevel.ERROR, content, hint)
        self._write_log(res)
        self._print_log(res)

        sys.stdout.flush()
        exit(1)

    def process_bar(self, percentage):
        """
        进度条，打印在屏幕上。
        :param percentage: [0,100] 整形参数，表示进度百分比。
        :return:
        """
        assert 0 <= percentage <= 100

        self._in_process_bar = True
        print('\r进度 {}%:'.format(percentage), '[' + ('█' * percentage) + (' ' * (100 - percentage)) + ']', end='')

    def process_bar_text(self, content):
        """
        直接文本进度条，打印在屏幕上。
        :param content: 直接文本
        :return:
        """
        self._in_process_bar = True
        print('\r' + content, end="")


# 单例模式，全局一个logger
logger = Logger()
