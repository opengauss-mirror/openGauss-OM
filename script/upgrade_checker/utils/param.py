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
参数模块
"""

import os
import sys
from getopt import getopt, GetoptError
from enum import Enum
from upgrade_checker.utils.exception import ParamParseException


class Action(Enum):
    """
    程序运行动作
    """
    HELP = 0
    VERIFY = 1
    EXPORT = 2


class ReportFormat(Enum):
    """
    报告格式
    """
    MARKDOWN = 0

    @staticmethod
    def suffix(fmt):
        if fmt == ReportFormat.MARKDOWN:
            return 'md'
        else:
            assert False


class ReportMode(Enum):
    """
    报告粒度
    """
    SUMMARY = 0
    DETAIL = 1


class Option(object):
    def __init__(self, value, shortopt, longopt, assign_func=None):
        """
        一个参数选项
        :param value: 默认值
        :param shortopt: 解析时的短命令
        :param longopt: 解析时的长命令
        :param assign_func: 设置新值时的检查函数
        :return:
        """
        self.value = value
        self.shortopt = shortopt
        self.longopt = longopt
        self.assign_func = assign_func
        
    def assign(self, value):
        self.value = value if self.assign_func is None else self.assign_func(value)


class Param(object):
    helper = """
    命令格式：
        python3 main.py [action [params, ...] ]

    参数 ACTION，所需执行的动作:
        check | verify      校验数据库元数据
        export              导出一份元数据地图
        help | -h | -?      打印帮助

    参数 params：
        -p | --port            数据库端口
        -F | --report_format   报告格式，支持markdown
        -M | --report_mode     报告模式，detail详细，summary摘要，默认summary
        -v | --vmap            指定使用某个地图，不然自己检测数据库版本并下载。默认自己检测
        -d | --debug           开启debug运行模式，将会打印更多的日志。
        -D | --database        对指定数据库进行导出或校验操作。

    更多详细内容参考《README.md》
    """

    def __init__(self, root_path, argv):
        self._opt_info = ['', []]   # shotopts, longopts
        self._opt_dict = {}

        self.root_path = root_path
        self.action = Action.HELP
        
        self.port = self._register(16666, 'p:', 'port=', Param.assign_port)
        self.report_format = self._register(ReportFormat.MARKDOWN, 'F:', 'report-format=', Param.assign_report_format)
        self.report_mode = self._register(ReportMode.SUMMARY, 'M:', 'report-mode=', Param.assign_report_mode)
        self.vmap = self._register(None, 'v:', 'vmap=', Param.assign_vmap)
        self.debug = self._register(False, 'd', 'debug', Param.assign_debug)
        self.database = self._register(None, 'D:', 'database=', Param.assign_database)

        try:
            self._parse(argv[1:])
        except ParamParseException as e:
            self.action = Action.HELP
            print('ERROR：', e)

    def __str__(self):
        return 'Param as: ' + str({
            'root_path': self.root_path,
            'action': self.action,
            'port': self.port.value,
            'report_format': self.report_format.value,
            'report_mode': self.report_mode.value,
            'vmap': self.vmap.value,
            'debug': self.debug.value,
            'database': self.database
        }) + '\n'

    def _register(self, value, shortopt, longopt, assign_func=None):
        """
        创建并返回一个Option，同时将长短指令添加到_opt_info中，用以解析，将Option添加到自身字典内，以长短指令为键
        :param value: 默认值
        :param shortopt: 解析时的短命令
        :param longopt: 解析时的长命令
        :param assign_func: 设置新值时的检查函数
        :return:
        """
        opt = Option(value, shortopt, longopt, assign_func)
        self._opt_info[0] += shortopt
        self._opt_info[1].append(longopt)

        short_key = '-' + (shortopt if shortopt[-1] != ':' else shortopt[:-1])
        long_key = '--' + (longopt if longopt[-1] != '=' else longopt[:-1])
        assert self._opt_dict.get(short_key) is None
        assert self._opt_dict.get(long_key) is None
        self._opt_dict[short_key] = opt
        self._opt_dict[long_key] = opt
        
        return opt

    def _parse(self, argv):
        """
        解析参数，第一个参数必须是action，后面的逐个解析
        :param argv: 参数列表
        :return:
        """
        self.action = Param.assign_action(argv)
        if self.is_help():
            return

        try:
            opts, unused = getopt(argv[1:], self._opt_info[0], self._opt_info[1])
        except GetoptError as e:
            raise ParamParseException(e.msg)
            
        if len(unused) > 0:
            raise ParamParseException('解析出错，未知的参数{}'.format(unused[0]))
        for key, value in opts:
            opt = self._opt_dict.get(key)
            assert opt is not None
            opt.assign(value)

    def is_help(self):
        return self.action == Action.HELP

    @staticmethod
    def assign_action(argv):
        if len(argv) == 0:
            return Action.HELP
            
        action = argv[0]
        if action.lower() in ("help", "--help", "-h", "-?"):
            return Action.HELP
        elif action.lower() in ["check", "verify"]:
            return Action.VERIFY
        elif action.lower() == "export":
            return Action.EXPORT
        else:
            raise ParamParseException("错误的动作参数'{0}'.".format(action))

    @staticmethod
    def assign_port(port):
        port = int(port)
        if 0 < port < 65535:
            return port
        else:
            raise ParamParseException("错误的端口参数port {0}, 请保持在(0, 65535)".format(port))

    @staticmethod
    def assign_report_format(fmt):
        if fmt.lower() in ['md', 'markdown']:
            return ReportFormat.MARKDOWN
        else:
            raise ParamParseException("错误的格式参数report-format {0},当前仅支持markdown格式。".format(fmt))

    @staticmethod
    def assign_report_mode(gran):
        if gran.lower() == 'summary':
            return ReportMode.SUMMARY
        elif gran.lower() == 'detail':
            return ReportMode.DETAIL
        else:
            raise ParamParseException("错误的模式参数report-mode {0}，仅支持summary、detail。".format(gran))

    @staticmethod
    def assign_vmap(vmap):
        return os.path.abspath(vmap)

    @staticmethod
    def assign_debug(debug):
        return True

    @staticmethod
    def assign_database(database):
        return database
        

if __name__ == "__main__":
    test_param = Param(sys.path[0], sys.argv)
    print(test_param)

