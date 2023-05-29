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
”工程“文件，将整个程序的运行抽象为一个工程类。
通过这个功能工程类来启动和运行工程。
"""

import time
import os

from upgrade_checker.utils.param import Action, ReportFormat, ReportMode, Param
from upgrade_checker.log import logger
from upgrade_checker.opengauss import og
from upgrade_checker.report import Reporter
from upgrade_checker.rules.vmap import VerifyMap
from upgrade_checker.verifier import Collector, Analyzer, Exporter


class Project(object):

    def __init__(self, param):
        """
        初始化程序运行的各种数据参数，主要拼接路径，路径的创建等后续逐步进行。
        :param param: 启动参数
        """
        assert param.action != Action.HELP
        self.param = param

        self.dir_root = param.root_path
        self.dir_workspace = "{0}/workspace".format(self.dir_root)
        self.dir_vmap = "{0}/vmap".format(self.dir_workspace)
        self.dir_results = "{0}/results".format(self.dir_root)

        self.id = int(time.time())
        self.name = "{0}-{1}".format(
            param.action.name,
            time.strftime('%Y-%m-%d-%H_%M_%S', time.localtime(self.id))
        )
        self.workspace = "{0}/{1}".format(self.dir_workspace, self.name)
        self.log = "{0}/run.log".format(self.workspace)

    def __str__(self):
        info = self.param.__str__()
        info += 'dir_root: ' + self.dir_root + '\n'
        info += 'dir_workspace: ' + self.dir_workspace + '\n'
        info += 'dir_vmap: ' + self.dir_vmap + '\n'
        info += 'dir_results: ' + self.dir_results + '\n'
        info += 'id: ' + str(self.id) + '\n'
        info += 'name: ' + self.name + '\n'
        info += 'workspace: ' + self.workspace + '\n'
        info += 'log: ' + self.log + '\n'
        return info

    def _prepare_workspace(self):
        """
        创建工作目录文件夹等。
        :return:
        """
        if not os.access(self.dir_workspace, os.F_OK):
            os.mkdir(self.dir_workspace, 0o700)

        if not os.access(self.dir_vmap, os.F_OK):
            os.mkdir(self.dir_vmap, 0o700)

        if not os.access(self.dir_results, os.F_OK):
            os.mkdir(self.dir_results, 0o700)

        os.mkdir(self.workspace, 0o700)

    def init(self):
        self._prepare_workspace()

        logger.set_file(self.log)
        logger.set_debug(self.param.debug.value)

        og.connect('postgres', self.param.port.value)

    def run(self):
        pass

    def close(self):
        pass


class ExportProj(Project):
    def __init__(self, param):
        assert param.action == Action.EXPORT
        super(ExportProj, self).__init__(param)
        self.vmap = "{0}/{1}.vmap".format(self.dir_results, self.name)

    def __str__(self):
        info = 'Export Project as:'
        info += super(ExportProj, self).__str__()
        info += 'vmap: ' + self.vmap + '\n'
        return info

    def init(self):
        super(ExportProj, self).init()

        logger.log("工程初始配置完成。")
        logger.debug('工程信息：\n' + self.__str__())

    def run(self):
        db_list = Collector.prepare_db_list(Action.VERIFY)
        collector = Collector(db_list)
        exporter = Exporter(self.vmap)

        logger.info('开始进行数据采集与记录。')
        for rule in collector:
            exporter.record(rule)

            percentage = collector.get_progress()
            logger.process_bar(percentage)

        logger.process_bar(100)
        logger.info('数据采集与记录完成，开始导出基准校验地图。')
        exporter.export()
        logger.info('基准校验地图导出完成:{0}'.format(self.vmap))

    def close(self):
        return self.vmap


class VerifyProj(Project):
    def __init__(self, param):
        assert param.action == Action.VERIFY
        super(VerifyProj, self).__init__(param)
        self.vmap = self.param.vmap.value
        self.report = "{0}/{1}-report.{2}".format(
            self.dir_results,
            self.name,
            ReportFormat.suffix(self.param.report_format.value)
        )

    def __str__(self):
        info = 'Verify Project as:'
        info += super(VerifyProj, self).__str__()
        info += 'vmap: ' + self.vmap + '\n'
        info += 'report: ' + self.report + '\n'
        return info

    def init(self):
        super(VerifyProj, self).init()

        # 准备基准校验文件，仅保证文件存在，是否可用将在后续加载时校验
        if self.vmap is not None:
            if os.access(self.vmap, os.F_OK):
                return
            else:
                logger.err('指定的基准校验地图文件{0}不存在。'.format(self.vmap))
        self.vmap = VerifyMap.prepare_vmap_file(self.dir_vmap)

        logger.log("工程初始配置完成。")
        logger.debug('工程信息：\n' + self.__str__())

    def run(self):
        db_list = Collector.prepare_db_list(Action.VERIFY)
        collector = Collector(db_list)
        analyzer = Analyzer(self.vmap)
        reporter = Reporter(self.report,
                            self.param.report_format.value,
                            self.param.report_mode.value)
        reporter.record_info(og, analyzer.vmap)

        logger.info('开始进行数据采集与分析。')
        for rule in collector:
            conclusion = analyzer.analyze(rule)
            reporter.record(collector.current_db(), conclusion)

            percentage = collector.get_progress()
            logger.process_bar(percentage)

        logger.process_bar(100)
        logger.info('数据采集与分析完成，准备整理报告。')
        reporter.report()
        logger.info('报告导出完成：{0}'.format(self.report))

    def close(self):
        return self.report


class ProjectFactory(object):
    @staticmethod
    def produce(param):
        if param.action == Action.EXPORT:
            return ExportProj(param)
        elif param.action == Action.VERIFY:
            return VerifyProj(param)
        else:
            assert False


if __name__ == "__main__":
    pass
