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
校验组件模块，由三个模块进行配合，进行整体的流程。
    collector：负责数据收集。连接数据库，构造校验规则Rule，并执行Rule进行数据的收集。
    analyzer：负责数据分析。依据vmap，对输入的携带有数据的Rule进行分析，生成结论Conclusion
    exporter：负责数据简化导出。将Rule的结果进行简化，记录到一个新的vmap内，最终导出生成vmap。
"""


from upgrade_checker.utils.param import Action
from upgrade_checker.rules.rule_maker import RuleMaker
from upgrade_checker.rules.vmap import VMapHeader, VerifyMap
from upgrade_checker.opengauss import og
from upgrade_checker.log import logger


class Collector(object):
    """
    负责数据收集。连接数据库，构造校验规则Rule，并执行Rule进行数据的收集。
    """
    @staticmethod
    def prepare_db_list(action):
        if action == Action.VERIFY:
            search_db_sql = "select datname from pg_database " \
                            "where datname not in ('template0', 'template1') and " \
                            "      datcompatibility != 'A'"
            qres = og.query(search_db_sql)
            if qres.row_count() != 0:
                ignore_list = ','.join([line[0] for line in qres])
                logger.warning(f'暂不支持非A库的校验，{ignore_list} 将被跳过。')
            
            search_db_sql = "select datname from pg_database " \
                            "where datname not in ('template0', 'template1') and " \
                            "      datcompatibility = 'A'"
            qres = og.query(search_db_sql)
            if qres.row_count() == 0:
                logger.fatal('没有需要校验的库。')
                
            return [row[0] for row in qres]
        elif action == Action.EXPORT:
            search_db_sql = "select datname from pg_database " \
                            "where datname = 'postgres' and datcompatibility = 'A'"
            qres = og.query(search_db_sql)
            if qres.row_count() == 0:
                logger.fatal('暂不支持非A兼容性的postgres库。')
            
            return ['postgres']
        else:
            assert False

    def __init__(self, db_list):
        """

        :param db_list: 需要收集的数据库名称列表
        """
        self._database_list = db_list
        self._idx = 0

        self._rule_buffer = []
        self._estimate = None

        logger.log('verifier.collector 数据库采集列表：[%s]。' % (', '.join(self._database_list)))
        logger.log('verifier.collector 初始化完成。')

    def __str__(self):
        return 'Collector: dblist [{0}]， current is {1}'.format(
            ', '.join(self._database_list),
            self._database_list[self._idx - 1]
        )

    def __iter__(self):
        return self

    def __next__(self):
        if len(self._rule_buffer) == 0 and self._collect_next_db() is None:
            raise StopIteration
        rule = self._rule_buffer.pop()
        rule.run()
        return rule

    def _estimate_workload(self):
        self._estimate = len(self._rule_buffer)

    def _collect_next_db(self):
        if self._idx >= len(self._database_list):
            return

        self._rule_buffer = RuleMaker.make_rules(self._database_list[self._idx])
        self._estimate_workload()
        logger.log('数据库%s的所有校验规则准备完毕，共计%d条，开始执行数据采集....' % (self._database_list[self._idx], len(self._rule_buffer)))

        self._idx += 1
        return self._rule_buffer

    def current_db(self):
        return self._database_list[self._idx - 1]

    def check_next_rule(self):
        if len(self._rule_buffer) == 0 and self._collect_next_db() is None:
            return

        rule = self._rule_buffer.pop()
        rule.run()
        return rule

    def get_progress(self):
        """
        返回当前采集的预估进度。
        """
        finished_db_percentage = (self._idx - 1) / len(self._database_list) * 100.0
        curr_db_percentage = (1.0 - len(self._rule_buffer) / self._estimate) / len(self._database_list) * 100.0

        percentage = int(finished_db_percentage + curr_db_percentage)
        if percentage < 0:
            percentage = 0
        elif percentage > 100:
            percentage = 100

        return percentage


class Analyzer(object):
    """
    负责数据分析。依据vmap，对输入的携带有数据的Rule进行分析，生成结论Conclusion
    """
    def __init__(self, vmap):
        self.vmap = VerifyMap(vmap)
        self.vmap.load()
        VMapHeader.check_availability(self.vmap.head)
        logger.log('verifier.analyzer 初始化完成。')

    def __del__(self):
        self.close()

    def __str__(self):
        return 'Analyzer: using vmap ({0})'.format(self.vmap.__str__())

    def analyze(self, rule):
        """
        在vmap内找到对应的规则预期输出，并进行分析处理。
        :param rule:
        :return:
        """
        expect = self.vmap.get(rule.sql)
        conclusion = rule.analyze(expect)
        logger.debug('分析完毕一条规则，共计{0}条小项，{1}告警，规则内容为：{2}。'.format(
            len(conclusion.details),
            len(conclusion.warnings),
            rule.sql)
        )
        return conclusion

    def close(self):
        pass


class Exporter(object):
    """
    负责数据简化导出。将Rule的结果进行简化，记录到一个新的vmap内，最终导出生成vmap。
    """
    def __init__(self, export_vmap_file):
        self.vmap = VerifyMap(export_vmap_file)
        logger.log('verifier.exporter 初始化完成。')

    def __str__(self):
        return 'Exporter: export to vmap ({0})'.format(self.vmap.show_info())

    def record(self, rule):
        self.vmap.push(rule)
        logger.debug('Exporter完成记录一条规则：%s。' % rule.sql)

    def export(self):
        self.vmap.dump()
        logger.debug('Exporter导出校验地图完成。')

    def close(self):
        self.vmap.dump()


