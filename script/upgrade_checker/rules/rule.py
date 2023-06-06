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

from enum import Enum
from upgrade_checker.opengauss import og
from upgrade_checker.log import logger
from upgrade_checker.rules.category import Category
from upgrade_checker.rules.meta import Accuracy


class Rule(object):
    """
    单条检测SQL。
    所有的检测sql都通过这个结构进行整理、检测、分析。
    通过此数据结构来进行检测SQL的执行、结果的整理，检测内容、结果描述信息的整理生成。
    """

    def __init__(self, sql, sql_desc="详见sql", key_desc="内容为%s的行", accuracy=Accuracy.STRICT,
                 callback=None):
        """

        :param sql: 校验sql
        :param sql_desc: 校验sql的描述，结尾不要带句号等标点符号
        :param key_desc: 键值的描述，需要带一个%s用于格式匹配，结尾不要带句号等标点符号
        :param accuracy: 校验精度
        :param callback: 回调函数，用于对结果做一些处理
        """
        self.sql = sql
        self.accuracy = accuracy
        self.sql_desc = sql_desc
        self.key_desc = key_desc
        self.callback = callback
        self.result = {}   # sql res key, val

    def run(self):
        """
        执行检查、重新执行检察。
        :return:
        """
        qres = og.query(self.sql)
        for row in qres.data:
            if self.result.get(row[0]) is not None:
                logger.warning('在规则%s的查询执行中，发现重复键值%s' % (self.sql, row[0]))

            if qres.col_count() == 1:
                self.result[row[0]] = row[0]
            else:
                assert qres.col_count() == 2
                self.result[row[0]] = row[1]

        if self.callback is not None:
            self.callback.run(self)

        logger.debug('规则查询完成，共得到%d条结果，规则内容：%s' % (len(self.result), self.sql))
        return self.result

    def simplify(self):
        """

        :return:
        """
        return {
            'sql': self.sql,
            'accuracy': self.accuracy.name,
            'sql_desc': self.sql_desc,
            'key_desc': self.key_desc,
            'result': self.result
        }

    def analyze(self, expect):
        """

        :param expect:
        :return:
        """
        return Conclusion(self, expect)


class ConclusionState(Enum):
    SUCCESS = 0
    FAILED = 1
    IGNORE = 2


class Conclusion(object):
    """
    表示一个rule的分析结论。
    """
    def __init__(self, rule, expect):
        """

        :param rule:
        :param expect:
        """
        assert expect is None or rule.sql == expect['sql']
        self.rule = rule
        self.expect = expect

        self.details = []
        self.warnings = []

        self._analyze(rule, expect)

    def _analyze_one_row(self, key, e_key, row_desc, val, e_val, accuracy):
        """

        :param key:
        :param e_key:
        :param row_desc:
        :param val:
        :param e_val:
        :param accuracy:
        :return:
        """
        detail = {
            'state': ConclusionState.SUCCESS,
            'summary': '成功'
        }
        if key is None:
            detail['state'] = ConclusionState.FAILED
            detail['summary'] = '%s 缺失' % row_desc
        elif e_key is None:
            if accuracy == Accuracy.ALLOW_MORE:
                detail['state'] = ConclusionState.SUCCESS
                detail['summary'] = '%s 允许冗余，校验成功' % row_desc
            else:
                detail['state'] = ConclusionState.FAILED
                detail['summary'] = '%s 冗余' % row_desc
        elif val != e_val:
            detail['state'] = ConclusionState.FAILED
            detail['summary'] = '%s 错误（预期%s 实际%s）' % (row_desc, e_val, val)
        else:
            detail['state'] = ConclusionState.SUCCESS
            detail['summary'] = '%s 校验成功' % row_desc

        self.details.append(detail)

    def _analyze(self, rule, expect):
        """

        :param rule:
        :param expect:
        :return:
        """
        # 是否能找到这条规则的预期
        if expect is None:
            self.warnings = ['规则%s在校验地图内不存在。可能是由于vmap与工具不匹配、系统表结构升级不正确等原因导致，请手动排查。' % rule.sql]
            return

        # 以rule为基础，对照expect进行判断
        for row_key, row_val in rule.result.items():
            row_desc = rule.key_desc % row_key
            erow_val = expect['result'].get(row_key)
            erow_key = row_key if erow_val is not None else None
            self._analyze_one_row(row_key, erow_key, row_desc, row_val, erow_val, rule.accuracy)

        # 找到expect里有但实际没有的
        for erow_key, erow_val in expect['result'].items():
            row_val = rule.result.get(erow_key)
            if row_val is not None:
                continue
            row_desc = expect['key_desc'] % erow_key
            self._analyze_one_row(None, erow_key, row_desc, '', erow_val, rule.accuracy)


class StructRule(Rule):
    """
    系统表结构校验规则。
    """
    def __init__(self, rel_key, category, sql, sql_desc="详见sql", key_desc="内容为%s的行",
                 accuracy=Accuracy.STRICT, callback=None):
        super(StructRule, self).__init__(sql, sql_desc, key_desc, accuracy, callback)
        self.rel_key = rel_key
        self.category = category

    def simplify(self):
        data = super(StructRule, self).simplify()
        data['rel_key'] = self.rel_key
        data['category'] = self.category.name
        return data

    def analyze(self, expect):
        """

        :param expect:
        :return:
        """
        conclusion = super(StructRule, self).analyze(expect)
        if self.category == Category.UNKNOWN:
            conclusion.warnings.append('发现未分类的系统表 {0}, 建议升级工具。'.format(self.rel_key))
        return conclusion


class ContentRule(Rule):
    """
    系统表内容校验规则。
    """
    def __init__(self, rel_key, category, sql, sql_desc="详见sql", key_desc="内容为%s的行",
                 accuracy=Accuracy.STRICT, callback=None):
        super(ContentRule, self).__init__(sql, sql_desc, key_desc, accuracy, callback)
        self.rel_key = rel_key
        self.category = category

    def simplify(self):
        data = super(ContentRule, self).simplify()
        data['rel_key'] = self.rel_key
        data['category'] = self.category.name
        return data

    def analyze(self, expect):
        """

        :param expect:
        :return:
        """
        conclusion = super(ContentRule, self).analyze(expect)
        return conclusion


class CommonRule(Rule):
    """
    常规通用校验规则。
    """
    def __init__(self, category, sql, sql_desc="详见sql", key_desc="内容为%s的行",
                 accuracy=Accuracy.STRICT, callback=None):
        super(CommonRule, self).__init__(sql, sql_desc, key_desc, accuracy, callback)
        self.category = category

    def simplify(self):
        data = super(CommonRule, self).simplify()
        data['category'] = self.category.name
        return data

    def analyze(self, expect):
        """

        :param expect:
        :return:
        """
        conclusion = super(CommonRule, self).analyze(expect)
        if self.category == Category.UNKNOWN:
            conclusion.warnings.append('发现未分类的通用规则 {0}，请升级工具。'.format(self.sql))
        return conclusion


class RuleCallback(object):
    def __init__(self):
        self.res_keys = []
        self.exp_keys = []
        self.callback = []

    def run(self, rule):
        pass


COMMON_RULES = [
    # 暂时没有，放个假的临时替代。
    CommonRule(Category.TABLE,
               "select 'test', 1",
               '暂无规则描述',
               '测试%s',
               Accuracy.STRICT
               )
]

