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
标题: 报告总结
数据库信息：版本、节点名等
标准元数据地图：xxxxxxxxx
校验结果：通过 or 失败
内容摘要：
    共校验xx个数据库。
    累计xx个系统元数据表，其中xx通过，xx个失败。
    校验规则共xx条，xx条通过，xx条失败。
    Category一共xxx个,其中xx个完全通过，xx个存在失败内容
    。。。
失败项摘要：
    - 规则编号：1
       数据库：postgres
       校验规则： select ...
       规则解读： 使用函数pg_get_ruledef校验重写规则的定义
       规则结果：
            行号  状态     内容
            1    Failed  规则定义def:pg_catalog.gs_session_memory_detail(_RETURN) 缺失
            2    ...
    - 规则编号：8
        数据库：postgres
       校验规则： select ...
       规则解读： ...
       规则结果： ...

警告：
    存在未分类的系统元数据表:
    建议排查来源，并修改本工具，添加至分类列表中。

TIPS:详细校验原理与说明详见本工具的"README.md"。

详细内容：
数据库postgres
元数据系统表结构
    共xx个系统表，校验项目xx条，通过xx条，失败xx条
    - 规则编号：1
       数据库：postgres
       校验规则： select ...
       规则解读： 使用函数pg_get_ruledef校验重写规则的定义
       规则结果：
            行号  状态     内容
            1    Failed  规则定义def:pg_catalog.gs_session_memory_detail(_RETURN) 缺失
            2    ...

分类内容
    共xx个系统表，校验项目xx条，通过xx条，失败xx条

数据库对象

数据库user1db
元数据系统表结构
   ....

"""

from enum import Enum
from upgrade_checker.utils.param import ReportFormat, ReportMode
from upgrade_checker.log import logger
from upgrade_checker.rules.rule import StructRule, ContentRule, CommonRule, ConclusionState
from upgrade_checker.style.markdown import MarkDown


class ConclusionCardType(Enum):
    SUMMARY = 0
    STRUCTURE = 1
    CONTENT = 2
    COMMON = 3


class ConclusionCard(object):
    error_num = 0

    def __init__(self, id, conclusion, dbname=None, tbname=None, category=None):
        self.id = id
        self.dbname = dbname
        self.tbname = tbname
        self.category = category

        self.conclusion = conclusion
        self.sql = conclusion.rule.sql
        self.sql_desc = conclusion.rule.sql_desc
        self.results = conclusion.details

    def serialize(self, style, cc_type):
        res = ''
        res += style.unordered_list([f'规则编号 {self.id}'])

        if cc_type == ConclusionCardType.SUMMARY:
            res += style.text('数据库：' + self.dbname)
        elif cc_type == ConclusionCardType.STRUCTURE:
            res += style.text('表名：' + self.conclusion.rule.rel_key)
        elif cc_type == ConclusionCardType.CONTENT:
            res += style.text('表名：' + self.conclusion.rule.rel_key)
            res += style.text('类别：' + self.conclusion.rule.category.name)
        elif cc_type == ConclusionCardType.CONTENT:
            res += style.text('类别：' + self.conclusion.rule.category.name)

        res += style.text('校验规则：' + self.sql)
        res += style.text('规则解读：' + self.sql_desc)
        res += style.text('规则结果：')

        rows = []
        for i, row in enumerate(self.results):
            if cc_type == ConclusionCardType.SUMMARY:
                if row['state'] == ConclusionState.SUCCESS:
                    continue
            result_state = 'SUCCESS' if row['state'] == ConclusionState.SUCCESS else 'Falied'
            rows.append((
                i,
                result_state,
                row['summary']
            ))

        res += style.table(["行号", "状态", "内容"], rows)
        return res


class Report(object):
    """
    报告
    """

    def __init__(self):
        self.db_info = ''
        self.vmap_info = ''
        self.pci_suc_count = 0
        self.pci_err_count = 0
        self.rule_suc_count = 0
        self.rule_err_count = 0
        self.detail_suc_count = 0
        self.detail_err_count = 0
        self.err_rules_res = []
        self.warnings = []
        self.content = {}  # { "dbname": [struct rules, content rules, common rules], ... }

    def serialize(self, style):
        rule_count = self.rule_suc_count + self.rule_err_count
        detail_count = self.detail_suc_count + self.detail_err_count
        verify_result = '成功' if self.rule_err_count == 0 else '失败'
        db_summary = "共校验 %d 个数据库。" % len(self.content)
        rul_summary = "校验规则累计执行%d条，%d条通过，%d条失败。" % (rule_count, self.rule_suc_count, self.rule_err_count)
        detail_summary = "所有校验规则累计生成%d条内容小项，%d条通过，%d条失败。" % (detail_count, self.detail_suc_count, self.detail_err_count)
        warning_summary = "警告信息%d条。" % len(self.warnings)

        report = style.title(1, "校验报告")
        report += style.title_paragraph("数据库信息", self.db_info)
        report += style.title_paragraph("基准元数据地图", self.vmap_info)
        report += style.title_paragraph("校验结果", verify_result)
        report += style.emphasize("内容摘要：")
        report += style.unordered_list([db_summary, rul_summary, detail_summary, warning_summary])
        report += style.title(2, "失败项摘要：")
        for conclusion_card in self.err_rules_res:
            report += conclusion_card.serialize(style, ConclusionCardType.SUMMARY)
        report += style.title(2, "警告：")
        report += style.unordered_list(self.warnings)
        report += style.title_paragraph("TIPS", "详细校验原理与说明参考本工具的《README.md》")

        report += style.title(1, "详细数据")
        for dbname, contents in self.content.items():
            report += style.title(2, "数据库%s" % dbname)
            report += style.title(3, "元数据系统表结构")
            for conclusion_card in contents[0]:
                report += conclusion_card.serialize(style, ConclusionCardType.STRUCTURE)

            report += style.title(3, "元数据系统表内容")
            for conclusion_card in contents[1]:
                report += conclusion_card.serialize(style, ConclusionCardType.CONTENT)

            report += style.title(3, "常规通用校验")
            for conclusion_card in contents[2]:
                report += conclusion_card.serialize(style, ConclusionCardType.COMMON)

        return report


class StyleFactory(object):
    """
    风格工厂
    """
    @staticmethod
    def produce(fmt):
        if fmt == ReportFormat.MARKDOWN:
            return MarkDown()
        else:
            return MarkDown()


class Reporter(object):
    """
    报告生成器
    """
    def __init__(self, file, fmt, granularity):
        self._file_path = file

        try:
            self._file = open(file, 'a')  # 结果文件
        except FileNotFoundError:
            logger.err('无法打开文件:' + file)

        self._current_dbname = ''  # 当前记录的数据库名称
        self._report = Report()  # 结果
        self._style = StyleFactory.produce(fmt)  # 风格
        self._granularity = granularity  # 粒度

    def __del__(self):
        if self._file is not None:
            self._file.close()

    def __str__(self):
        return 'Reporter: granularity{0}, file({1})'.format(self._granularity, self._file_path)

    def record_info(self, db_info='', vmap_info=''):
        self._report.db_info = db_info
        self._report.vmap_info = vmap_info

    def _collect_statistic(self, old_errno, new_errno, dbname, conclusion):
        """
        整理记录校验过程中的统计信息。
        :param old_errno:
        :param new_errno:
        :param dbname:
        :param conclusion:
        :return:
        """
        suc = True if old_errno == new_errno else False
        if suc:
            self._report.rule_suc_count += 1
        else:
            self._report.rule_err_count += 1

        detail_err_count = new_errno - old_errno
        detail_suc_count = len(conclusion.details) - detail_err_count
        self._report.detail_suc_count += detail_suc_count
        self._report.detail_err_count += detail_err_count


        if self._granularity == ReportMode.DETAIL:
            data = self._report.content.get(dbname)
            assert data is not None
            logger.debug('当前数据库{0}记录结论小项分别为{1},{2},{3}'.format(
                dbname,
                len(data[0]),
                len(data[1]),
                len(data[2]))
            )

    def _transform_conclusion(self, dbname, conclusion):
        """

        :param dbname:
        :param conclusion:
        :return:
        """
        row_num = 0

        for row in conclusion.details:
            row_num += 1

            result_state = 'SUCCESS' if row['state'] == ConclusionState.SUCCESS else \
                'ERROR(err-num-%d)' % self._current_errno
            row_res_base = [
                conclusion.rule.sql,
                conclusion.rule.sql_desc,
                row_num,
                result_state,
                row['summary']
            ]
            if row['state'] == ConclusionState.FAILED:
                self._report.err_rules_res.append([dbname] + row_res_base)
                self._current_errno += 1

    def record(self, dbname, conclusion):
        """
        记录一条结论到report内。并更新统计数据
        """
        if dbname != self._current_dbname:
            self._report.content[dbname] = [[], [], []]
            self._current_dbname = dbname

        # statistic
        if conclusion.all_success():
            self._report.rule_suc_count += 1
        else:
            self._report.rule_err_count += 1
        self._report.detail_suc_count += conclusion.suc_count
        self._report.detail_err_count += conclusion.err_count
        logger.debug('reporter 新增记录规则结论，结论成功状态{0}, 结论明细共计{1}条, 成功{2}，失败{3}。'.format(
            conclusion.all_success(),
            len(conclusion.details),
            conclusion.suc_count,
            conclusion.err_count)
        )

        # record warnings
        self._report.warnings += conclusion.warnings

        # record details
        if conclusion.all_success() and self._granularity == ReportMode.SUMMARY:
            # if rule success and not need detail, just return
            return
        cc = ConclusionCard((self._report.rule_suc_count + self._report.rule_err_count), conclusion, dbname)
        # generate summary
        if not conclusion.all_success():
            self._report.err_rules_res.append(cc)
        # generate detail
        if self._granularity != ReportMode.SUMMARY:
            data = self._report.content.get(dbname)
            assert data is not None
            if isinstance(conclusion.rule, StructRule):
                data[0].append(cc)
            elif isinstance(conclusion.rule, ContentRule):
                data[1].append(cc)
            elif isinstance(conclusion.rule, CommonRule):
                data[2].append(cc)
            else:
                assert False

    def report(self):
        """
        :return:
        """
        logger.log('开始整理生成报告......')
        if self._granularity == ReportMode.DETAIL:
            logger.info('详细报告整理中，这可能需要较长时间......')

        self._file.write(self._report.serialize(self._style))
        logger.log('报告生成完成 %s。' % self._file_path)
