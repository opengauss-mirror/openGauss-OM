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
用于创建Rule的构造器
"""

import copy
from enum import Enum
from upgrade_checker.log import logger
from upgrade_checker.opengauss import og
from upgrade_checker.rules.meta import META, filter_uncertain_metas
from upgrade_checker.rules.rule import StructRule, ContentRule, COMMON_RULES


class RelKind(Enum):
    UNKNOWN = ''
    TABLE = 'r'
    VIEW = 'v'
    INDEX = 'i'


class PgClassItem(object):
    @staticmethod
    def construct_sql():
        """
        PgClassItem的构造SQL，将会通过这个SQL的查询结构，构造一个PgClassItem。
        :return:
        """
        uncertain_metas = filter_uncertain_metas()
        tables = [("'%s'" % tb) for tb in uncertain_metas]
        tables = ', '.join(tables)
        sql = """
            select c.oid,
                   c.relnamespace,
                   n.nspname,
                   c.relname,
                   c.relhasoids,
                   c.relkind,
                   ( select string_agg(a.attname, ',' order by a.attnum)::text
                     from pg_attribute a
                     where a.attrelid = c.oid and a.attnum > 0 and a.attisdropped != true
                   ) as columns,
                   n.nspname || '.' || c.relname as relkey
            from pg_class c
                 left join pg_namespace n on c.relnamespace = n.oid
            where c.relkind = 'r' and (c.oid < 16384 or relkey in (%s));
        """ % tables
        return sql

    def __init__(self, meta1):
        """
        通过数据库查询到的结果和工具内的分类信息等，构造一个检查对象。
        :param meta1: 通过construct_sql到数据库查询来的数据。
        """
        self.oid = int(meta1[0])
        self.schema = int(meta1[1])
        self.schema_name = meta1[2]
        self.name = meta1[3]
        self.key = "%s.%s" % (self.schema_name, self.name)
        self.has_oid = True if meta1[4] == 't' else False
        self.kind = meta1[5]
        self.columns = meta1[6].split(',')
        if self.has_oid:
            self.columns.append('oid')

        meta2 = META.get(self.key)
        if meta2 is None:
            meta2 = META["default.default"]
        self.category = meta2.category
        self.desc = meta2.desc
        self.certain = meta2.certain

        logger.debug("pg_class item: %s 生成完成。" % self.key)
        logger.debug(self.show_info())

    def show_info(self):
        return 'PgClassItem: {0}, {1}'.format(self.key, self.category)


class RuleMaker(object):

    @staticmethod
    def process_oid_projection(columns):
        """
        将这一系列类型oid的列名加case when，大于1W时调整为0，并返回列表
        :param columns: 类型为oid的列。
        :return:
        """
        if isinstance(columns, str):
            columns = columns.split(",")

        projections = []
        for col in columns:
            projections.append("(case when %s < 10000 then %s else 0 end)" % (col, col))
        return projections

    @staticmethod
    def construct_text_concat_projection(columns):
        """
        将这些列，类型转换为text并进行链接
        :param columns:
        :return:
        """
        text_columns = ['({0}::text)'.format(col) for col in columns]
        return ' || '.join(text_columns)

    @staticmethod
    def construct_md5_projection(column):
        """
        传入MD5函数，构造这么一个投影
        :param column:
        :return:
        """
        return 'md5(' + column + ")"

    @staticmethod
    def make_structure_rules(pci):
        """
        为一个系统表，构造一份校验基本表结构的方案。
        :param pci:
        :return:
        """
        rules = []
        # 通过函数获取综合信息。
        # pg_get_tabledef是不稳定的，当有多个索引时，索引的输出顺序根据缓存命中顺序而定，因此需要进行特殊处理。
        stable_proj = "select string_agg(x, e'\n' order by x collate \"C\")" \
                      "from (select json_array_elements(" \
                      "                 array_to_json(" \
                      "                     string_to_array(" \
                      "                         pg_get_tabledef('{0}'), e'\n')))::text" \
                      "     ) as a(x)".format(pci.key)
        sql = "SELECT 'pg_get_tabledef({0})', md5(({1}))".format(pci.key, stable_proj)
        sql_desc = "通过pg_get_tabledef()函数整体校验系统表%s的结构信息" % pci.name
        key_desc = "系统表%s"
        rules.append(StructRule(pci.key, pci.category, sql, sql_desc, key_desc))
        logger.debug('pic structure rule 生成完成。')
        return rules

    @staticmethod
    def make_content_rules(pci):
        """
        对一个系统表，构造一个校验内容的方案。
        :param pci: pg_class item
        :return:
        """
        rules = []

        # 对于不一定存在的系统表，不校验内容。
        if not pci.certain or pci.oid > 16383:
            return rules

        metas = META.get(pci.key)
        if metas is None:
            metas = META.get("default.default")

        for meta in metas.content_rules_meta:
            # 如果提供了完整的SQL，则直接使用
            if meta.complete_sql is not None:
                assert meta.complete_sql_desc is not None
                rules.append(
                    ContentRule(pci.key, pci.category, meta.complete_sql,
                                meta.complete_sql_desc, meta.key_desc, meta.accuracy)
                )
                continue

            # 生成检测列的投影。忽略需要忽略的列，oid类型的列处理后统一放在最前面。
            # 不可用set做删除操作，会导致顺序错乱，进而无法。
            val_columns = []
            should_ignore = meta.ignore_col + meta.oid_col
            for col in pci.columns:
                if col in should_ignore:
                    continue
                val_columns.append(col)

            val_columns += RuleMaker.process_oid_projection(meta.oid_col)
            val_project = RuleMaker.construct_text_concat_projection(val_columns)
            val_project = RuleMaker.construct_md5_projection(val_project)

            # 处理运算键的投影, 如果没有写，则默认内容就当作键。
            key_project = meta.key if meta.key is not None else val_project

            # 合成一个sql
            sql = "select {0}, {1} from {2} where {3}".format(
                key_project, val_project, pci.key, meta.filters
            )
            sql_desc = "校验系统表{0}内容，其功能为:{1}。校验忽略列({2})".format(
                pci.key, pci.desc, ",".join(meta.ignore_col)
            )

            # 构造一个规则
            rules.append(ContentRule(pci.key, pci.category, sql, sql_desc, meta.key_desc, meta.accuracy))

        logger.debug('pci content rule 生成完成。')
        return rules

    @staticmethod
    def make_common_rules():
        return copy.deepcopy(COMMON_RULES)

    @staticmethod
    def make_rules(database):
        """
        连接数据库
        :param database:
        :return:
        """
        rules = []
        og.connect(database)
        qres = og.query(PgClassItem.construct_sql())
        for row in qres:
            pci = PgClassItem(row)
            rules += RuleMaker.make_structure_rules(pci)
            rules += RuleMaker.make_content_rules(pci)
        rules += RuleMaker.make_common_rules()
        return rules
