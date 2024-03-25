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
MarkDown格式。
定义了md格式的各种封装了的操作。
"""


class MDUnorderedList(object):
    """
    MD格式无序列表。样例格式如下：
    - content1
    - content2
    """
    def __init__(self):
        self.line_count = 0
        self.res = ""

    def append(self, content):
        """

        :param content:
        :return:
        """
        self.res += ('- ' + content + '\n')
        self.line_count += 1

    def serialize(self):
        """

        :return:
        """
        if self.line_count == 0:
            return '无\n\n'

        return self.res + '\n\n'


class MDTable(object):
    """
    MD格式的表。样例格式如下:
    <table>
      <thead align="left">
        <tr>
          <th class="cellrowborder" valign="top"><p>名称</p></th>
          ...
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="cellrowborder" valign="top"><p>schemaname</p></td>
            ...
        </tr>
        ...
      </tbody>
    </table>
    """

    def __init__(self, title):
        """

        :param title:
        """
        self.column_len = len(title)
        if self.column_len == 0:
            return

        self.thead = '    <tr>\n'
        for col in title:
            self.thead += '      <th class="cellrowborder" valign="top"><p>{0}</p></th>\n'.format(col)
        self.thead += '    </tr>\n'

        self.tbody = ''

    def append(self, row):
        """
        追加一行数据
        :param row:
        :return:
        """
        if self.column_len == 0:
            return
        self.tbody += '    <tr>\n'
        for i in range(0, self.column_len):
            data = row[i] if i < len(row) else ' - '
            self.tbody += '      <td class="cellrowborder" valign="top"><p>{0}</p></td>\n'.format(data)
        self.tbody += '    </tr>\n'

    def serialize(self):
        """
        序列化输出结果
        :return:
        """
        if self.column_len == 0:
            return ''

        if self.tbody == '':
            self.append([])

        return "<table>\n" \
               "  <thead align=\"left\">\n" \
               "{0}" \
               "  </thead>\n" \
               "  <tbody>\n" \
               "{1}" \
               "  </tbody>\n" \
               "</table>\n\n".format(self.thead, self.tbody)


class MarkDown(object):

    @staticmethod
    def title(level, title):
        """
        样例: # title
        :param level: 等级
        :param title: 内容
        :return:
        """
        return "#" * level + ' ' + title + '\n\n'

    @staticmethod
    def title_paragraph(title, content):
        """
        样例:  **title**: paragraph
        :param title:
        :param content:
        :return:
        """
        return '**%s**: %s\n\n' % (title, content)

    @staticmethod
    def emphasize(content):
        """
        样例：**xxx**
        :param content:
        :return:
        """
        return '**%s**\n\n' % content

    @staticmethod
    def text(content, indent=1):
        """

        :param content:
        :param indent:
        :return:
        """
        return '  ' * indent + content + '\n\n'

    @staticmethod
    def line_wrap():
        """

        :return:
        """
        return '\n\n'

    @staticmethod
    def table(title, tuples):
        """

        :param title:
        :param tuples:
        :return:
        """
        md_table = MDTable(title)
        for tup in tuples:
            md_table.append(tup)
        return md_table.serialize()

    @staticmethod
    def unordered_list(contents):
        """

        :param contents:
        :return:
        """
        uo_list = MDUnorderedList()
        for content in contents:
            uo_list.append(content)
        return uo_list.serialize()
