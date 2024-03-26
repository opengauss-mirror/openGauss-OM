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
openGauss查询模块，用于连接og进行sql查询，并将查询结果进行包装返回。
"""

import subprocess
from subprocess import Popen, PIPE
from upgrade_checker.log import logger
from upgrade_checker.utils.singleton import singleton
from upgrade_checker.utils.command import Shell


class QueryResult(object):
    """
    og查询结果。用于将查询结果进行封装和处理。
    需要注意的是，目前暂时不能处理结果行中包含换行的场景，会导致结果拆分错误，因此在设计查询SQL时应注意。
    """
    def __init__(self, sql, data, err):
        self._sql = sql  # sql
        self.errmsg = err if err != '' else None  # 错误信息
        self.attr = []  # 列名
        self.data = []  # 结果
        self._idx = 0   # 迭代输出结果的指针

        if self.errmsg is not None:
            logger.err("openGauss查询出错，\n查询命令:\n%s\n错误信息：\n%s" % (sql, err))

        if data is None or len(data) == 0:
            return

        data = data.split('\n')
        self.attr = [name.strip() for name in data[0].split('|')]
        for row in data[2:-3]:  # 删掉最后的行数和空行
            self.data.append(tuple(col.strip() for col in row.split('|')))

    def __getitem__(self, idx):
        if idx >= len(self.data):
            raise StopIteration
        row = self.data[idx]
        return row

    def row_count(self):
        return len(self.data)

    def col_count(self):
        return len(self.attr)

    def size(self):
        """
        :return: 行数, 列数
        """
        return self.row_count(), self.col_count()

    def output(self):
        return self.attr, self.data

    def value(self):
        assert self.size() == (1, 1)
        return self.data[0][0]

    def reset_iterate(self):
        self._idx = 0

    def iterate(self, format_dict=False):
        """
        迭代输出下一行，直接输出tuple，或者组装成dict进行输出
        :return:
        """
        if self._idx >= len(self.data):
            self._idx = 0
            return

        if format_dict:
            row = dict(zip(self.attr, self.data[self._idx]))
        else:
            row = self.data[self._idx]

        return row


@singleton
class OpenGauss(object):
    """
    openGauss连接模块，用于连接openGauss，执行查询、非查询语句。
    """
    def __init__(self):
        self._dbname = 'postgres'
        self._port = 5432
        self.version_info = ''
        self.version = ''
        self.nodename = ''

    def __str__(self):
        return '{0} [ RUN - nodename {1} port {2} ]'.format(
            self.version_info,
            self.nodename,
            self._port)

    def connect(self, dbname=None, port=None):
        """
        链接数据库
        :param dbname: database name
        :param port: 端口号
        :return:
        """
        self._dbname = dbname if dbname is not None else self._dbname
        self._port = port if port is not None else self._port

        self.version_info = self.query('select version();').value()
        parts = self.version_info.split(' ')
        self.version = parts[1] if parts[0] == '(openGauss' else parts[3]

        res = self.query('show pgxc_node_name;')
        self.nodename = res.data[0][0]

        logger.log('openGauss {0} {1} (port={2} db={3}) 连接成功.'.format(
            self.version,
            self.nodename,
            self._port,
            self._dbname))
        return self

    def query(self, sql, dbname=None, port=None):
        """
        执行select，获取结果
        :param sql: 查询语句
        :param dbname: 指定的数据库名
        :param port: 指定的端口号
        :return:
        """
        dbname = dbname if dbname is not None else self._dbname
        port = port if port is not None else self._port
        cmd = 'gsql -p {0} -d {1} -r'.format(port, dbname)
        data, err = Shell.communicate(cmd, sql, check=False)
        logger.debug('openGauss查询执行：{0}\n{1}'.format(cmd, sql))
        return QueryResult(sql, data, err)

    def execute(self, sql):
        """
        执行非select语句。
        :param sql:查询语句
        :return:
        """
        cmd = 'gsql -d %s -p %d -c "%s"' % (self._dbname, self._port, sql)
        Shell.communicate(cmd, sql, check=True)


# 单例模式，全局仅一个
og = OpenGauss()


if __name__ == "__main__":
    pass
