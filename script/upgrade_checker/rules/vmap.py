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
vmap结构
"""

import json
import time
import os
from json import JSONDecodeError
from upgrade_checker.utils.version import UPGRADE_CHECKER_VERSION
from upgrade_checker.utils.command import Download
from upgrade_checker.utils.exception import ShellExecException
from upgrade_checker.log import logger
from upgrade_checker.opengauss import og
from upgrade_checker.rules.rule import StructRule, ContentRule, CommonRule


class VMapHeader(object):
    """
    vmap的头部信息
    """

    @staticmethod
    def check_availability(head):
        """
        校验一个vmap是否在当前工具内可用。
        """
        curr = VMapHeader()
        if curr.vmap_version != head.vmap_version:
            err = "vmap版本不一致，期望{0}, 实际{1}".format(curr.vmap_version, head.vmap_version)
            logger.err(err)
        if curr.db_version != head.db_version:
            err = "vmap的数据库版本不一致。期望{0}, 实际{1}".format(curr.db_version, head.db_version)
            logger.err(err)

    def __init__(self, src=None):
        self.vmap_version = UPGRADE_CHECKER_VERSION
        self.db_version = og.version
        self.create_time = time.strftime("%Y-%m-%d-%H_%M_%S", time.localtime())
        
        if src is not None:
            self.vmap_version = src.get('vmap_version')
            self.db_version = src.get('db_version')
            self.create_time = src.get('create_time')
            assert self.vmap_version is not None and \
                   self.db_version is not None and \
                   self.create_time is not None
    
    def __str__(self):
        return 'version {0}, for openGauss {1}, {2}'.format(
            self.vmap_version,
            self.db_version,
            self.create_time
        )
    
    def to_dict(self):
        return {
            'vmap_version': self.vmap_version,
            'db_version': self.db_version,
            'create_time': self.create_time
        }


class VerifyMap(object):
    
    @staticmethod
    def standard_name(tool_version, db_version):
        """
        :param tool_version: 工具版本
        :param db_version: openGauss 版本
        :return: 标准校验地图的名字
        """
        return "standard_meta_verify_map_{0}_{1}.vmap".format(tool_version, db_version)
    
    @staticmethod
    def download_address(tool_version, db_version):
        """
        :param tool_version: 工具版本
        :param db_version: openGauss 版本
        :return: 标准校验地图的下载位置
        """
        return "https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker/{0}".format(
            VerifyMap.standard_name(tool_version, db_version))

    @staticmethod
    def prepare_vmap_file(directory):
        """
        准备或下载vmap文件, 检查可用操作在后续加载之后，通过vmap内记录的info信息进行。
        :param directory: 存放vmap的文件夹位置。
        :return:
        """
        standard_vmap_name = VerifyMap.standard_name(UPGRADE_CHECKER_VERSION, og.version)

        vmap_file = directory + '/' + standard_vmap_name
        if os.access(vmap_file, os.F_OK):
            logger.log('基准校验地图(%s)已存在。' % vmap_file)
        else:
            url = VerifyMap.download_address(UPGRADE_CHECKER_VERSION, og.version)
            logger.info('开始下载基准校验地图: {0}'.format(url))
            try:
                Download.wget(url, vmap_file)
                logger.info('基准校验地图下载完成: {0}'.format(vmap_file))
            except ShellExecException as e:
                msg = '基准校验地图下载失败。\n{0}'.format(e.__str__())
                logger.err(msg)
        return vmap_file

    def __init__(self, file_path):
        self.head = VMapHeader()
        self._file_path = file_path
        self._structure_map = {}     # {rule.sql: rule.simplify(), ... }
        self._content_map = {}
        self._common_map = {}

    def __str__(self):
        return 'Verify Map ({0}): {1}'.format(self.head.__str__(), self._file_path)

    def push(self, rule):
        """
        将规则加到vmap里
        """
        if self.get(rule.sql) is not None:
            logger.err('正在尝试向vmap内插入重复rule.')

        if isinstance(rule, StructRule):
            self._structure_map[rule.sql] = rule.simplify()
        elif isinstance(rule, ContentRule):
            self._content_map[rule.sql] = rule.simplify()
        elif isinstance(rule, CommonRule):
            self._common_map[rule.sql] = rule.simplify()
        else:
            assert False

    def get(self, sql):
        return self._structure_map.get(sql) or \
               self._content_map.get(sql) or \
               self._common_map.get(sql)

    def load(self):
        with open(self._file_path, 'r') as f:
            try:
                data = json.load(f)
                self.head = VMapHeader(data[0])
                self._structure_map = data[1]
                self._content_map = data[2]
                self._common_map = data[3]
                logger.log('verify map 加载成功：' + self._file_path)
            except JSONDecodeError as e:
                logger.err('文件格式内容错误，verify map 加载失败：' + self._file_path)
        
        return self

    def dump(self):
        with open(self._file_path, 'w') as f:
            data = [self.head.to_dict(),
                    self._structure_map,
                    self._content_map,
                    self._common_map]
            json.dump(data, f)
        logger.log('verify map 导出成功：' + self._file_path)

