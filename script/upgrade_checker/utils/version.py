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

# 工具版本号
# 格式举例：5000000 -> 05 00 00 00，用以对应openGauss版本号5.0.0 以及工具小版本的修改
# 不必每个版本号都完整对应，一个工具版本理论上是可以上下兼容好几个og的版本的。
UPGRADE_CHECKER_VERSION = 5010000

# 适用的openGauss版本, 起点终点的闭区间
VERSION_SUPPORT = ['5.1.0', '100.0.0']

def is_support_version(version):
    def _version_to_num(_version):
        parts = _version.split('.')
        if int(parts[0]) > 10000 or int(parts[1]) > 10000 or int(parts[2]) > 10000:
            raise ValueError('invalid version num.')
        return int(parts[0]) * 10000 * 10000 + int(parts[1]) * 10000  + int(parts[2])
    
    version_num = _version_to_num(version)
    upper_limit = _version_to_num(VERSION_SUPPORT[1])
    lower_limit = _version_to_num(VERSION_SUPPORT[0])
    
    return lower_limit <= version_num <= upper_limit
    
