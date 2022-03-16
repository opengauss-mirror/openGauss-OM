# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
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
#############################################################################

from base_diff.comm_constants import CommConstants


class SingleInstDiff:
    """utility for single instance"""
    @staticmethod
    def get_package_tar_lists(is_single_inst, packageDir):
        tarDir = "*.log script version.cfg lib"
        tar_lists = "--exclude=script/*.log --exclude=%s %s %s" % \
                    (tarDir, CommConstants.UPGRADE_SQL_SHA,
                     CommConstants.UPGRADE_SQL_FILE)
        return tar_lists

