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
        """
        When compressing the lib directory of om[openGauss-Package-bak_commitid.tar.gz], 
        always some users decompress all om and server packages together.
        we should excluded the server library to avoid influence each other.
        But sometimes libpython3.*.so is needed.
        """
        tarDir = "*.log script version.cfg lib"
        tar_lists = "lib/libpython* --exclude=lib/lib*.so* "\
        "--exclude=script/*.log --exclude=%s --ignore-failed-read %s %s" % \
                    (tarDir, CommConstants.UPGRADE_SQL_SHA,
                     CommConstants.UPGRADE_SQL_FILE)
        return tar_lists

