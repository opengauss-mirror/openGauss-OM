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


class CommConstants:
    """ constants for open gauss."""
    PACKAGE_TYPE = "bz2File"
    VERSION_PATTERN = r'[0-9]+\.[0-9]+\.[0-9]+'
    VERSION_EXAMPLE = "openGauss-1.0"

    # upgrade sql sha file and sql file
    UPGRADE_SQL_SHA = "upgrade_sql.sha256"
    UPGRADE_SQL_FILE = "upgrade_sql.tar.gz"
    # not support grep upgrade
    FIRST_GREY_UPGRADE_NUM = -1
    DIST_NAME_TUPLE = ("redhat", "euleros", "centos", "openEuler", "FusionOS")
