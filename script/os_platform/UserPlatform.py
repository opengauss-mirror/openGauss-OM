# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2020 Huawei Technologies Co.,Ltd.
# Portions Copyright (c) 2007 Agendaless Consulting and Contributors.
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
# Description  : glable os platform instance.
# ############################################################################

from gspylib.common.ErrorCode import ErrorCode
from os_platform.common import SUPPORT_WHOLE_PLATFORM_LIST, SUSE, \
    SUPPORT_RHEL_SERIES_PLATFORM_LIST, SUPPORT_USER_DEFINED_OS_LIST
from os_platform.linux_distro import LinuxDistro
from os_platform.rhel_platform import RHELPlatform
from os_platform.sles_platform import SLESPlatform


class UserPlatform(object):
    """
    manage Red Hat Enterprise Linux command,config or service for muti-platform
    """
    def __init__(self):
        """
        function : Check support OS version and init OS class
        """
        # now we support this platform:
        #     RHEL/CentOS     "6.4", "6.5", "6.6", "6.7", "6.8", "6.9",
        #     "7.0", "7.1", "7.2", "7.3", "7.4", "7.5 "64bit
        #     EulerOS         "2.0", "2.3" 64bit
        #     SuSE11          sp1/2/3/4 64bit
        #     SuSE12          sp0/1/2/3 64bit
        #     Kylin           "10" 64bit
        #     Ubuntu          "18.04" 64bit
        dist_name = LinuxDistro.linux_distribution()[0]
        if dist_name.lower() not in SUPPORT_WHOLE_PLATFORM_LIST \
            and dist_name.lower() not in SUPPORT_USER_DEFINED_OS_LIST:
            raise Exception(ErrorCode.GAUSS_519["GAUSS_51900"] +
                            "Supported platforms are: %s." % str(
                SUPPORT_WHOLE_PLATFORM_LIST))

        if dist_name.lower() == SUSE:
            # SuSE11.X SUSE12.X
            self.userPlatform = SLESPlatform()
        elif dist_name.lower() in SUPPORT_RHEL_SERIES_PLATFORM_LIST:
            # RHEL6.X RHEL7.X
            self.userPlatform = RHELPlatform()
        else:
            # EULEROS 2.0/2.3
            self.userPlatform = RHELPlatform()
        try:
            self.userPlatform.getCurrentPlatForm()
        except Exception as excep:
            raise Exception(str(excep))

# global platform class
g_Platform = UserPlatform().userPlatform
