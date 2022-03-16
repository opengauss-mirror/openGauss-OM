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
# Description  : cluster_user.py for user utility.
#############################################################################
import os
import subprocess

import pwd

from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.GaussLog import GaussLog
from base_utils.os.env_util import EnvUtil
from base_utils.os.user_util import UserUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ClusterUser:
    """user utility for cluster"""

    def __init__(self):
        pass

    @staticmethod
    def checkUser(user, strict=True):
        """
        function : Check if user exists and if is the right user
        input : String,boolean
        output : NA
        """
        # get group
        try:
            UserUtil.check_user_exist(user)
        except Exception as excep:
            raise Exception(str(excep))

        # if not strict, skip
        if not strict:
            return

        # get $GAUSS_ENV, and make sure the result is correct.
        mpprc_file = EnvUtil.getEnv(EnvUtil.MPPRC_FILE_ENV)
        if mpprc_file != "" and mpprc_file is not None:
            gauss_env = EnvUtil.getEnvironmentParameterValue("GAUSS_ENV", user, mpprc_file)
        else:
            gauss_env = EnvUtil.getEnvironmentParameterValue("GAUSS_ENV", user,
                                                             ClusterConstants.BASHRC)
        if not gauss_env or str(gauss_env) != "2":
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"] %
                            ("installation path of designated user %s" % user)
                            + " Maybe the user is not right.")

    @staticmethod
    def check_user_empty(user):
        """
        function : if user if empty, exit with error
        input : user name
        output : exit with error
        """
        if user == "":
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 'U' + ".")

    @staticmethod
    def checkUserParameter(user):
        """
        Check parameter
        """
        ClusterUser.check_user_empty(user)
        if ":" in user:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % 'U')

        # check if user exists
        cmd = "cat /etc/passwd|grep -v nologin|grep -v halt|" \
              "grep -v shutdown|awk -F: '{ print $1 }'|" \
              " grep '^%s$' 2>/dev/null" % user
        status = subprocess.getstatusoutput(cmd)[0]
        if status == 0:
            if pwd.getpwnam(user).pw_uid == 0:
                # user exists and uid is 0, exit.
                GaussLog.exitWithError(ErrorCode.GAUSS_503["GAUSS_50302"])

    @staticmethod
    def checkGroupParameter(user, group):
        """
        Check group information
        """
        if group == "":
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                   % 'G' + ".")
        if user == "root" or group == "root":
            GaussLog.exitWithError(ErrorCode.GAUSS_503["GAUSS_50301"]
                                   + "User:Group[%s:%s]."
                                   % (user, group))

    @staticmethod
    def get_pg_user():
        """
        get pguser
        :return:
        """
        # get rdsAdmin user name
        user_name = pwd.getpwuid(os.getuid()).pw_name
        pg_user = EnvUtil.getEnvironmentParameterValue("PGUSER", user_name)
        if not pg_user:
            pg_user = user_name
            if not pg_user:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50300"] % user_name)
        return pg_user
