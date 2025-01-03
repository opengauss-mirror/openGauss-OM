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
# Description  : env_util.py is utility for system user info.
#############################################################################
import os
import subprocess
import pwd
import grp
from gspylib.common.ErrorCode import ErrorCode


class UserUtil(object):
    """utility for system user info"""
    @staticmethod
    def check_user_exist(user):
        """
        function : get user id
        input : user
        output : user id
        """
        try:
            pwd.getpwnam(user).pw_uid
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"] % user + "Detail msg: %s" % str(e))

    @staticmethod
    def getUserHomePath():
        """
        Get home path of user
        """
        # converts the relative path to an absolute path
        cmd = "echo ~ 2>/dev/null"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % "user home")
        return output

    @staticmethod
    def getUserInfo():
        """
        function : Get user information
        input  : null
        output : user_info
        """
        user_info = {"uid": os.getuid(), "name": pwd.getpwuid(
            os.getuid()).pw_name,
                    "gid": pwd.getpwuid(os.getuid()).pw_gid}
        user_info["g_name"] = grp.getgrgid(user_info["gid"]).gr_name

        return user_info

    @staticmethod
    def getGroupByUser(user):
        """
        function : get group by user
        input : user
        output : group
        """
        try:
            group = grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"] % user +
                            "Detail msg: %s" % str(e))
        return group

    @staticmethod
    def getPathOwner(path_name):
        """
        function : Get the owner user of path.
        input : path_name
        output : user and group
        """
        user = ""
        group = ""
        # check path
        if not os.path.exists(path_name):
            return user, group
        # get use and group information
        try:
            user = pwd.getpwuid(os.stat(path_name).st_uid).pw_name
            group = grp.getgrgid(os.stat(path_name).st_gid).gr_name
            return user, group
        except Exception:
            return "", ""

    @staticmethod
    def check_path_owner(path):
        if os.path.exists(path) and os.stat(path).st_uid == 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51251"] % path)

    @staticmethod
    def is_root_user():
        """
        function : check if current user is root
        input : null
        output : true or false
        """
        if os.getuid() == 0:
            return True
        return False
