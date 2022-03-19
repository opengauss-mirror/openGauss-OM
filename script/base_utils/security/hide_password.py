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
# Description  : hide_password.py is utility for hiding password in ps commands.
#############################################################################

class HidePassword(object):
    """
    hiding password in ps commands
    """
    @staticmethod
    def get_su_user_cmd_without_real_cmd(user):
        """
        get su command and the command doesn't have real command
        """
        return 'su - %s -c "sh -"' % user

    @staticmethod
    def get_su_cmd_for_hide_password(cmd, user):
        """
        get su command, and the command has been hidden the password
        """
        su_command = HidePassword.get_su_user_cmd_without_real_cmd(user)
        return 'echo %s | %s' % (cmd, su_command)
