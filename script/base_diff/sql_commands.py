# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# openGauss-OM is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

from base_utils.common.constantsbase import ConstantsBase


class SqlCommands:
    @staticmethod
    def getSQLCommandForInplaceUpgradeBackup(port, database=ConstantsBase.DEFAULT_DB_NAME,
                                             gsqlBin="gsql"):
        """
        function: get SQL command for Inplace Upgrade backupOneInstanceOldClusterDBAndRel
        input: port, database
        output: cmd
        """
        cmd = ConstantsBase.SQL_EXEC_COMMAND_WITHOUT_HOST_WITHOUT_USER % (
            gsqlBin, port, database)
        return cmd

    @staticmethod
    def getSQLCommand(port, database=ConstantsBase.DEFAULT_DB_NAME,
                      gsqlBin="gsql", user_name="", user_pwd=""):
        """
        function : get SQL command
        input : port, database
        output : cmd
        """
        if user_name and user_pwd:
            cmd = ConstantsBase.SQL_EXEC_COMMAND_WITHOUT_HOST_WITH_USER % (
                gsqlBin, str(port), database, user_name, user_pwd)
            return cmd
        cmd = ConstantsBase.SQL_EXEC_COMMAND_WITHOUT_HOST_WITHOUT_USER % (
            gsqlBin, str(int(port) + 1), database)
        return cmd
