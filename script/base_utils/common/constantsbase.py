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


class ConstantsBase:
    """contants"""
    def __init__(self):
        pass

    __slots__ = ()

    TRACE_ID_ENV_NAME = "OM_TRACE_ID"
    DEFAULT_DB_NAME = "postgres"
    PUBLIC_CLOUD_TEMP_TOKEN_PATH = "/tmp/tmptoken"


    ###########################
    # init authority parameter
    ###########################
    # directory mode
    DIRECTORY_MODE = 750
    # directory permission
    DIRECTORY_PERMISSION = 0o750
    # file node
    FILE_MODE = 640
    FILE_MODE_PERMISSION = 0o640
    KEY_DIRECTORY_PERMISSION = 0o700
    KEY_FILE_MODE = 600
    MIN_FILE_MODE = 400
    SPE_FILE_MODE = 500
    KEY_FILE_PERMISSION = 0o600
    KEY_DIRECTORY_MODE = 700
    MAX_DIRECTORY_MODE = 755
    SQL_FILE_MODE = 644
    # the host file permission. Do not changed it.
    HOSTS_FILE = 644
    KEY_HOSTS_FILE = 0o644

    SUCCESS = "Success"
    FAILURE = "Failure"

    ###########################
    # parallel number
    ###########################
    DEFAULT_PARALLEL_NUM = 12

    #SQL_EXEC_COMMAND
    SQL_EXEC_COMMAND_WITHOUT_HOST_WITHOUT_USER = "%s -p %s -d %s "
    SQL_EXEC_COMMAND_WITHOUT_HOST_WITH_USER = "%s -p %s -d %s -U %s -W '%s' "
