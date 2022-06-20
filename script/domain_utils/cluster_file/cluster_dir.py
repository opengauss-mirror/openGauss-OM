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
# ----------------------------------------------------------------------------
# Description  : cluster_dir.py is a utility for handling cluster dir.
#############################################################################

import os
import pwd
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.security.security_checker import SecurityChecker
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ClusterDir:

    @staticmethod
    def getInstallDir(user):
        """
        function : Get the installation directory for user
        input : NA
        output : String
        """
        # get the installation directory for user by $GAUSSHOME
        return EnvUtil.getEnvironmentParameterValue("GAUSSHOME", user)

    @staticmethod
    def getLogDirFromEnv(user):
        """
        function : Get the GAUSSLOG directory for user
        input : NA
        output : String
        """
        # get the GAUSSLOG for user
        return EnvUtil.getEnvironmentParameterValue("GAUSSLOG", user)

    @staticmethod
    def getClusterToolPath(user=""):
        """
        function : Get the value of cluster's tool path. The value can't be None or null
        input : NA
        output : String
        """
        mpprc_file = EnvUtil.getEnv(EnvUtil.MPPRC_FILE_ENV)
        echo_env_cmd = "echo $%s" % ClusterConstants.TOOL_PATH_ENV
        if not mpprc_file:
            if user != "":
                userpath = pwd.getpwnam(user).pw_dir
                mpprc_file = os.path.join(userpath, ".bashrc")
            else:
                mpprc_file = ClusterConstants.BASHRC
        cmd = CmdUtil.getExecuteCmdWithUserProfile(user, mpprc_file, echo_env_cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % ClusterConstants.TOOL_PATH_ENV
                            + " Error: \n%s" % output)

        cluster_tool_path = output.split("\n")[0]
        if not cluster_tool_path:
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % ClusterConstants.TOOL_PATH_ENV
                            + "Value: %s." % cluster_tool_path)

        #Check if the path contains illegal characters
        SecurityChecker.check_injection_char(cluster_tool_path)

        return cluster_tool_path

    @staticmethod
    def getPreClusterToolPath(xml):
        """
        function: get the cluster tool path
        input : NA
        output: NA
        """
        try:
            configed_tool_path = ClusterConfigFile.getOneClusterConfigItem("gaussdbToolPath",
                                                                           xml)
            if configed_tool_path == "":
                configed_tool_path = ClusterConstants.CLUSTER_TOOL_PATH
            SecurityChecker.check_injection_char(configed_tool_path)
            return configed_tool_path
        except Exception as exception:
            raise Exception(str(exception))

    @staticmethod
    def getUserLogDirWithUser(user):
        """
        function : Get the log directory from user
        input : String
        output : String
        """
        try:
            return EnvUtil.getEnvironmentParameterValue("GAUSSLOG", user)
        except Exception:
            return "%s/%s" % (ClusterConstants.GAUSSDB_DIR, user)

    @staticmethod
    def getBackupDir(subDir="", user=""):
        """
        function : Get the cluster's default backup directory for upgrade
        input : String
        output : String
        """
        bak_dir = "%s/backup" % ClusterDir.getClusterToolPath(user)
        if subDir != "":
            bak_dir = os.path.join(bak_dir, subDir)

        return bak_dir

    @staticmethod
    def get_pg_host():
        """
        get_pg_host
        """
        pg_host = os.environ.get("PGHOST")
        if not pg_host:
            _, pg_host = ClusterDir.get_env("PGHOST")
            return pg_host
        SecurityChecker.check_injection_char(pg_host)
        return pg_host

    @staticmethod
    def get_gauss_home():
        """
        get_gauss_home
        """
        gauss_home = os.environ.get("GAUSSHOME")
        if not gauss_home:
            _, gauss_home = ClusterDir.get_env("GAUSSHOME")
            return gauss_home
        SecurityChecker.check_injection_char(gauss_home)
        return gauss_home

    @staticmethod
    def get_env(env_param):
        cmd = "source %s; echo $%s" % (ClusterConstants.BASHRC, env_param)
        status, result = CmdUtil.exec_by_popen(cmd)
        SecurityChecker.check_injection_char(result)

        return status, result
