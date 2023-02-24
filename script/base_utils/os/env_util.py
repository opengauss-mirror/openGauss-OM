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
# Description  : env_util.py is utility for env file or values.
#############################################################################

import os
import subprocess
import pwd
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.user_util import UserUtil
from base_utils.security.security_checker import SecurityChecker
from domain_utils.domain_common.cluster_constants import ClusterConstants


class EnvUtil(object):
    """utility for env file or values"""
    # env parameter
    MPPRC_FILE_ENV = "MPPDB_ENV_SEPARATE_PATH"

    @staticmethod
    def getEnvSilently(env_param, default_value=None):
        """
        function: get the filter environment variable
        input:envparam: String
              default_value: String
        output:envValue
        """
        try:
            return EnvUtil.getEnv(env_param, default_value)
        except Exception:
            return None

    @staticmethod
    def getEnv(env_param, default_value=None):
        """
        function: get the filter environment variable
        input:envparam: String
              default_value: String
        output:envValue
        """
        env_value = os.getenv(env_param)

        if env_value is None:
            if default_value:
                return default_value
            else:
                return env_value

        env_value = env_value.replace("\\", "\\\\").replace('"', '\\"\\"')

        SecurityChecker.check_injection_char(env_value)

        return env_value

    @staticmethod
    def getTmpDirFromEnv(user=""):
        """
        function : Get the temporary directory from PGHOST
        precondition: only root user or install user can call this function
        input : String
        output : String
        """
        if os.getuid() == 0 and user == "":
            return ""
        # get the temporary directory from PGHOST
        return EnvUtil.getEnvironmentParameterValue("PGHOST", user)

    @staticmethod
    def getTempDir(dir_name):
        """
        function: create temp directory in PGHOST
        input: dir_name
        output:
              pathName
        """
        tmp_path = EnvUtil.getTmpDirFromEnv()
        return os.path.join(tmp_path, dir_name)

    @staticmethod
    def getEnvironmentParameterValue(environment_parameter_name, user, env_file=None):
        """
        function : Get the environment parameter value from user
        input : String,String
        output : String
        """
        if env_file is not None:
            user_profile = env_file
        else:
            user_profile = EnvUtil.getMpprcFile()
        # buid the shell command
        SecurityChecker.check_injection_char(environment_parameter_name)
        execute_cmd = "echo $%s" % environment_parameter_name
        cmd = CmdUtil.getExecuteCmdWithUserProfile(user, user_profile, execute_cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0:
            env_value = output.split("\n")[0]
            env_value = env_value.replace("\\", "\\\\").replace('"', '\\"\\"')
            SecurityChecker.check_injection_char(env_value)
            return env_value
        return ""

    @staticmethod
    def getMpprcFile():
        """
        function : get mpprc file
        input : NA
        output : String
        """
        # get mpp file by env parameter MPPDB_ENV_SEPARATE_PATH
        mpprc_file = EnvUtil.getEnv(EnvUtil.MPPRC_FILE_ENV)
        if mpprc_file != "" and mpprc_file is not None:
            if not os.path.isabs(mpprc_file):
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51206"] % mpprc_file)
            if not os.path.exists(mpprc_file):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % mpprc_file)
        elif os.getuid() == 0:
            return ClusterConstants.ETC_PROFILE
        else:
            user_absolute_home_path = UserUtil.getUserHomePath()
            mpprc_file = os.path.join(user_absolute_home_path, ".bashrc")
        if not os.path.isfile(mpprc_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % mpprc_file)
        return mpprc_file

    @staticmethod
    def get_mpprc_global(mpprc_file):
        """
        function : get mpprc global file
        input : NA
        output : String
        """
        if mpprc_file == ClusterConstants.BASHRC or \
                mpprc_file == ClusterConstants.HOME_USER_BASHRC % \
                pwd.getpwuid(os.getuid()).pw_name:
            return ClusterConstants.ETC_PROFILE
        else:
            _, mpprc_name = os.path.split(mpprc_file)
            return "/etc/%s_global" % mpprc_name

    @staticmethod
    def source(path):
        """
        function : Get the source
        input : string
        output: True or False
        """
        cmd = CmdUtil.SOURCE_CMD
        cmd += " %s" % path
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error:\n%s" % output)
        return True

    @staticmethod
    def get_env_param(user=None, source_file=None, env_param=None,
                      other_cmd=None, out_flag=False):
        """
        function : get env param
        input : string
        output: string
        """
        cmd = ""
        if source_file:
            cmd += "source %s &&" % source_file
        else:
            cmd = "unset MPPDB_ENV_SEPARATE_PATH && source /etc/profile && " \
                  "source ~/.bashrc && if [ $MPPDB_ENV_SEPARATE_PATH ]; then " \
                  "if [ -f ${MPPDB_ENV_SEPARATE_PATH} ] ;then source " \
                  "${MPPDB_ENV_SEPARATE_PATH};fi; fi &&"

        cmd += " echo $%s " % env_param

        if user:
            cmd = "su - %s -c '%s' " % (user, cmd)

        if other_cmd:
            cmd += other_cmd

        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception("Failed to obtain the environment variable %s. "
                            "Error:\n%s" % (env_param, output))
        if not out_flag:
            if not output or output.strip() == "":
                raise Exception("Failed to obtain the environment variable %s. "
                                "Error:\n%s" % (env_param, output))

        SecurityChecker.check_injection_char(output.strip())

        return output.strip()

    @staticmethod
    def get_rdma_type(user=""):
        if os.getuid() == 0 and user == "":
            return ""
        return EnvUtil.getEnvironmentParameterValue("RDMA_TYPE", user)

    @staticmethod
    def get_rdma_config(user=""):
        if os.getuid() == 0 and user == "":
            return ""
        return EnvUtil.getEnvironmentParameterValue("RDMA_CONFIG",
                                                    user).replace("/", " ")

    @staticmethod
    def get_dss_ssl_status(user=""):
        if os.getuid() == 0 and user == "":
            return ""
        return EnvUtil.getEnvironmentParameterValue("DSS_SSL", user)

    @staticmethod
    def get_dss_home(user=""):
        if os.getuid() == 0 and user == "":
            return ""
        return EnvUtil.getEnvironmentParameterValue("DSS_HOME", user)

    @staticmethod
    def is_fuzzy_upgrade(user, logger=None, env_file=None):
        '''
        If gauss_env is 2 or the $GAUSSHOME/bin is exist, is upgrade.
        '''
        app_bin = os.path.realpath(
            os.path.join(
                EnvUtil.getEnvironmentParameterValue('GAUSSHOME',
                                                     user,
                                                     env_file=env_file),
                'bin'))
        gauss_env = EnvUtil.getEnvironmentParameterValue('GAUSS_ENV',
                                                         user,
                                                         env_file=env_file)
        if os.path.isdir(app_bin):
            if logger:
                logger.debug("The $GAUSSHOME/bin is exist.")
        if gauss_env in ["1", "2"]:
            if logger:
                logger.debug(f"The $GAUSS_ENV is {gauss_env}.")
        if os.path.isdir(app_bin) or gauss_env in ["2"]:
            if logger:
                logger.debug("There is the upgrade is in progress.")
            return True
        return False

    @staticmethod
    def is_dss_mode(user):
        dss_home = EnvUtil.get_dss_home(user)
        vgname = EnvUtil.getEnv('VGNAME')
        if os.path.isdir(dss_home) and vgname:
            return True
        else:
            return False
