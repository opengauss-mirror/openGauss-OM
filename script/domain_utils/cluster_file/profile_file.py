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

import os
import subprocess

from base_diff.env_variables import EnvVariables
from gspylib.common.ErrorCode import ErrorCode
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.file_util import FileUtil
from base_utils.executor.local_remote_cmd import LocalRemoteCmd
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ProfileFile:
    """ profile file utility"""

    def __init__(self):
        pass


    @staticmethod
    def removeTmpMpp(mpprc_file):
        """
        function : remove tmp mpprc file
        input : NA
        output : NA
        """
        mpp_tmp_rm = os.path.dirname(mpprc_file) + "/mpprcfile_tmp"
        if os.path.exists(mpp_tmp_rm):
            FileUtil.removeDirectory(mpp_tmp_rm)

    @staticmethod
    def checkAllNodesMpprcFile(host_list, mpprc_file):
        """
        function:check All Nodes mpprc_file
        input: host_list, appPath, mpprc_file
        output:NA
        """
        # get mppfile, make sure it exists
        if mpprc_file is None or mpprc_file == ClusterConstants.ETC_PROFILE or \
                mpprc_file == ClusterConstants.BASHRC or not os.path.exists(mpprc_file):
            return
        if len(host_list) == 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51203"] % "hostanme")
        mppTmp = os.path.dirname(mpprc_file) + "/mpprcfile_tmp"
        # Clean old tmp dir
        ProfileFile.removeTmpMpp(mpprc_file)
        # Create tmp dir for all mppfile
        FileUtil.createDirectory(mppTmp)
        # Copy every mppfile, rename them by hostname
        for host in host_list:
            catCmd = "%s %s > %s 2>&1" % (
            CmdUtil.getCatCmd(), mpprc_file, ClusterConstants.DEV_NULL)
            cmd = CmdUtil.getSshCommand(host, catCmd)
            (status, _) = subprocess.getstatusoutput(cmd)
            if status == 0:
                tmpEnv = "%s/%s_env" % (mppTmp, host)
                scpCmd = LocalRemoteCmd.getRemoteCopyCmd(mpprc_file, tmpEnv, host, False)
                CmdExecutor.execCommandLocally(scpCmd)
                ProfileFile.checkMpprcFileChange(tmpEnv, host, mpprc_file)

        # remove tmp dir
        ProfileFile.removeTmpMpp(mpprc_file)

    @staticmethod
    def checkMpprcFileChange(mpprcFile, host="local host", mpprcFile_rm=""):
        """
        function:Check if mppfile has been changed
        input: mppfile
        output:NA
        """
        # get mppfile, make sure it exists
        if mpprcFile == "" or mpprcFile is None \
                or mpprcFile == ClusterConstants.ETC_PROFILE \
                or mpprcFile == ClusterConstants.BASHRC \
                or not os.path.exists(mpprcFile):
            ProfileFile.removeTmpMpp(mpprcFile)
            return

        if host == "" or host is None:
            host = "local host"

        # read the content of mppfile
        with open(mpprcFile, 'r') as fp:
            mpp_content = fp.read()
            env_list = mpp_content.split('\n')
        while '' in env_list:
            env_list.remove('')
        env_list = EnvVariables.filter_env_variable(env_list, mpprcFile, mpprcFile_rm)

        # white elements
        list_white = ["ELK_CONFIG_DIR", "ELK_SYSTEM_TABLESPACE", "MPPDB_ENV_SEPARATE_PATH",
                      "GPHOME", "UNPACKPATH", "PATH", "LD_LIBRARY_PATH", "PYTHONPATH",
                      "GAUSS_WARNING_TYPE", "GAUSSHOME", "PATH", "LD_LIBRARY_PATH",
                      "S3_CLIENT_CRT_FILE", "GAUSS_VERSION", "PGHOST", "GS_CLUSTER_NAME",
                      "GAUSSLOG", "GAUSS_ENV", "umask"]
        # black elements
        list_black = ["|", ";", "&", "<", ">", "`", "\\", "!", "\n"]

        # check mpprcfile
        for env in env_list:
            env = env.strip()
            if env == "":
                continue
            for white in list_white:
                flag_white = 0
                flag = env.find(white)
                if env.startswith('export') or flag >= 0:
                    flag_white = 1
                    break
            if flag_white == 0:
                ProfileFile.removeTmpMpp(mpprcFile_rm)
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50219"] % env +
                    " There are illegal characters in %s." % host)
            for black in list_black:
                flag = env.find(black)
                if (flag >= 0 and env != ""):
                    ProfileFile.removeTmpMpp(mpprcFile_rm)
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50219"] % env +
                        " There are illegal characters in %s." % host)

    @staticmethod
    def sourceEnvFile(file_env):
        """
        Execute source file
        """
        cmd = "%s '%s'" % (CmdUtil.SOURCE_CMD, file_env)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or output.strip() != "":
            return (False, output)
        return (True, "")

    @staticmethod
    def check_env_file(mpprc_file="", user=""):
        """
        function: check if the env file contains msg which may cause the program failed.
        input: NA
        output: NA
        """
        (status, output) = ProfileFile.sourceEnvFile(ClusterConstants.ETC_PROFILE)
        if not status:
            return False, output

        if mpprc_file and os.path.isfile(mpprc_file):
            env_global = EnvVariables.get_mpprc_wrapper(mpprc_file)
            if os.path.exists(env_global):
                (status, output) = ProfileFile.sourceEnvFile(env_global)
                if not status:
                    return False, output

        if user and os.getuid() == 0:
            execute_cmd = "%s '%s' && %s '%s'" % (CmdUtil.SOURCE_CMD,
                                                  ClusterConstants.ETC_PROFILE,
                                                  CmdUtil.SOURCE_CMD,
                                                  ClusterConstants.BASHRC)
            if mpprc_file:
                remote_source_cmd = "if [ -f '%s' ] ; then %s '%s'; fi" % \
                                  (mpprc_file, CmdUtil.SOURCE_CMD,
                                   EnvVariables.get_mpprc_wrapper(mpprc_file))
                execute_cmd = "%s && %s" % (execute_cmd, remote_source_cmd)
            cmd = CmdUtil.getExecuteCmdWithUserProfile(user, ClusterConstants.BASHRC,
                                                          execute_cmd, False)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0 or output.strip() != "":
                return False, output
        return True, ""

    @staticmethod
    def updateUserEnvVariable(userProfile, variable, value):
        """
        function : Update the user environment variable
        input : String,String,String
        output : NA
        """
        try:
            # delete old env information
            delete_content = "^\\s*export\\s*%s=.*$" % variable
            FileUtil.deleteLine(userProfile, delete_content)
            # write the new env information into userProfile
            write_content = ['export %s=%s' % (variable, value)]
            FileUtil.writeFile(userProfile, write_content)
        except Exception as e:
            raise Exception(str(e))
