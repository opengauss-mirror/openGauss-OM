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
# Description  : execute local or remote cmd
#############################################################################
import os
import subprocess
import threading
import re

from base_utils.common.constantsbase import ConstantsBase
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.net_util import NetUtil
from gspylib.os.gsfile import g_file
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.security.security_checker import SecurityChecker
from base_utils.os.file_util import FileUtil
from base_utils.os.hosts_util import HostsUtil


class LocalRemoteCmd(object):
    """
    execute local or remote cmd
    """

    @staticmethod
    def cleanFile(file_name, hostname=""):
        """
        function : remove file
        input : String,hostname
        output : NA
        """
        file_list = file_name.split(",")

        cmd = ""
        for _file_name in file_list:
            delete_cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (_file_name, _file_name)
            if cmd != "":
                cmd += ';%s' % delete_cmd
            else:
                cmd = delete_cmd

        if "" != hostname and NetUtil.GetHostIpOrName() != hostname:
            cmd = CmdUtil.getSshCommand(hostname, cmd)
        CmdExecutor.execCommandLocally(cmd)

    @staticmethod
    def cleanFileDir(dir_name, g_ssh_tool=None, hostname=None):
        """
        function: clean directory or file
        input: dir_name, g_sshTool, hostname
        output:NA
        """
        cmd = g_file.SHELL_CMD_DICT["deleteDir"] % (dir_name, dir_name)
        # If clean file or directory  on local node
        if g_ssh_tool is None:
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + "Error:\n%s" % str(output))
        else:
            # Assign some remote node to clean directory or file.
            if not hostname:
                g_ssh_tool.executeCommand(cmd)
            else:
                g_ssh_tool.executeCommand(cmd, ConstantsBase.SUCCESS, hostname)

    @staticmethod
    def scpFile(ip, source_path, target_path, copy_to=True):
        """
        function : if copyTo is True, scp files to remote host else,
                   scp files to local host
        input : destination host ip
                source path
                target path
                copyTo
        output: NA
        """
        scp_cmd = ""
        if os.path.isdir(source_path):
            scp_cmd = LocalRemoteCmd.getRemoteCopyCmd(
                source_path, target_path, ip, copy_to, "directory")
        elif os.path.exists(source_path):
            scp_cmd = LocalRemoteCmd.getRemoteCopyCmd(
                source_path, target_path, ip, copy_to)

        (status, output) = subprocess.getstatusoutput(scp_cmd)
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % scp_cmd +
                            " Error:\n%s" % output)

    @staticmethod
    def checkRemoteDir(g_ssh_tool, remote_dir, hostname, mpprc_file="", local_mode=False):
        '''
        function: check the remoteDir is existing on hostname
        input: remoteDir, hostname, mpprcFile
        output:NA
        '''
        # check package dir
        # package path permission can not change to 750, or it will have permission issue.
        toolpath = remote_dir.split("/")
        toolpath[0] = "/" + toolpath[0]
        pathcmd = ""
        for path in toolpath:
            if path == "":
                continue
            cmd = g_file.SHELL_CMD_DICT["createDir"] % (
                path, path, ConstantsBase.MAX_DIRECTORY_MODE)
            pathcmd += "%s; cd '%s';" % (cmd, path)
        pathcmd = pathcmd[:-1]
        CmdExecutor.execCommandWithMode(pathcmd,
                                        g_ssh_tool, local_mode, mpprc_file, hostname)

    @staticmethod
    def getRemoteCopyCmd(src, dest, remote_host, copy_to=True,
                         path_type="", other_host=None):
        """get pssh pscp cmd"""
        opts = ""
        trace_id = threading.currentThread().getName()
        
        ENV_SOURCE_CMD = "source /etc/profile;source ~/.bashrc;" \
                     "if [ $MPPDB_ENV_SEPARATE_PATH ]; " \
                     "then source $MPPDB_ENV_SEPARATE_PATH; fi"

        if path_type == "directory":
            opts = "-x -r"
        if not SecurityChecker.check_is_ip(remote_host):
            remote_host = HostsUtil.hostname_to_ip(remote_host)
        if copy_to:
            if NetUtil.get_ip_version(remote_host) == NetUtil.NET_IPV6:
                remote_host = "[" + remote_host + "]"
            cmd = "%s;pscp --trace-id %s %s -H %s %s %s " % \
                (ENV_SOURCE_CMD, trace_id, opts.strip(), remote_host, src, dest)
            return cmd
        else:
            localhost = NetUtil.getLocalIp()
            if other_host is not None:
                localhost = other_host
            if not SecurityChecker.check_is_ip(remote_host):
                remote_host = HostsUtil.hostname_to_ip(remote_host)
            if not SecurityChecker.check_is_ip(localhost):
                localhost = HostsUtil.hostname_to_ip(localhost)
            if NetUtil.get_ip_version(localhost) == NetUtil.NET_IPV6:
                localhost = "[" + localhost + "]"
            return "%s;pssh --trace-id %s -s -H %s \" pscp %s -H %s %s %s \" " % \
                   (ENV_SOURCE_CMD, trace_id, remote_host, opts.strip(), localhost, src, dest)

