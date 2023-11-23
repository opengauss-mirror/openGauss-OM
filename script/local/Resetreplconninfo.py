#!/usr/bin/env python3
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
# Description  : Resetreplconninfo.py is a utility to reset local replconninfo.
#############################################################################
import os
import getopt
import sys
import subprocess
import re
import datetime

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from domain_utils.cluster_file.cluster_log import ClusterLog

########################################################################
# Global variables define
########################################################################
g_opts = None


########################################################################
class CmdOptions():
    """
    """

    def __init__(self):
        """
        """
        self.action = ""
        self.clusterUser = ""
        self.log_file = ""


def usage():
    """
Resetreplconninfo.py is a utility to reset replconninfos on local node.

Usage:
  python3 Resetreplconninfo.py --help
  python3 Resetreplconninfo.py -U omm -t reset

General options:
  -U                                 Cluster user.
  -t                                 reset.
  --help                             Show help information for this utility,
                                     and exit the command line mode.
    """
    print(usage.__doc__)


def parseCommandLine():
    """
    function: parse command line
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "U:t:h:l", ["help"])
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

    if len(args) > 0:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    for (key, value) in opts:
        if key == "-h" or key == "--help":
            usage()
            sys.exit(0)
        elif key == "-t":
            g_opts.action = value
        elif key == "-U":
            g_opts.clusterUser = value
        elif key == "-l":
            g_opts.log_file = value


def checkParameter():
    """
    function: check parameter
    """
    if g_opts.clusterUser == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 'U' + ".")
    if g_opts.action == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + ".")
    if g_opts.action != "reset":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % 't')
    if (g_opts.log_file == ""):
        g_opts.log_file = ClusterLog.getOMLogPath(
                ClusterConstants.LOCAL_LOG_FILE, g_opts.clusterUser, "")

def init_globals():
    """
    function: Init global log
    input : NA
    output: NA
    """
    # state global variable
    global g_logger
    # Init the log file
    g_logger = GaussLog(g_opts.log_file, "resetreplconninfo")
    
class Resetreplconninfo():
    """
    class: Resetreplconninfo
    """

    def __init__(self):
        """
        function: configure all instance on local node
        """
        # get mpprc file
        envfile = EnvUtil.getEnv('MPPDB_ENV_SEPARATE_PATH')
        if envfile is not None and envfile != "":
            self.userProfile = \
                envfile.replace("\\", "\\\\").replace('"', '\\"\\"')
        else:
            self.userProfile = ClusterConstants.BASHRC

    def __getStatusByOM(self):
        """
        function :Get the environment parameter.
        output : String
        """
        cmd = "source %s;gs_om -t status --detail" % self.userProfile
        (status, output) = subprocess.getstatusoutput(cmd)
        g_logger.debug("gs_om -t status output: %s" % output)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                            % cmd + " Error: \n%s" % output)
        return output.split("\n")

    def resetRepl(self):
        """
        function: reset Repl
        input : NA
        output: NA
        """
        output_list = self.__getStatusByOM()
        output_num = 0
        pattern = re.compile("(\d+) (.*) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (.*)")
        has_cm_component = True if [i for i in output_list if "CMServer State" in i] else False
        if has_cm_component:
            output_list = [i for i in output_list if i]
            output_list = output_list[-1].split('|')
        for content in output_list:
            if pattern.search(content):
                output_num += 1
        status_list = output_list[-output_num:]
        repl_list = ['replconninfo' + str(i) for i in
                     range(1, len(status_list))]

        # each information index after split space. displayed as:
        #     node    node_ip         port      instance                       state
        # ------------------------------------------------------------------------------------------
        # 1  ecs-66cc 192.168.0.1   5432       6001 /opt/install/data/dn   P Primary Normal
        # 2  ecs-6ac8 192.168.0.2   5432       6002 /opt/install/data/dn   S Standby Normal
        # If the displayed information is changed, please modify the idx value here.
        nodename_split_idx = 1
        nodeip_split_idx = 2
        dndir_split_idx = 5
        instype_split_id = 7
        if has_cm_component:
            dndir_split_idx = 4
            instype_split_id = 6

        localhost = NetUtil.GetHostIpOrName()
        remote_ip_dict = {}
        g_logger.debug("status_list is: %s" % status_list)
        g_logger.debug("repl_list is: %s" % repl_list)
        for info_all in status_list:
            info = info_all.split()
            if info[nodename_split_idx] == localhost:
                local_dndir = info[dndir_split_idx]
            else:
                remote_ip_dict[info[nodeip_split_idx]] = info[instype_split_id]
        head_cmd = "source %s;" % self.userProfile
        for repl in repl_list:
            cmd = head_cmd + 'gs_guc check -N %s -D %s -c "%s"' % \
                  (localhost, local_dndir, repl)
            status, output = subprocess.getstatusoutput(cmd)
            g_logger.debug("cmd is %s output: %s" % (cmd, output))
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                cmd + " Error:\n%s" % output)
            # get remote ip and check iscascade
            replinfo_all = output.split('\n')[-2].strip().split("'")
            if len(replinfo_all) < 2:
                continue
            replinfo_value = replinfo_all[1].split()
            g_logger.debug("replinfo_all is %s" % replinfo_all)
            g_logger.debug("remote_ip_dict is: %s" % remote_ip_dict)
            g_logger.debug("repl is: %s" % repl)
            for remoteip in remote_ip_dict:
                if remoteip in replinfo_all[1]:
                    if remote_ip_dict[remoteip] == "Cascade" and \
                            "iscascade=true" not in replinfo_value:
                        replinfo_value.append("iscascade=true")
                    elif remote_ip_dict[remoteip] != "Cascade" and \
                            "iscascade=true" in replinfo_value:
                        replinfo_value.remove("iscascade=true")
                    else:
                        break
                    replinfo_all = \
                        replinfo_all[0] + "'" + " ".join(replinfo_value) + "'"
                    g_logger.debug("replinfo_value is: %s" % replinfo_value)
                    g_logger.debug("remoteip is: %s" % remoteip)
                    cmd = head_cmd + 'gs_guc reload -N %s -D %s -c "%s"' % \
                          (localhost, local_dndir, replinfo_all)
                    g_logger.debug("replinfo_all is: %s" % replinfo_all)
                    status, output = subprocess.getstatusoutput(cmd)
                    g_logger.debug("cmd is %s output: %s" % (cmd, output))
                    if status != 0:
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                        cmd + " Error:\n%s" % output)
                    break


if __name__ == '__main__':
    try:
        # parse and check input parameters
        parseCommandLine()
        checkParameter()
        init_globals()

        # reset replconninfos
        reseter = Resetreplconninfo()
        reseter.resetRepl()

    except Exception as e:
        GaussLog.exitWithError(str(e))

    sys.exit(0)
