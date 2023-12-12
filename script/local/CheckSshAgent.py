#!/usr/bin/env python3
"""
-*- coding:utf-8 -*-
#############################################################################
# Copyright (c): 2021-2030, Huawei Tech. Co., Ltd.
# FileName     : CheckSshAgent.py
# Version      : GaussV5
# Date         : 2021-06-03
# Description  : CheckSshAgent.py is a utility to check whether the ssh-agent done or not.
#############################################################################
"""

try:
    import sys
    import os
    import pwd
    import optparse
    import subprocess

    sys.path.append(sys.path[0] + "/../")
    from gspylib.common.GaussLog import GaussLog
    from gspylib.common.ParameterParsecheck import Parameter
    from gspylib.common.Common import DefaultValue, ClusterCommand
    from gspylib.common.ErrorCode import ErrorCode
    from base_utils.common.fast_popen import FastPopen
    from domain_utils.cluster_file.cluster_log import ClusterLog
    from base_utils.os.env_util import EnvUtil
    from domain_utils.cluster_os.cluster_user import ClusterUser
    from domain_utils.domain_common.cluster_constants import ClusterConstants
except ImportError as err:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(err))

PIPE = -1

def usage():
    """
Usage:
    python3 CheckSshAgent.py -h|--help
    python3 CheckSshAgent.py -U user
    """
    print(usage.__doc__)


def option_parser():
    """
    :return:
    """
    parser = optparse.OptionParser(conflict_handler='resolve', version='1.0')
    parser.add_option('-h', action="store_true", dest='help', default=False,
                      help='CheckSshAgent.py thelp')
    parser.add_option('-U', dest='db_ser', type='string', default='', help='Execution User')
    parser.add_option('-X', dest='xml_file', type='string', default='', help='Execution xml file')
    return parser

def parse_args():
    """
    :return:
    """
    parser = option_parser()
    opts, args = parser.parse_args()
    if opts.help:
        usage()
        sys.exit(0)
    for key, value in list(vars(opts).items()):
        Parameter.check_parse(key, str(value))
    return opts

def kill_ssh_agent(ssh_agent, logger=""):
    """
    :param ssh_agent:
    :return:
    """
    kill_cmd = "ps ux|grep '%s'|grep -v grep |" \
               " awk '{print $2}'| xargs kill -9" % (ssh_agent)
    status, output = subprocess.getstatusoutput(kill_cmd)
    if logger:
        logger.debug("kill ssh-agent process,status is [%s],result is:%s" % (status, output))

def check_ssh_agent_available(bashrc_file, logger):
    """
    :param bashrc_file:
    :param logger:
    :return:
    """
    check_cmd = "source %s;export LD_LIBRARY_PATH=/usr/lib64;ssh-add -l" % bashrc_file
    proc = FastPopen(check_cmd, stdout=PIPE, stderr=PIPE,
                     preexec_fn=os.setsid, close_fds=True)
    stdout, stderr = proc.communicate()
    output = stdout + stderr
    status = proc.returncode
    if status == 0:
        return True
    else:
        if logger:
            logger.log("The ssh-agent process is not available;"
                       "result is:%s" % str(output))
        return False


def checkParameter():
    """
    :return:
    """
    # check user
    if optIns.db_ser == "":
        optIns.db_ser = pwd.getpwuid(os.getuid()).pw_name

    try:
        execuser = pwd.getpwuid(os.getuid()).pw_name
        if execuser != optIns.db_ser:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "U")
        #Check if user exists and if is the right user
        ClusterUser.checkUser(optIns.db_ser, False)
    except Exception as e:
        GaussLog.exitWithError(str(e))

def main():
    """
    function: main function:
              1.check ssh-agent process
              2.set ssh-agent
    input : NA
    output: NA
    """
    #Mounting private keys to ssh-agent
    bashrc_file = os.path.join(pwd.getpwuid(os.getuid()).pw_dir,
                               ".bashrc")
    list_agent_pid = DefaultValue.get_pid("ssh-agent")
    if len(list_agent_pid) > 0:
        available_flag = check_ssh_agent_available(bashrc_file, g_logger)
        if available_flag:
            return
    g_logger.log("restart the ssh-agent process fot [%s]." %optIns.db_ser)
    kill_ssh_agent("ssh-agent")
    # register ssh agent for ssh passphrase
    secret = ClusterCommand.get_pass_phrase()
    g_logger.log("Successfully get passphrase.")
    mpprcfile = EnvUtil.getMpprcFile()
    DefaultValue.register_ssh_agent(mpprcfile, g_logger)
    localDirPath = os.path.dirname(os.path.realpath(__file__))
    shell_file = os.path.join(localDirPath, "./ssh-agent.sh")
    DefaultValue.add_ssh_id_rsa(secret, bashrc_file, shell_file, g_logger)
    g_logger.log("Successfully register ssh agent.")

if __name__ == '__main__':
    try:
        # Init logger
        global g_logger
        optIns = parse_args()
        checkParameter()
        logFile = ClusterLog.getOMLogPath(ClusterConstants.LOCAL_LOG_FILE,
                                            optIns.db_ser, xml=optIns.xml_file)
        g_logger = GaussLog(logFile, "CheckSshAgent")
        main()
    except Exception as err:
        if g_logger:
            g_logger.error(str(err))
        GaussLog.exitWithError(str(err))
