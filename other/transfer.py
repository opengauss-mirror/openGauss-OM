#!/usr/bin/env python3
#Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
#openGauss is licensed under Mulan PSL v2.
#You can use this software according to the terms and conditions of the Mulan PSL v2.
#You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#-------------------------------------------------------------------------
#
# transfer.py
#    relfilenode to oid mapping cache.
#
# IDENTIFICATION
#    src/manager/om/other/transfer.py
#
#-------------------------------------------------------------------------

import os
import sys
import pwd
import getopt
import shlex

GPPATH = os.getenv("GPHOME")
sys.path.insert(0, GPPATH)
from script.gspylib.common.DbClusterInfo import dbClusterInfo
from script.gspylib.common.Common import DefaultValue
from script.gspylib.common.GaussLog import GaussLog
from script.gspylib.common.ErrorCode import ErrorCode
from script.gspylib.threads.SshTool import SshTool
from domain_utils.cluster_file.cluster_log import ClusterLog
from domain_utils.domain_common.cluster_constants import ClusterConstants

# source file path
SRCFILEPATH = ""
DRCPATH = ""
DNINSTANCEID = []
ISALLHOSTS = False
g_logger = None
g_clusterUser = ""
g_clusterInfo = None
g_sshTool = ""

def usage():
    """
transfer.py is a utility to transfer C function lib file to all nodes or standy node.

Usage:
  transfer.py -? | --help
  transfer.py 1 sourcefile  destinationpath            copy sourcefile to Cluster all nodes.
  transfer.py 2 sourcefile  pgxc_node_name             copy sourcefile to the same path of node contain pgxc_node_name standy instance.
    """

    print (usage.__doc__)


def initGlobals():
    global g_logger
    global g_clusterUser
    global g_clusterInfo
    global g_sshTool

    if os.getuid() == 0:
        GaussLog.exitWithError(ErrorCode.GAUSS_501["GAUSS_50105"])
        sys.exit(1)
    # Init user
    g_clusterUser = pwd.getpwuid(os.getuid()).pw_name
    # Init logger
    logFile = ClusterLog.getOMLogPath(ClusterConstants.LOCAL_LOG_FILE, g_clusterUser, "", "")
    g_logger = GaussLog(logFile, "Transfer_C_function_file")
    # Init ClusterInfo
    g_clusterInfo = dbClusterInfo()
    g_clusterInfo.initFromStaticConfig(g_clusterUser)
    # Init sshtool
    g_sshTool = SshTool(g_clusterInfo.getClusterNodeNames(), g_logger.logFile)

def check_injection_char(name, value):
    """
        Check injection character in parameter value
    """
    dangerous_chars = [
        "&&", "||", "$(", "${", "IFS",
        "|", ";", "&", "$", "`", "'", "\"", "\\", "<", ">",
        "(", ")", "[", "]", "{", "}", "~", "*", "?", "!", "\n", "\r"
    ]
    for ch in dangerous_chars:
        if ch in value:
            g_logger.logExit(f"Parameter [{name}] contains dangerous character: [{ch}], input illegal")

def normalize_abs_path(path):
    """
        Path normalization: force absolute path, prevent ../ path traversal, special naming
    """
    abs_p = os.path.abspath(path)
    real_p = os.path.realpath(abs_p)
    # Prevent path traversal ..
    if ".." in real_p:
        g_logger.logExit(f"Path [{path}] contains path traversal .., forbidden")
    # Limit file to GPHOME directory (business whitelist)
    ghome = os.path.abspath(GPPATH)
    if not (real_p == ghome or real_p.startswith(ghome + os.sep)):
        g_logger.logExit(f"Path [{path}] out of safe GPHOME scope [{ghome}]")
    return real_p

def checkSrcFile(srcFile):
    g_logger.log("Check whether the source file exists.")
    # First check injection character and path whitelist, then check file existence
    src_safe = normalize_abs_path(srcFile)
    if not os.path.isfile(src_safe):
        g_logger.debug(f"The {src_safe} does not exist or not regular file.")
        return False
    g_logger.log("The source file exists and passed security check.")
    return True

def parseCommandLine():
    global SRCFILEPATH
    global DRCPATH
    global DNINSTANCEID
    global ISALLHOSTS
    g_logger.log("Start parse parameter.")
    try:
        opts, args = getopt.getopt(sys.argv[1:], "")
        if len(args) != 3:
            raise getopt.GetoptError("The number of parameters is not equal to 3.")
    except getopt.GetoptError as e:
        g_logger.logExit("Parameter error, Error:\n%s" % str(e))
    if args[0] not in ['1', '2']:
        g_logger.logExit("Parameter error.")

    src_raw = args[1]
    dst_raw = args[2]
    # Unified security validation: injection character check + path whitelist
    check_injection_char("source file", src_raw)
    check_injection_char("destination path", dst_raw)
    src_safe = normalize_abs_path(src_raw)

    if args[0] == "1":
        # mode 1: copy to all nodes ,dst_raw is absolute path
        dst_safe = normalize_abs_path(dst_raw)
        ISALLHOSTS = True
        if not checkSrcFile(src_safe):
            g_logger.logExit("Source file check failed.")
        SRCFILEPATH = src_safe
        DRCPATH = dst_safe
    elif args[0] == "2":
        # mode 2: copy to standy node ,dst_raw is pgxc_node_name
        dst_safe = dst_raw
        if not checkSrcFile(src_safe):
            g_logger.logExit("Source file check failed.")
        SRCFILEPATH = src_safe
        nodenamelst = dst_safe.split("_")
        if len(nodenamelst) == 3:
            DNINSTANCEID.append(nodenamelst[2])
        else:
            for dnId in nodenamelst[2:]:
                DNINSTANCEID.append(dnId)
    g_logger.log("Successfully parse parameter, all input passed security filter.")

def scpFileToAllHost(srcFile, drcpath):
    try:
        g_logger.log("Transfer C function file to all hosts.")
        g_sshTool.scpFiles(srcFile, drcpath, g_clusterInfo.getClusterNodeNames())
        # [Fix 3] Use shlex.quote to fully escape the target path for Shell
        safe_dst = shlex.quote(drcpath)
        cmd = f"chmod 600 {safe_dst}"
        g_sshTool.executeCommand(cmd, DefaultValue.SUCCESS, g_clusterInfo.getClusterNodeNames())
    except Exception as e:
        raise Exception(ErrorCode.GAUSS_536["GAUSS_53611"] % str(e))

def scpFileToStandy(srcFile, InstanceID):
    try:
        g_logger.log("Transfer C function file to standy node.")
        mirrorID = 0
        peerNode = []
        for dbNode in g_clusterInfo.dbNodes:
            for dbInst in dbNode.datanodes:
                if str(dbInst.instanceId) == InstanceID:
                    mirrorID = dbInst.mirrorId
        if mirrorID == 0:
            g_logger.logExit("Failed to find primary instance mirrorId.")
        for node in g_clusterInfo.dbNodes:
            for instance in node.datanodes:
                if instance.mirrorId == mirrorID and (instance.instanceType == 1 or instance.instanceType == 0):
                    peerNode.append(node.name)
        (despath, sofile) = os.path.split(srcFile)
        for deshost in peerNode:
            status = g_sshTool.checkRemoteFileExist(deshost, srcFile, "")
            if not status:
                g_sshTool.scpFiles(srcFile, despath, [deshost])
    except Exception as e:
        raise Exception(ErrorCode.GAUSS_536["GAUSS_53611"] % str(e))


if __name__ == '__main__':
    # help info
    if "-?" in sys.argv[1:] or "--help" in sys.argv[1:]:
        usage()
        sys.exit(0)

    # Init globle
    initGlobals()
    g_logger.log("Start transfer C function file.")

    # parse command line
    parseCommandLine()
    # start send soFile
    try:
        if ISALLHOSTS:
            scpFileToAllHost(SRCFILEPATH, DRCPATH)
        else:
            for dnInstanceId in DNINSTANCEID:
                scpFileToStandy(SRCFILEPATH, dnInstanceId)
    except Exception as e:
        g_logger.logExit("Failed to transfer C function file. Error:%s" % str(e))
    g_logger.log("Successfully transfer C function file.")
    sys.exit(0)
