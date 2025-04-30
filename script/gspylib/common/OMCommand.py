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
# Description  : OMCommand.py is utility to execute the OM command
#############################################################################
import os
import sys
import time
import subprocess
from datetime import datetime, timedelta
from multiprocessing.dummy import Pool as ThreadPool

sys.path.append(sys.path[0] + "/../../")
from gspylib.common.Common import DefaultValue, ClusterCommand, \
    TempfileManagement
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.user_util import UserUtil
from base_utils.os.cmd_util import CmdUtil


class OMCommand():
    """
    Descript command of om
    """

    def __init__(self):
        '''  
        Constructor
        '''

    @staticmethod
    def getLocalScript(script):
        """
        function: get local script by GPHOME
        input : script, path
        output: path
        """
        Current_Path = os.path.dirname(os.path.realpath(__file__))

        if os.getuid() != 0:
            gp_home = EnvUtil.getEnv("GPHOME")
            if gp_home:
                Current_Path = os.path.join(gp_home, "script/gspylib/common")

        LocalScript = {
            "Local_Backup": os.path.normpath(
                Current_Path + "/../../local/Backup.py"),
            "Local_Check_Config": os.path.normpath(
                Current_Path + "/../../local/CheckConfig.py"),
            "Local_Check_Install": os.path.normpath(
                Current_Path + "/../../local/CheckInstall.py"),
            "Local_Check_Uninstall": os.path.normpath(
                Current_Path + "/../../local/CheckUninstall.py"),
            "Local_Clean_Instance": os.path.normpath(
                Current_Path + "/../../local/CleanInstance.py"),
            "Local_Clean_OsUser": os.path.normpath(
                Current_Path + "/../../local/CleanOsUser.py"),
            "Local_Config_Hba": os.path.normpath(
                Current_Path + "/../../local/ConfigHba.py"),
            "Local_Config_CM_Res": os.path.normpath(
                Current_Path + "/../../local/config_cm_resource.py"),
            "Local_Config_Instance": os.path.normpath(
                Current_Path + "/../../local/ConfigInstance.py"),
            "Local_Init_Instance": os.path.normpath(
                Current_Path + "/../../local/InitInstance.py"),
            "Local_Install": os.path.normpath(
                Current_Path + "/../../local/Install.py"),
            "Local_Restore": os.path.normpath(
                Current_Path + "/../../local/Restore.py"),
            "Local_Uninstall": os.path.normpath(
                Current_Path + "/../../local/Uninstall.py"),
            "Local_PreInstall": os.path.normpath(
                Current_Path + "/../../local/PreInstallUtility.py"),
            "Local_Check_PreInstall": os.path.normpath(
                Current_Path + "/../../local/CheckPreInstall.py"),
            "Local_UnPreInstall": os.path.normpath(
                Current_Path + "/../../local/UnPreInstallUtility.py"),
            "Local_Roach": os.path.normpath(
                Current_Path + "/../../local/LocalRoach.py"),
            "Gauss_UnInstall": os.path.normpath(
                Current_Path + "/../../gs_uninstall"),
            "Gauss_Backup": os.path.normpath(
                Current_Path + "/../../gs_backup"),
            "Local_CheckOS": os.path.normpath(
                Current_Path + "/../../local/LocalCheckOS.py"),
            "Local_CheckSE": os.path.normpath(
                Current_Path + "/../../local/LocalCheckSE.py"),
            "Local_Check_Pre_Upgrade": os.path.normpath(
                Current_Path + "/../../local/local_check_pre_upgrade.py"),
            "Local_Check": os.path.normpath(
                Current_Path + "/../../local/LocalCheck.py"),
            "LOCAL_PERFORMANCE_CHECK": os.path.normpath(
                Current_Path + "/../../local/LocalPerformanceCheck.py"),
            "Gauss_CheckOS": os.path.normpath(
                Current_Path + "/../../gs_checkos"),
            "Gauss_CheckSE": os.path.normpath(
                Current_Path + "/../../gs_checkse"),
            "Gauss_PreInstall": os.path.normpath(
                Current_Path + "/../../gs_preinstall"),
            "Gauss_Replace": os.path.normpath(
                Current_Path + "/../../gs_replace"),
            "Gauss_Om": os.path.normpath(Current_Path + "/../../gs_om"),
            "UTIL_GAUSS_STAT": os.path.normpath(
                Current_Path + "/../../gspylib/common/GaussStat.py"),
            "Gauss_Check": os.path.normpath(Current_Path + "/../../gs_check"),
            "Local_Collect": os.path.normpath(
                Current_Path + "/../../local/LocalCollect.py"),
            "Local_Kerberos": os.path.normpath(
                Current_Path + "/../../local/KerberosUtility.py"),
            "Local_Execute_Sql": os.path.normpath(
                Current_Path + "/../../local/ExecuteSql.py"),
            "Local_StartInstance": os.path.normpath(
                Current_Path + "/../../local/StartInstance.py"),
            "Local_StopInstance": os.path.normpath(
                Current_Path + "/../../local/StopInstance.py"),
            "Local_Check_Upgrade": os.path.normpath(
                Current_Path + "/../../local/CheckUpgrade.py"),
            "Local_Check_SshAgent": os.path.normpath(Current_Path
                                                     + "/../../local/CheckSshAgent.py"),
            "Local_Upgrade_Utility": os.path.normpath(
                Current_Path + "/../../local/UpgradeUtility.py"),
            "Local_Upgrade_CM": os.path.normpath(
                Current_Path + "/../../local/upgrade_cm_utility.py"),
            "Local_Operate_CM": os.path.normpath(
                Current_Path + "/../../local/LocalCmOpt.py")
        }

        return "python3 '%s'" % LocalScript[script]

    @staticmethod
    def doCheckStaus(user, nodeId, cluster_normal_status=None,
                     expected_redistributing=""):
        """
        function: Check cluster status
        input : user, nodeId, cluster_normal_status, expected_redistributing
        output: status, output
        """
        try:

            statusFile = "%s/gauss_check_status_%s_%d.dat" % (os.environ['HOME'], user,
                                                              os.getpid())
            TempfileManagement.removeTempFile(statusFile)
            cmd = ClusterCommand.getQueryStatusCmd("", statusFile)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                TempfileManagement.removeTempFile(statusFile)
                return (status, output)

            clusterStatus = DbClusterStatus()
            clusterStatus.initFromFile(statusFile)
            TempfileManagement.removeTempFile(statusFile)
        except Exception as e:
            FileUtil.cleanTmpFile(statusFile)
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51600"] + "Error: %s." % str(e))
        status = 0
        output = ""
        statusRep = None
        if nodeId > 0:
            nodeStatus = clusterStatus.getDbNodeStatusById(nodeId)
            if nodeStatus is None:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51619"] % nodeId)

            status = 0 if nodeStatus.isNodeHealthy() else 1
            statusRep = nodeStatus.getNodeStatusReport()
        else:
            status = 0 if clusterStatus.isAllHealthy(cluster_normal_status) \
                          and (clusterStatus.redistributing ==
                                expected_redistributing or
                                expected_redistributing == "") else 1
            statusRep = clusterStatus.getClusterStatusReport()
            output += "cluster_state      : %s\n" % clusterStatus.clusterStatus
            output += "redistributing     : %s\n" % clusterStatus.redistributing
            output += "node_count         : %d\n" % statusRep.nodeCount
        output += "Datanode State\n"
        output += "    primary        : %d\n" % statusRep.dnPrimary
        output += "    standby        : %d\n" % statusRep.dnStandby
        output += "    secondary      : %d\n" % statusRep.dnDummy
        output += "    building       : %d\n" % statusRep.dnBuild
        output += "    abnormal       : %d\n" % statusRep.dnAbnormal
        output += "    down           : %d\n" % statusRep.dnDown

        return (status, output)

    @staticmethod
    def getClusterStatus(isExpandScene=False):
        """
        function: get cluster status
        input : user
        output: clusterStatus
        """
        userAbsolutePath = UserUtil.getUserHomePath()
        statusFile = "%s/gauss_check_status_%d.dat" % (
        userAbsolutePath, os.getpid())
        TempfileManagement.removeTempFile(statusFile)
        cmd = ClusterCommand.getQueryStatusCmd("", statusFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            TempfileManagement.removeTempFile(statusFile)
            return None
        clusterStatus = DbClusterStatus()
        clusterStatus.initFromFile(statusFile, isExpandScene)
        TempfileManagement.removeTempFile(statusFile)
        return clusterStatus

    @staticmethod
    def wait_for_normal(logger, user, timeout=300, delta=5):

        status_file = os.path.join(os.path.expanduser(f"~{user}"), "gauss_check_status_%d.dat" % os.getpid())

        try:
            logger.debug("Waiting for cluster status being satisfied.")
            end_time = None if timeout <= 0 else datetime.now() + timedelta(
                seconds=timeout)
            check_status = 0
            while True:
                time.sleep(delta)
                if end_time is not None and datetime.now() >= end_time:
                    check_status = 1
                    logger.debug("Timeout. The cluster is not available.")
                    break
                # View the cluster status
                cmd = ClusterCommand.getQueryStatusCmd(outFile=status_file)
                status, output = CmdUtil.retryGetstatusoutput(cmd, retry_time=0)
                if status != 0:
                    logger.debug(
                        "Failed to obtain the cluster status. Error: \n%s" %
                        output)
                    continue
                # Determine whether the cluster status is normal or degraded
                cluster_status = DbClusterStatus()
                cluster_status.initFromFile(status_file)
                if cluster_status.clusterStatus == "Normal":
                    logger.log("The cluster status is Normal.")
                    break
                else:
                    logger.debug("Cluster status is %s(%s)." %
                                 (cluster_status.clusterStatus,
                                  cluster_status.clusterStatusDetail))

            if check_status != 0:
                raise Exception(ErrorCode.GAUSS_528["GAUSS_52800"] %
                                (cluster_status.clusterStatus,
                                 cluster_status.clusterStatusDetail))
            logger.debug("Successfully wait for cluster status become Normal.",
                         "constant")
        finally:
            if os.path.exists(status_file):
                os.remove(status_file)
