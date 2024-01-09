# -*- coding:utf-8 -*-
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
import os
import sys
import subprocess
import time
import timeit
import json
import csv
import traceback
import copy
import re

from datetime import datetime, timedelta

from gspylib.common.Common import DefaultValue, ClusterCommand, \
    ClusterInstanceConfig
from gspylib.common.DbClusterInfo import instanceInfo, \
    dbNodeInfo, dbClusterInfo, compareObject
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.SshTool import SshTool
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.os.gsfile import g_file
from gspylib.inspection.common import SharedFuncs
from gspylib.component.CM.CM_OLAP.CM_OLAP import CM_OLAP
from impl.upgrade.UpgradeConst import GreyUpgradeStep
from impl.upgrade.UpgradeConst import DualClusterStage
import impl.upgrade.UpgradeConst as const
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.executor.local_remote_cmd import LocalRemoteCmd
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.package_info import PackageInfo
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.sql_handler.sql_result import SqlResult
from base_utils.os.net_util import NetUtil


class OldVersionModules():
    """
    class: old version modules
    """

    def __init__(self):
        """
        function: constructor
        """
        # old cluster information
        self.oldDbClusterInfoModule = None
        # old cluster status
        self.oldDbClusterStatusModule = None


class UpgradeImpl:
    """
    Class: The class is used to do perform upgrade
    """
    def __init__(self, upgrade):
        """
        function: constructor
        """
        self.dnInst = None
        self.dnStandbyInsts = []
        self.context = upgrade
        self.newCommitId = ""
        self.oldCommitId = ""
        self.isLargeInplaceUpgrade = False
        self.__upgrade_across_64bit_xid = False
        self.action = upgrade.action
        self.primaryDn = None
        self.operate_action = ""

    def exitWithRetCode(self, action, succeed=True, msg=""):
        """
        funtion: should be called after cmdline parameter check
        input : action, succeed, msg, strategy
        output: NA
        """
        #########################################
        # doUpgrade
        #
        # binary-upgrade      success    failure
        #                     0          1
        #
        # binary-rollback     success    failure
        #                     2          3

        # commit-upgrade      success    failure
        #                     5          1
        #########################################

        #########################################
        # choseStrategy
        #                     success    failure
        #                     4          1
        #########################################
        if not succeed:
            if action == const.ACTION_AUTO_ROLLBACK:
                retCode = 3
            else:
                retCode = 1
        elif action in [const.ACTION_SMALL_UPGRADE,
                        const.ACTION_LARGE_UPGRADE,
                        const.ACTION_INPLACE_UPGRADE]:
            retCode = 0
        elif action == const.ACTION_AUTO_ROLLBACK:
            retCode = 2
        elif action == const.ACTION_CHOSE_STRATEGY:
            retCode = 4
        elif action == const.ACTION_COMMIT_UPGRADE:
            retCode = 5
        else:
            retCode = 1

        if msg != "":
            if self.context.logger is not None:
                if succeed:
                    self.context.logger.log(msg)
                else:
                    self.context.logger.error(msg)
            else:
                print(msg)
        sys.exit(retCode)

    def initGlobalInfos(self):
        """
        function: init global infos
        input : NA
        output: NA
        """
        self.context.logger.debug("Init global infos", "addStep")
        self.context.sshTool = SshTool(
            self.context.clusterNodes, self.context.localLog,
            DefaultValue.TIMEOUT_PSSH_BINARY_UPGRADE)
        self.initVersionInfo()
        self.initClusterConfig()
        self.initClusterType()
        self.context.logger.debug("Successfully init global infos", "constant")

    def initVersionInfo(self):
        """
        Initialize the old and new version information

        :return:
        """
        newVersionFile = VersionInfo.get_version_file()
        newClusterVersion, newClusterNumber, newCommitId = VersionInfo.get_version_info(
            newVersionFile)
        gaussHome = ClusterDir.getInstallDir(self.context.user)

        newPath = gaussHome + "_%s" % newCommitId
        oldPath = self.getClusterAppPath(const.OLD)

        if oldPath == "":
            oldPath = os.path.realpath(gaussHome)
        oldVersionFile = "%s/bin/upgrade_version" % oldPath
        try:

            (oldClusterVersion, oldClusterNumber, oldCommitId) = VersionInfo.get_version_info(
                oldVersionFile)
            self.context.logger.debug("Successfully obtained version information of "
                                      "old clusters by %s." % oldVersionFile)
        except Exception as er:
            if os.path.exists(self.context.upgradeBackupPath):
                # if upgradeBackupPath exist, it means that we do rollback first.
                # and we get cluster version from the backup file
                possibOldVersionFile = "%s/old_upgrade_version" % self.context.upgradeBackupPath
                self.context.logger.debug(str(er))
                self.context.logger.debug("Try to get the version information "
                                          "from %s." % possibOldVersionFile)
                (oldClusterVersion, oldClusterNumber, oldCommitId) = VersionInfo.get_version_info(
                    possibOldVersionFile)
            else:
                raise Exception(str(er))

        self.context.newClusterVersion = newClusterVersion
        self.context.newClusterNumber = newClusterNumber
        self.context.oldClusterVersion = oldClusterVersion
        self.context.oldClusterNumber = oldClusterNumber
        self.context.newClusterAppPath = newPath
        self.context.oldClusterAppPath = oldPath
        self.newCommitId = newCommitId
        self.oldCommitId = oldCommitId

    def setClusterDetailInfo(self):
        """
        function: set cluster detail info
        input  : NA
        output : NA
        """
        for dbNode in self.context.clusterInfo.dbNodes:
            dbNode.setDnDetailNum()
        #self.context.clusterInfo.setClusterDnCount()

    def removeOmRollbackProgressFile(self):
        """
        function: remove om rollback process file
        input  : NA
        output : NA
        """
        self.context.logger.debug("Remove the om rollback"
                                  " record progress file.")
        fileName = os.path.join(self.context.tmpDir,
                                ".upgrade_task_om_rollback_result")
        cmd = "(if [ -f '%s' ];then rm -f '%s';fi)" % (fileName, fileName)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)

    def initOmRollbackProgressFile(self):
        """
        function: init om rollback process file
        input  : NA
        output : NA
        """
        filePath = os.path.join(self.context.tmpDir,
                                ".upgrade_task_om_rollback_result")
        cmd = "echo \"OM:RUN\" > %s" % filePath
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.context.logger.debug("The cmd is %s " % cmd)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % filePath
                            + "Error: \n%s" % str(output))

        if (not self.context.isSingle):
                # send file to remote nodes
            self.context.sshTool.scpFiles(filePath, self.context.tmpDir)
        self.context.logger.debug("Successfully write file %s." % filePath)

    def run(self):
        """
        function: Do upgrade
        input : NA
        output: NA
        """
        # the action may be changed in each step,
        # if failed in auto-rollback,
        # we will check if we need to rollback
        action = self.context.action
        # upgrade backup path
        self.context.tmpDir = EnvUtil.getTmpDirFromEnv(self.context.user)
        if self.context.tmpDir == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
        self.context.upgradeBackupPath = \
            "%s/%s" % (self.context.tmpDir, "binary_upgrade")
        try:
            self.initGlobalInfos()
            self.removeOmRollbackProgressFile()
            self.commonCheck()
            
            # record operate action when gs_upgradectl
            self.operate_action = self.context.action

            # 4. get upgrade type
            # After choseStrategy, it will assign action to self.context.action
            # to do full-upgrade or binary-upgrade
            if self.context.action == const.ACTION_AUTO_UPGRADE:
                self.context.action = self.choseStrategy()
                self.context.logger.debug(
                    "%s execution takes %s steps in total" % (
                        const.GS_UPGRADECTL, ClusterCommand.countTotalSteps(
                            const.GS_UPGRADECTL, self.context.action)))
                # If get upgrade strategy failed,
                # then try to get rollback strategy.
                # Set strategyFlag as True to check
                # upgrade parameter is correct or not
                if self.context.action in [const.ACTION_LARGE_UPGRADE,
                                           const.ACTION_SMALL_UPGRADE]:
                    self.doGreyBinaryUpgrade()
                else:
                    self.doInplaceBinaryUpgrade()
            # After choseStrategy, it will assign action to self.context.action
            elif self.context.action == const.ACTION_AUTO_ROLLBACK:
                # because if we rollback with auto rollback,
                # we will rollback all the nodes,
                # but if we rollback under upgrade,
                # we will only rollback specified nodes
                self.context.action = self.choseStrategy()
                self.context.rollback = True
                if self.context.oldClusterNumber < const.RELMAP_4K_VERSION and self.context.forceRollback:
                    errMsg = "could not do force rollback in this version: %s" % self.context.oldClusterNumber
                    self.context.logger.log(errMsg)
                    self.exitWithRetCode(action, False, errMsg)
                if self.context.action == const.ACTION_INPLACE_UPGRADE:
                    self.exitWithRetCode(const.ACTION_AUTO_ROLLBACK,
                                         self.doInplaceBinaryRollback())
                else:
                    self.exitWithRetCode(const.ACTION_AUTO_ROLLBACK,
                                         self.doGreyBinaryRollback(
                                             const.ACTION_AUTO_ROLLBACK))
            elif self.context.action == const.ACTION_COMMIT_UPGRADE:
                self.context.action = self.choseStrategy()
                if self.context.action == const.ACTION_INPLACE_UPGRADE:
                    self.doInplaceCommitUpgrade()
                else:
                    self.doGreyCommitUpgrade()
            else:
                self.doChoseStrategy()
        except Exception as e:
            self.context.logger.debug(traceback.format_exc() + str(e))
            if not self.context.sshTool:
                self.context.sshTool = SshTool(
                    self.context.clusterNodes, self.context.logger,
                    DefaultValue.TIMEOUT_PSSH_BINARY_UPGRADE)
            if action == const.ACTION_AUTO_ROLLBACK and \
                    self.checkBakPathNotExists():
                if os.path.isfile(self.context.upgradePhaseInfoPath):
                    self.recordDualClusterStage(self.oldCommitId, DualClusterStage.STEP_UPGRADE_END)
                self.context.logger.log("No need to rollback.")
                self.exitWithRetCode(action, True)
            else:
                self.context.logger.error(str(e))
                self.exitWithRetCode(action, False, str(e))
        finally:
            # only used under grey upgrade, grey upgrade commit or grey upgrade rollback
            # under force and standby cluster upgrade, we don't close enable_transaction_read_only
            # at beginning, so no need to restore
            if not (self.context.is_inplace_upgrade or self.context.standbyCluster):
                cm_nodes = []
                for node in self.context.clusterInfo.dbNodes:
                    if node.cmservers:
                        cm_nodes.append(node.name)
                self.restore_cm_server_guc(const.GREY_CLUSTER_CMSCONF_FILE, False, cm_nodes)
            if self.operate_action == const.ACTION_COMMIT_UPGRADE:
                self.reload_cm_proc()

    def commonCheck(self):
        """
        Check in the common process.
        :return:
        """
        self.checkReadOnly()
        if self.context.is_grey_upgrade:
            self.getOneDNInst(checkNormal=True)
            self.checkUpgradeMode()

    def checkReadOnly(self):
        """
        check if in read only mode under grey upgrade, grey upgrade commit or
         grey upgrade rollback if not in read only, then record the value of
          enable_transaction_read_only and set it to off
        """
        # no need to check read only mode and close enable_transaction_read_only
        if self.context.standbyCluster:
            self.context.logger.debug("no need to check read only in force or"
                                      " standby cluster mode upgrade")
            return
        try:
            self.context.logger.debug("Check if in read only mode.")
            greyUpgradeFlagFile = os.path.join(self.context.upgradeBackupPath,
                                               const.GREY_UPGRADE_STEP_FILE)
            # only used under grey upgrade, grey upgrade commit or grey upgrade
            #  rollback if under grey upgrade, the flag file
            # greyUpgradeFlagFile has not been created
            # so we use is_inplace_upgrade to judge the mode
            if (self.context.action == const.ACTION_AUTO_UPGRADE and
                    not self.context.is_inplace_upgrade or
                    (os.path.isfile(greyUpgradeFlagFile) and
                     self.context.action in [const.ACTION_AUTO_ROLLBACK,
                                             const.ACTION_COMMIT_UPGRADE])):
                if self.unSetClusterReadOnlyMode() != 0:
                    raise Exception("NOTICE: "
                                    + ErrorCode.GAUSS_529["GAUSS_52907"])
            if self.context.forceRollback and not self.context.is_inplace_upgrade:
                self.close_cm_server_gucs_before_install()
                self.context.logger.debug("no need to check read only in "
                                          "force rollback after grey upgrade")
                return
            if (self.context.action == const.ACTION_AUTO_UPGRADE and
                    not self.context.is_inplace_upgrade or
                    (os.path.isfile(greyUpgradeFlagFile) and
                     self.context.action in [const.ACTION_AUTO_ROLLBACK, const.ACTION_COMMIT_UPGRADE])):
                gucStr = "default_transaction_read_only:%s" % "off"
                self.checkParam(gucStr, False)
                self.close_cm_server_gucs_before_install()
        except Exception as e:
            raise Exception(str(e))

    def checkUpgradeMode(self):
        """
        used to check if upgrade_mode is 0 under before upgrade
        if not, we set it to 0
        """
        tempPath = self.context.upgradeBackupPath
        filePath = os.path.join(tempPath, const.INPLACE_UPGRADE_STEP_FILE)
        if self.context.action == const.ACTION_AUTO_UPGRADE \
                and not os.path.exists(filePath):
            try:
                self.setUpgradeMode(0)
                self.context.logger.log(
                    "Successfully set upgrade_mode to 0.")
            except Exception as e:
                self.context.logger.log("Failed to set upgrade_mode to 0, "
                                        "please set it manually, "
                                        "or rollback first.")
                raise Exception(str(e))

    def checkBakPathNotExists(self):
        """
        check binary_upgrade exists on all nodes,
        :return: True if not exists on all nodes
        """
        try:
            cmd = "if [ -d '%s' ]; then echo 'GetDir'; else echo 'NoDir'; fi" \
                  % self.context.upgradeBackupPath
            self.context.logger.debug("Command for checking if upgrade bak "
                                      "path exists: %s" % cmd)
            outputCollect = self.context.sshTool.getSshStatusOutput(cmd)[1]
            if outputCollect.find('GetDir') >= 0:
                self.context.logger.debug("Checking result: %s"
                                          % outputCollect)
                return False
            self.context.logger.debug("Path %s does not exists on all node."
                                      % self.context.upgradeBackupPath)
            return True
        except Exception:
            self.context.logger.debug("Failed to check upgrade bak path.")
            return False

    def doChoseStrategy(self):
        """
        function: chose the strategy for upgrade
        input : NA
        output: NA
        """
        self.context.logger.debug("Choosing strategy.")
        try:
            self.context.action = self.choseStrategy()
            # we only support binary-upgrade.
            if self.context.action in [const.ACTION_SMALL_UPGRADE,
                                       const.ACTION_LARGE_UPGRADE]:
                self.exitWithRetCode(const.ACTION_CHOSE_STRATEGY,
                                     True,
                                     "Upgrade strategy: %s."
                                     % self.context.action)
            # Use inplace upgrade under special case
            else:
                self.exitWithRetCode(const.ACTION_CHOSE_STRATEGY,
                                     True,
                                     "Upgrade strategy: %s."
                                     % self.context.action)
        except Exception as e:
            self.exitWithRetCode(const.ACTION_CHOSE_STRATEGY, False, str(e))
        self.context.logger.debug("Successfully got the upgrade strategy.")

    def choseStrategy(self):
        """
        function: chose upgrade strategy
        input : NA
        output: NA
        """
        upgradeAction = None
        try:
            # get new cluster info
            newVersionFile = VersionInfo.get_version_file()
            newClusterVersion, newClusterNumber, newCommitId = \
                VersionInfo.get_version_info(newVersionFile)
            gaussHome = ClusterDir.getInstallDir(self.context.user)
            if gaussHome == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"]
                                % "$GAUSSHOME")
            if not os.path.islink(gaussHome):
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52915"])
            newPath = gaussHome + "_%s" % newCommitId
            # new app dir should exist after preinstall,
            # then we can use chose strategy
            if not os.path.exists(newPath):
                if self.context.action != const.ACTION_AUTO_ROLLBACK:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                                    % newPath)
            self.context.logger.debug(
                "Successfully obtained version information"
                " of new clusters by %s." % newVersionFile)

            # get the old cluster info, if binary_upgrade does not exists,
            # try to copy from other nodes
            oldPath = self.getClusterAppPath(const.OLD)
            if oldPath == "":
                self.context.logger.debug("Cannot get the old install "
                                          "path from table and file.")
                oldPath = os.path.realpath(gaussHome)
            self.context.logger.debug("Old cluster app path is %s" % oldPath)

            oldVersionFile = "%s/bin/upgrade_version" % oldPath
            try:
                (oldClusterVersion, oldClusterNumber, oldCommitId) = \
                    VersionInfo.get_version_info(oldVersionFile)
                self.context.logger.debug("Successfully obtained version"
                                          " information of old clusters by %s."
                                          % oldVersionFile)
            except Exception as e:
                if os.path.exists(self.context.upgradeBackupPath):
                    # if upgradeBackupPath exist,
                    # it means that we do rollback first.
                    # and we get cluster version from the backup file
                    possibOldVersionFile = "%s/old_upgrade_version" \
                                           % self.context.upgradeBackupPath
                    self.context.logger.debug(str(e))
                    self.context.logger.debug(
                        "Try to get the version information from %s."
                        % possibOldVersionFile)
                    (oldClusterVersion, oldClusterNumber, oldCommitId) = \
                        VersionInfo.get_version_info(possibOldVersionFile)
                else:
                    raise Exception(str(e))

            # if last success commit upgrade_type is grey upgrade,
            # the symbolic link should point to the
            # old app path with old commit id
            if oldCommitId == newCommitId:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52901"])
            self.context.logger.debug(
                "Successfully obtained version information of new and old "
                "clusters.\n           The old cluster number:%s, the new "
                "cluster number:%s." % (oldClusterNumber, newClusterNumber))

            self.canDoRollbackOrCommit()

            if oldClusterVersion > newClusterVersion:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52902"]
                                % (oldClusterVersion, newClusterVersion))

            self.checkLastUpgrade(newCommitId)

            if float(newClusterNumber) < float(oldClusterNumber):
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51629"]
                                % newClusterNumber)
            elif float(newClusterNumber) == float(oldClusterNumber):
                if self.context.is_inplace_upgrade:
                    upgradeAction = const.ACTION_INPLACE_UPGRADE
                else:
                    upgradeAction = const.ACTION_SMALL_UPGRADE
            else:
                if int(float(newClusterNumber)) > int(float(oldClusterNumber)):
                    raise Exception(ErrorCode.GAUSS_529["GAUSS_52904"]
                                    + "This cluster version is "
                                      "not supported upgrade.")
                elif ((float(newClusterNumber) - int(float(newClusterNumber)))
                      > (float(oldClusterNumber) -
                         int(float(oldClusterNumber)))):
                    if self.context.is_inplace_upgrade:
                        upgradeAction = const.ACTION_INPLACE_UPGRADE
                        self.isLargeInplaceUpgrade = True
                    else:
                        upgradeAction = const.ACTION_LARGE_UPGRADE
                else:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51629"]
                                    % newClusterNumber)
            self.context.logger.debug("The matched upgrade strategy is: %s."
                                      % upgradeAction)
            return upgradeAction
        except Exception as e:
            self.clean_gs_secure_files()
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52900"] % str(e)
                            + " Do nothing this time.")

    def canDoRollbackOrCommit(self):
        """
        Check whether rollback or commit is required.
        :return:
        """
        try:
            if self.context.action == const.ACTION_AUTO_ROLLBACK or \
                    self.context.action == const.ACTION_COMMIT_UPGRADE:
                inplaceUpgradeFlagFile = os.path.join(
                    self.context.upgradeBackupPath,
                    const.INPLACE_UPGRADE_FLAG_FILE)
                grayUpgradeFlagFile = os.path.join(
                    self.context.upgradeBackupPath,
                    const.GREY_UPGRADE_STEP_FILE)
                self.context.is_inplace_upgrade = False
                # we do rollback by the backup directory
                if os.path.isfile(inplaceUpgradeFlagFile):
                    self.context.logger.debug("inplace upgrade flag exists, "
                                              "use inplace rollback or commit.")
                    self.context.is_inplace_upgrade = True
                if os.path.isfile(grayUpgradeFlagFile):
                    self.context.logger.debug("grey upgrade flag exists, "
                                              "use grey rollback or commit.")
                    self.context.is_grey_upgrade = True
                if not (self.context.is_inplace_upgrade or
                        self.context.is_grey_upgrade):
                    if self.context.action == const.ACTION_AUTO_ROLLBACK \
                            and not self.checkBakPathNotExists():
                        self.cleanBinaryUpgradeBakFiles(True)
                    exitMsg = "No need to {0}".format(self.context.action)
                    self.exitWithRetCode(self.context.action, True, exitMsg)
        except Exception as e:
            raise Exception("Failed to check whether the rollback or commit."
                            " Error {0}".format(str(e)))

    def checkLastUpgrade(self, newCommitId):
        """
        check the last fail upgrade type is same with this time
        check the last upgrade version is same with this time
        under grey upgrade, if under inplace upgrade, we will
        rollback first, under grey upgrade, we will upgrade again
        """
        if self.context.action == const.ACTION_AUTO_UPGRADE:
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            cmd = "if [ -f '%s' ]; then echo 'True';" \
                  " else echo 'False'; fi" % stepFile
            (resultMap, outputCollect) = \
                self.context.sshTool.getSshStatusOutput(cmd)
            self.context.logger.debug(
                "The result of checking grey upgrade step flag"
                " file on all nodes is:\n%s" % outputCollect)
            if self.context.is_inplace_upgrade:
                # if the grey upgrade rollback failed, it should have file,
                # so cannot do grey upgrade now
                if outputCollect.find('True') >= 0:
                    ermsg = ErrorCode.GAUSS_502["GAUSS_50200"] \
                            % const.GREY_UPGRADE_STEP_FILE \
                            + "In grey upgrade process, " \
                              "cannot do inplace upgrade!"
                    raise Exception(str(ermsg))
            else:
                inplace_upgrade_flag_file =\
                    "%s/inplace_upgrade_flag" % self.context.upgradeBackupPath
                if os.path.isfile(inplace_upgrade_flag_file):
                    ermsg = ErrorCode.GAUSS_502["GAUSS_50200"] % \
                            inplace_upgrade_flag_file + \
                            "In inplace upgrade process, " \
                            "cannot do grey upgrade!"
                    raise Exception(ermsg)
                # it may have remaining when last upgrade use
                #  --force to forceRollback
                self.checkBakPathAndTable(outputCollect)
                self.checkNewCommitid(newCommitId)
        elif self.context.action == const.ACTION_AUTO_ROLLBACK or \
                self.context.action == const.ACTION_COMMIT_UPGRADE:
            self.checkNewCommitid(newCommitId)

    def checkBakPathAndTable(self, outputCollect):
        """
        if the record step file in all nodes not exists, and the
        table exists, so this situation means the last upgrade
        remaining table
        if the table and step file exists, check if the content is correct
        :param resultMap:
        :param outputCollect:
        :return:
        """
        # no need to check and drop schema under force upgrade
        if not self.existTable(const.RECORD_NODE_STEP):
            return
        output = outputCollect.split('\n')
        output = output[:-1]
        findBakPath = False
        for record in output:
            # if can find step, means this
            if record.find('True') >= 0:
                findBakPath = True
                break
        if not findBakPath:
            self.dropSupportSchema()
            return

    def checkNewCommitid(self, newCommitId):
        """
        the commitid is in version.cfg, it should be same with the record
        commitid in record app directory file
        :param newCommitId: version.cfg line 3
        :return: NA
        """
        newPath = self.getClusterAppPath(const.NEW)
        if newPath != "":
            LastNewCommitId = newPath[-8:]
            # When repeatedly run gs_upgradectl script,
            # this time upgrade version should be same
            # with last record upgrade version
            if newCommitId != LastNewCommitId:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52935"])

    def setGUCValue(self, guc_key, guc_value, action_type="reload"):
        """
        function: do gs_guc
        input : gucKey - parameter name
                gucValue - parameter value
                actionType - guc action type(set/reload). default is 'reload'
                onlySetCn - whether only set CN instance. default is False
        """
        tmp_file = ""
        if guc_value != "":
            guc_str = "%s='%s'" % (guc_key, guc_value)
        else:
            guc_str = "%s" % guc_key
        try:
            self.context.logger.debug("Start to set GUC value %s." % guc_str)
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s --guc_string=\"%s\" -l %s --setType=%s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_SET_GUC_VALUE,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   guc_str,
                   self.context.localLog,
                   action_type)
            if action_type == "reload":
                tmp_file = os.path.join(EnvUtil.getTmpDirFromEnv(self.context.user),
                                       const.TMP_DYNAMIC_DN_INFO)
                self.generateDynamicInfoFile(tmp_file)
            self.context.logger.debug("Cmd for setting parameter: %s." % cmd)
            host_list = copy.deepcopy(self.context.clusterNodes)
            self.context.execCommandInSpecialNode(cmd, host_list)
            self.context.logger.debug("Successfully set guc value.")
        except Exception as er:
            if self.context.forceRollback:
                self.context.logger.debug("WARNING: failed to set value %s." % guc_str)
            else:
                raise Exception(str(er))
        finally:
            if os.path.exists(tmp_file):
                delete_cmd = "(if [ -f '%s' ]; then rm -f '%s'; fi) " % \
                              (tmp_file, tmp_file)
                host_list = copy.deepcopy(self.context.clusterNodes)
                self.context.execCommandInSpecialNode(delete_cmd, host_list)

    def setClusterReadOnlyMode(self):
        """
        function: Set the cluster read-only mode
        input : NA
        output: 0  successfully
                1  failed
        """
        try:
            self.context.logger.debug("Setting up the cluster read-only mode.")
            if self.context.standbyCluster:
                self.context.logger.debug("no need to set cluster "
                                          "read only mode under force or standby cluster upgrade")
                return 0
            self.setGUCValue("default_transaction_read_only", "true")
            self.context.logger.debug("successfully set the cluster read-only mode.")
            return 0
        except Exception as e:
            self.context.logger.debug("WARNING: Failed to set default_transaction_read_only "
                                      "parameter. %s" % str(e))
            return 1

    def unSetClusterReadOnlyMode(self):
        """
        function: Canceling the cluster read-only mode
        input : NA
        output: 0  successfully
                1  failed
        """
        try:
            self.context.logger.debug("Canceling the cluster read-only mode.")
            if self.context.standbyCluster:
                self.context.logger.debug("no need to unset cluster "
                                          "read only mode under force or standby cluster upgrade")
                return 0
            self.setGUCValue("default_transaction_read_only", "false")
            self.context.logger.debug("Successfully cancelled the cluster read-only mode.")
            return 0
        except Exception as e:
            self.context.logger.debug("WARNING: Failed to set default_transaction_read_only "
                                      "parameter. %s" % str(e))
            return 1

    def stopCluster(self):
        """
        function: Stopping the cluster
        input : NA
        output: NA
        """
        self.context.logger.debug("Stopping the cluster.", "addStep")
        # Stop cluster applications
        cmd = "%s -U %s -R %s -t %s" % (
            OMCommand.getLocalScript("Local_StopInstance"),
            self.context.user, self.context.clusterInfo.appPath,
            const.UPGRADE_TIMEOUT_CLUSTER_STOP)
        self.context.logger.debug("Command for stop cluster: %s" % cmd)
        CmdExecutor.execCommandWithMode(
            cmd, self.context.sshTool,
            self.context.isSingle or self.context.localMode,
            self.context.mpprcFile)
        self.context.logger.debug("Successfully stopped cluster.")

    def startCluster(self):
        """
        function: start cluster
        input : NA
        output: NA
        """
        versionFile = os.path.join(
            self.context.oldClusterAppPath, "bin/upgrade_version")
        if os.path.exists(versionFile):
            _, number, _ = VersionInfo.get_version_info(versionFile)
            cmd = "%s -U %s -R %s -t %s --cluster_number=%s" % (
                OMCommand.getLocalScript("Local_StartInstance"),
                self.context.user, self.context.clusterInfo.appPath,
                const.UPGRADE_TIMEOUT_CLUSTER_START, number)
        else:
            cmd = "%s -U %s -R %s -t %s" % (
                OMCommand.getLocalScript("Local_StartInstance"),
                self.context.user, self.context.clusterInfo.appPath,
                const.UPGRADE_TIMEOUT_CLUSTER_START)
        CmdExecutor.execCommandWithMode(
            cmd, self.context.sshTool,
            self.context.isSingle or self.context.localMode,
            self.context.mpprcFile)
        self.context.logger.log("Successfully started cluster.")

    def set_cm_parameters(self, cm_nodes, cms_para_dict):
        """
        function:set cms parameters
        """
        # set cm_server parameters
        for cm_node in cm_nodes:
            cmserver_file = os.path.join(cm_node.cmservers[0].datadir, "cm_server.conf")
            cmd = "echo -e '\n' > /dev/null 2>&1"
            for para in list(cms_para_dict.keys()):
                cmd += " && sed -i '/\<%s\>/d' '%s' && echo '%s = %s' >> '%s'" % \
                       (para, cmserver_file, para, cms_para_dict[para], cmserver_file)
            self.context.logger.debug("Command for setting CMServer parameters: %s." % cmd)

            if self.context.isSingle:
                (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
                if status != 0 and not self.context.ignoreInstance:
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] %
                                    ",".join(list(cms_para_dict.keys())) + " Error:%s." % output)
            else:
                (status, output) = self.context.sshTool.getSshStatusOutput(cmd, [cm_node.name])
                if status[cm_node.name] != DefaultValue.SUCCESS:
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] %
                                    ",".join(list(cms_para_dict.keys())) + " Error:%s." % output)

    def save_cm_server_guc(self, cmsParaDict, fileName):
        """
        function : Save the old parameters to the json file
                   will create an empty file if the cmsParaDict is empty
        @param cmsParaDict: parameter dict
        @param fileName: json file name
        """
        try:
            self.context.logger.debug("Start to save the old parameters to the json file")
            # Save the parameters to one file
            FileUtil.createFileInSafeMode(fileName)
            with open(fileName, 'w') as fp_json:
                json.dump(cmsParaDict, fp_json)

            if not self.context.isSingle:
                self.context.sshTool.scpFiles(fileName, os.path.dirname(fileName) + "/",
                                              hostList=self.context.clusterNodes)
            self.context.logger.debug("Successfully written and send file %s. "
                                      "The list context is %s." % (fileName, cmsParaDict))
        except Exception as er:
            if not self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.debug("WARNING: Failed to save the CMServer parameters.")

    def set_cm_server_guc(self, cmsParaDict, needReload=True):
        """
        function : set cm_server parameters and restart cm_server instance
        @param cmsParaDict: parameter dict
        @param needReload: kill -1
        """
        self.context.logger.debug("Start set and restart cm_server instance.")
        if len(cmsParaDict.keys()) == 0 or self.context.standbyCluster:
            self.context.logger.debug("no need to do.")
            return

        cmNodes = []
        # Get all the nodes that contain the CMSERVER instance
        for dbNode in self.context.clusterInfo.dbNodes:
            if len(dbNode.cmservers) > 0:
                cmNodes.append(dbNode)

        self.set_cm_parameters(cmNodes, cmsParaDict)

        if not needReload:
            return

        # Restart the instance CMSERVERS

        # Reload cm parameters using kill -1
        cmd = DefaultValue.killInstProcessCmd("cm_server", False, 1)
        self.context.logger.debug("Command for reloading CMServer instances: %s." % cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
        if status != 0:
            self.context.logger.warn("Kill CMS failed. OUTPUT: {0}".format(output))
        # Waiting for CMS instance to automatically refresh and reload
        time.sleep(10)
        self.context.logger.debug("Successfully set and reload CMServer instance.")

    def base_close_cm_server_guc(self):
        """
        function: Close cm_server guc parameter interface
        """
        if self.context.is_inplace_upgrade:
            self.close_cm_server_guc(const.CLUSTER_CMSCONF_FILE,
                                     const.CMSERVER_GUC_DEFAULT_HA,
                                     const.CMSERVER_GUC_CLOSE_HA)
        else:
            self.close_cm_server_guc(const.GREY_CLUSTER_CMSCONF_FILE,
                                     const.CMSERVER_GUC_GREYUPGRADE_DEFAULT,
                                     const.CMSERVER_GUC_GREYUPGRADE_CLOSE)
        self.set_enable_ssl("off")

    def close_cm_server_gucs_before_install(self):
        """
        function: Close CM parameter before install new binary
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) == 0:
            self.context.logger.debug("Old cluster not exist CM component, "
                                      "no need close guc parameter in before install binary files.")
            return
        self.context.logger.debug("Close cm_server parameters start before install binary files.")
        self.base_close_cm_server_guc()

    def close_cm_server_gucs_after_install(self):
        """
        function: Close CM parameter after install new binary
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) != 0:
            self.context.logger.debug("Old cluster not exist CM component, "
                                      "no need close guc parameter in after install binary files.")
            return
        self.context.logger.debug("Close cm_server parameters start after install binary files.")
        self.base_close_cm_server_guc()

    def close_cm_server_guc(self, backUpFile, OriginalGUCparas, closedGUCparas):
        """
        function: save old cm_server parameters, set new value by backUpFile
        input : NA
        output: NA
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) == 0:
            self.context.logger.debug("New cluster not exist CM component, no need to restore guc parameter.")
            return
        self.context.logger.debug("Start to close CMServer parameters.")
        if self.context.standbyCluster:
            self.context.logger.debug("No need to close CMServer guc under force upgrade.")
            return
        closeGUCparas = {}
        try:
            cmsGucFile = os.path.join(EnvUtil.getTmpDirFromEnv(), backUpFile)
            cmsGucFileSet = cmsGucFile + ".done"
            if os.path.isfile(cmsGucFileSet):
                self.context.logger.debug("Result: The file [%s] exists, it means that the GUC "
                                          "parameter values have been closed." % cmsGucFileSet)
                return

            # If the backup file already exists, read it through the backup file, otherwise,
            # connect to the database to get it
            if os.path.isfile(cmsGucFile):
                try:
                    with open(cmsGucFile, "r") as fp:
                        oldGUCParas = json.load(fp)
                except Exception as _:
                    # if file exists, but not available, we need to remove it firsts
                    self.context.logger.debug("WARNING: the cms guc back file is unavailable. "
                                              "Maybe we should keep guc consistent manually "
                                              "if failed")
                    cmd = "%s '%s'" % (CmdUtil.getRemoveCmd("file"), cmsGucFile)
                    hostList = copy.deepcopy(self.context.clusterNodes)
                    self.context.execCommandInSpecialNode(cmd, hostList)
                    oldGUCParas = self.getCMServerGUC(OriginalGUCparas)
            else:
                oldGUCParas = self.getCMServerGUC(OriginalGUCparas)
            if len(list(oldGUCParas.keys())) == 0:
                self.context.logger.debug("There is no GUC parameters on CMS instance, "
                                          "so don't need to close them.")
                self.save_cm_server_guc(oldGUCParas, cmsGucFileSet)
                return

            for para in list(oldGUCParas.keys()):
                if para in list(closedGUCparas.keys()):
                    closeGUCparas[para] = closedGUCparas[para]

            self.save_cm_server_guc(oldGUCParas, cmsGucFile)
            self.set_cm_server_guc(closeGUCparas)

            cmd = "mv '%s' '%s'" % (cmsGucFile, cmsGucFileSet)
            hostList = copy.deepcopy(self.context.clusterNodes)
            self.context.execCommandInSpecialNode(cmd, hostList)

            # make sure all cm_server child process has been killed. Example: gs_check
            gaussHome = ClusterDir.getInstallDir(self.context.user)
            cmServerFile = "%s/bin/cm_server" % gaussHome
            cmNodes = []
            # Get all the nodes that contain the CMSERVER instance
            for dbNode in self.context.clusterInfo.dbNodes:
                if len(dbNode.cmservers) > 0:
                    cmNodes.append(dbNode)
            # only kill the child process, not including cm_server
            pstree = "%s -c" % os.path.realpath(
                os.path.dirname(os.path.realpath(__file__)) + "/../../py_pstree.py")
            if self.context.isSingle:
                cmd = "pidList=`ps aux | grep \"%s\" | grep -v 'grep' | awk '{print $2}' | " \
                      "xargs `; " % cmServerFile
                cmd += "for pid in $pidList; do %s $pid | xargs -r -n 100 kill -9; done" % pstree
                (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
            else:
                cmd = "pidList=\`ps aux | grep \"%s\" | grep -v 'grep' | awk '{print \$2}' | " \
                      "xargs \`; " % cmServerFile
                cmd += "for pid in \$pidList; do %s \$pid | xargs -r -n 100 kill -9; done" % pstree
                (status, output) = self.context.sshTool.getSshStatusOutput(
                                    cmd, [cmNode.name for cmNode in cmNodes])
            self.context.logger.debug("Command for killing all cm_server child process: %s." % cmd)
            self.context.logger.debug("The result of kill cm_server child process commands. "
                                      "Status:%s, Output:%s." % (status, output))
            self.waitClusterNormalDegrade(waitTimeOut=60)

            self.context.logger.debug("Successfully closed the CMServer parameters.", "constant")
        except Exception as er:
            if not self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.debug("WARNING: Failed to close the CMServer parameters.")

    def restore_cm_server_guc(self, backUpFile, isCommit=False, hostList=None):
        """
        function: restore cm_server parameters
        input : NA
        output: NA
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) == 0:
            self.context.logger.debug("Origin cluster not exist CM component, no need to restore guc parameter.")
            return
        if hostList is None:
            hostList = []
        old_guc_paras = dict()
        filename = ""
        self.context.logger.debug("Start to restore the CMServer parameters in file.")
        if self.context.standbyCluster:
            self.context.logger.debug("No need to restore the CMServer guc in standby cluster.")
            return
        try:
            cms_guc_file = os.path.join(EnvUtil.getTmpDirFromEnv(), backUpFile)
            cms_guc_file_set = cms_guc_file + ".done"
            if not os.path.isfile(cms_guc_file_set) and not os.path.isfile(cms_guc_file):
                self.context.logger.debug("The CMServer parameters file [%s] and [%s] does not "
                                          "exists, so don't need to restore them." %
                                          (cms_guc_file_set, cms_guc_file))
            else:
                if os.path.isfile(cms_guc_file_set):
                    filename = cms_guc_file_set
                else:
                    filename = cms_guc_file
                with open(filename) as fp_json:
                    old_guc_paras = json.load(fp_json)
                self.context.logger.debug("Get CMServer parameters from [{0}]:"
                                          "{1}".format(filename, old_guc_paras))

            if isCommit:
                self.context.logger.debug("Set CMServer parameters for upgrade commit.")
                for cmsPara in list(const.CMSERVER_GUC_DEFAULT.keys()):
                    if cmsPara not in list(old_guc_paras.keys()):
                        old_guc_paras[cmsPara] = const.CMSERVER_GUC_DEFAULT[cmsPara]

            if len(list(old_guc_paras.keys())) != 0:
                self.set_cm_server_guc(old_guc_paras)
            else:
                self.context.logger.debug("There is no GUC parameters in file %s, "
                                          "so don't need to restore them.But still need clean file." % filename)

            cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (cms_guc_file_set, cms_guc_file_set)
            cmd += " && {0}".format(g_file.SHELL_CMD_DICT["deleteFile"] % (cms_guc_file, cms_guc_file))
            
            if len(hostList) == 0:
                hosts = copy.deepcopy(self.context.clusterNodes)
                self.context.execCommandInSpecialNode(cmd, hosts)
            else:
                self.context.execCommandInSpecialNode(cmd, copy.deepcopy(hostList))
            self.context.logger.debug("Successfully restored the CMServer parameters.")
        except Exception as er:
            if not self.context.forceRollback:
                raise Exception(str(er) + "\nFailed to restore CMServer parameters. " + 
                                "You may restore manually with file.")
            self.context.logger.debug("WARNING: Failed to restore the CMServer parameters.")
        if os.path.isfile(os.path.join(self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)) and \
                     self.context.action not in [const.ACTION_AUTO_ROLLBACK, const.ACTION_COMMIT_UPGRADE]:
            return
        # open enable_ssl parameter
        self.set_enable_ssl("on")

    def clean_cms_param_file(self):
        """
        Clean enable_ssl_on and cluster_cmsconf.json.done in PGHOST
        """
        enable_ssl_on_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "enable_ssl_on")
        enable_ssl_off_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "enable_ssl_off")
        cms_param_json_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "cluster_cmsconf.json.done")
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (enable_ssl_on_file, enable_ssl_on_file)
        cmd += " && {0}".format(g_file.SHELL_CMD_DICT["deleteFile"] % (enable_ssl_off_file, enable_ssl_off_file))
        cmd += " && {0}".format(g_file.SHELL_CMD_DICT["deleteFile"] % (cms_param_json_file, cms_param_json_file))

        self.context.logger.debug("Clean cms param file CMD is: {0}".format(cmd))
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Clean cms param file success.")

    def createCommitFlagFile(self):
        """
        function: create a flag file, if this file exists,
                  means that user have called commit interface,
                  but still not finished. if create failed, script should exit.
        input : NA
        output: NA
        """
        commitFlagFile = "%s/commitFlagFile" % self.context.upgradeBackupPath
        self.context.logger.debug("Start to create the commit flag file.")
        try:
            cmd = "(if [ -d '%s' ]; then touch '%s'; fi) " % (
                self.context.upgradeBackupPath, commitFlagFile)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50206"]
                            % ("commit flag file: %s" % str(e)))
        self.context.logger.debug("Successfully created the commit flag file.")

    def checkCommitFlagFile(self):
        """
        function: check if commit flag file exists.
        input : NA
        output: return 0, If there is the file commitFlagFile.
                else, return 1
        """
        commitFlagFile = "%s/commitFlagFile" % self.context.upgradeBackupPath
        if (os.path.isfile(commitFlagFile)):
            return 0
        else:
            return 1

    def createInplaceUpgradeFlagFile(self):
        """
        function: create inplace upgrade flag file on
                  all nodes if is doing inplace upgrade
                  1.check if is inplace upgrade
                  2.get new and old cluster version number
                  3.write file
        Input: NA
        output : NA
        """
        self.context.logger.debug("Start to create inplace upgrade flag file.")
        try:
            newClusterNumber = self.context.newClusterNumber
            oldClusterNumber = self.context.oldClusterNumber

            inplace_upgrade_flag_file = "%s/inplace_upgrade_flag" % \
                                        self.context.upgradeBackupPath
            FileUtil.createFile(inplace_upgrade_flag_file)
            FileUtil.writeFile(inplace_upgrade_flag_file,
                             ["newClusterNumber:%s" % newClusterNumber], 'a')
            FileUtil.writeFile(inplace_upgrade_flag_file,
                             ["oldClusterNumber:%s" % oldClusterNumber], 'a')
            if (not self.context.isSingle):
                self.context.sshTool.scpFiles(inplace_upgrade_flag_file,
                                              self.context.upgradeBackupPath)
            if float(self.context.oldClusterNumber) <= float(
                    const.UPGRADE_VERSION_64bit_xid) < \
                    float(self.context.newClusterNumber):
                self.__upgrade_across_64bit_xid = True

            self.context.logger.debug("Successfully created inplace"
                                      " upgrade flag file.")
        except Exception as e:
            raise Exception(str(e))

    def setUpgradeFromParam(self, cluster_version_number, is_check=True):
        """
        function: set upgrade_from parameter
        Input : oldClusterNumber
        output : NA
        """
        if not DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) > 0:
            self.context.logger.debug("No need to set cm parameter.")
            return
        self.context.logger.debug("Set upgrade_from guc parameter.")
        working_grand_version = int(float(cluster_version_number) * 1000)
        cmd = "gs_guc set -Z cmagent -N all -I all -c 'upgrade_from=%s'" % working_grand_version
        self.context.logger.debug("setting cmagent parameter: %s." % cmd)
        try:
            (status, output) = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                self.context.logger.debug("Set upgrade_from failed. "
                                          "cmd:%s\nOutput:%s" % (cmd, str(output)))
                raise Exception(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + "Error: \n%s" % str(output))
            if is_check:
                gucStr = "%s:%s" % ("upgrade_from", str(working_grand_version).strip())
                self.checkParam(gucStr, True)
            self.context.logger.debug("Successfully set cmagent parameter "
                                      "upgrade_from=%s." % working_grand_version)
        except Exception as er:
            if self.context.action == const.ACTION_INPLACE_UPGRADE or \
                    not self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.log("NOTICE: Failed to set upgrade_from, "
                                    "please set it manually with command: \n%s" % str(cmd))

    def setUpgradeMode(self, mode, set_type="reload"):
        """
        function: set upgrade_mode parameter
        Input : upgrade_mode
        output : NA
        """
        try:
            self.setUpgradeModeGuc(mode, set_type)
        except Exception as er:
            if self.context.action != const.ACTION_INPLACE_UPGRADE and \
                    not self.context.forceRollback:
                raise Exception(str(er))
            try:
                self.setUpgradeModeGuc(mode, "set")
            except Exception as _:
                self.context.logger.log("NOTICE: Failed to set upgrade_mode to {0}, "
                                        "please set it manually.".format(mode))

    def setUpgradeModeGuc(self, mode, set_type="reload"):
        """
        function: set upgrade mode guc
        input  : mode, setType
        output : NA
        """
        self.context.logger.debug("Set upgrade_mode guc parameter.")
        cmd = "gs_guc %s -Z datanode -I all -c 'upgrade_mode=%d'" % (set_type, mode)
        self.context.logger.debug("Command for setting database"
                                  " node parameter: %s." % cmd)
        retry_count = 0
        while retry_count < 5:
            try:
                CmdExecutor.execCommandWithMode(cmd,
                                                self.context.sshTool)
                break
            except Exception as _:
                retry_count += 1
                if retry_count < 5:
                    time.sleep(5)
                    continue

        guc_str = "upgrade_mode:%d" % mode
        self.checkParam(guc_str)
        self.context.logger.debug("Successfully set "
                                  "upgrade_mode to %d." % mode)

    def checkParam(self, gucStr, fromFile=False):
        """
        function: check the cmagent guc value
        Input : gucStr the guc key:value string
        output : NA
        """
        if "dual-standby" in self.context.clusterType:
            return
        self.context.logger.debug("Start to check GUC value %s." % gucStr)
        try:
            # send cmd to that node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s" \
                  " --guc_string=\"%s\" -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_CHECK_GUC,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   gucStr,
                   self.context.localLog)
            if fromFile:
                cmd += " --fromFile"
            self.context.logger.debug("Command for checking"
                                      " parameter: %s." % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
            self.context.logger.debug("Successfully checked guc value.")
        except Exception as e:
            raise Exception(str(e))

    def backup_disaster_user_file(self):
        """backup_disaster_user_file"""
        bin_path = os.path.join(EnvUtil.getEnv("GAUSSHOME"), "bin")
        cipher_file = os.path.join(bin_path, "hadr.key.cipher")
        if os.path.isfile(cipher_file):
            FileUtil.cpFile(cipher_file, "%s/" % self.context.tmpDir)
        rand_file = os.path.join(bin_path, "hadr.key.rand")
        if os.path.isfile(rand_file):
            FileUtil.cpFile(rand_file, "%s/" % self.context.tmpDir)
        self.context.logger.debug("Back up rand and cipher file to temp dir.")

    def restore_origin_disaster_user_file(self):
        """restore_origin_disaster_user_file"""
        bin_path = os.path.join(self.context.newClusterAppPath, "bin")
        cipher_file = os.path.join(self.context.tmpDir, "hadr.key.cipher")
        if os.path.isfile(cipher_file):
            self.context.sshTool.scpFiles(cipher_file, bin_path)
        rand_file = os.path.join(self.context.tmpDir, "hadr.key.rand")
        if os.path.isfile(rand_file):
            self.context.sshTool.scpFiles(rand_file, bin_path)
        self.context.logger.debug("Restore rand and cipher file to gausshome.")

    def floatMoreThan(self, numOne, numTwo):
        """
        function: float more than
        input  : numOne, numTwo
        output : True/False
        """
        if float(numOne) - float(numTwo) > float(const.DELTA_NUM):
            return True
        return False

    def floatEqualTo(self, numOne, numTwo):
        """
        function: float equal to
        input: numOne, numTwo
        output: True/False
        """
        if float(-const.DELTA_NUM) < (float(numOne) - float(numTwo)) \
                < float(const.DELTA_NUM):
            return True
        return False

    def floatGreaterOrEqualTo(self, numOne, numTwo):
        """
        function: float greater or equal to
        input: numOne, numTwo
        output: True/False
        """
        if self.floatMoreThan(numOne, numTwo) or \
                self.floatEqualTo(numOne, numTwo):
            return True
        return False

    def reloadVacuumDeferCleanupAge(self):
        """
        function: reload the guc paramter vacuum_defer_cleanup_age value on
        inplace upgrade or grey large upgrade
        input : NA
        """
        self.setGUCValue("vacuum_defer_cleanup_age", "100000", "reload")

    def is_config_cm_params(self):
        """
        Check conditions for ssl_enable
        """
        self.context.logger.log("Start check CMS parameter.")
        new_version = int(float(self.context.newClusterNumber) * 1000)
        old_version = int(float(self.context.oldClusterNumber) * 1000)
        check_version = 92574
        self.context.logger.debug("New version: [{0}]. Old version: [{1}]. "
                                  "Check version: [{2}]".format(new_version, 
                                                                old_version, 
                                                                check_version))

        if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) == 0:
            self.context.logger.debug("Not exist CM component. No need to check CMS parameter.")
            return False

        if new_version >= check_version > old_version:
            self.context.logger.debug(
                "Old cluster cm_server not supported ssl_enable parameter. New version supported.")
            return True

        self.context.logger.log("Old cluster version number less than 92574.")
        return False

    def get_current_enable_ssl_value(self):
        """
        Get the value of enable_ssl from remote node
        """
        all_cm_server_inst = [inst for node in self.context.clusterInfo.dbNodes for inst in node.cmservers]
        first_cms_inst = all_cm_server_inst[0]
        server_conf_file = os.path.join(first_cms_inst.datadir, "cm_server.conf")
        remote_cmd = "grep -E '^enable_ssl = ' {0}".format(server_conf_file)
        ssh_cmd = "pssh -s -H {0} \"{1}\"".format(first_cms_inst.hostname, remote_cmd)
        status, output = subprocess.getstatusoutput(ssh_cmd)
        if status != 0 or "=" not in output:
            self.context.logger.warn("Get enable_ssl failed. Output:: [{0}]".format(output))
            return False
        self.context.logger.debug("Get the value of enable_ssl is [{0}] "
                                  "from node [{1}].".format(output.split("=")[1].strip(), first_cms_inst.hostname))
        return output.split("=")[1].strip()

    def generate_enable_ssl_flag_file(self):
        """
        Generate enable_ssl flag file for upgrade commit
        Please ensure that there are CMS nodes in the cluster.
        """
        enable_ssl_value = self.get_current_enable_ssl_value()
        if not enable_ssl_value:
            self.context.logger.debug("No exist enable_ssl value.")
            return

        flag_file_name = "enable_ssl_on" if enable_ssl_value == "on" else "enable_ssl_off"
        flag_file_path = os.path.join(EnvUtil.getTmpDirFromEnv(), flag_file_name)
        generate_cmd = "touch {0} && chmod 400 {0}".format(flag_file_path)
        self.context.sshTool.executeCommand(generate_cmd, hostList=self.context.clusterInfo.getClusterNodeNames())
        self.context.logger.debug("Generate enable_ssl flag file [{0}] successfully.".format(flag_file_path))

    def set_enable_ssl(self, value):
        """
        Check CM parameter ssl_enable
        """
        self.context.logger.debug("Turn {0} enable_ssl parameter.".format(value))
        if not self.is_config_cm_params():
            return

        if value == "off":
            self.context.logger.debug("Backup file before disabling the parameter.")
            self.generate_enable_ssl_flag_file()
        else:
            self.context.logger.debug("Get enable_ssl flag file.")
            ssl_off_flag = os.path.join(EnvUtil.getTmpDirFromEnv(), "enable_ssl_off")
            ssl_on_flag = os.path.join(EnvUtil.getTmpDirFromEnv(), "enable_ssl_on")
            if os.path.isfile(ssl_off_flag):
                self.context.logger.debug("Old cluster turn off enable_ssl.")
                rm_flag_cmd = "rm -f {0}".format(ssl_off_flag)
                self.context.sshTool.executeCommand(rm_flag_cmd,
                                                    hostList=self.context.clusterInfo.getClusterNodeNames())
                return
            if os.path.isfile(ssl_on_flag):
                self.context.logger.debug("Old cluster turn on enable_ssl [{0}].".format(ssl_on_flag))
                rm_flag_cmd = "rm -f {0}".format(ssl_on_flag)
                self.context.sshTool.executeCommand(rm_flag_cmd,
                                                    hostList=self.context.clusterInfo.getClusterNodeNames())
            else:
                self.context.logger.debug("Old cluster not set enable_ssl parameter.")
                return

        cm_nodes = [node for node in self.context.clusterInfo.dbNodes if node.cmservers]
        cm_node_names = [node.name for node in cm_nodes]
        if not cm_nodes:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51212"] % "CMS")
        cm_server_dir = cm_nodes[0].cmservers[0].datadir
        cm_agent_dir = os.path.join(cm_nodes[0].cmDataDir, "cm_agent")
        cms_conf_file = os.path.join(cm_server_dir, "cm_server.conf")
        cma_conf_file = os.path.join(cm_agent_dir, "cm_agent.conf")
        origin_value = "off" if value == "on" else "on"

        if not os.path.exists(cms_conf_file) or not os.path.exists(cma_conf_file):
            self.context.logger.debug("CM config file not exists, no need set ssl.")
            return

        cmd = "sed -i 's/enable_ssl = {0}/enable_ssl = {1}/g' {2}".format(origin_value, value, cma_conf_file)
        self.context.sshTool.executeCommand(cmd, hostList=cm_node_names)

        cmd = "sed -i 's/enable_ssl = {0}/enable_ssl = {1}/g' {2}".format(origin_value, value, cms_conf_file)
        self.context.sshTool.executeCommand(cmd, hostList=self.context.clusterInfo.getClusterNodeNames())

        self.reload_cmserver()
        self.context.logger.debug("Turn {0} enable_ssl parameter.".format(value))


    def doGreyBinaryUpgrade(self):
        """
        function: do grey binary upgrade, which essentially replace the binary
        files, for the new version than 91.255, support this strategy to
        change binary upgrade(Inplace), use the symbolic links to change the
        binary file directory instead of installing the new bin in the same
        directory.choose minority nodes to upgrade first, observe to decide
        whether upgrade remaining nodes or rollback grey nodes
        input : NA
        output: NA
        """
        upgradeAgain = False
        try:
            # 1. distribute xml configure file to every nodes.
            self.distributeXml()
            # 2. check if the app path is ready and sha256 is right and others
            self.checkUpgrade()
            if self.context.action == const.ACTION_LARGE_UPGRADE and \
                    "dual-standby" not in self.context.clusterType:
                # 4. check the cluster pressure
                self.HASyncReplayCheck()
            # 5. before do grey binary upgrade, we must make sure the
            # cluster is Normal and the database could be
            # connected, if not, exit.
            (status, output) = self.doHealthCheck(const.OPTION_PRECHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] %
                                "cluster" + "Detail: " + output)
            # 6.chose the node name list that satisfy the condition as
            # upgrade nodes
            self.chooseUpgradeNodes()
            
            # 7.refresh dynamic once
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            if self.get_upgrade_cm_strategy() == 0 \
                    and not os.path.exists(stepFile):
                self.refresh_dynamic_config_file()
            
            # check if it satisfy upgrade again, if it is the second loop to
            # upgrade, it can go go upgrade again branch
            upgradeAgain = self.canUpgradeAgain()
            if not upgradeAgain:
                self.recordDualClusterStage(self.oldCommitId,
                                            DualClusterStage.STEP_UPGRADE_UNFINISHED)
                self.context.logger.log("NOTICE: The directory %s will be deleted after "
                                        "commit-upgrade, please make sure there is no personal "
                                        "data." % self.context.oldClusterAppPath)
        except Exception as e:
            # before this step, the upgrade process do nothing to the cluster,
            # this time has no remaining
            self.context.logger.debug(traceback.format_exc())
            self.context.logger.log(ErrorCode.GAUSS_529["GAUSS_52934"] +
                                    "Nodes are the old version.\n" +
                                    "Error: %s." % str(e) +
                                    " Do nothing this time.")
            self.exitWithRetCode(self.action, False, str(e))

        if not upgradeAgain:
            try:
                if not self.doGreyBinaryRollback():
                    self.exitWithRetCode(const.ACTION_AUTO_ROLLBACK, False)
                self.removeOmRollbackProgressFile()
                self.recordDualClusterStage(self.oldCommitId,
                                            DualClusterStage.STEP_UPGRADE_UNFINISHED)
                self.context.logger.log(
                    "The directory %s will be deleted after commit-upgrade, "
                    "please make sure there is no personal data." %
                    self.context.oldClusterAppPath)
                # 7. prepare upgrade function for sync and table
                # RECORD_NODE_STEP, init the step of all nodes as 0
                self.prepareGreyUpgrade()

                # 8. install the new bin in the appPath which has been
                # prepared in the preinstall
                self.installNewBin()

                # decompress the catalog upgrade_sql.tar.gz to temp dir,
                # include upgrade sql file and guc set
                self.prepareUpgradeSqlFolder()

                self.recordNodeStep(GreyUpgradeStep.STEP_UPDATE_CATALOG)
                # 9. if we update catalog after switch to the new bin,
                # the system will raise error cannot find
                # catalog or column until finish the updateCatalog function
                # we can not recognize if it really cannot
                # find the column, or just because the old version. So we
                # will update the catalog in the old version
                if self.context.action == const.ACTION_LARGE_UPGRADE and \
                        "dual-standby" not in self.context.clusterType:
                    self.updateCatalog()
                elif self.context.action == const.ACTION_LARGE_UPGRADE and \
                     "dual-standby" in self.context.clusterType:
                    self.setUpgradeFromParam(self.context.oldClusterNumber)
                    self.reloadCmAgent()
                    self.reload_cmserver()
                self.greySyncGuc()
                self.recordNodeStep(GreyUpgradeStep.STEP_SWITCH_NEW_BIN)
                self.CopyCerts()
                self.upgradeAgain()
            except Exception as e:
                errmsg = ErrorCode.GAUSS_529["GAUSS_52934"] + \
                         "You can use --grey to upgrade or manually rollback."
                self.context.logger.log(errmsg + str(e))
                self.exitWithRetCode(self.context.action, False)
        else:
            self.upgradeAgain()
        self.exitWithRetCode(self.context.action, True)

    def upgradeAgain(self):
        try:
            self.context.logger.debug(
                "From this step, you can use -h to upgrade again if failed.")
            # we have guarantee specified nodes have same step,
            # so we only need to get one node step
            currentStep = self.getOneNodeStep(self.context.nodeNames[0])
            self.context.logger.debug("Current node step is %d" % currentStep)
            # first time execute grey upgrade, we will record the step for
            # all the nodes, if we upgrade remain nodes,
            # reenter the upgrade process, we will not rollback autonomously,
            #  just upgrade again
            if currentStep < GreyUpgradeStep.STEP_UPGRADE_PROCESS:
                self.backupHotpatch()
                # 10. sync Cgroup configure and etc.
                # use the symbolic link to change the bin dir
                # sync old config to new bin path, the pg_plugin save the
                # C function .so file(but not end with .so),
                # so if it create in the old appPath after copy to the
                # newAppPath but not switch to new bin
                # the new version may not recognize the C function
                self.greyUpgradeSyncOldConfigToNew()
                # 11. switch the cluster version to new version
                self.getOneDNInst(checkNormal=True)
                self.switchBin(const.NEW)
                self.restore_origin_disaster_user_file()
                # create CA for CM
                if len(self.context.nodeNames) == len(self.context.clusterNodes):
                    self.create_ca_for_cm()
                    # turn off enable_ssl for upgrade
                    self.set_enable_ssl("off")
                else:
                    self.createCmCaForRollingUpgrade()

                self.setNewVersionGuc()
                self.recordNodeStep(GreyUpgradeStep.STEP_UPGRADE_PROCESS)
            if currentStep < GreyUpgradeStep.STEP_UPDATE_POST_CATALOG:
                # 12. kill the old existing process, will judge whether
                # each process is the required version
                self.switchExistsProcess()
                self.recordNodeStep(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)

        except Exception as e:
            self.context.logger.log("Failed to upgrade, can use --grey to "
                                    "upgrade again after rollback. Error: "
                                    "%s" % str(e))
            self.context.logger.debug(traceback.format_exc())
            self.exitWithRetCode(self.context.action, False, str(e))
        self.context.logger.log(
            "The nodes %s have been successfully upgraded to new version. "
            "Then do health check." % self.context.nodeNames)

        try:
            # 13. check the cluster status, the cluster status can be degraded
            (status, output) = self.doHealthCheck(const.OPTION_POSTCHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] %
                                "cluster" + output)
            if self.isNodeSpecifyStep(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG):
                # 14. exec post upgrade script
                if self.context.action == const.ACTION_LARGE_UPGRADE:
                    self.waitClusterForNormal()
                    # backup global relmap file before doing upgrade-post
                    self.backupGlobalRelmapFile()
                    if "dual-standby" not in self.context.clusterType:
                        self.prepareSql("rollback-post")
                        self.execRollbackUpgradedCatalog(scriptType="rollback-post")
                        self.prepareSql("upgrade-post")
                        self.execRollbackUpgradedCatalog(scriptType="upgrade-post")
                        self.getLsnInfo()
                hosts = copy.deepcopy(self.context.clusterNodes)
                self.recordNodeStep(
                    GreyUpgradeStep.STEP_PRE_COMMIT, nodes=hosts)
                self.recordDualClusterStage(self.newCommitId, DualClusterStage.STEP_UPGRADE_FINISH)
                self.printPrecommitBanner()
        except Exception as e:
            hintInfo = "Nodes are new version. " \
                       "Please check the cluster status. ERROR: \n"
            self.context.logger.log(hintInfo + str(e))
            self.context.logger.debug(traceback.format_exc())
            self.exitWithRetCode(self.context.action, False, hintInfo + str(e))

        greyNodeNames = self.getUpgradedNodeNames(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)   
        if len(greyNodeNames) < len(self.context.clusterNodes):
            self.context.logger.log("The nodes % have been successfully upgraded."
                                    "Then can upgrade the remaining nodes." % self.context.nodeNames)
        else:                                    
            self.context.logger.log("Successfully upgrade all nodes.")
        self.exitWithRetCode(self.context.action, True)

    def getOneNodeStep(self, nodeName):
        """
        get the node's step
        """
        currentStep = self.getOneNodeStepInFile(nodeName)
        return currentStep

    def getOneNodeStepInFile(self, nodeName):
        """
        get the node's step from step file
        """
        try:
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            self.context.logger.debug(
                "trying to get one node step in file %s" % stepFile)
            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row['node_host'] == nodeName:
                        step = int(row['step'])
                        break
            self.context.logger.debug("successfully got one node step {0} "
                                      "in file {1}".format(step, stepFile))
            return step
        except Exception as e:
            exitMsg = "Failed to get node step in step file. ERROR {0}".format(
                str(e))
            self.exitWithRetCode(self.action, False, exitMsg)

    def greySyncGuc(self):
        """
        delete the old version guc
        """
        cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_GREY_SYNC_GUC,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.localLog)
        self.context.logger.debug("Command for sync GUC in upgrade: %s" % cmd)
        hostList = copy.deepcopy(self.context.clusterNodes)
        self.context.sshTool.executeCommand(cmd, hostList=hostList)
        self.context.logger.debug("Successfully sync guc.")

    def greyUpgradeSyncOldConfigToNew(self):
        """
        function: sync old cluster config to the new cluster install path
        input : NA
        output: NA
        """
        # restore list:
        #    etc/gscgroup_xxx.cfg
        #    lib/postgresql/pg_plugin
        #    initdb_param
        #    server.key.cipher
        #    server.key.rand
        #    /share/sslsert/ca.key
        #    /share/sslsert/etcdca.crt
        self.context.logger.log("Sync cluster configuration.")
        try:
            # backup DS libs and gds file
            cmd = "%s -t %s -U %s -V %d --old_cluster_app_path=%s " \
                  "--new_cluster_app_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_GREY_UPGRADE_CONFIG_SYNC,
                   self.context.user,
                   int(float(self.context.oldClusterNumber) * 1000),
                   self.context.oldClusterAppPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            self.context.logger.debug("Command for syncing config files: %s"
                                      % cmd)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, hostList=hostList)

            # change the owner of application
            cmd = "chown -R %s:%s '%s'" % \
                  (self.context.user, self.context.group,
                   self.context.newClusterAppPath)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, hostList=hostList)
        except Exception as e:
            raise Exception(str(e) + " Failed to sync configuration.")
        self.context.logger.log("Successfully synced cluster configuration.")

    def _check_and_start_cluster(self):
        """
        Check cluster state and start cluster
        """
        self.context.logger.log("Check cluster state.")
        cmd = "source {0};gs_om -t query".format(self.context.userProfile)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.context.logger.debug("Check cluster state failed. Output: {0}".format(output))
        if "cluster_state   : Degraded" in output or "cluster_state   : Normal" in output:
            self.context.logger.log("Cluster state: {0}".format(output))
            return
        self.context.logger.log("Cluster need start now.")
        cmd = "source {0};gs_om -t start".format(self.context.userProfile)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.context.logger.debug("Start cluster state failed. Output: {0}".format(output))
            return
        self.context.logger.log("Cluster is started now.")

    def switchExistsProcess(self, isRollback=False):
        """
        switch all the process
        :param isRollback:
        :return:
        """
        self.context.logger.log("Switching all db processes.", "addStep")
        self._check_and_start_cluster()
        if DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) > 0:
            self.setUpgradeFromParam(self.context.oldClusterNumber)
            self.reloadCmAgent()
            self.reload_cmserver()
        self.createCheckpoint()
        self.switchDn(isRollback)
        try:
            self.waitClusterNormalDegrade()
        except Exception as e:
            # can't promise normal status in force upgrade or forceRollback
            if self.context.forceRollback:
                self.context.logger.log("WARNING: Failed to wait "
                                        "cluster normal or degrade.")
            else:
                raise Exception(str(e))
        self.context.logger.log("Successfully switch all process version",
                                "constant")

    def createCheckpoint(self):
        try:
            self.context.logger.log("Create checkpoint before switching.")
            start_time = timeit.default_timer()
            if self.context.forceRollback or self.context.standbyCluster:
                self.context.logger.debug("No need to do checkpoint.")
                return
            # create checkpoint
            sql = "CHECKPOINT;"
            for i in range(10):
                (status, output) = self.execSqlCommandInPrimaryDN(sql)
                # no need to retry under force upgrade
                if status == 0:
                    break
                self.context.logger.debug("Waring: checkpoint creation fails "
                                          "for the %s time. Fail message:%s."
                                          "try again at one second intervals" %
                                          (str(i), str(output)))
                time.sleep(1)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))

            elapsed = timeit.default_timer() - start_time
            self.context.logger.debug("Time to create checkpoint: %s" %
                                      self.getTimeFormat(elapsed))
        except Exception as e:
            if self.context.forceRollback:
                self.context.logger.log(
                    "WARNING: Failed to create checkpoint, "
                    "the switch process may use more time.")
            else:
                raise Exception(str(e))

    def need_rolling(self, is_roll_back):
        """
        Get is need switch UDF subprocess from upgrade mode
        """
        self.context.logger.debug("Start check need rolling.")
        new_static_config = os.path.realpath(os.path.join(self.context.newClusterAppPath, 
                                                          "bin", "cluster_static_config"))
        old_static_config = os.path.realpath(os.path.join(self.context.oldClusterAppPath, 
                                                          "bin", "cluster_static_config"))
        cluster_info = dbClusterInfo()
        if is_roll_back:
            self.context.logger.debug("This check need rolling for rollback.")
            if not os.path.isfile(new_static_config):
                self.context.logger.debug("Rollback not found new static config file [{0}]. "
                                          "No need to switch UDF.".format(new_static_config))
                return False
            cluster_info.initFromStaticConfig(self.context.user, new_static_config)
            if cluster_info.cmscount > 0:
                self.context.logger.debug("Rollback cluster info include CMS instance. "
                                          "So need to switch UDF.")
                return True
            self.context.logger.debug("Rollback new version cluster not include CMS instance. "
                                      "So no need to switch UDF.")
            return True
        self.context.logger.debug("This check need rolling for upgrade.")
        cluster_info.initFromStaticConfig(self.context.user, old_static_config)
        if cluster_info.cmscount > 0:
            self.context.logger.debug("Old cluster include CMS instance. So need to switch UDF.")
            return True
        self.context.logger.debug("Old cluster exclude CMS instance. So no need to switch UDF.")
        return False

    def switchDn(self, isRollback):
        self.context.logger.log("Switching DN processes.")
        is_rolling = False
        start_time = timeit.default_timer()
        # under upgrade, kill the process from old cluster app path,
        # rollback: kill from new cluster app path
        cmd = "%s -t %s -U %s -V %d --old_cluster_app_path=%s " \
              "--new_cluster_app_path=%s -X '%s' -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_SWITCH_DN,
               self.context.user,
               int(float(self.context.oldClusterNumber) * 1000),
               self.context.oldClusterAppPath,
               self.context.newClusterAppPath,
               self.context.xmlFile,
               self.context.localLog)

        if isRollback:
            cmd += " --rollback"
        if self.context.forceRollback:
            cmd += " --force"
        if len(self.context.nodeNames) != len(self.context.clusterNodes):
            is_rolling = True
        if self.need_rolling(isRollback) or is_rolling:
            self.context.logger.log("Switch DN processes for rolling upgrade.")
            cmd += " --rolling"
        self.context.logger.debug(
            "Command for switching DN processes: %s" % cmd)
        hostList = copy.deepcopy(self.context.nodeNames)
        self.context.sshTool.executeCommand(cmd, hostList=hostList)
        start_cluster_time = timeit.default_timer()
        self.greyStartCluster()
        end_cluster_time = timeit.default_timer() - start_cluster_time
        self.context.logger.debug("Time to start cluster is %s" %
                                  self.getTimeFormat(end_cluster_time))
        elapsed = timeit.default_timer() - start_time
        self.context.logger.debug("Time to switch DN process version: %s"
                                  % self.getTimeFormat(elapsed))

    def greyStartCluster(self):
        """
        start cluster in grey upgrade
        :return:
        """
        self.context.logger.log("Ready to grey start cluster.")
        versionFile = os.path.join(
            self.context.oldClusterAppPath, "bin/upgrade_version")
        if os.path.exists(versionFile):
            _, number, _ = VersionInfo.get_version_info(versionFile)
            cmd = "gs_om -t start --cluster-number='%s' --time-out=600" % (number)
        else:
            cmd = "gs_om -t start"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            "Command:%s. Error:\n%s" % (cmd, output))
        self.context.logger.log("Grey start cluster successfully.")

    def isNodeSpecifyStep(self, step, nodes=None):
        """
        check if all the specfied nodes is the step
        """
        return self.isNodeSpecifyStepInFile(step, nodes)

    def isNodeSpecifyStepInFile(self, step=-1, nodes=None):
        """
        step = -1 means we just check if step in all the specfied nodes is the
        same otherwise, we check if all the specfied nodes is the given step
        """
        try:
            if nodes:
                self.context.logger.debug(
                    "check if the nodes %s step is %s" % (nodes, step))
            else:
                self.context.logger.debug(
                    "check if all the nodes step is %s" % step)
                nodes = copy.deepcopy(self.context.clusterNodes)
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            if not os.path.isfile(stepFile):
                self.context.logger.debug(
                    "no step file, which means nodes %s step is same" % nodes)
                return True

            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row['node_host'] in nodes:
                        if step == -1:
                            step = int(row['step'])
                        else:
                            if step == int(row['step']):
                                continue
                            else:
                                self.context.logger.debug(
                                    "the nodes %s step is not all %s" % (
                                        nodes, step))
                                return False
            self.context.logger.debug(
                "the nodes %s step is all %s" % (nodes, step))
            return True
        except Exception as e:
            exitMsg = \
                "Failed to check node step in file. ERROR {0}".format(str(e))
            self.exitWithRetCode(self.action, False, exitMsg)

    def getLsnInfo(self):
        """
            Obtain the maximum LSN of each DN instance.
        """
        self.context.logger.debug("Start to get lsn info.")
        try:
            # prepare dynamic cluster info file in every node
            self.getOneDNInst(checkNormal=True)
            execHosts = [self.dnInst.hostname]
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_GET_LSN_INFO,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug("Command for geting lsn info: %s." % cmd)
            self.context.sshTool.executeCommand(cmd, hostList=execHosts)
            self.context.logger.debug(
                "Successfully get lsn info in instanse node.")
        except Exception as e:
            if self.context.forceRollback:
                self.context.logger.debug(
                    "Failed to get lsn info in force Scenario.")
                return
            raise Exception(
                "Failed to get lsn info in instanse node. "
                "Error:{0}".format(str(e)))

    def chooseUpgradeNodes(self):
        # Already set the self.context.nodesNum = 1
        # when number and node names is empty
        self.context.logger.debug("Choose the nodes to be upgraded.")
        self.setClusterDetailInfo()
        
        # check nodename following paramter -h whether have been upgraded 
        if len(self.context.nodeNames) != 0:
            self.context.logger.log(
                "Upgrade nodes %s." % self.context.nodeNames)
            greyNodeNames = self.getUpgradedNodeNames()
            checkH_nodes = \
                [val for val in greyNodeNames if val in self.context.nodeNames]
            if len(checkH_nodes) > 0:
                raise Exception("The nodes %s have been upgrade" %
                            checkH_nodes)
        # confirm in checkParameter
        elif self.context.upgrade_remain:
            greyNodeNames = self.getUpgradedNodeNames()
            otherNodeNames = [
                i for i in self.context.clusterNodes if i not in greyNodeNames]
            self.context.nodeNames = otherNodeNames
            self.context.logger.debug(
                "Upgrade remain nodes %s." % self.context.nodeNames)
        # when number and node names is empty 
        else:
            nodeTotalNum = len(self.context.clusterNodes)
            if len(self.context.clusterNodes) == 1:
                self.context.nodeNames.append(
                    self.context.clusterInfo.dbNodes[0].name)
                self.context.logger.log(
                    "Upgrade one node '%s'." % self.context.nodeNames[0])
            # SinglePrimaryMultiStandbyCluster
            else:
                self.context.nodeNames = self.context.clusterNodes
                self.context.logger.log("Upgrade all nodes.")

    def getUpgradedNodeNames(self, step=GreyUpgradeStep.STEP_INIT_STATUS):
        """
        by default, return upgraded nodes
        otherwise, return the nodes that step is more than given step
        under force upgrade, we only get step from file
        """
        return self.getUpgradedNodeNamesInFile(step)

    def getUpgradedNodeNamesInFile(self, step=GreyUpgradeStep.STEP_INIT_STATUS):
        """
        get upgraded nodes from step file
        by default, return upgraded nodes
        otherwise, return the nodes that step is more than given step
        """
        try:
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            self.context.logger.debug(
                "trying to get upgraded nodes from %s" % (stepFile))
            if not os.path.isfile(stepFile):
                return []
            greyNodeNames = []
            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if int(row['step']) > step:
                        greyNodeNames.append(row['node_host'])
            self.context.logger.debug("upgraded nodes are {0}".format(
                greyNodeNames))
            return greyNodeNames
        except Exception as e:
            exitMsg = "Failed to get upgraded nodes from step file. " \
                      "ERROR {0}".format(str(e))
            self.exitWithRetCode(self.action, False, exitMsg)

    def existTable(self, relname):
        """
        funcation: if the table exist in pg_class
        input : NA
        output: NA
        """
        try:
            sql = "select count(*) from pg_catalog.pg_class c, " \
                  "pg_catalog.pg_namespace n " \
                  "where n.nspname = '%s' AND relname = '%s' " \
                  "AND c.relnamespace = n.oid;" % (
                const.UPGRADE_SCHEMA, relname)
            self.context.logger.debug("Sql to query if has the table: %s" % sql)
            (status, output) = self.execSqlCommandInPrimaryDN(sql)
            if status != 0 or SqlResult.findErrorInSql(output):
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] %
                                sql + " Error: \n%s" % str(output))
            if output == '0':
                self.context.logger.debug("Table does not exist.")
                return False
            self.context.logger.debug("Table exists.")
            return True
        except Exception as e:
            raise Exception(str(e))

    def canUpgradeAgain(self):
        """
        judge if we should rollback or can upgrade again,
        if has the nodes whose step is more than switch bin
        """
        self.context.logger.debug("Check if we can upgrade again.")
        greyNodeNames = self.getUpgradedNodeNames(
            GreyUpgradeStep.STEP_SWITCH_NEW_BIN)
        if len(greyNodeNames) > 0:
            self.context.logger.debug(
                "Has nodes step greater or equal than %d. Can upgrade again."
                % GreyUpgradeStep.STEP_SWITCH_NEW_BIN)
            return True
        self.context.logger.debug(
            "There is no node step greater or equal than %d. "
            "Can not do upgrade again." % GreyUpgradeStep.STEP_SWITCH_NEW_BIN)
        return False

    def prepareGreyUpgrade(self):
        """
        function: do pre-upgrade stuffs for primary and standby HA
        sync check, and create table to record step
        input : NA
        output: NA
        """
        if self.context.upgrade_remain:
            self.context.logger.debug("No need to create pre-upgrade stuffs")
            return
        self.context.logger.debug("Start to create pre-upgrade stuffs")
        # under force upgrade, we only prepare the files
        self.prepareGreyUpgradeFiles()
        # all stuffs done successfully, return 0
        self.context.logger.debug("Successfully created pre-upgrade stuffs.")

    def prepareGreyUpgradeFiles(self):
        # the bakpath is created in checkUpgrade,
        # but may deleted when rollback, so need to check
        try:
            self.context.logger.debug("start to prepare grey upgrade files")
            self.createBakPath()
            self.initNodeStepInCsv()
            self.initUpgradeProcessStatus()
            self.recordDirFile()
            self.copyBakVersion()
            self.context.logger.debug(
                "successfully prepared grey upgrade files")
        except Exception as e:
            self.context.logger.debug("failed to prepare grey upgrade files")
            raise Exception(str(e))

    def initNodeStepInCsv(self):
        bakStepFile = os.path.join(self.context.upgradeBackupPath,
                                   const.GREY_UPGRADE_STEP_FILE + "_bak")
        self.context.logger.debug("Create and init the file %s." % bakStepFile)
        FileUtil.createFile(bakStepFile, True, DefaultValue.KEY_FILE_MODE)
        header = ["node_host", "upgrade_action", "step"]
        FileUtil.createFileInSafeMode(bakStepFile)
        writeInfo = []
        for dbNode in self.context.clusterInfo.dbNodes:
            writeInfo.append([('%s' % dbNode.name),
                              ('%s' % self.context.action),
                              ('%s' % GreyUpgradeStep.STEP_INIT_STATUS)])
        with open(bakStepFile, "w") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)
            writer.writerows(writeInfo)
        finalStepFile = os.path.join(self.context.upgradeBackupPath,
                                     const.GREY_UPGRADE_STEP_FILE)
        FileUtil.rename(bakStepFile, finalStepFile)
        # so if we can get the step file, we can get the step information
        self.context.logger.debug("Rename the file %s to %s." % (
            bakStepFile, finalStepFile))
        self.distributeFile(finalStepFile)
        self.context.logger.debug("Successfully inited the file %s and "
                                  "send it to each node." % finalStepFile)

    def initUpgradeProcessStatus(self):
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                const.INPLACE_UPGRADE_STEP_FILE)
        self.context.logger.debug("Create and init the file %s" % stepFile)
        FileUtil.removeFile(stepFile, "python")
        FileUtil.createFile(stepFile, True, DefaultValue.KEY_FILE_MODE)
        self.recordNodeStepInplace(self.context.action,
                                   GreyUpgradeStep.STEP_INIT_STATUS)
        self.context.logger.debug("Successfully inited the file %s "
                                  "and send it to each node" % stepFile)

    def recordNodeStep(self, step, nodes=None):
        """
        under normal rollback, if not have the binary_upgrade dir,
        recordNodeStepInplace will create a file named binary_upgrade,
        so we should raise error, and use the force rollback mode
        For commit upgrade, we should create the dir to record the cannot
         rollback flag to avoid node inconsistency
        :param step: upgrade or rollback step
        :param nodes: the nodes shoud be the step
        :return:NA
        """
        cmd = "if [ -d '%s' ]; then echo 'True'; else echo 'False'; fi" %\
              self.context.upgradeBackupPath
        hostList = copy.deepcopy(self.context.clusterNodes)
        (resultMap, outputCollect) = self.context.sshTool.getSshStatusOutput(
            cmd, hostList)
        self.context.logger.debug(
            "The result of checking distribute directory is:\n%s" %
            outputCollect)
        if outputCollect.find('False') >= 0:
            if step != GreyUpgradeStep.STEP_BEGIN_COMMIT:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                self.context.upgradeBackupPath)
            self.createBakPath()
        self.recordNodeStepInplace(self.context.action, step)
        # under force upgrade, we only record step to file
        self.recordNodeStepInCsv(step, nodes)
        self.context.logger.debug(
            "Successfully record node step %s." % str(step))

    def recordNodeStepInCsv(self, step, nodes=None):
        if nodes is None:
            nodes = []
        self.context.logger.debug("Record node step %s in file" % str(step))
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                const.GREY_UPGRADE_STEP_FILE)
        stepTempFile = os.path.join(self.context.upgradeBackupPath,
                                    "upgrade_step_temp.csv")
        FileUtil.createFileInSafeMode(stepTempFile)
        with open(stepFile, 'r') as csvfile, \
                open(stepTempFile, 'w') as tempfile:
            header = ["node_host", "upgrade_action", "step"]
            reader = csv.DictReader(csvfile)
            writer = csv.writer(tempfile)
            writer.writerow(header)
            writeInfo = []
            if not nodes:
                nodes = self.context.nodeNames
            if nodes:
                for row in reader:
                    if row['node_host'] in nodes:
                        writeInfo.append([row['node_host'], row[
                            'upgrade_action'], str(step)])
                    else:
                        writeInfo.append([row['node_host'], row[
                            'upgrade_action'], row['step']])
            else:
                for row in reader:
                    writeInfo.append([row['node_host'],
                                      row['upgrade_action'], str(step)])
            writer.writerows(writeInfo)

        FileUtil.removeFile(stepFile)
        FileUtil.rename(stepTempFile, stepFile)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, stepFile)
        # distribute the node step file to each node
        self.distributeFile(stepFile)

    def doInplaceBinaryUpgrade(self):
        """
        function: do binary upgrade, which essentially replace the binary files
        input : NA
        output: NA
        """
        # 1. distribute new package to every nodes.
        self.distributeXml()
        # 2. check whether we should do rollback or not.
        if not self.doInplaceBinaryRollback():
            self.exitWithRetCode(const.ACTION_AUTO_ROLLBACK, False)
        try:
            if self.context.action == const.ACTION_LARGE_UPGRADE and \
                    "dual-standby" not in self.context.clusterType:
                # check the cluster pressure
                self.HASyncReplayCheck()
            self.checkUpgrade()

            # 3. before do binary upgrade, we must make sure the cluster is
            # Normal and the database could be connected
            #    if not, exit.
            self.start_strategy(is_final=False)

            # uninstall kerberos if has already installed
            pghost_path = EnvUtil.getEnvironmentParameterValue(
                'PGHOST', self.context.user)
            kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
            if os.path.exists(kerberosflagfile):
                self.stop_strategy(is_final=False)
                self.context.logger.log("Starting uninstall Kerberos.",
                                        "addStep")
                cmd = "source %s && " % self.context.userProfile
                cmd += "%s -m uninstall -U %s" % (OMCommand.getLocalScript(
                    "Local_Kerberos"), self.context.user)
                self.context.sshTool.executeCommand(cmd)
                self.context.logger.log("Successfully uninstall Kerberos.")
                self.start_strategy(is_final=False)
            # Disable CM parameter in normal scenarios
            self.close_cm_server_gucs_before_install()
            if self.unSetClusterReadOnlyMode() != 0:
                raise Exception("NOTICE: "
                                + ErrorCode.GAUSS_529["GAUSS_52907"])
            self.recordNodeStepInplace(const.ACTION_INPLACE_UPGRADE,
                                       const.BINARY_UPGRADE_STEP_INIT_STATUS)

            (status, output) = self.doHealthCheck(const.OPTION_PRECHECK)
            if status != 0:
                self.exitWithRetCode(const.ACTION_INPLACE_UPGRADE, False,
                                     ErrorCode.GAUSS_516["GAUSS_51601"]
                                     % "cluster" + output)
            self.getOneDNInst()
            # 4.record the old and new app dir in file
            self.recordDirFile()
            if self.isLargeInplaceUpgrade:
                self.recordLogicalClusterName()
            # 6. reload vacuum_defer_cleanup_age to new value
            if self.isLargeInplaceUpgrade:
                if self.__upgrade_across_64bit_xid:
                    self.reloadVacuumDeferCleanupAge()

            if self.setClusterReadOnlyMode() != 0:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52908"])

            # after checkUpgrade, the bak path is ready, we can use it now
            # create inplace upgrade flag file if is doing inplace upgrade
            self.createInplaceUpgradeFlagFile()
            # 7. backup current application and configuration.
            # The function only be used by binary upgrade.
            #    to ensure the transaction atomicity,
            #    it will be used with checkUpgrade().
            self.backupNodeVersion()
            # For inplace upgrade, we have to perform additional checks
            # and then backup catalog files.
            if self.isLargeInplaceUpgrade:
                self.prepareUpgradeSqlFolder()
                self.HASyncReplayCheck()
                self.backupOldClusterDBAndRelInfo()
            # 8. stop old cluster
            self.recordNodeStepInplace(const.ACTION_INPLACE_UPGRADE,
                                       const.BINARY_UPGRADE_STEP_STOP_NODE)
            self.context.logger.debug("Start to stop all instances"
                                      " on the node.", "addStep")
            self.stop_strategy(is_final=False)
            self.context.logger.debug("Successfully stop all"
                                      " instances on the node.", "constant")
            # 9. back cluster config. including this:
            #    cluster_static_config
            #    cluster_dynamic_config
            #    etc/gscgroup_xxx.cfg
            #    lib/postgresql/pg_plugin
            #    server.key.cipher
            #    server.key.rand
            #    Data Studio lib files
            #    gds files
            #    physical catalog files if performing inplace upgrade
            self.recordNodeStepInplace(
                const.ACTION_INPLACE_UPGRADE,
                const.BINARY_UPGRADE_STEP_BACKUP_VERSION)
            self.backupClusterConfig()

            # 10. Upgrade application on node
            #     install new bin file
            self.recordNodeStepInplace(const.ACTION_INPLACE_UPGRADE,
                                       const.BINARY_UPGRADE_STEP_UPGRADE_APP)
            self.installNewBin()

            # 11. restore the cluster config. including this:
            #    cluster_static_config
            #    cluster_dynamic_config
            #    etc/gscgroup_xxx.cfg
            #    lib/postgresql/pg_plugin
            #    server.key.cipher
            #    server.key.rand
            #    Data Studio lib files
            #    gds files
            #    cn cert files
            #    At the same time, sync newly added guc for instances
            #    Install CM instance
            self.restoreClusterConfig()
            self.syncNewGUC()
            # unset cluster readonly
            self.start_strategy(is_final=False)
            if self.unSetClusterReadOnlyMode() != 0:
                raise Exception("NOTICE: "
                                + ErrorCode.GAUSS_529["GAUSS_52907"])
            # Disable the CM parameter in the upgrade scenario from no CM component to with CM component.
            self.close_cm_server_gucs_after_install()
            # flush new app dynamic configuration
            dynamicConfigFile = "%s/bin/cluster_dynamic_config" % \
                                self.context.newClusterAppPath
            # If the target to upgrade has CM, there is no need to update the dynamic file,
            # because the dynamic configuration files of OM and CM are inconsistent,
            # and problems may occur after OM updates the dynamic file.
            if self.get_upgrade_cm_strategy() == 0 \
                    and os.path.exists(dynamicConfigFile) \
                    and self.isLargeInplaceUpgrade:
                self.refresh_dynamic_config_file()
                self.context.logger.debug(
                    "Successfully refresh dynamic config file")
            self.stop_strategy(is_final=False)
            if self.get_upgrade_cm_strategy() == 0 \
                    and os.path.exists(dynamicConfigFile) \
                    and self.isLargeInplaceUpgrade:
                self.restore_dynamic_config_file()
            # 12. modify GUC parameter unix_socket_directory
            self.modifySocketDir()
            # 13. start new cluster
            self.recordNodeStepInplace(const.ACTION_INPLACE_UPGRADE,
                                       const.BINARY_UPGRADE_STEP_START_NODE)
            self.context.logger.debug("Start to start all instances"
                                      " on the node.", "addStep")

            # update catalog
            # start cluster in normal mode
            if self.isLargeInplaceUpgrade:
                self.touchRollbackCatalogFlag()
                self.updateCatalog()
            self.CopyCerts()
            if DefaultValue.is_create_grpc(self.context.logger, self.context.oldClusterAppPath):
                self.context.createGrpcCa()
            self.context.logger.debug("Successfully createGrpcCa.")

            # stop cluster for switch new bin
            self.stop_strategy(is_final=False)
            self.switchBin(const.NEW)
            # create CA for CM
            self.create_ca_for_cm()
            self.start_strategy(is_final=False)
            if self.isLargeInplaceUpgrade:
                self.modifyPgProcIndex()
                self.context.logger.debug("Start to exec post upgrade script")
                self.doUpgradeCatalog(postUpgrade=True)
                self.context.logger.debug(
                    "Successfully exec post upgrade script")
            self.context.logger.debug("Successfully start all "
                                      "instances on the node.", "constant")
            if self.setClusterReadOnlyMode() != 0:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52908"])
            # 14. check the cluster status
            (status, output) = self.doHealthCheck(const.OPTION_POSTCHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"]
                                % "cluster" + output)

            # 15. record precommit step status
            self.recordNodeStepInplace(const.ACTION_INPLACE_UPGRADE,
                                       const.BINARY_UPGRADE_STEP_PRE_COMMIT)
            self.printPrecommitBanner()
        except Exception as e:
            self.context.logger.error(str(e))
            self.context.logger.log("Binary upgrade failed. Rollback"
                                    " to the original cluster.")
            # do rollback
            self.exitWithRetCode(const.ACTION_AUTO_ROLLBACK,
                                 self.doInplaceBinaryRollback())
        self.exitWithRetCode(const.ACTION_INPLACE_UPGRADE, True)

    def backupGlobalRelmapFile(self):
        """
        Wait and check if all standbys have replayed upto flushed xlog
        positions of primaries, then backup global/pg_filenode.map.
        if old cluster version num >= RELMAP_4K_VERSION, then no need to backup
        """
        if self.context.oldClusterNumber >= const.RELMAP_4K_VERSION:
            self.context.logger.debug("no need to backup global relmap file")
            return

        # perform a checkpoint and wait standby catchup
        self.createCheckpoint()
        self.getAllStandbyDnInsts()
        # wait standby catchup first
        self.HASyncReplayCheck(False)
        # then wait all cascade standby(if any)
        for standby in self.dnStandbyInsts:
            self.HASyncReplayCheck(False, standby)
        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -l %s -V %d" % \
                (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                const.ACTION_BACKUP_GLOBAL_RELMAP_FILE,
                self.context.user,
                self.context.localLog,
                int(float(self.context.oldClusterNumber) * 1000))
        self.context.logger.debug("backup global relmap file: %s." % cmd)
        hostList = copy.deepcopy(self.context.clusterNodes)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Successfully backup global relmap file.")

    def cleanTmpGlobalRelampFile(self):
        """
        remove global/pg_filenode.map when commit, if old cluster
        version num >= RELMAP_4K_VERSION, then no need to remove.
        """
        if self.context.oldClusterNumber >= const.RELMAP_4K_VERSION:
            self.context.logger.debug("no need to clean tmp global relmap file")
            return
        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -l %s -V %d" % \
                (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                const.ACTION_CLEAN_TMP_GLOBAL_RELMAP_FILE,
                self.context.user,
                self.context.localLog,
                int(float(self.context.oldClusterNumber) * 1000))

        self.context.logger.debug("clean tmp global relmap file when commit or rollback: %s." % cmd)
        hostList = copy.deepcopy(self.context.clusterNodes)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Successfully clean tmp global relmap file.")

    def restoreGlobalRelampFile(self):
        """
        restore global/pg_filenode.map when rollback, if old cluster
        version num >= RELMAP_4K_VERSION, then no need to restore.
        use pg_filenode.old.map to recover pg_filenode.map and pg_filenode.map.backup
        """
        if self.context.oldClusterNumber >= const.RELMAP_4K_VERSION:
            self.context.logger.debug("no need to restore global relmap file")
            return

        # perform checkpoint and wait standby sync before rollback
        self.createCheckpoint()
        self.getAllStandbyDnInsts()
        # wait standby catchup first
        self.HASyncReplayCheck(False)
        # then wait all cascade standby(if any)
        for standby in self.dnStandbyInsts:
            self.HASyncReplayCheck(False, standby)

        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -l %s -V %d" % \
                (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                const.ACTION_RESTORE_GLOBAL_RELMAP_FILE,
                self.context.user,
                self.context.localLog,
                int(float(self.context.oldClusterNumber) * 1000))

        self.context.logger.debug("restore global relmap file when commit: %s." % cmd)
        hostList = copy.deepcopy(self.context.clusterNodes)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Successfully restore global relmap file.")

    def doInplaceCommitUpgrade(self):
        """
        function: commit binary upgrade and clean up backup files
                  1. unset read-only
                  2. drop old PMK schema
                  3. restore UDF
                  4. clean backup catalog physical
                   files if doing inplace upgrade
                  5. clean up other upgrade tmp files
        input : NA
        output: NA
        """
        self.context.logger.log("NOTICE: Start to commit binary upgrade.")
        self.context.logger.log("Start to check whether can be committed.", "addStep")
        if self.getNodeStepInplace() != const.BINARY_UPGRADE_STEP_PRE_COMMIT:
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52916"]
                            + " Please check if previous upgrade"
                              " operation was successful or if"
                              " upgrade has already been committed.")
        self.context.logger.log("Can be committed.", "constant")
        self.context.logger.log("Start to set commit flag.", "addStep")
        # create commit flag file
        self.createCommitFlagFile()
        self.context.logger.log("Set commit flag succeeded.", "constant")
        self.context.logger.log("Start to do operations that cannot be rollback.", "addStep")

        # variable to indicate whether we should keep step file
        # and cleanup list file for re-entry
        cleanUpSuccess = True

        # drop table and index after large upgrade
        if self.isLargeInplaceUpgrade and self.check_upgrade_mode():
            self.drop_table_or_index()
        # 1.unset read-only
        self.setUpgradeFromParam(const.UPGRADE_UNSET_NUM)
        self.restart_cm_proc()
        if self.isLargeInplaceUpgrade:
            self.setUpgradeMode(0)

        if self.unSetClusterReadOnlyMode() != 0:
            self.context.logger.log("NOTICE: "
                                    + ErrorCode.GAUSS_529["GAUSS_52907"])
            cleanUpSuccess = False
        if self.isLargeInplaceUpgrade:
            self.cleanCsvFile()
        # 2. drop old PMK schema
        # we sleep 10 seconds first because DB might be updating
        # ha status after unsetting read-only
        self.context.logger.log("Cancel the upgrade status succeeded.", "constant")
        self.context.logger.log("Start to clean temp files for upgrade.", "addStep")
        time.sleep(10)

        # restore the CM parameter
        try:
            self.restore_cm_server_guc(const.CLUSTER_CMSCONF_FILE, True)
        except Exception as er:
            self.context.logger.debug("Failed to restore CM parameter. " + str(er))
            cleanUpSuccess = False

        # 3. clean backup catalog physical files if doing inplace upgrade
        if self.cleanBackupedCatalogPhysicalFiles() != 0:
            self.context.logger.debug(
                "Failed to clean backup files in directory %s. "
                % self.context.upgradeBackupPath)

        if not cleanUpSuccess:
            self.context.logger.log("NOTICE: Cleanup is incomplete during commit. "
                                    "Please re-commit upgrade once again or cleanup manually")
        else:
            # 8. clean up other upgrade tmp files
            # and uninstall inplace upgrade support functions
            self.cleanInstallPath(const.OLD)
            # Only delete the old_upgrade_version file under the binary_upgrade directory to 
            # prevent gaussdb from starting with the old version. However, keep the binary_upgrade
            # directory temporarily so that CM remains in maintenance mode when restarting,
            # ensuring that the primary does not switch after the restart.
            # After the restart is complete, delete the binary_upgrade directory.
            self._cleanOldUpgradVersion()
            if self.isLargeInplaceUpgrade:
                self.stop_strategy(is_final=False)
                self.start_strategy(is_final=False)
            # After starting the cluster, delete the binary_upgrade directory to avoid entering
            # non-maintenance mode during startup, which could cause a host switch.
            self.cleanBinaryUpgradeBakFiles()

            # install Kerberos
            self.install_kerberos()
            self.context.logger.log("Clean temp files for upgrade succeeded.", "constant")
            self.context.logger.log("NOTICE: Commit binary upgrade succeeded.")
            
        # remove global relmap file
        self.cleanTmpGlobalRelampFile()
        self.exitWithRetCode(const.ACTION_INPLACE_UPGRADE, cleanUpSuccess)

    def _cleanOldUpgradVersion(self):
        """
        clean binary_upgrade/olg_upgrade_version
        """
        olg_upgrade_version_path = os.path.join(self.context.upgradeBackupPath, "old_upgrade_version")
        cmd = "(if [ -f '{path}' ]; then rm -rf '{path}'; fi) ".format(
            path=olg_upgrade_version_path)
        self.context.logger.debug("Command for clean olg_upgrade_version files: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd, self.context.sshTool,
            self.context.isSingle, self.context.mpprcFile)

    def install_kerberos(self):
        """
        install kerberos after upgrade
        :return:NA
        """
        pghost_path = EnvUtil.getEnvironmentParameterValue(
            'PGHOST', self.context.user)
        kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
        if os.path.exists(kerberosflagfile):
            # install kerberos
            cmd = "source %s &&" % self.context.userProfile
            cmd += "gs_om -t stop && "
            cmd += "%s -m install -U %s --krb-server" % (
                OMCommand.getLocalScript("Local_Kerberos"),
                self.context.user)
            (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                "Command:%s. Error:\n%s" % (cmd, output))
            cmd = "source %s && " % self.context.userProfile
            cmd += "%s -m install -U %s --krb-client " % (
            OMCommand.getLocalScript("Local_Kerberos"), self.context.user)
            self.context.sshTool.executeCommand(
                cmd, hostList=self.context.clusterNodes)
            self.context.logger.log("Successfully install Kerberos.")
            cmd = "source %s && gs_om -t start" % self.context.userProfile
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                "Command:%s. Error:\n%s" % (cmd, output))
            os.remove(kerberosflagfile)

    def refresh_dynamic_config_file(self):
        """
        refresh dynamic config file
        :return:
        """
        cmd = "source %s ;gs_om -t refreshconf" % self.context.userProfile
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            "Command:%s. Error:\n%s" % (cmd, output))

    def restore_dynamic_config_file(self):
        """
        restore dynamic config file
        :return:
        """
        cmd = "%s -t %s -U %s -V %d --upgrade_bak_path=%s " \
              "--old_cluster_app_path=%s --new_cluster_app_path=%s " \
              "-l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            const.ACTION_RESTORE_DYNAMIC_CONFIG_FILE,
            self.context.user,
            int(float(self.context.oldClusterNumber) * 1000),
            self.context.upgradeBackupPath,
            self.context.oldClusterAppPath,
            self.context.newClusterAppPath,
            self.context.localLog)

        self.context.logger.debug("Command for restoring "
                                  "config files: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)

    def cleanCsvFile(self):
        """
        clean csv file
        :return:
        """
        clusterNodes = self.context.clusterInfo.dbNodes
        for dbNode in clusterNodes:
            if len(dbNode.datanodes) == 0:
                continue
            dnInst = dbNode.datanodes[0]
            dndir = dnInst.datadir
            pg_proc_csv_path = \
                '%s/pg_copydir/tbl_pg_proc_oids.csv' % dndir
            new_pg_proc_csv_path = \
                '%s/pg_copydir/new_tbl_pg_proc_oids.csv' % dndir
            if os.path.exists(pg_proc_csv_path):
                FileUtil.removeFile(pg_proc_csv_path)
            if os.path.exists(new_pg_proc_csv_path):
                FileUtil.removeFile(new_pg_proc_csv_path)

    def check_upgrade_mode(self):
        """
        check upgrade_mode value
        :return:
        """
        cmd = "source %s ; gs_guc check -N all -I all -c 'upgrade_mode'" % \
              self.context.userProfile
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_500[
                                "GAUSS_50010"] % 'upgrade_mode' +
                            "Error: \n%s" % str(output))
        if output.find("upgrade_mode=0") >= 0:
            return False
        else:
            return True

    def cleanBackupedCatalogPhysicalFiles(self, isRollBack=False):
        """
        function : clean backuped catalog physical files
        input : isRollBack, default is False
        output: return 0, if the operation is done successfully.
                return 1, if the operation failed.
        """
        try:
            if self.isLargeInplaceUpgrade:
                self.context.logger.log("Clean up backup catalog files.")
                # send cmd to all node and exec
                cmd = "%s -t %s -U %s --upgrade_bak_path=%s -X '%s' -l %s" % \
                      (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                       const.ACTION_CLEAN_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.xmlFile,
                       self.context.localLog)
                if isRollBack:
                    cmd += " --rollback --oldcluster_num='%s'" % \
                           self.context.oldClusterNumber
                self.context.logger.debug(
                    "Command for cleaning up physical catalog files: %s." % cmd)
                CmdExecutor.execCommandWithMode(
                    cmd,
                    self.context.sshTool,
                    self.context.isSingle,
                    self.context.userProfile)
                self.context.logger.debug(
                    "Successfully cleaned up backup catalog files.")
            return 0
        except Exception as e:
            if isRollBack:
                raise Exception(
                    "Fail to clean up backup catalog files: %s" % str(e))
            else:
                self.context.logger.debug(
                    "Fail to clean up backup catalog files. " +
                    "Please re-commit upgrade once again or clean up manually.")
                return 1

    def recordLogicalClusterName(self):
        """
        function: record the logical node group name in bakpath,
        so that we can restore specfic name in bakpath,
        used in restoreCgroup, and refresh the CgroupConfigure
        input : NA
        output: NA
        """
        lcgroupfile = "%s/oldclusterinfo.json" % self.context.tmpDir
        try:
            self.context.logger.debug(
                "Write and send logical cluster info file.")
            # check whether file is exists
            if os.path.isfile(lcgroupfile):
                return 0
            # check whether it is lc cluster
            sql = """SELECT true AS group_kind
                     FROM pg_class c, pg_namespace n, pg_attribute attr
                     WHERE c.relname = 'pgxc_group' AND n.nspname = 'pg_catalog'
                      AND attr.attname = 'group_kind' AND c.relnamespace = 
                      n.oid AND attr.attrelid = c.oid; """
            self.context.logger.debug(
                "Check if the cluster type is a logical cluster.")
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql,
                self.context.user,
                self.dnInst.hostname,
                self.dnInst.port,
                False,
                DefaultValue.DEFAULT_DB_NAME,
                IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513[
                                    "GAUSS_51300"] % sql + " Error: \n%s" % str(
                    output))
            if not output or output.strip() != 't':
                self.context.logger.debug(
                    "The old cluster is not logical cluster.")
                return 0
            self.context.logger.debug("The old cluster is logical cluster.")
            # get lc group name lists
            sql = "SELECT group_name FROM pgxc_group WHERE group_kind = 'v';"
            self.context.logger.debug(
                "Getting the list of logical cluster names.")
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql,
                self.context.user,
                self.dnInst.hostname,
                self.dnInst.port,
                False,
                DefaultValue.DEFAULT_DB_NAME,
                IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513[
                                    "GAUSS_51300"] % sql + " Error: \n%s" % str(
                    output))
            lcgroupnames = output.split("\n")
            self.context.logger.debug(
                "The list of logical cluster names: %s." % lcgroupnames)
            # create the file
            FileUtil.createFile(lcgroupfile)
            FileUtil.changeOwner(self.context.user, lcgroupfile)
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, lcgroupfile)
            # write result to file
            with open(lcgroupfile, "w") as fp_json:
                json.dump({"lcgroupnamelist": lcgroupnames}, fp_json)
            # send file to remote nodes
            if not self.context.isSingle:
                self.context.sshTool.scpFiles(lcgroupfile, self.context.tmpDir)
                self.context.logger.debug(
                    "Successfully to write and send logical cluster info file.")
            return 0
        except Exception as e:
            cmd = "(if [ -f '%s' ]; then rm -f '%s'; fi)" % (
                lcgroupfile, lcgroupfile)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.userProfile)
            raise Exception(str(e))

    def prepareUpgradeSqlFolder(self):
        """
        function: verify upgrade_sql.tar.gz and extract it to binary backup
        path, because all node need set_guc, so
        we will decompress on all nodes
        input : NA
        output: NA
        """
        self.context.logger.debug("Preparing upgrade sql folder.")
        if self.context.standbyCluster:
            self.context.logger.debug("no need prepare upgrade sql folder under force upgrade")
            return
        hosts = self.context.clusterNodes
        cmd = "%s -t %s -U %s --upgrade_bak_path=%s -X %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_UPGRADE_SQL_FOLDER,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.xmlFile,
               self.context.localLog)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.userProfile,
                                        hosts)

    def HASyncReplayCheck(self, catchupFailedOk=True, host=None):
        """
        function: Wait and check if all standbys have replayed upto flushed
                  xlog positions of primaries.We record primary xlog flush
                  position at start of the check and wait until standby replay
                  upto that point.
                  Attention: If autovacuum is turned on, primary xlog flush
                  position may increase during the check.We do not check such
                   newly added xlog because they will not change catalog
                   physical file position.
        Input: catchupFailedOk, if it's ok standby catch up primay failed
        output : NA
        """
        host = self.dnInst if host == None else host
        self.context.logger.debug("Start to wait and check if all the standby"
                                  " instances have replayed all xlogs, host: %s" % \
                                  host.hostname)
        if self.context.standbyCluster or self.context.forceRollback:
            self.context.logger.debug("no need to do HA sync replay check "
                                      "under force upgrade/rollback and standby cluster mode")
            return
        self.doReplay(catchupFailedOk, host)
        self.context.logger.debug("Successfully performed the replay check "
                                  "of the standby instance.")

    def doReplay(self, catchupFailedOk, host):
        refreshTimeout = 180
        waitTimeout = 300
        RefreshTime = datetime.now() + timedelta(seconds=refreshTimeout)
        EndTime = datetime.now() + timedelta(seconds=waitTimeout)
        # wait and check sync status between primary and standby

        NeedReplay = True
        PosList = []
        while NeedReplay:
            sql = "SELECT sender_flush_location,receiver_replay_location " \
                  "from pg_catalog.pg_stat_get_wal_senders() " \
                  "where peer_role != 'Secondary';"
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql,
                self.context.user,
                host.hostname,
                host.port,
                False,
                DefaultValue.DEFAULT_DB_NAME,
                IsInplaceUpgrade=True)
            if status != 0:
                self.context.logger.debug(
                    "Primary and Standby may be not in sync.")
                self.context.logger.debug(
                    "Sync status: %s. Output: %s" % (str(status), output))
            elif output != "":
                self.context.logger.debug(
                    "Sync status: %s. Output: %s" % (str(status), output))
                tmpPosList = self.getXlogPosition(output)
                if len(PosList) == 0:
                    PosList = copy.deepcopy(tmpPosList)
                    self.context.logger.debug(
                        "Primary and Standby may be not in sync.")
                else:
                    NeedReplay = False
                    for eachRec in PosList:
                        for eachTmpRec in tmpPosList:
                            if self.needReplay(eachRec, eachTmpRec):
                                NeedReplay = True
                                self.context.logger.debug(
                                    "Primary and Standby may be not in sync.")
                                break
                        if NeedReplay:
                            break
            else:
                NeedReplay = False

            # Standby replay postion may keep falling behind primary
            #  flush position if it is at the end of one xlog page and the
            # free space is less than xlog record header size.
            # We do a checkpoint to avoid such situation.
            if datetime.now() > RefreshTime and NeedReplay:
                self.context.logger.debug(
                    "Execute CHECKPOINT to refresh xlog position.")
                refreshsql = "set statement_timeout=300000;CHECKPOINT;"
                (status, output) = ClusterCommand.remoteSQLCommand(
                    refreshsql,
                    self.context.user,
                    host.hostname,
                    host.port,
                    False,
                    DefaultValue.DEFAULT_DB_NAME,
                    IsInplaceUpgrade=True)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] % refreshsql +
                        "Error: \n%s" % str(output))

            if datetime.now() > EndTime and NeedReplay:
                logStr = "WARNING: " + ErrorCode.GAUSS_513["GAUSS_51300"] % sql +\
                    " Timeout while waiting for standby replay."
                if catchupFailedOk:
                    self.context.logger.log(logStr)
                    return
                raise Exception(logStr)
            time.sleep(5)

    def getXlogPosition(self, output):
        """
        get xlog position from output
        """
        tmpPosList = []
        resList = output.split('\n')
        for eachLine in resList:
            tmpRec = {}
            (flushPos, replayPos) = eachLine.split('|')
            (flushPosId, flushPosOff) = (flushPos.strip()).split('/')
            (replayPosId, replayPosOff) = (replayPos.strip()).split('/')
            tmpRec['nodeName'] = self.getHAShardingName()
            tmpRec['flushPosId'] = flushPosId.strip()
            tmpRec['flushPosOff'] = flushPosOff.strip()
            tmpRec['replayPosId'] = replayPosId.strip()
            tmpRec['replayPosOff'] = replayPosOff.strip()
            tmpPosList.append(tmpRec)
        return tmpPosList

    def getHAShardingName(self):
        """
        in centralized cluster, used to get the only one sharding name
        """
        peerInsts = self.context.clusterInfo.getPeerInstance(self.dnInst)
        (instance_name, _, _) = ClusterInstanceConfig.\
            getInstanceInfoForSinglePrimaryMultiStandbyCluster(
                self.dnInst, peerInsts)
        return instance_name

    def needReplay(self, eachRec, eachTmpRec):
        """
        judeg if need replay by xlog position
        """
        if eachRec['nodeName'] == eachTmpRec['nodeName'] \
                and (int(eachRec['flushPosId'], 16) > int(
            eachTmpRec['replayPosId'], 16) or (
                int(eachRec['flushPosId'], 16) == int(
            eachTmpRec['replayPosId'], 16) and int(
            eachRec['flushPosOff'], 16) > int(eachTmpRec['replayPosOff'], 16))):
            return True
        else:
            return False

    def backupOldClusterDBAndRelInfo(self):

        """
        function: backup old cluster db and rel info
                  send cmd to that node
        input : NA
        output: NA
        """
        tmpFile = os.path.join(EnvUtil.getTmpDirFromEnv(
            self.context.user), const.TMP_DYNAMIC_DN_INFO)
        try:
            self.context.logger.debug("Start to backup old cluster database"
                                      " and relation information.")
            # prepare backup path
            backup_path = os.path.join(
                self.context.upgradeBackupPath, "oldClusterDBAndRel")
            cmd = "rm -rf '%s' && mkdir '%s' -m '%s' " % \
                  (backup_path, backup_path, DefaultValue.KEY_DIRECTORY_MODE)
            hostList = copy.deepcopy(self.context.clusterNodes)
            self.context.sshTool.executeCommand(cmd, hostList=hostList)
            # prepare dynamic cluster info file in every node
            self.generateDynamicInfoFile(tmpFile)
            # get dn primary hosts
            dnPrimaryNodes = self.getPrimaryDnListFromDynamicFile()
            execHosts = list(set(dnPrimaryNodes))

            # send cmd to all node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s -X '%s' -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_BACKUP_OLD_CLUSTER_DB_AND_REL,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.xmlFile,
                   self.context.localLog)
            self.context.logger.debug(
                "Command for backing up old cluster database and "
                "relation information: %s." % cmd)
            self.context.sshTool.executeCommand(cmd, hostList=execHosts)
            self.context.logger.debug("Backing up information of all nodes.")
            self.context.logger.debug("Successfully backed up old cluster "
                                      "database and relation information")
        except Exception as e:
            raise Exception(str(e))
        finally:
            if os.path.exists(tmpFile):
                deleteCmd = "(if [ -f '%s' ]; then rm -f '%s'; fi) " % \
                            (tmpFile, tmpFile)
                hostList = copy.deepcopy(self.context.clusterNodes)
                self.context.sshTool.executeCommand(
                    deleteCmd, hostList=hostList)

    def generateDynamicInfoFile(self, tmpFile):
        """
        generate dynamic info file and send to every node
        :return:
        """
        self.context.logger.debug(
            "Start to generate dynamic info file and send to every node.")
        try:
            cmd = ClusterCommand.getQueryStatusCmd("", outFile=tmpFile)
            SharedFuncs.runShellCmd(cmd, self.context.user,
                                    self.context.userProfile)
            if not os.path.exists(tmpFile):
                raise Exception("Can not genetate dynamic info file")
            self.context.distributeFileToSpecialNode(tmpFile,
                                                     os.path.dirname(tmpFile),
                                                     self.context.clusterNodes)
            self.context.logger.debug(
                "Success to generate dynamic info file and send to every node.")
        except Exception as er:
            raise Exception("Failed to generate dynamic info file in "
                            "these nodes: {0}, error: {1}".format(
                self.context.clusterNodes, str(er)))

    def getPrimaryDnListFromDynamicFile(self):
        """
        get primary dn list from dynamic file
        :return: primary dn list
        """
        try:
            self.context.logger.debug(
                "Start to get primary dn list from dynamic file.")
            tmpFile = os.path.join(EnvUtil.getTmpDirFromEnv(
                self.context.user), const.TMP_DYNAMIC_DN_INFO)
            if not os.path.exists(tmpFile):
                raise Exception(ErrorCode.GAUSS_529["GAUSS_50201"] % tmpFile)
            dynamicClusterStatus = DbClusterStatus()
            dynamicClusterStatus.initFromFile(tmpFile)
            cnAndPrimaryDnNodes = []
            # Find the master DN instance
            for dbNode in dynamicClusterStatus.dbNodes:
                for instance in dbNode.datanodes:
                    if instance.status == 'Primary':
                        for staticDBNode in self.context.clusterInfo.dbNodes:
                            if staticDBNode.id == instance.nodeId:
                                cnAndPrimaryDnNodes.append(staticDBNode.name)
            result = list(set(cnAndPrimaryDnNodes))
            self.context.logger.debug("Success to get primary dn list from "
                                      "dynamic file: {0}.".format(result))
            return result
        except Exception as er:
            raise Exception("Failed to get primary dn list from dynamic file. "
                            "Error:{0}".format(str(er)))


    def touchRollbackCatalogFlag(self):
        """
        before update system catalog, touch a flag file.
        """
        # touch init flag file
        # during rollback, if init flag file has not been touched,
        # we do not need to do catalog rollback.
        cmd = "touch '%s/touch_init_flag'" % self.context.upgradeBackupPath
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.userProfile)

    def updateCatalog(self):
        """
        function: update catalog to new version
                  steps:
                  1.prepare update sql file and check sql file
                  2.do update catalog
        Input: NA
        output : NA
        """
        try:
            self.prepareSql("upgrade-post")
            self.prepareSql("upgrade")
            self.prepareSql("rollback-post")
            self.prepareSql("rollback")
            self.doUpgradeCatalog()
        except Exception as e:
            raise Exception(
                "Failed to execute update sql file. Error: %s" % str(e))

    def doUpgradeCatalog(self, postUpgrade=False):
        """
        function: update catalog to new version
                  1.set upgrade_from param
                  2.start cluster
                  3.touch init files and do pre-upgrade staffs
                  4.connect database and update catalog one by one
                  5.stop cluster
                  6.unset upgrade_from param
                  7.start cluster
        Input: oldClusterNumber
        output : NA
        """
        self.context.logger.debug("Start upgrade catalog.")
        try:
            if not postUpgrade:
                self.context.logger.debug("Not post upgrade.")
                self.setUpgradeFromParam(self.context.oldClusterNumber)
                if self.context.action == const.ACTION_INPLACE_UPGRADE:
                    # Must set guc after start cluster by setUpgradeMode, because checking guc
                    # needs to connect database to execute sql statement.
                    self.start_strategy(is_final=False)
                    self.setUpgradeMode(1, "reload")
                    self.touchInitFile()
                else:
                    # the guc parameter upgrade_from need to restart cmagent to take effect
                    self.setUpgradeMode(2)
                    self.reloadCmAgent()
                    # kill snapshot thread in kernel
                    self.context.killKernalSnapshotThread(self.dnInst)

                self.execRollbackUpgradedCatalog(scriptType="rollback")
                self.execRollbackUpgradedCatalog(scriptType="upgrade")
                self.pgxcNodeUpdateLocalhost("upgrade")
            else:
                self.context.logger.debug("Post upgrade.")
                self.waitClusterForNormal()
                # backup global relmap file before doing upgrade-post
                self.backupGlobalRelmapFile()
                self.execRollbackUpgradedCatalog(scriptType="rollback-post")
                self.execRollbackUpgradedCatalog(scriptType="upgrade-post")

            self.getLsnInfo()
            if self.context.action == \
                    const.ACTION_INPLACE_UPGRADE and not postUpgrade and not \
                    int(float(self.context.newClusterNumber) * 1000) > 92298:
                self.updatePgproc()
        except Exception as e:
            raise Exception("update catalog failed.ERROR: %s" % str(e))

    def updatePgproc(self):
        """
        function: update pg_proc during large upgrade
        :return:
        """
        self.context.logger.debug(
            "Start to update pg_proc in inplace large upgrade ")
        # generate new csv file
        execHosts = [self.dnInst.hostname]
        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -R '%s' -l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            const.ACTION_CREATE_NEW_CSV_FILE,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        self.context.logger.debug(
            "Command for create new csv file: %s." % cmd)
        self.context.sshTool.executeCommand(cmd, hostList=execHosts)
        self.context.logger.debug(
            "Successfully created new csv file.")
        # select all databases
        database_list = self.getDatabaseList()
        # create pg_proc_temp_oids
        new_pg_proc_csv_path = '%s/pg_copydir/new_tbl_pg_proc_oids.csv' % \
                               self.dnInst.datadir
        self.createPgprocTempOids(new_pg_proc_csv_path, database_list)
        # create pg_proc_temp_oids index
        self.createPgprocTempOidsIndex(database_list)
        # make checkpoint
        self.replyXlog(database_list)
        # create pg_proc_mapping.txt to save the mapping between pg_proc
        #  file path and pg_proc_temp_oids file path
        cmd = "%s -t %s -U %s -R '%s' -l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            const.ACTION_CREATE_PG_PROC_MAPPING_FILE,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        CmdExecutor.execCommandWithMode(
            cmd,
            self.context.sshTool,
            self.context.isSingle,
            self.context.userProfile)
        self.context.logger.debug(
            "Successfully created file to save mapping between pg_proc file "
            "path and pg_proc_temp_oids file path.")
        # stop cluster
        self.stop_strategy()
        # replace pg_proc data file by pg_proc_temp data file
        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -R '%s' -l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            const.ACTION_REPLACE_PG_PROC_FILES,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        CmdExecutor.execCommandWithMode(
            cmd,
            self.context.sshTool,
            self.context.isSingle,
            self.context.userProfile)
        self.context.logger.debug(
            "Successfully replaced pg_proc data files.")

    def createPgprocTempOids(self, new_pg_proc_csv_path, database_list):
        """
        create pg_proc_temp_oids
        :return:
        """
        sql = \
            """START TRANSACTION; SET IsInplaceUpgrade = on; 
            CREATE TABLE pg_proc_temp_oids (proname name NOT NULL, 
            pronamespace oid NOT NULL, proowner oid NOT NULL, prolang oid 
            NOT NULL, procost real NOT NULL, prorows real NOT NULL, 
            provariadic oid NOT NULL, protransform regproc NOT NULL, 
            proisagg boolean NOT NULL, proiswindow boolean NOT NULL, 
            prosecdef boolean NOT NULL, proleakproof boolean NOT NULL, 
            proisstrict boolean NOT NULL, proretset boolean NOT NULL, 
            provolatile "char" NOT NULL, pronargs smallint NOT NULL, 
            pronargdefaults smallint NOT NULL, prorettype oid NOT NULL, 
            proargtypes oidvector NOT NULL, proallargtypes oid[], 
            proargmodes "char"[], proargnames text[], proargdefaults 
            pg_node_tree, prosrc text, probin text, proconfig text[], 
            proacl aclitem[], prodefaultargpos int2vector,fencedmode boolean, 
            proshippable boolean, propackage boolean, prokind "char" NOT 
            NULL) with oids;"""
        sql += "copy pg_proc_temp_oids  WITH OIDS from '%s' with " \
               "delimiter ',' csv header FORCE NOT NULL proargtypes;" % \
               new_pg_proc_csv_path
        sql += "COMMIT;"
        # update proisagg and proiswindow message sql
        sql += \
            "update pg_proc_temp_oids set proisagg = CASE WHEN prokind = 'a' " \
            "THEN True ELSE False END, proiswindow = CASE WHEN prokind = 'w' " \
            "THEN True ELSE False END;"
        self.context.logger.debug("pg_proc_temp_oids sql is %s" % sql)
        # creat table
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))

    def createPgprocTempOidsIndex(self, database_list):
        """
        create index pg_proc_oid_index_temp and
        pg_proc_proname_args_nsp_index_temp
        :return:
        """
        sql = "CREATE UNIQUE INDEX pg_proc_oid_index_temp ON " \
              "pg_proc_temp_oids USING btree (oid) TABLESPACE pg_default;"
        sql += "CREATE UNIQUE INDEX pg_proc_proname_args_nsp_index_temp ON" \
               " pg_proc_temp_oids USING btree (proname, proargtypes," \
               " pronamespace) TABLESPACE pg_default;"
        # creat index
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))

    def getDatabaseList(self):
        """
        check database list in cluster
        :return:
        """
        self.context.logger.debug("Get database list in cluster.")
        sql = "select datname from pg_database;"
        mode = True if "dual-standby" in self.context.clusterType else False
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql, self.context.user,
            self.dnInst.hostname, self.dnInst.port, False,
            DefaultValue.DEFAULT_DB_NAME, IsInplaceUpgrade=True, maintenance_mode=mode)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                            " Error: \n%s" % str(output))
        if "" == output:
            raise Exception("No database objects were found in the cluster!")
        reslines = (output.strip()).split('\n')
        if (len(reslines) < 3
                or "template1" not in reslines
                or "template0" not in reslines
                or "postgres" not in reslines):
            raise Exception("The database list is invalid:%s." % str(reslines))
        self.context.logger.debug("Database list in cluster is %s." % reslines)
        return reslines

    def replyXlog(self, database_list):
        """
        make checkpoint
        :return:
        """
        mode = True if "dual-standby" in self.context.clusterType else False
        sql = 'CHECKPOINT;'
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True, maintenance_mode=mode)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))

    def execRollbackUpgradedCatalog(self, scriptType="rollback"):
        """
        function : connect database and rollback/upgrade catalog one by one
                   1.find a node that has dn instance
                   2.scp sql files to that node
                   3.send cmd to that node and exec
        input : NA
        output: NA
        """
        self.context.logger.debug("Start to {0} catalog.".format(scriptType))
        try:
            old_cluster_config_file = \
            os.path.realpath(os.path.join(self.context.oldClusterAppPath,
                                          "bin", "cluster_static_config"))
            new_cluster_config_file = \
            os.path.realpath(os.path.join(self.context.newClusterAppPath,
                                          "bin", "cluster_static_config"))

            # Cm have no maintain during switching process in grey upgrade due to ensure RTO time.
            # So there exists occasion that primary and stadby is likely to change during switching
            # process in grey upgrade.
            # There are conditions to need to handle when cluster has cm.
            # (1) Cluster mode possibly change after switching process in grey quto-upgrade, So primary
            # has to be aquired in real time from cm_ctl query before executing rollback-post script.
            # (2) when executing upgrade-post script, primary has been aquired in executing rollback-post.
            # (3) Cluster mode possibly change after switching process in grey auto-rollback, So primary
            # has to be aquired in real time from cm_ctl query before executing rollback script.
            if self.get_cms_num(new_cluster_config_file) > 0 and (scriptType == "rollback-post" or \
               scriptType == "upgrade-post"):
                if (scriptType == "rollback-post"):
                    self.getPrimaryDN(checkNormal=True)
                    dnNodeName = self.primaryDn.hostname
                else:
                    dnNodeName = self.primaryDn.hostname
                self.context.logger.debug("Primary dn {0} from cm_ctl query".format(
                                           dnNodeName))
            elif self.operate_action == const.ACTION_AUTO_ROLLBACK and \
                 self.get_cms_num(old_cluster_config_file) > 0 and scriptType == "rollback":
                self.getPrimaryDN(checkNormal=True)
                dnNodeName = self.primaryDn.hostname
                self.context.logger.debug("Primary dn {0} from cm_ctl query".format(
                                          dnNodeName))
            else:
                dnNodeName = self.dnInst.hostname
                self.context.logger.debug("Primary dn {0} from config file".format(
                                          dnNodeName))
                                          
            if dnNodeName == "":
                raise Exception(ErrorCode.GAUSS_526["GAUSS_52602"])
            self.context.logger.debug("dn nodes is {0}".format(dnNodeName))
            # scp sql files to that node
            maindb_sql = "%s/%s_catalog_maindb_tmp.sql" \
                         % (self.context.upgradeBackupPath, scriptType)
            otherdb_sql = "%s/%s_catalog_otherdb_tmp.sql" \
                          % (self.context.upgradeBackupPath, scriptType)
            if "upgrade" == scriptType:
                check_upgrade_sql = \
                    "%s/check_upgrade_tmp.sql" % self.context.upgradeBackupPath
                if not os.path.isfile(check_upgrade_sql):
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50210"] % check_upgrade_sql)
                self.context.logger.debug("Scp {0} file to nodes {1}".format(
                    check_upgrade_sql, dnNodeName))
                if not self.context.isSingle:
                    LocalRemoteCmd.scpFile(dnNodeName, check_upgrade_sql,
                                    self.context.upgradeBackupPath)
            if not os.path.isfile(maindb_sql):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % maindb_sql)
            if not os.path.isfile(otherdb_sql):
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50210"] % otherdb_sql)
            if (not self.context.isSingle):
                LocalRemoteCmd.scpFile(dnNodeName, maindb_sql,
                                self.context.upgradeBackupPath)
                LocalRemoteCmd.scpFile(dnNodeName, otherdb_sql,
                                self.context.upgradeBackupPath)
                self.context.logger.debug(
                    "Scp {0} file and {1} file to nodes {2}".format(
                        maindb_sql, otherdb_sql, dnNodeName))
            # send cmd to that node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s --script_type=%s -l " \
                  "%s" % (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                          const.ACTION_UPDATE_CATALOG,
                          self.context.user,
                          self.context.upgradeBackupPath,
                          scriptType,
                          self.context.localLog)
            self.context.logger.debug(
                "Command for executing {0} catalog.".format(scriptType))
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.userProfile,
                                            [dnNodeName])
            self.context.logger.debug(
                "Successfully {0} catalog.".format(scriptType))
        except Exception as e:
            self.context.logger.log("Failed to {0} catalog.".format(scriptType))
            if not self.context.forceRollback:
                raise Exception(str(e))

    def pgxcNodeUpdateLocalhost(self, mode):
        """
        This function is used to modify the localhost of the system table
        which pgxc_node
        :param mode:
        :return:
        """
        try:
            if int(float(self.context.newClusterNumber) * 1000) < 92069 or \
                    int(float(self.context.oldClusterNumber) * 1000) >= 92069:
                return
            if mode == "upgrade":
                self.context.logger.debug("Update localhost in pgxc_node.")
            else:
                self.context.logger.debug("Rollback localhost in pgxc_node.")
            for dbNode in self.context.clusterInfo.dbNodes:
                for dn in dbNode.datanodes:
                    sql = "START TRANSACTION;"
                    sql += "SET %s = on;" % const.ON_INPLACE_UPGRADE
                    if mode == "upgrade":
                        sql += "UPDATE PGXC_NODE SET node_host = '%s', " \
                               "node_host1 = '%s' WHERE node_host = " \
                               "'localhost'; " % (dn.listenIps[0],
                                                  dn.listenIps[0])
                    else:
                        sql += "UPDATE PGXC_NODE SET node_host = " \
                               "'localhost', node_host1 = 'localhost' WHERE" \
                               " node_type = 'C' and node_host = '%s';" %\
                               (dn.listenIps[0])
                    sql += "COMMIT;"
                    self.context.logger.debug("Current sql %s." % sql)
                    (status, output) = ClusterCommand.remoteSQLCommand(
                        sql, self.context.user, dn.hostname, dn.port,
                        False, DefaultValue.DEFAULT_DB_NAME,
                        IsInplaceUpgrade=True)
                    if status != 0:
                        if self.context.forceRollback:
                            self.context.logger.debug("In forceRollback, "
                                                      "roll back pgxc_node. "
                                                      "%s " % str(output))
                        else:
                            raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"]
                                            % sql + " Error: \n%s" %
                                            str(output))
            if mode == "upgrade":
                self.context.logger.debug(
                    "Success update localhost in pgxc_node.")
            else:
                self.context.logger.debug(
                    "Success rollback localhost in pgxc_node.")
        except Exception as e:
            raise Exception(str(e))

    def touchInitFile(self):
        """
        function: touch upgrade init file for every primary/standby and
                  do pre-upgrade staffs
        input : NA
        output: NA
        """
        try:
            if self.isLargeInplaceUpgrade:
                self.context.logger.debug("Start to create upgrade init file.")
                # send cmd to all node and exec
                cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                      (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                       const.ACTION_TOUCH_INIT_FILE,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.localLog)
                CmdExecutor.execCommandWithMode(cmd,
                                                self.context.sshTool,
                                                self.context.isSingle,
                                                self.context.userProfile)
                self.context.logger.debug(
                    "Successfully created upgrade init file.")
        except Exception as e:
            raise Exception(str(e))

    def prepareSql(self, mode="rollback"):
        """
        function : prepare 4 files: rollback_catalog_maindb_tmp.sql,
                   rollback_catalog_otherdb_tmp.sql and upgrade file
                  2.for each result file: filter all files and merge
                  into the *_tmp.sql file

        :param rollback: can be rollback or upgrade
        """
        try:
            self.prepareSqlForDb(mode)
            self.prepareSqlForDb(mode, "otherdb")
            if mode == "upgrade":
                self.prepareCheckSql()
        except Exception as e:
            raise Exception("Failed to prepare %s sql file failed. ERROR: %s"
                            % (mode, str(e)))

    def prepareSqlForDb(self, mode, dbType="maindb"):
        self.context.logger.debug(
            "Start to prepare {0} sql files for {1}.".format(mode, dbType))
        header = self.getSqlHeader()
        if "upgrade" in mode:
            listName = "upgrade"
        else:
            listName = "rollback"
        fileNameList = self.getFileNameList("{0}_catalog_{1}".format(
            listName, dbType), mode)
        if "rollback" in mode:
            fileNameList.sort(reverse=True)
        else:
            fileNameList.sort()
        """
        we move the 506 at last one,because it change the pg_proc index, 
        and rebuild index,it will hold the level 1 lock, and it make upgrade
        mode slow and sometimes will not send the Invalid message, it cause 
        some function can't be found, so move it to last ont to avoid it.
        """
        if 'rollback_catalog_maindb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback_catalog_maindb_92_506.sql')
            fileNameList.append('rollback_catalog_maindb_92_506.sql')
        if 'rollback_catalog_otherdb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback_catalog_otherdb_92_506.sql')
            fileNameList.append('rollback_catalog_otherdb_92_506.sql')
        if 'rollback-post_catalog_maindb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback-post_catalog_maindb_92_506.sql')
            fileNameList.append('rollback-post_catalog_maindb_92_506.sql')
        if 'rollback-post_catalog_otherdb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback-post_catalog_otherdb_92_506.sql')
            fileNameList.append('rollback-post_catalog_otherdb_92_506.sql') 
        fileName = "{0}_catalog_{1}_tmp.sql".format(mode, dbType)
        self.context.logger.debug("The real file list for %s: %s" % (
            dbType, fileNameList))
        self.togetherFile(header, "{0}_catalog_{1}".format(listName, dbType),
                          fileNameList, fileName)
        self.context.logger.debug("Successfully prepared sql files for %s."
                                  % dbType)

    def prepareCheckSql(self):
        header = ["START TRANSACTION;"]
        fileNameList = self.getFileNameList("check_upgrade")
        fileNameList.sort()
        """
        we move the 506 at last one,because it change the pg_proc index, 
        and rebuild index,it will hold the level 1 lock, and it make upgrade
        mode slow and sometimes will not send the Invalid message, it cause 
        some function can't be found, so move it to last ont to avoid it.
        """
        if 'rollback_catalog_maindb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback_catalog_maindb_92_506.sql')
            fileNameList.append('rollback_catalog_maindb_92_506.sql')
        if 'rollback_catalog_otherdb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback_catalog_otherdb_92_506.sql')
            fileNameList.append('rollback_catalog_otherdb_92_506.sql')
        if 'rollback-post_catalog_maindb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback-post_catalog_maindb_92_506.sql')
            fileNameList.append('rollback-post_catalog_maindb_92_506.sql')
        if 'rollback-post_catalog_otherdb_92_506.sql' in fileNameList:
            fileNameList.remove('rollback-post_catalog_otherdb_92_506.sql')
            fileNameList.append('rollback-post_catalog_otherdb_92_506.sql')
        self.context.logger.debug("The real file list for checking upgrade: "
                                  "%s" % fileNameList)
        self.togetherFile(header, "check_upgrade", fileNameList,
                          "check_upgrade_tmp.sql")

    def togetherFile(self, header, filePathName, fileNameList, executeFileName):
        writeFile = ""
        try:
            filePath = "%s/upgrade_sql/%s" % (self.context.upgradeBackupPath,
                                              filePathName)
            self.context.logger.debug("Preparing [%s]." % filePath)
            writeFile = "%s/%s" % (self.context.upgradeBackupPath,
                                   executeFileName)
            FileUtil.createFile(writeFile)
            FileUtil.writeFile(writeFile, header, 'w')

            with open(writeFile, 'a') as sqlFile:
                for each_file in fileNameList:
                    each_file_with_path = "%s/%s" % (filePath, each_file)
                    self.context.logger.debug("Handling file: %s" %
                                              each_file_with_path)
                    with open(each_file_with_path, 'r') as fp:
                        for line in fp:
                            sqlFile.write(line)
                    sqlFile.write(os.linesep)
            FileUtil.writeFile(writeFile, ["COMMIT;"], 'a')
            self.context.logger.debug(
                "Success to together {0} file".format(writeFile))
            if not os.path.isfile(writeFile):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % writeFile)
        except Exception as e:
            raise Exception("Failed to write {0} sql file. ERROR: {1}".format(
                writeFile, str(e)))

    def om_stop_cluster(self):
        """
        Stop cluster with gs_om
        """
        cmd = "source %s ;gs_om -t stop" % self.context.userProfile
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51610"] % "cluster" +
                            "Output: %s" % output)
        self.context.logger.log("Stop cluster with gs_om successfully.")

    def om_start_cluster(self):
        """
        Start Cluster with om
        """
        cmd = "source %s ;gs_om -t start" % self.context.userProfile
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster" +
                            "Output: %s" % output)
        self.context.logger.debug("Start cluster with gs_om successfully.")

    def cm_start_cluster(self):
        """
        Start Cluster with cm
        """
        self.context.logger.debug("Starting cluster with cm.")
        gauss_home = EnvUtil.getEnv("GAUSSHOME")
        gauss_log = EnvUtil.getEnv("GAUSSLOG")
        # check whether om_monitor started
        check_monitor_cmd = "gs_ssh -c 'ps x | grep -v grep | grep om_monitor'"
        start_monitor_cmd = "gs_ssh -c 'nohup om_monitor -L %s/cm/om_monitor >> " \
            "/dev/null 2>&1 &'" % gauss_log
        self.context.logger.debug("check monitor cmd: " + check_monitor_cmd)
        self.context.logger.debug("start monitor cmd: " + start_monitor_cmd)
        cluster_start_timeout = 300
        wait_time = 0
        while wait_time < cluster_start_timeout:
            status, output = subprocess.getstatusoutput(check_monitor_cmd)
            if status == 0 and output.find("FAILURE") == -1:
                break
            self.context.logger.debug("check monitor output: " + output)
            status, output = subprocess.getstatusoutput(start_monitor_cmd)
            wait_time += 1
            time.sleep(1)
        if wait_time >= cluster_start_timeout:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % ("cluster in %ds" % cluster_start_timeout) +
                "\nSome om_monitor is not running, please check.\n"
                "Hint: please check max number of open files limit.")

        # remove cluster_manual_start file to start cluster
        cluster_manual_start_file = os.path.join(gauss_home, "bin", "cluster_manual_start")
        cmd = "source %s ; gs_ssh -c 'rm %s -f'" % (
            self.context.userProfile, cluster_manual_start_file)
        self.context.logger.debug("cm start cluster cmd: %s" % cmd)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster" +
                "cmd: %s\nOutput: %s" % (cmd, output))
        cmd = "source %s ;gs_om -t query" % self.context.userProfile
        while wait_time < cluster_start_timeout:
            status, output = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster" +
                                "Output: %s" % output)
            if output.find("cluster_state   : Normal") != -1:
                break
            time.sleep(1)
            wait_time += 1
        if wait_time >= cluster_start_timeout:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % ("cluster in %ds" % cluster_start_timeout) +
                "Current cluster state:\n%s" % output)
        self.context.logger.debug("Start cluster with cm successfully.")

    def get_cms_num(self, cluster_config_file):
        """
        Get cm_server num from static config file
        """
        cluster_info = dbClusterInfo()
        cluster_info.initFromStaticConfig(self.context.user, cluster_config_file)
        return DefaultValue.get_cm_server_num_from_static(cluster_info)

    def _get_strategy_with_cm_num(self, old_cm_num, new_cm_num):
        """
        Get strategy with CM server instance number
        """
        if new_cm_num == 0 and old_cm_num == 0:
            self.context.logger.debug("No CM instance exists in the new and old clusters.")
            return 0
        if new_cm_num > 0 and old_cm_num == 0:
            self.context.logger.debug("The new cluster has a CM components "
                                      "but the old cluster does not have a CM components.")
            return 1
        if new_cm_num > 0 and old_cm_num > 0:
            self.context.logger.debug("CM components has in origin cluster.")
            return 2
        else:
            return -1


    def get_upgrade_cm_strategy(self):
        """
        Get strategy for start cluster
        """
        old_cluster_config_file = \
            os.path.realpath(os.path.join(self.context.oldClusterAppPath,
                                          "bin", "cluster_static_config"))
        new_cluster_config_file = \
            os.path.realpath(os.path.join(self.context.newClusterAppPath,
                                          "bin", "cluster_static_config"))

        if not os.path.isfile(new_cluster_config_file):
            self.context.logger.debug("Start cluster with om tool, "
                                      "[{0}]".format(new_cluster_config_file))
            if os.path.isfile(old_cluster_config_file):
                if self.get_cms_num(old_cluster_config_file) == 0:
                    return 0
                else:
                    return 2
            return -1

        new_cm_num = self.get_cms_num(new_cluster_config_file)

        if not os.path.isfile(old_cluster_config_file):
            self.context.logger.debug("Not exist old static_config_file "
                                      "[{0}]".format(old_cluster_config_file))
            if new_cm_num == 0:
                return 0
            else:
                return 2

        old_cm_num = self.get_cms_num(old_cluster_config_file)
        return self._get_strategy_with_cm_num(old_cm_num, new_cm_num)

    def start_strategy(self, is_final=True):
        """
        Start cluster
        """
        cm_strategy = self.get_upgrade_cm_strategy()
        if cm_strategy == -1:
            raise Exception("cm_strategy = -1. This is usually impossible.\n"
                "Hint: please check \n"
                "1. whether the old and new static files exist."
                "2. whether the upgrade strategy is \"have_cm\" to \"have_no_cm\".")
        if cm_strategy == 0:
            self.startCluster()
        elif cm_strategy == 1:
            if is_final:
                self.om_start_cluster()
            else:
                self.startCluster()
        else:
            self.cm_start_cluster()

    def stop_strategy(self, is_final=True):
        """
        Start cluster
        """
        cm_strategy = self.get_upgrade_cm_strategy()
        if cm_strategy == -1:
            raise Exception("cm_strategy = -1. This is usually impossible.\n"
                "Hint: please check \n"
                "1. whether the old and new static files exist."
                "2. whether the upgrade strategy is \"have_cm\" to \"have_no_cm\".")
        if cm_strategy == 0:
            self.stopCluster()
        elif cm_strategy == 1:
            if is_final:
                self.om_stop_cluster()
            else:
                self.stopCluster()
        else:
            self.om_stop_cluster()

    def modifyPgProcIndex(self):
        """
        1. 执行重建pg_proc index 的sql
        2. make checkpoint
        3. stop cluster
        4. start cluster
        :return:
        """
        self.context.logger.debug("Begin to modify pg_proc index.")
        time.sleep(3)
        database_list = self.getDatabaseList()
        # 执行重建pg_proc index 的sql
        sql = """START TRANSACTION;SET IsInplaceUpgrade = on;
        drop index pg_proc_oid_index;SET LOCAL 
        inplace_upgrade_next_system_object_oids=IUO_CATALOG,false,
        true,0,0,0,2690;CREATE UNIQUE INDEX pg_proc_oid_index ON pg_proc 
        USING btree (oid);SET LOCAL 
        inplace_upgrade_next_system_object_oids=IUO_CATALOG,false,
        true,0,0,0,0;commit;CHECKPOINT;"""
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))
        sql = """START TRANSACTION;SET IsInplaceUpgrade = on;
        drop index if exists pg_proc_proname_args_nsp_index;SET LOCAL 
        inplace_upgrade_next_system_object_oids=IUO_CATALOG,false,
        true,0,0,0,2691;create UNIQUE INDEX pg_proc_proname_args_nsp_index 
        ON pg_proc USING btree (proname, proargtypes, pronamespace);SET 
        LOCAL inplace_upgrade_next_system_object_oids=IUO_CATALOG,false,
        true,0,0,0,0;commit;CHECKPOINT;"""
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Error: \n%s" % str(output))
        # stop cluster
        self.stop_strategy()
        # start cluster
        self.start_strategy()
        self.context.logger.debug("Successfully modified pg_proc index.")

    def setNewVersionGuc(self):
        """
        function: set new Version guc
        input  : NA
        output : NA
        """
        pass

    def setActionFile(self):
        """
        set the action from step file, if not find, set it to large upgrade,
        if the upgrade type is small upgrade, but we set it to large upgrade,
        just kill the cm agent as expense, take no effect to transaction
        But if the action should be large, we does not set the upgrade_mode,
        some new feature will not opened
        :return: NA
        """
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                const.GREY_UPGRADE_STEP_FILE)
        self.context.logger.debug("Get the action from file %s." % stepFile)
        if not (os.path.exists(stepFile) or os.path.isfile(stepFile)):
            self.context.logger.debug("Step file does not exists or not file,"
                                      " cannot get action from it. "
                                      "Set it to large upgrade.")
            self.context.action = const.ACTION_LARGE_UPGRADE
            return
        with open(stepFile, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                self.context.action = row['upgrade_action']
                break
        self.context.logger.debug("Set the action to %s"
                                  % self.context.action)

    def getClusterAppPath(self, mode=const.OLD):
        """
        if cannot get path from table, try to get from the backup file
        :param mode:
        :return:
        """
        self.context.logger.debug("Get the install path from table or file.")
        path = self.getClusterAppPathFromFile(mode)
        return path

    def getClusterAppPathFromFile(self, mode=const.OLD):
        """
        get the app path from backup dir, mode is new or old,
        :param mode: 'old', 'new'
        :return: the real path of appPath
        """
        dirFile = "%s/%s" % (self.context.upgradeBackupPath,
                             const.RECORD_UPGRADE_DIR)
        self.context.logger.debug("Get the %s app path from file %s"
                                  % (mode, dirFile))
        if mode not in [const.OLD, const.NEW]:
            raise Exception(traceback.format_exc())
        if not os.path.exists(dirFile):
            self.context.logger.debug(ErrorCode.GAUSS_502["GAUSS_50201"]
                                      % dirFile)
            if self.checkBakPathNotExists():
                return ""
            # copy the binary_upgrade dir from other node,
            # if one node is damaged while binary_upgrade may disappear,
            # user repair one node before commit, and send the commit
            # command to the repair node, we need to copy the
            # dir from remote node
            cmd = "if [ -f '%s' ]; then echo 'GetFile';" \
                  " else echo 'NoThisFile'; fi" % dirFile
            self.context.logger.debug("Command for checking file: %s" % cmd)
            (status, output) = self.context.sshTool.getSshStatusOutput(
                cmd, self.context.clusterNodes, self.context.mpprcFile)
            outputMap = self.context.sshTool.parseSshOutput(
                self.context.clusterNodes)
            self.context.logger.debug("Output: %s" % output)
            copyNode = ""
            for node in self.context.clusterNodes:
                if status[node] == DefaultValue.SUCCESS:
                    if 'GetFile' in outputMap[node]:
                        copyNode = node
                        break
            if copyNode:
                if not os.path.exists(self.context.upgradeBackupPath):
                    self.context.logger.debug("Create directory %s."
                                              % self.context.tmpDir)
                    FileUtil.createDirectory(
                        self.context.upgradeBackupPath, True,
                        DefaultValue.KEY_DIRECTORY_MODE)
                self.context.logger.debug("Copy the directory %s from node %s."
                                          % (self.context.upgradeBackupPath,
                                             copyNode))
                cmd = LocalRemoteCmd.getRemoteCopyCmd(
                    self.context.upgradeBackupPath, self.context.tmpDir,
                    str(copyNode), False, 'directory')
                self.context.logger.debug("Command for copying "
                                          "directory: %s" % cmd)
                CmdExecutor.execCommandLocally(cmd)
            else:
                # binary_upgrade exists, but no step file
                return ""
        if not os.path.isfile(dirFile):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % dirFile)
        with open(dirFile, 'r') as fp:
            retLines = fp.readlines()
        if len(retLines) != 2:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] % dirFile)
        if mode == const.OLD:
            path = retLines[0].strip()
        else:
            path = retLines[1].strip()
        # if can get the path from file, the path must be valid,
        # otherwise the file is damaged accidentally
        DefaultValue.checkPathVaild(path)
        if not os.path.exists(path):
            if mode == const.NEW and \
                    self.context.action == const.ACTION_AUTO_ROLLBACK:
                self.context.logger.debug("Under rollback, the new "
                                          "cluster app path does not exists.")
            elif mode == const.OLD and \
                    self.context.action == const.ACTION_COMMIT_UPGRADE:
                self.context.logger.debug("Under commit, no need to "
                                          "check the old path exists.")
            else:
                self.context.logger.debug(traceback.format_exc())
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        self.context.logger.debug("Successfully Get the app"
                                  " path [%s] from file" % path)
        return path

    def printPrecommitBanner(self):
        """
        funcation: if in pre-commit status, and do not execute
                   the commit cmd, then can print this message
        input : NA
        output: NA
        """
        self.context.logger.log("Upgrade main process has been finished,"
                                " user can do some check now.")
        self.context.logger.log("Once the check done, please execute "
                                "following command to commit upgrade:")
        xmlFile = self.context.xmlFile \
            if len(self.context.xmlFile) else "XMLFILE"
        self.context.logger.log("\n    gs_upgradectl -t "
                                "commit-upgrade -X %s   \n" % xmlFile)

    def doGreyCommitUpgrade(self):
        """
        function: commit binary upgrade and clean up backup files
                  1. unset read-only
                  2. drop old PMK schema
                  3. clean up other upgrade tmp files
        input : NA
        output: NA
        """
        self.checkDualClusterCommit()
        try:
            (status, output) = self.doHealthCheck(const.OPTION_POSTCHECK)
            if status != 0:
                raise Exception(
                    "NOTICE: " + ErrorCode.GAUSS_516[
                        "GAUSS_51601"] % "cluster" + output)
            if self.unSetClusterReadOnlyMode() != 0:
                raise Exception("NOTICE: " + ErrorCode.GAUSS_529["GAUSS_52907"])

            if not (self.isNodeSpecifyStep(GreyUpgradeStep.STEP_PRE_COMMIT)
                    or self.isNodeSpecifyStep(
                    GreyUpgradeStep.STEP_BEGIN_COMMIT)):
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52916"])
            # for the reenter commit, the schema may have been deleted
            if self.existTable(const.RECORD_NODE_STEP):
                self.recordNodeStep(GreyUpgradeStep.STEP_BEGIN_COMMIT)
            self.recordDualClusterStage(self.newCommitId, DualClusterStage.STEP_UPGRADE_COMMIT)

            self.setActionFile()
            if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) > 0:
                self.setUpgradeFromParam(const.UPGRADE_UNSET_NUM)
                self.restart_cm_proc()
            if self.context.action == const.ACTION_LARGE_UPGRADE:
                if "dual-standby" not in self.context.clusterType:
                    self.setUpgradeMode(0)
            time.sleep(10)
            # turn on enable_ssl for CM
            self.set_enable_ssl("on")
            if self.dropPMKSchema() != 0:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52917"])

            self.clearOtherToolPackage()
            self.cleanInstallPath(const.OLD)
            if "dual-standby" not in self.context.clusterType:
                self.dropSupportSchema()
            self.cleanConfBakOld()
            self.recordDualClusterStage(self.newCommitId, DualClusterStage.STEP_UPGRADE_END)
            self.cleanBinaryUpgradeBakFiles()
            # remove tmp global relmap file
            self.cleanTmpGlobalRelampFile()
            self.context.logger.log("Commit upgrade succeeded.")
        except Exception as e:
            self.exitWithRetCode(const.ACTION_COMMIT_UPGRADE, False, str(e))
        self.exitWithRetCode(const.ACTION_COMMIT_UPGRADE, True)

    def dropPMKSchema(self):
        """
        function: Notice: the pmk schema on database postgres
        input : NA
        output: return 0, if the operation is done successfully.
                return 1, if the operation failed.
        """
        try:
            self.context.logger.debug("Start to drop schema PMK.")
            if self.context.standbyCluster:
                self.context.logger.debug("no need to delete schema PMK in standby cluster mode.")
                return 0
            # execute drop commands by the CN instance
            sql = "DROP SCHEMA IF EXISTS pmk CASCADE; "
            retry_times = 0
            while True:
                (status, output) = self.execSqlCommandInPrimaryDN(sql)
                if status != 0 or SqlResult.findErrorInSql(output):
                    if retry_times < 12:
                        self.context.logger.debug(
                            "ERROR: Failed to DROP SCHEMA pmk for the %d time."
                            " Error: \n%s" % (retry_times + 1, str(output)))
                    else:
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                            " Error: \n%s" % str(output))
                else:
                    break

                time.sleep(5)
                retry_times += 1
            self.context.logger.debug("Succcessfully deleted schema PMK.")
            return 0
        except Exception as e:
            self.context.logger.log(
                "NOTICE: Failed to execute SQL command on CN instance, "
                + "please re-commit upgrade once again or " +
                "re-execute SQL command 'DROP SCHEMA "
                "IF EXISTS pmk CASCADE' manually.")
            self.context.logger.debug(str(e))
            return 1

    def getCMServerGUC(self, defaultGUCparas, cmNodesIn=None):
        """
        function : get cm_servers parameters
                   return an empty dict if no expected parameters found
        input : NA
        output: oldGUCparas
        """
        self.context.logger.debug("Start obtained the CMServer parameter list.")
        if cmNodesIn is None:
            cmNodesIn = []
        oldGUCparas = {}
        if len(list(defaultGUCparas.keys())) == 0:
            return oldGUCparas

        cmNodes = []
        try:
            # get ALL CMS node information
            if cmNodesIn:
                cmNodes = cmNodesIn
            else:
                for dbNode in self.context.clusterInfo.dbNodes:
                    if len(dbNode.cmservers) > 0:
                        cmNodes.append(dbNode)

            for cmpara in list(defaultGUCparas.keys()):
                for cmNode in cmNodes:
                    matchExpression = "\<'%s'\>" % str(cmpara).strip()
                    cmServerConfigFile = os.path.join(cmNode.cmservers[0].datadir, "cm_server.conf")
                    cmd = "%s -E '%s' %s" % (
                        CmdUtil.getGrepCmd(), matchExpression, cmServerConfigFile)
                    if cmNode.name.strip() == NetUtil.GetHostIpOrName():
                        executeCmd = cmd
                    else:
                        sshCmd = "%s " % CmdUtil.getSshCmd(cmNode.name)
                        executeCmd = "%s \"%s\"" % (sshCmd, cmd)
                    self.context.logger.debug(
                        "Command for getting CMServer parameters: %s." % executeCmd)
                    (status, output) = CmdUtil.retryGetstatusoutput(executeCmd, 5, 5)
                    if status != 0 and status != const.ERR_GREP_NO_RESULT:
                        raise Exception(
                            ErrorCode.GAUSS_514["GAUSS_51400"] % executeCmd + "\nError: " + output)

                    for line in output.split('\n'):
                        confInfo = line.strip()
                        if confInfo.startswith('#') or confInfo == "":
                            continue
                        elif confInfo.startswith(cmpara):
                            configValue = confInfo.split('#')[0].split('=')[1].strip().lower()
                            self.context.logger.debug(
                                "configValue in cmnode %s is %s:" % (cmNode.name, configValue))
                            if cmpara in oldGUCparas and oldGUCparas[cmpara] != configValue and \
                                    not self.context.forceRollback:
                                raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] %
                                                "Parameter '%s', it is different in cm_servers" %
                                                cmpara)
                            oldGUCparas[cmpara] = configValue
                            break
            self.context.logger.debug("Successfully obtained the CMServer parameter list. "
                                      "The list context is %s." % oldGUCparas)
        except Exception as er:
            if not self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.debug("WARNING: Failed to get the CMServer parameters.")

        return oldGUCparas

    def cleanConfBakOld(self):
        """
        clean conf.bak.old files in all instances
        input : NA
        output : NA
        """
        try:
            cmd = "%s -t %s -U %s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_CLEAN_CONF_BAK_OLD,
                   self.context.user,
                   self.context.localLog)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, hostList=hostList)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.debug(
            "Successfully cleaned conf.bak.old in all instances.")

    def doGreyBinaryRollback(self, action=""):
        """
        function: rollback the upgrade of binary
        input : NA
        output: return True, if the operation is done successfully.
                return False, if the operation failed.
        """
        self.context.logger.log("Performing grey rollback.")
        # before prepare upgrade function and table or after commit,
        # table does not exist means not rollback
        # if we read the step for file, means we have force to rollback,
        #  the record in table is not same with file
        # we can only read the step from file
        try:
            self.distributeXml()
            if action == const.ACTION_AUTO_ROLLBACK:
                self.checkDualClusterRollback()
                self.clearOtherToolPackage(action)
                self.recordDualClusterStage(self.oldCommitId,
                                            DualClusterStage.STEP_UPGRADE_UNFINISHED)
            try:
                self.getOneDNInst(True)
            except Exception as e:
                # don't promise DN is available in force rollback
                if self.context.forceRollback:
                    self.context.logger.debug("Error: %s" % str(e))
                else:
                    raise Exception(str(e))
            # if the cluster is degrade and cn is down,
            # the set command will be False, ignore the error
            if self.unSetClusterReadOnlyMode() != 0:
                self.context.logger.log(
                    "WARNING: Failed to unset cluster read only mode.")

            if self.context.forceRollback:
                # if one node is uninstalled,
                # there will be no binary_upgrade dir
                self.createBakPath()
                self.setReadStepFromFile()
                self.createGphomePack()
            # first time user may use forcerollback, but next time user may
            # not use force rollback, so the step file and step
            # table is not same, so we can only read step from file,
            # consider if need to sync them, not important
            # under force upgrade, only read step from file
            maxStep = self.getNodeStep()
            self.checkDualClusterRollback()
            # if -2, it means there is no need to exec rollback
            # if under upgrade continue mode, it will do upgrade not rollback,
            #  it can enter the upgrade process
            # when the binary_upgrade bak dir has some files
            if maxStep == const.BINARY_UPGRADE_NO_NEED_ROLLBACK:
                self.cleanBinaryUpgradeBakFiles(True)
                self.recordDualClusterStage(self.oldCommitId, DualClusterStage.STEP_UPGRADE_END)
                self.context.logger.log("No need to rollback.")
                return True

            elif maxStep == GreyUpgradeStep.STEP_BEGIN_COMMIT:
                self.context.logger.log(
                    ErrorCode.GAUSS_529["GAUSS_52919"] +
                    " Please commit again! Can not rollback any more.")
                return False

            # Mark that we leave pre commit status,
            # so that if we fail at the first few steps,
            # we won't be allowed to commit upgrade any more.
            elif maxStep == GreyUpgradeStep.STEP_PRE_COMMIT:
                nodes = self.getNodesWithStep(maxStep)
                self.recordNodeStep(
                    GreyUpgradeStep.STEP_UPDATE_POST_CATALOG, nodes)
                maxStep = self.getNodeStep()
            self.checkDualClusterRollback()
            if maxStep == GreyUpgradeStep.STEP_UPDATE_POST_CATALOG:
                self.context.logger.debug(
                    "Record the step %d to mark it has leaved pre-commit"
                    " status." % GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)
                try:
                    if self.context.action == const.ACTION_LARGE_UPGRADE\
                            and \
                            self.isNodeSpecifyStep(
                                GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)\
                            and "dual-standby" not in self.context.clusterType:
                        self.prepareUpgradeSqlFolder()
                        self.prepareSql("rollback-post")
                        self.setUpgradeMode(2)
                        self.execRollbackUpgradedCatalog(
                            scriptType="rollback-post")
                        # restore old relmap file after rollback-post
                        self.restoreGlobalRelampFile()
                except Exception as e:
                    if self.context.forceRollback:
                        self.context.logger.debug("Error: %s" % str(e))
                    else:
                        raise Exception(str(e))
                nodes = self.getNodesWithStep(maxStep)
                self.recordNodeStep(GreyUpgradeStep.STEP_UPGRADE_PROCESS, nodes)
            # rollback the nodes from maxStep, each node do its rollback
            needSwitchProcess = False
            if maxStep >= GreyUpgradeStep.STEP_UPGRADE_PROCESS:
                needSwitchProcess = True

            if maxStep >= GreyUpgradeStep.STEP_SWITCH_NEW_BIN:
                self.greyRestoreConfig()
                self.clean_cm_instance()
                self.switchBin(const.OLD)
                self.greyRestoreGuc()
                if needSwitchProcess:
                    self.rollbackHotpatch()
                    self.getOneDNInst(checkNormal=True)
                    self.switchExistsProcess(True)
                self.recordNodeStep(GreyUpgradeStep.STEP_UPDATE_CATALOG)
            if maxStep >= GreyUpgradeStep.STEP_UPDATE_CATALOG and\
                    self.context.action == const.ACTION_LARGE_UPGRADE:
                if "dual-standby" not in self.context.clusterType:
                    self.rollbackCatalog()
                self.recordNodeStep(GreyUpgradeStep.STEP_INIT_STATUS)

            if maxStep >= GreyUpgradeStep.STEP_INIT_STATUS:
                # clean on all the node, because the binary_upgrade temp
                #  dir will create in every node
                self.cleanInstallPath(const.NEW)
                self.getOneDNInst()
                if "dual-standby" not in self.context.clusterType:
                    self.dropSupportSchema()
                self.initOmRollbackProgressFile()
                self.recordDualClusterStage(self.oldCommitId, DualClusterStage.STEP_UPGRADE_END)
                self.cleanBinaryUpgradeBakFiles(True)
                self.cleanTmpGlobalRelampFile()
        except Exception as e:
            self.context.logger.debug(str(e))
            self.context.logger.debug(traceback.format_exc())
            self.context.logger.log("Rollback failed. Error: %s" % str(e))
            return False
        self.context.logger.log("Rollback succeeded.")
        return True

    def setReadStepFromFile(self):
        readFromFileFlag = os.path.join(self.context.upgradeBackupPath,
                                        const.READ_STEP_FROM_FILE_FLAG)
        self.context.logger.debug("Under force rollback mode.")
        FileUtil.createFile(readFromFileFlag, True, DefaultValue.KEY_FILE_MODE)
        self.distributeFile(readFromFileFlag)
        self.context.logger.debug("Create file %s. " % readFromFileFlag +
                                  "Only read step from file.")

    def getNodeStep(self):
        """
        get node step from file or tacle
        """
        maxStep = self.getNodeStepFile()
        return maxStep

    def getNodeStepFile(self):
        if not os.path.exists(self.context.upgradeBackupPath):
            self.context.logger.debug("Directory %s does not exist. "
                                      "Only clean remaining files and schema."
                                      % self.context.upgradeBackupPath)
            return const.BINARY_UPGRADE_NO_NEED_ROLLBACK
        if not os.path.isdir(self.context.upgradeBackupPath):
            raise Exception(ErrorCode.GAUSS_513["GAUSS_50211"] %
                            self.context.upgradeBackupPath)
        # because the binary_upgrade dir is used to block expand,
        # so we should clean the dir when rollback
        fileList = os.listdir(self.context.upgradeBackupPath)
        if not fileList:
            return GreyUpgradeStep.STEP_INIT_STATUS
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                const.GREY_UPGRADE_STEP_FILE)
        if not os.path.exists(stepFile):
            self.context.logger.debug(
                "No need to rollback. File %s does not exist." % stepFile)
            return const.BINARY_UPGRADE_NO_NEED_ROLLBACK

        self.context.logger.debug("Get the node step from file %s." % stepFile)
        with open(stepFile, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            maxStep = const.INVALID_UPRADE_STEP
            for row in reader:
                self.checkStep(row['step'])
                maxStep = max(int(row['step']), maxStep)
                if row['upgrade_action'] != self.context.action:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] %
                                    stepFile +
                                    "\nIncorrect upgrade strategy, input "
                                    "upgrade type: %s; record upgrade type: %s"
                                    % (self.context.action,
                                       row['upgrade_action']))
        self.context.logger.debug("Get the max step [%d] from file." % maxStep)
        self.context.logger.debug(
            "Successfully get the node step from file %s." % stepFile)
        return maxStep

    def checkActionInTableOrFile(self):
        """
        under force upgrade, step file and table may not be coincident.
        So we only use step file
        """
        self.checkActionInFile()

    def checkActionInFile(self):
        """
        function: check whether current action is same
                  with record action in file
        input : NA
        output: NA
        """
        try:
            self.context.logger.debug("Check the action in file.")
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    const.GREY_UPGRADE_STEP_FILE)
            if not os.path.isfile(stepFile):
                self.context.logger.debug(
                    ErrorCode.GAUSS_502["GAUSS_50201"] % (stepFile))
                return

            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    upgrade_action = row['upgrade_action']
                    if self.context.action != upgrade_action:
                        raise Exception(ErrorCode.GAUSS_529["GAUSS_52925"] % (
                            self.context.action, upgrade_action))
            self.context.logger.debug("Successfully check the action in file.")
            return
        except Exception as e:
            self.context.logger.debug("Failed to check action in table.")
            raise Exception(str(e))

    def getNodesWithStep(self, step):
        """
        get nodes with the given step from step file or table
        """
        nodes = self.getNodesWithStepFile(step)
        return nodes

    def getNodesWithStepFile(self, step):
        """
        get nodes with the given step from file upgrade_step.csv
        """
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                const.GREY_UPGRADE_STEP_FILE)
        self.context.logger.debug("Get the node step from file %s." % stepFile)
        nodes = []
        with open(stepFile, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if not row['step'].isdigit():
                    raise Exception(ErrorCode.GAUSS_529["GAUSS_52926"])
                if int(row['step']) == step:
                    nodes.append(row['node_host'])
        self.context.logger.debug("Nodes %s is step %d" % (nodes, step))
        return nodes

    def greyRestoreConfig(self):
        """
        deal with the lib/postgresql/pg_plugin
        Under rollback, we will use new pg_plugin dir as base, the file in
        new dir but not in old dir will be moved to old dir considering add
        the C function, and remove from old dir considering drop the C function
        copy the config from new dir to old dir if the config may change
        by user action
        """

        cmd = "%s -t %s -U %s --old_cluster_app_path=%s " \
              "--new_cluster_app_path=%s -l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            const.ACTION_GREY_RESTORE_CONFIG,
            self.context.user,
            self.context.oldClusterAppPath,
            self.context.newClusterAppPath,
            self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for restoring config: %s" % cmd)
        rollbackList = copy.deepcopy(self.context.clusterNodes)
        self.context.sshTool.executeCommand(cmd, hostList=rollbackList)
        self.context.logger.debug("Successfully restore config.")

    def greyRestoreGuc(self):
        """
        restore the old guc in rollback
        :return: NA
        """
        cmd = "%s -t %s -U %s --old_cluster_app_path=%s -X %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_GREY_RESTORE_GUC,
               self.context.user,
               self.context.oldClusterAppPath,
               self.context.xmlFile,
               self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for restoring GUC: %s" % cmd)
        rollbackList = copy.deepcopy(self.context.clusterNodes)
        self.context.sshTool.executeCommand(cmd, hostList=rollbackList)
        self.context.logger.debug("Successfully restore guc.")

    def dropSupportSchema(self):
        self.context.logger.debug("Drop schema.")
        sql = "DROP SCHEMA IF EXISTS %s CASCADE;" % const.UPGRADE_SCHEMA
        retryTime = 0
        try:
            while retryTime < 5:
                (status, output) = self.execSqlCommandInPrimaryDN(sql)
                if status != 0 or SqlResult.findErrorInSql(output):
                    retryTime += 1
                    self.context.logger.debug(
                        "Failed to execute SQL: %s. Error: \n%s. retry" % (
                            sql, str(output)))
                else:
                    break
            if status != 0 or SqlResult.findErrorInSql(output):
                self.context.logger.debug(
                    "Failed to execute SQL: %s. Error: \n%s" % (
                        sql, str(output)))
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Please drop manually with this command.")
            self.context.logger.debug("Successfully drop schema %s cascade." %
                                      const.UPGRADE_SCHEMA)
        except Exception as e:
            if self.context.forceRollback:
                self.context.logger.log(
                    "Failed to drop schema. Please drop manually "
                    "with this command: \n     %s" % sql)
            else:
                raise Exception(str(e))

    def doInplaceBinaryRollback(self):
        """
        function: rollback the upgrade of binary
        input : NA
        output: return True, if the operation is done successfully.
                return False, if the operation failed.
        """
        self.context.logger.log("Performing inplace rollback.")
        # step flag
        # const.BINARY_UPGRADE_NO_NEED_ROLLBACK value is -2
        # const.INVALID_UPRADE_STEP value is -1
        # const.BINARY_UPGRADE_STEP_INIT_STATUS value is 0
        # const.BINARY_UPGRADE_STEP_STOP_NODE value is 2
        # const.BINARY_UPGRADE_STEP_BACKUP_VERSION value is 3
        # const.BINARY_UPGRADE_STEP_UPGRADE_APP value is 4
        # const.BINARY_UPGRADE_STEP_START_NODE value is 5
        # const.BINARY_UPGRADE_STEP_PRE_COMMIT value is 6
        self.distributeXml()
        step = self.getNodeStepInplace()
        if step == const.BINARY_UPGRADE_NO_NEED_ROLLBACK:
            self.context.logger.log("Rollback succeeded.")
            return True

        # if step <= -1, it means the step file is broken, exit.
        if step <= const.INVALID_UPRADE_STEP:
            self.context.logger.debug("Invalid upgrade step: %s." % str(step))
            return False

        # if step value is const.BINARY_UPGRADE_STEP_PRE_COMMIT
        # and find commit flag file,
        # means user has commit upgrade, then can not do rollback
        if step == const.BINARY_UPGRADE_STEP_PRE_COMMIT:
            if not self.checkCommitFlagFile():
                self.context.logger.log(
                    "Upgrade has already been committed, "
                    "can not execute rollback command any more.")
                return False

        try:
            self.checkStaticConfig()
            self.start_strategy()
            # Mark that we leave pre commit status,
            # so that if we fail at the first few steps,
            # we won't be allowed to commit upgrade any more.
            if step == const.BINARY_UPGRADE_STEP_PRE_COMMIT:
                self.recordNodeStepInplace(
                    const.ACTION_INPLACE_UPGRADE,
                    const.BINARY_UPGRADE_STEP_START_NODE)

            if step >= const.BINARY_UPGRADE_STEP_START_NODE:
                # drop table and index after large upgrade
                if self.isLargeInplaceUpgrade:
                    if self.check_upgrade_mode():
                        self.drop_table_or_index()
                self.restoreClusterConfig(True)
                self.clean_cm_instance()
                self.switchBin(const.OLD)
                if self.isLargeInplaceUpgrade:
                    touchInitFlagFile = os.path.join(
                        self.context.upgradeBackupPath, "touch_init_flag")
                    if os.path.exists(touchInitFlagFile):
                        self.rollbackCatalog()
                        self.cleanCsvFile()
                    else:
                        self.setUpgradeMode(0)
                else:
                    self.setUpgradeFromParam(const.UPGRADE_UNSET_NUM)
                    self.stop_strategy()
                self.recordNodeStepInplace(
                    const.ACTION_INPLACE_UPGRADE,
                    const.BINARY_UPGRADE_STEP_UPGRADE_APP)

            if step >= const.BINARY_UPGRADE_STEP_UPGRADE_APP:
                self.restoreNodeVersion()
                self.restoreClusterConfig(True)
                self.recordNodeStepInplace(
                    const.ACTION_INPLACE_UPGRADE,
                    const.BINARY_UPGRADE_STEP_BACKUP_VERSION)

            if step >= const.BINARY_UPGRADE_STEP_BACKUP_VERSION:
                self.cleanBackupedCatalogPhysicalFiles(True)
                self.recordNodeStepInplace(
                    const.ACTION_INPLACE_UPGRADE,
                    const.BINARY_UPGRADE_STEP_STOP_NODE)

            if step >= const.BINARY_UPGRADE_STEP_STOP_NODE:
                self.start_strategy()
                self.recordNodeStepInplace(
                    const.ACTION_INPLACE_UPGRADE,
                    const.BINARY_UPGRADE_STEP_INIT_STATUS)

            if step >= const.BINARY_UPGRADE_STEP_INIT_STATUS:
                # restore the CM parameters
                if DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) != 0:
                    self.restore_cm_server_guc(const.CLUSTER_CMSCONF_FILE)
                else:
                    self.clean_cms_param_file()
                if self.unSetClusterReadOnlyMode() != 0:
                    raise Exception("NOTICE: " +
                                    ErrorCode.GAUSS_529["GAUSS_52907"])
                self.cleanBinaryUpgradeBakFiles(True)
                self.cleanInstallPath(const.NEW)
                self.cleanTmpGlobalRelampFile()
                # install kerberos
                self.install_kerberos()
        except Exception as e:
            self.context.logger.error(str(e))
            self.context.logger.log("Rollback failed.")
            return False

        self.context.logger.log("Rollback succeeded.")
        return True

    def check_table_or_index_exist(self, name, eachdb):
        """
        check a table exist
        :return:
        """
        mode = True if "dual-standby" in self.context.clusterType else False
        sql = "select count(*) from pg_class where relname = '%s';" % name
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql, self.context.user,
            self.dnInst.hostname, self.dnInst.port, False,
            eachdb, IsInplaceUpgrade=True, maintenance_mode=mode)
        if status != 0 or SqlResult.findErrorInSql(output):
            raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                            " Error: \n%s" % str(output))
        if output == '0':
            self.context.logger.debug("Table does not exist.")
            return False
        self.context.logger.debug("Table exists.")
        return True

    def drop_table_or_index(self):
        """
        drop a table
        :return:
        """
        self.context.logger.debug("Start to drop table or index")
        database_list = self.getDatabaseList()
        # drop table and index
        maindb = "postgres"
        otherdbs = database_list
        otherdbs.remove("postgres")
        # check table exist in postgres
        table_name = 'pg_proc_temp_oids'
        if self.check_table_or_index_exist(table_name, maindb):
            self.drop_one_database_table_or_index([maindb])
        else:
            return
        # drop other database table and index
        self.drop_one_database_table_or_index(otherdbs)
        self.context.logger.debug(
            "Successfully droped table or index.")

    def drop_one_database_table_or_index(self,
                                         database_list):
        """
        drop a table in one database
        :return:
        """
        table_name = 'pg_proc_temp_oids'
        delete_table_sql = "START TRANSACTION;SET IsInplaceUpgrade = on;" \
                           "drop table %s;commit;" % table_name
        index_name_list = ['pg_proc_oid_index_temp',
                           'pg_proc_proname_args_nsp_index_temp']
        for eachdb in database_list:
            if self.check_table_or_index_exist(table_name, eachdb):
                (status, output) = ClusterCommand.remoteSQLCommand(
                    delete_table_sql, self.context.user,
                    self.dnInst.hostname, self.dnInst.port, False,
                    eachdb, IsInplaceUpgrade=True)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] % delete_table_sql
                        + " Error: \n%s" % str(output))
            for index in index_name_list:
                if self.check_table_or_index_exist(index, eachdb):
                    sql = "START TRANSACTION;SET IsInplaceUpgrade = on;" \
                          "drop index %s;commit;" % index
                    (status, output) = ClusterCommand.remoteSQLCommand(
                        sql, self.context.user,
                        self.dnInst.hostname, self.dnInst.port, False,
                        eachdb, IsInplaceUpgrade=True)
                    if status != 0:
                        raise Exception(
                            ErrorCode.GAUSS_513[
                                "GAUSS_51300"] % sql + " Error: \n%s" % str(
                                output))

    def rollbackCatalog(self):
        """
        function: rollback catalog change
                  steps:
                  1.prepare update sql file and check sql file
                  2.do rollback catalog
        input : NA
        output: NA
        """
        try:
            if self.context.action == const.ACTION_INPLACE_UPGRADE and int(
                    float(self.context.oldClusterNumber) * 1000) <= 93000:
                raise Exception("For this old version %s, we only support "
                                "physical rollback." % str(
                    self.context.oldClusterNumber))
            self.context.logger.log("Rollbacking catalog.")
            self.prepareUpgradeSqlFolder()
            self.prepareSql()
            self.doRollbackCatalog()
            self.context.logger.log("Successfully Rollbacked catalog.")
        except Exception as e:
            if self.context.action == const.ACTION_INPLACE_UPGRADE:
                self.context.logger.debug(
                    "Failed to perform rollback operation by rolling "
                    "back SQL files:\n%s" % str(e))
                try:
                    self.context.logger.debug("Try to recover again using "
                                              "catalog physical files")
                    self.doPhysicalRollbackCatalog()
                except Exception as e:
                    raise Exception(
                        "Failed to rollback catalog. ERROR: %s" % str(e))
            else:
                raise Exception(
                    "Failed to rollback catalog. ERROR: %s" % str(e))


    def doRollbackCatalog(self):
        """
        function : rollback catalog change
                   steps:
                   stop cluster
                   set upgrade_from param
                   start cluster
                   connect database and rollback catalog changes one by one
                   stop cluster
                   unset upgrade_from param
        input : NA
        output: NA
        """
        if self.context.action == const.ACTION_INPLACE_UPGRADE:
            self.start_strategy(is_final=False)
            self.setUpgradeFromParam(self.context.oldClusterNumber)
            self.setUpgradeMode(1)
        else:
            self.setUpgradeFromParam(self.context.oldClusterNumber)
            self.setUpgradeMode(2)
        self.reloadCmAgent()
        self.execRollbackUpgradedCatalog()
        self.pgxcNodeUpdateLocalhost("rollback")
        self.setUpgradeFromParam(const.UPGRADE_UNSET_NUM)
        self.setUpgradeMode(0)
        if self.context.action == const.ACTION_INPLACE_UPGRADE:
            self.stop_strategy(is_final=False)
        else:
            self.reloadCmAgent()


    def doPhysicalRollbackCatalog(self):
        """
        function : rollback catalog by restore physical files
                   stop cluster
                   unset upgrade_from param
                   restore physical files
        input : NA
        output: NA
        """
        try:
            self.start_strategy(is_final=False)
            self.setUpgradeFromParam(const.UPGRADE_UNSET_NUM)
            self.setUpgradeMode(0)
            self.stop_strategy(is_final=False)
            self.execPhysicalRollbackUpgradedCatalog()
        except Exception as e:
            raise Exception(str(e))

    def execPhysicalRollbackUpgradedCatalog(self):
        """
        function : rollback catalog by restore physical files
                   send cmd to all node
        input : NA
        output: NA
        """
        try:
            if self.isLargeInplaceUpgrade:
                self.context.logger.debug(
                    "Start to restore physical catalog files.")
                # send cmd to all node and exec
                cmd = "%s -t %s -U %s --upgrade_bak_path=%s " \
                      "--oldcluster_num='%s' -X '%s' -l %s" % \
                      (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                       const.ACTION_RESTORE_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.oldClusterNumber,
                       self.context.xmlFile,
                       self.context.localLog)
                self.context.logger.debug(
                    "Command for restoring physical catalog files: %s." % cmd)
                CmdExecutor.execCommandWithMode(
                    cmd,
                    self.context.sshTool,
                    self.context.isSingle,
                    self.context.userProfile)
                self.context.logger.debug(
                    "Successfully restored physical catalog files.")
        except Exception as e:
            raise Exception(str(e))

    def getSqlHeader(self):
        """
        function: get sql header
        input  : NA
        output : NA
        """
        header = ["START TRANSACTION;"]
        header.append("SET %s = on;" % const.ON_INPLACE_UPGRADE)
        header.append("SET search_path = 'pg_catalog';")
        header.append("SET local client_min_messages = NOTICE;")
        header.append("SET local log_min_messages = NOTICE;")
        return header

    def getFileNameList(self, filePathName, scriptType="_"):
        """
        function: get file name list
        input  : filePathName
        output : []
        """
        filePath = "%s/upgrade_sql/%s" % (self.context.upgradeBackupPath,
                                          filePathName)
        allFileList = os.listdir(filePath)
        upgradeFileList = []
        if len(allFileList) == 0:
            return []
        for each_sql_file in allFileList:
            if not os.path.isfile("%s/%s" % (filePath, each_sql_file)):
                continue
            prefix = each_sql_file.split('.')[0]
            resList = prefix.split('_')
            if len(resList) != 5 or scriptType not in resList:
                continue
            file_num = "%s.%s" % (resList[3], resList[4])
            if self.floatMoreThan(float(file_num),
                                  self.context.oldClusterNumber) and \
                    self.floatGreaterOrEqualTo(self.context.newClusterNumber,
                                               float(file_num)):
                upgradeFileList.append(each_sql_file)
        return upgradeFileList

    def initClusterInfo(self, dbClusterInfoPath):
        """
        function: init the cluster
        input : dbClusterInfoPath
        output: dbClusterInfo
        """
        clusterInfoModules = OldVersionModules()
        fileDir = os.path.dirname(os.path.realpath(dbClusterInfoPath))
        sys.path.insert(0, fileDir)
        # init cluster information
        gp_home = ClusterDir.getClusterToolPath(self.context.user)
        gauss_home = ClusterDir.getInstallDir(self.context.user)
        gp_home_version = os.path.join(gp_home, "script", "gspylib", "common", "VersionInfo.py")
        gauss_home_version = os.path.join(gauss_home, "bin", "script",
                                          "gspylib", "common", "VersionInfo.py")
        if not os.path.isfile(gp_home_version) and os.path.isfile(gauss_home_version):
            FileUtil.cpFile(gauss_home_version, gp_home_version)

        clusterInfoModules.oldDbClusterInfoModule = __import__('DbClusterInfo')
        sys.path.remove(fileDir)
        return clusterInfoModules.oldDbClusterInfoModule.dbClusterInfo()

    def initOldClusterInfo(self, dbClusterInfoPath):
        """
        function: init old cluster information
        input : dbClusterInfoPath
        output: clusterInfoModules.oldDbClusterInfoModule.dbClusterInfo()
        """
        clusterInfoModules = OldVersionModules()
        fileDir = os.path.dirname(os.path.realpath(dbClusterInfoPath))
        # script and OldDbClusterInfo.py are in the same PGHOST directory
        sys.path.insert(0, fileDir)
        # V1R8 DbClusterInfo.py is "from gspylib.common.ErrorCode import
        # ErrorCode"
        sys.path.insert(0, os.path.join(fileDir, "script"))
        # init old cluster information
        clusterInfoModules.oldDbClusterInfoModule = \
            __import__('OldDbClusterInfo')
        return clusterInfoModules.oldDbClusterInfoModule.dbClusterInfo()

    def initClusterConfig(self):
        """
        function: init cluster info
        input : NA
        output: NA
        """
        gaussHome = \
            EnvUtil.getEnvironmentParameterValue("GAUSSHOME",
                                                      self.context.user)
        # $GAUSSHOME must has available value.
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
        (appPath, appPathName) = os.path.split(gaussHome)
        commonDbClusterInfoModule = \
            "%s/bin/script/gspylib/common/DbClusterInfo.py" % gaussHome
        commonStaticConfigFile = "%s/bin/cluster_static_config" % gaussHome
        try:
            if self.context.action == const.ACTION_INPLACE_UPGRADE:

                # get DbClusterInfo.py and cluster_static_config both of backup
                # path and install path
                # get oldClusterInfo
                #     if the backup file exists, we use them;
                #     if the install file exists, we use them;
                #     else, we can not get oldClusterInfo, exit.
                # backup path exists
                commonDbClusterInfoModuleBak = "%s/../OldDbClusterInfo.py" % \
                                               self.context.upgradeBackupPath
                commonStaticConfigFileBak = "%s/../cluster_static_config" % \
                                            self.context.upgradeBackupPath

                # if binary.tar exist, decompress it
                if os.path.isfile("%s/%s" % (self.context.upgradeBackupPath,
                                             self.context.binTarName)):
                    cmd = "cd '%s'&&tar xfp '%s'" % \
                          (self.context.upgradeBackupPath,
                           self.context.binTarName)
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if (status != 0):
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                        cmd + "Error: \n%s" % str(output))

                if (os.path.isfile(commonDbClusterInfoModuleBak)
                        and os.path.isfile(commonStaticConfigFileBak)):
                    try:
                        # import old module
                        # init old cluster config
                        self.context.oldClusterInfo = \
                            self.initOldClusterInfo(
                                commonDbClusterInfoModuleBak)
                        self.context.oldClusterInfo.initFromStaticConfig(
                            self.context.user, commonStaticConfigFileBak)
                    except Exception as e:
                        # maybe the old cluster is V1R5C00 TR5 version, not
                        # support specify static config file
                        # path for initFromStaticConfig function,
                        # so use new cluster format try again
                        self.context.oldClusterInfo = dbClusterInfo()
                        self.context.oldClusterInfo.initFromStaticConfig(
                            self.context.user, commonStaticConfigFileBak)
                # if backup path not exist, then use install path
                elif (os.path.isfile(commonDbClusterInfoModule)
                      and os.path.isfile(commonStaticConfigFile)):
                    # import old module
                    # init old cluster config
                    self.context.oldClusterInfo = \
                        self.initClusterInfo(commonDbClusterInfoModule)
                    self.context.oldClusterInfo.initFromStaticConfig(
                        self.context.user, commonStaticConfigFile)
                else:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                    "static config file")

                # get the accurate logPath
                logPathWithUser = EnvUtil.getEnv("GAUSSLOG")
                DefaultValue.checkPathVaild(logPathWithUser)
                splitMark = "/%s" % self.context.user
                self.context.oldClusterInfo.logPath = \
                    logPathWithUser[0:(logPathWithUser.rfind(splitMark))]

                # init new cluster config
                #     if xmlFile != "",  init it by initFromXml();
                #     else, using oldClusterInfo
                if self.context.xmlFile != "":
                    # get clusterInfo
                    # if falied to do dbClusterInfo, it means the
                    # DbClusterInfo.py is not correct
                    # we will use the backup file to instead of it
                    self.context.clusterInfo = dbClusterInfo()
                    try:
                        self.context.clusterInfo.initFromXml(
                            self.context.xmlFile)
                    except Exception as e:
                        self.context.logger.error(str(e))
                        try:
                            # init clusterinfo from backup dbclusterinfo
                            self.context.clusterInfo = \
                                self.initOldClusterInfo(
                                    commonDbClusterInfoModuleBak)
                            self.context.clusterInfo.initFromXml(
                                self.context.xmlFile)
                        except Exception as e:
                            try:
                                self.context.clusterInfo = \
                                    self.initClusterInfo(
                                        commonDbClusterInfoModule)
                                self.context.clusterInfo.initFromXml(
                                    self.context.xmlFile)
                            except Exception as e:
                                raise Exception(str(e))
                    # verify cluster config info between old and new cluster
                    self.verifyClusterConfigInfo(self.context.clusterInfo,
                                                 self.context.oldClusterInfo)
                    # after doing verifyClusterConfigInfo(),
                    # the clusterInfo and oldClusterInfo are be changed,
                    # so we should do init it again
                    self.context.clusterInfo = dbClusterInfo()
                    try:
                        self.context.clusterInfo.initFromXml(
                            self.context.xmlFile)
                    except Exception as e:
                        self.context.logger.debug(str(e))
                        try:
                            # init clusterinfo from backup dbclusterinfo
                            self.context.clusterInfo = \
                                self.initOldClusterInfo(
                                    commonDbClusterInfoModuleBak)
                            self.context.clusterInfo.initFromXml(
                                self.context.xmlFile)
                        except Exception as e:
                            try:
                                self.context.clusterInfo = \
                                    self.initClusterInfo(
                                        commonDbClusterInfoModule)
                                self.context.clusterInfo.initFromXml(
                                    self.context.xmlFile)
                            except Exception as e:
                                raise Exception(str(e))
                else:
                    self.context.clusterInfo = self.context.oldClusterInfo
            elif (self.context.action == const.ACTION_CHOSE_STRATEGY
                  or self.context.action == const.ACTION_COMMIT_UPGRADE):
                # after switch to new bin, the gausshome points to newversion,
                # so the oldClusterNumber is same with
                # newClusterNumber, the oldClusterInfo is same with new
                try:
                    self.context.oldClusterInfo = self.context.clusterInfo
                    self.getOneDNInst(True)
                    if os.path.isfile(commonDbClusterInfoModule) and \
                            os.path.isfile(commonStaticConfigFile):
                        # import old module
                        # init old cluster config
                        self.context.oldClusterInfo = \
                            self.initClusterInfo(commonDbClusterInfoModule)
                        self.context.oldClusterInfo.initFromStaticConfig(
                            self.context.user, commonStaticConfigFile)
                    else:
                        raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                        "static config file")
                except Exception as e:
                    # upgrade backup path
                    if (os.path.exists(
                            "%s/%s/bin/script/util/DbClusterInfo.py" % (
                            self.context.upgradeBackupPath, appPathName))):
                        binaryModuleBak = \
                            "%s/%s/bin/script/util/DbClusterInfo.py" % \
                            (self.context.upgradeBackupPath, appPathName)
                    else:
                        binaryModuleBak = \
                            "%s/%s/bin/script/gspylib/common/" \
                            "DbClusterInfo.py" % \
                            (self.context.upgradeBackupPath, appPathName)
                    binaryStaticConfigFileBak = \
                        "%s/%s/bin/cluster_static_config" % \
                        (self.context.upgradeBackupPath, appPathName)

                    if os.path.isfile(binaryModuleBak) and \
                            os.path.isfile(binaryStaticConfigFileBak):
                        # import old module
                        # init old cluster config
                        commonDbClusterInfoModuleBak = \
                            "%s/../OldDbClusterInfo.py" % \
                            self.context.upgradeBackupPath
                        self.context.oldClusterInfo = \
                            self.initOldClusterInfo(
                                commonDbClusterInfoModuleBak)
                        self.context.oldClusterInfo.initFromStaticConfig(
                            self.context.user, binaryStaticConfigFileBak)
                    else:
                        raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                        "static config file")
            elif (self.context.action in
                  [const.ACTION_SMALL_UPGRADE, const.ACTION_AUTO_UPGRADE,
                   const.ACTION_LARGE_UPGRADE, const.ACTION_AUTO_ROLLBACK]):
                # 1. get new cluster info
                self.context.clusterInfo = dbClusterInfo()
                self.context.clusterInfo.initFromXml(self.context.xmlFile)
                # 2. get oldClusterInfo
                # when under rollback
                # the gausshome may point to old or new clusterAppPath,
                # so we must choose from the record table
                # when upgrade abnormal nodes, the gausshome points to
                # newClusterAppPath

                oldPath = self.getClusterAppPath()
                if oldPath != "" and os.path.exists(oldPath):
                    self.context.logger.debug("The old install path is %s" %
                                              oldPath)
                    commonDbClusterInfoModule = \
                        "%s/bin/script/gspylib/common/DbClusterInfo.py" % \
                        oldPath
                    commonStaticConfigFile = \
                        "%s/bin/cluster_static_config" % oldPath
                else:
                    self.context.logger.debug("The old install path is %s"
                                              % os.path.realpath(gaussHome))
                if (os.path.isfile(commonDbClusterInfoModule)
                        and os.path.isfile(commonStaticConfigFile)):
                    # import old module
                    # init old cluster config
                    self.context.oldClusterInfo = \
                        self.initClusterInfo(commonDbClusterInfoModule)
                    self.context.oldClusterInfo.initFromStaticConfig(
                        self.context.user, commonStaticConfigFile)
                else:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                    "static config file")

                staticClusterInfo = dbClusterInfo()
                config = os.path.join(gaussHome, "bin/cluster_static_config")
                if not os.path.isfile(config):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                    os.path.realpath(config))
                staticClusterInfo.initFromStaticConfig(self.context.user,
                                                       config)

                # verify cluster config info between old and new cluster
                self.verifyClusterConfigInfo(self.context.clusterInfo,
                                             staticClusterInfo)
                # after doing verifyClusterConfigInfo(), the clusterInfo and
                # oldClusterInfo are be changed,
                # so we should do init it again
                self.context.clusterInfo = dbClusterInfo()
                # we will get the self.context.newClusterAppPath in
                # choseStrategy
                self.context.clusterInfo.initFromXml(self.context.xmlFile)
                if self.context.is_inplace_upgrade or \
                        self.context.action == const.ACTION_AUTO_ROLLBACK:
                    self.getOneDNInst()
                self.context.logger.debug("Successfully init cluster config.")
            else:
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % 't' +
                                " Value: %s" % self.context.action)

            # judgment has installed kerberos before action_inplace_upgrade
            self.context.logger.debug(
                "judgment has installed kerberos before action_inplace_upgrade")
            xmlfile = os.path.join(os.path.dirname(self.context.userProfile),
                                   DefaultValue.FI_KRB_XML)
            if os.path.exists(xmlfile) and \
                    self.context.action == const.ACTION_AUTO_UPGRADE \
                    and self.context.is_grey_upgrade:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50200"] % "kerberos")
            if os.path.exists(xmlfile) and self.context.is_inplace_upgrade:
                pghost_path = EnvUtil.getEnvironmentParameterValue(
                    'PGHOST', self.context.user)
                destfile = "%s/krb5.conf" % os.path.dirname(
                    self.context.userProfile)
                kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
                cmd = "cp -rf %s %s " % (destfile, kerberosflagfile)
                (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50206"] % kerberosflagfile
                        + " Error: \n%s" % output)
                self.context.logger.debug(
                    "Successful back up kerberos config file.")
        except Exception as e:
            self.context.logger.debug(traceback.format_exc())
            self.exitWithRetCode(self.context.action, False, str(e))

    def getAllStandbyDnInsts(self):
        """
        function: find all normal standby dn instances by dbNodes.
        input : NA
        output: DN instances
        """
        try:
            self.context.logger.debug("Get all standby DN.")
            dnList = []
            dnInst = None
            clusterNodes = self.context.oldClusterInfo.dbNodes
            standbyDn, output = DefaultValue.getStandbyNode(
                self.context.userProfile, self.context.logger)
            self.context.logger.debug(
                "Cluster status information is %s;The standbyDn is %s" % (
                    output, standbyDn))
            if not standbyDn or standbyDn == []:
                self.context.logger.debug("There is no standby dn")
                return []
            for dbNode in clusterNodes:
                if len(dbNode.datanodes) == 0:
                    continue
                dnInst = dbNode.datanodes[0]
                if dnInst.hostname not in standbyDn:
                    continue
                dnList.append(dnInst)

            (checkStatus, checkResult) = OMCommand.doCheckStaus(
                self.context.user, 0)
            if checkStatus == 0:
                self.context.logger.debug("The cluster status is normal,"
                                            " no need to check standby dn status.")
            else:
                dnList = []
                clusterStatus = \
                    OMCommand.getClusterStatus()
                if clusterStatus is None:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51600"])
                clusterInfo = dbClusterInfo()
                clusterInfo.initFromXml(self.context.xmlFile)
                clusterInfo.dbNodes.extend(clusterNodes)
                for dbNode in clusterInfo.dbNodes:
                    if len(dbNode.datanodes) == 0:
                        continue
                    dn = dbNode.datanodes[0]
                    if dn.hostname not in standbyDn:
                        continue
                    dbInst = clusterStatus.getInstanceStatusById(
                        dn.instanceId)
                    if dbInst is None:
                        continue
                    if dbInst.status == "Normal":
                        self.context.logger.debug(
                            "DN from %s is healthy." % dn.hostname)
                        dnList.append(dn)
                    else:
                        self.context.logger.debug(
                            "DN from %s is unhealthy." % dn.hostname)

            if not dnList or dnList == []:
                self.context.logger.debug("There is no normal standby dn")
            else:
                self.context.logger.debug("Successfully get all standby DN: %s" % \
                     ','.join(d.hostname for d in dnList))
                self.dnStandbyInsts = dnList

        except Exception as e:
            self.context.logger.log("Failed to get all standby DN. Error: %s" % str(e))
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51624"])

    def getOneDNInst(self, checkNormal=False):
        """
        function: find a dn instance by dbNodes,
                  which we can execute SQL commands
        input : NA
        output: DN instance
        """
        try:
            self.context.logger.debug(
                "Get one DN. CheckNormal is %s" % checkNormal)
            dnInst = None
            clusterNodes = self.context.oldClusterInfo.dbNodes
            primaryDnNode, output = DefaultValue.getPrimaryNode(
                self.context.userProfile, self.context.logger)
            self.context.logger.debug(
                "Cluster status information is %s;The primaryDnNode is %s" % (
                    output, primaryDnNode))
            if not primaryDnNode:
                self.context.logger.error("Get primary DN failed. Please check cluster.")
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51652"] % "Get primary DN failed.")
            for dbNode in clusterNodes:
                if len(dbNode.datanodes) == 0:
                    continue
                dnInst = dbNode.datanodes[0]
                if dnInst.hostname not in primaryDnNode:
                    continue
                break

            if checkNormal:
                (checkStatus, checkResult) = OMCommand.doCheckStaus(
                    self.context.user, 0)
                if checkStatus == 0:
                    self.context.logger.debug("The cluster status is normal,"
                                              " no need to check dn status.")
                else:
                    clusterStatus = \
                        OMCommand.getClusterStatus()
                    if clusterStatus is None:
                        raise Exception(ErrorCode.GAUSS_516["GAUSS_51600"])
                    clusterInfo = dbClusterInfo()
                    clusterInfo.initFromXml(self.context.xmlFile)
                    clusterInfo.dbNodes.extend(clusterNodes)
                    for dbNode in clusterInfo.dbNodes:
                        if len(dbNode.datanodes) == 0:
                            continue
                        dn = dbNode.datanodes[0]
                        if dn.hostname not in primaryDnNode:
                            continue
                        dbInst = clusterStatus.getInstanceStatusById(
                            dn.instanceId)
                        if dbInst is None:
                            continue
                        if dbInst.status == "Normal":
                            self.context.logger.debug(
                                "DN from %s is healthy." % dn.hostname)
                            dnInst = dn
                            break
                        self.context.logger.debug(
                            "DN from %s is unhealthy." % dn.hostname)

            # check if contain DN on nodes
            if not dnInst or dnInst == []:
                raise Exception(ErrorCode.GAUSS_526["GAUSS_52602"])
            else:
                self.context.logger.debug("Successfully get one DN from %s."
                                          % dnInst.hostname)
                self.dnInst = dnInst

        except Exception as e:
            self.context.logger.log("Failed to get one DN. Error: %s" % str(e))
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51624"])

    def verifyClusterConfigInfo(self, clusterInfo, oldClusterInfo,
                                ignoreFlag="upgradectl"):
        """
        function: verify cluster config info between xml and static config
        input : clusterInfo, oldClusterInfo
        output: NA
        """
        try:
            # should put self.context.clusterInfo before
            # self.context.oldClusterInfo,
            # because self.context.oldClusterInfo is not the istance of
            # dbCluster
            # covert new cluster information to compare cluster
            compnew = self.covertToCompCluster(clusterInfo)
            # covert old cluster information to compare cluster
            compold = self.covertToCompCluster(oldClusterInfo)
            # do compare
            # if it is not same, print it.
            theSame, tempbuffer = compareObject(compnew, compold,
                                                "clusterInfo", [], ignoreFlag)
            if (theSame):
                self.context.logger.log("Static configuration matched with "
                                        "old static configuration files.")
            else:
                msg = "Instance[%s] are not the same.\nXml cluster " \
                      "information: %s\nStatic cluster information: %s\n" % \
                      (tempbuffer[0], tempbuffer[1], tempbuffer[2])
                self.context.logger.debug("The old cluster information is "
                                          "from the cluster_static_config.")
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51217"] +
                                "Error: \n%s" % msg.strip("\n"))
        except Exception as e:
            raise Exception(str(e))

    def covertToCompCluster(self, dbclusterInfo):
        """
        function: covert to comp cluster
        input : clusterInfo, oldClusterInfo
        output: compClusterInfo
        """
        # init dbcluster class
        compClusterInfo = dbClusterInfo()
        # get name
        compClusterInfo.name = dbclusterInfo.name
        # get appPath
        compClusterInfo.appPath = dbclusterInfo.appPath
        # get logPath
        compClusterInfo.logPath = dbclusterInfo.logPath

        for dbnode in dbclusterInfo.dbNodes:
            compNodeInfo = dbNodeInfo()
            # get datanode instance information
            for datanode in dbnode.datanodes:
                compNodeInfo.datanodes.append(
                    self.coverToCompInstance(datanode))
            # get node information
            compClusterInfo.dbNodes.append(compNodeInfo)
        return compClusterInfo

    def coverToCompInstance(self, compinstance):
        """
        function: cover to comp instance
                  1. get instanceId
                  2. get mirrorId
                  3. get port
                  4. get datadir
                  5. get instanceType
                  6. get listenIps
                  7. get haIps
        input : compinstance
        output: covertedInstanceInfo
        """
        covertedInstanceInfo = instanceInfo()
        # get instanceId
        covertedInstanceInfo.instanceId = compinstance.instanceId
        # get mirrorId
        covertedInstanceInfo.mirrorId = compinstance.mirrorId
        # get port
        covertedInstanceInfo.port = compinstance.port
        # get datadir
        covertedInstanceInfo.datadir = compinstance.datadir
        # get instanceType
        covertedInstanceInfo.instanceType = compinstance.instanceType
        # get listenIps
        covertedInstanceInfo.listenIps = compinstance.listenIps
        # get haIps
        covertedInstanceInfo.haIps = compinstance.haIps
        return covertedInstanceInfo

    def distributeXml(self):
        """
        function: distribute package to every host
        input : NA
        output: NA
        """
        self.context.logger.debug("Distributing xml configure file.",
                                  "addStep")

        try:

            hosts = self.context.clusterInfo.getClusterNodeNames()
            hosts.remove(NetUtil.GetHostIpOrName())

            # Send xml file to every host
            DefaultValue.distributeXmlConfFile(self.context.sshTool,
                                               self.context.xmlFile,
                                               hosts,
                                               self.context.mpprcFile,
                                               self.context.isSingle)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.debug("Successfully distributed xml "
                                  "configure file.", "constant")

    def recordNodeStepInplace(self, action, step):
        """
        function: record step info on all nodes
        input : action, step
        output: NA
        """
        try:
            # record step info on local node

            tempPath = self.context.upgradeBackupPath
            filePath = os.path.join(tempPath, const.INPLACE_UPGRADE_STEP_FILE)
            cmd = "echo \"%s:%d\" > %s" % (action, step, filePath)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] %
                                filePath + "Error: \n%s" % str(output))

            if not self.context.isSingle:
                # send file to remote nodes
                self.context.sshTool.scpFiles(filePath, tempPath)
            self.context.logger.debug("Successfully wrote step file[%s:%d]."
                                      % (action, step))
        except Exception as e:
            raise Exception(str(e))

    def distributeFile(self, step_file):
        """
        function: distribute file
        input  : step_file
        output : NA
        """
        self.context.logger.debug("Distribute the file %s" % step_file)
        # send the file to each node
        hosts = self.context.clusterInfo.getClusterNodeNames()
        hosts.remove(NetUtil.GetHostIpOrName())
        if not self.context.isSingle:
            stepDir = os.path.normpath(os.path.dirname(step_file))
            self.context.sshTool.scpFiles(step_file, stepDir, hosts)
            self.context.logger.debug("Successfully distribute the file %s"
                                  % step_file)

    def getNodeStepInplace(self):
        """
        function: Get the upgrade step info for inplace upgrade
        input : action
        output: the upgrade step info
        """
        try:
            tempPath = self.context.upgradeBackupPath
            # get file path and check file exists
            filePath = os.path.join(tempPath, const.INPLACE_UPGRADE_STEP_FILE)
            if not os.path.exists(filePath):
                self.context.logger.debug("The cluster status is Normal. "
                                          "No need to rollback.")
                return const.BINARY_UPGRADE_NO_NEED_ROLLBACK

            # read and check record format
            stepInfo = FileUtil.readFile(filePath)[0]
            stepList = stepInfo.split(":")
            if len(stepList) != 2:
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % filePath)

            recordType = stepList[0].strip()
            recordStep = stepList[1].strip()
            # check upgrade type
            # the record value must be consistent with the upgrade type
            if self.context.action != recordType:
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % "t" +
                                "Input upgrade type: %s record upgrade type: "
                                "%s\nMaybe you chose the wrong interface." %
                                (self.context.action, recordType))
            # if record value is not digit, exit.
            if not recordStep.isdigit() or int(recordStep) > \
                    const.BINARY_UPGRADE_STEP_PRE_COMMIT or \
                    int(recordStep) < const.INVALID_UPRADE_STEP:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51633"] %
                                recordStep)
        except Exception as e:
            self.context.logger.error(str(e))
            return const.INVALID_UPRADE_STEP
        self.context.logger.debug("The rollback step is %s" % recordStep)
        return int(recordStep)

    def checkStep(self, step):
        """
        function: check step
        input  : step
        output : NA
        """
        if not step.isdigit() or \
                int(step) > GreyUpgradeStep.STEP_BEGIN_COMMIT or \
                int(step) < const.INVALID_UPRADE_STEP:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51633"] % str(step))

    ##########################################################################
    # Offline upgrade functions
    ##########################################################################
    def checkUpgrade(self):
        """
        function: Check the environment for upgrade
        input : action
        output: NA
        """
        self.context.logger.log("Checking upgrade environment.", "addStep")
        try:
            # Check the environment for upgrade
            cmd = "%s -t %s -R '%s' -l '%s' -N '%s' -X '%s'" % \
                  (OMCommand.getLocalScript("Local_Check_Upgrade"),
                   self.context.action,
                   self.context.oldClusterAppPath,
                   self.context.localLog,
                   self.context.newClusterAppPath,
                   self.context.xmlFile)
            self.context.logger.debug("Command for checking upgrade "
                                      "environment: %s." % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            self.context.logger.log("Failed to check upgrade environment.",
                                    "constant")
            raise Exception(str(e))
        if not self.context.forceRollback:
            if self.context.oldClusterNumber >= \
                    const.ENABLE_STREAM_REPLICATION_VERSION:
                self.check_gucval_is_inval_given(
                    const.ENABLE_STREAM_REPLICATION_NAME, const.VALUE_ON)
        try:
            if self.context.action == const.ACTION_INPLACE_UPGRADE:
                self.context.logger.log(
                    "Successfully checked upgrade environment.", "constant")
                return
            self.checkActionInTableOrFile()
            self.checkDifferentVersion()
            self.checkOption()
        except Exception as e:
            self.context.logger.log(
                "Failed to check upgrade environment.", "constant")
            raise Exception(str(e))
        self.checkDualClusterUpgrade()
        self.context.logger.log(
            "Successfully checked upgrade environment.", "constant")

    def check_gucval_is_inval_given(self, guc_name, val_list):
        """
        Checks whether a given parameter is a given value list in a
        given instance list.
        """
        self.context.logger.debug("checks whether the parameter:{0} is "
                                  "the value:{1}.".format(guc_name, val_list))
        guc_str = "{0}:{1}".format(guc_name, ",".join(val_list))
        self.checkParam(guc_str)
        self.context.logger.debug("Success to check the parameter:{0} value "
                                  "is in the value:{1}.".format(guc_name,
                                                                val_list))

    def checkDifferentVersion(self):
        """
        if the cluster has only one version. no need to check
        if the cluster has two version, it should be the new
        version or the old version
        :return:
        """
        self.context.logger.debug("Check the amount of cluster version.")
        failedHost = []
        failMsg = ""
        gaussHome = ClusterDir.getInstallDir(self.context.user)
        # $GAUSSHOME must has available value.
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
        versionFile = os.path.join(gaussHome, "bin/upgrade_version")
        cmd = "sed -n \'3,1p\' %s" % versionFile
        hostList = copy.deepcopy(self.context.clusterNodes)
        (resultMap, outputCollect) = \
            self.context.sshTool.getSshStatusOutput(cmd, hostList)
        for key, val in resultMap.items():
            if DefaultValue.FAILURE in val:
                failedHost.append(key)
                failMsg += val
        if failedHost:
            self.context.recordIgnoreOrFailedNodeInEveryNode(
                self.context.failedNodeRecordFile, failedHost)
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52929"] + failMsg)
        for result in outputCollect:
            if result.find(self.newCommitId) or result.find(self.oldCommitId):
                continue
            self.context.logger.debug(
                "Find the gausssdb version %s is not same with"
                " current upgrade version" % str(result))
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52935"])
        self.context.logger.debug(
            "Successfully checked the amount of cluster version.")

    def checkOption(self):
        """
        if user use -g first, and then use -h <last -g choose nodes>,
        we can upgrade again
        :return:
        """
        if self.context.is_grey_upgrade:
            self.check_option_grey()
        if len(self.context.nodeNames) != 0:
            self.checkOptionH()
        elif self.context.upgrade_remain:
            self.checkOptionContinue()
        else:
            self.checkOptionG()

    def check_option_grey(self):
        """
        if nodes have been upgraded, no need to use --grey to upgrade again
        :return:
        """
        stepFile = os.path.join(
            self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                const.GREY_UPGRADE_STEP_FILE)
            return
        
        # check cluster nodes wheather all have been upgraded
        grey_node_names = self.getUpgradedNodeNames(GreyUpgradeStep.STEP_UPGRADE_PROCESS)
        if len(grey_node_names) == len(self.context.clusterNodes):
            self.context.logger.log(
                "All nodes have been upgrade, no need to upgrade again.")
            self.exitWithRetCode(self.action, True)
        else:
            self.context.logger.log(
                "%s node have been upgrade, can upgrade the remaining nodes." 
                % grey_node_names)

    def checkOptionH(self):
        self.checkNodeNames()
        stepFile = os.path.join(
            self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                const.GREY_UPGRADE_STEP_FILE)
            return
        if not self.isNodesSameStep(self.context.nodeNames):
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52909"])
        if self.isNodeSpecifyStep(
                GreyUpgradeStep.STEP_UPDATE_POST_CATALOG,
                self.context.nodeNames):
            raise Exception(
                ErrorCode.GAUSS_529["GAUSS_52910"] % self.context.nodeNames)
        nodes = self.getNodeLessThan(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)
        # compare whether current upgrade nodes are same with
        # last unfinished node names
        if nodes:
            a = [i for i in self.context.nodeNames if i not in nodes]
            b = [i for i in nodes if i not in self.context.nodeNames]
            if len(a) != 0 or len(b) != 0:
                raise Exception(
                    ErrorCode.GAUSS_529["GAUSS_52911"] % nodes +
                    " Please upgrade them first.")

    def checkNodeNames(self):
        self.context.logger.debug(
            "Check if the node name is invalid or duplicated.")
        clusterNodes = self.context.clusterInfo.getClusterNodeNames()
        for nodeName in self.context.nodeNames:
            if nodeName not in clusterNodes:
                raise Exception(
                    ErrorCode.GAUSS_500["GAUSS_50011"] % ("-h", nodeName))

        undupNodes = set(self.context.nodeNames)
        if len(self.context.nodeNames) != len(undupNodes):
            self.context.logger.log(
                ErrorCode.GAUSS_500["GAUSS_50004"] % (
                        "h" + "Duplicates node names"))
            nodeDict = {}.fromkeys(self.context.nodeNames, 0)
            for name in self.context.nodeNames:
                nodeDict[name] = nodeDict[name] + 1
            for key, value in nodeDict.items():
                if value > 1:
                    self.context.logger.log(
                        "Duplicates node name %s, "
                        "only keep one in grey upgrade!" % key)
            self.context.nodeNames = list(undupNodes)

    def isNodesSameStep(self, nodes):
        """
        judge if given nodes are same step
        """
        return self.isNodeSpecifyStepInFile(nodes=nodes)

    def getNodeLessThan(self, step):
        """
        get the nodes whose step is less than specified step, and can not be 0
        """
        nodes = self.getNodeLessThanInFile(step)
        return nodes

    def getNodeLessThanInFile(self, step):
        """
        get the nodes whose step is less than specified step, and can not be 0
        """
        try:
            stepFile = os.path.join(
                self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)
            self.context.logger.debug("trying to get nodes that step is "
                                      "less than %s from %s" % (step, stepFile))
            if not os.path.isfile(stepFile):
                return []
            nodes = []
            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if int(row['step']) != 0 and int(row['step']) < step:
                        nodes.append(row['node_host'])
            self.context.logger.debug("successfully got nodes that step is "
                                      "less than %s from %s" % (step, stepFile))
            return nodes
        except Exception as e:
            exitMsg = "Failed to get nodes that step is less than {0} " \
                      "from {1}. ERROR {2}".format(step, stepFile, str(e))
            self.exitWithRetCode(self.action, False, exitMsg)

    def checkOptionContinue(self):
        stepFile = os.path.join(
            self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52920"] +
                            "Need to upgrade some nodes first.")
        
        # check cluster nodes wheather all have been upgraded
        # get upgraded nodes list
        greyNodeNames = self.getUpgradedNodeNames()
        # the nodes that have upgraded that should reached to precommit
        # if nodes < STEP_UPDATE_POST_CATALOG, indicate that this node not
        # upgrade completely, need to rollback fistly and upgrade again
        if not self.isNodeSpecifyStep(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG,
                                      greyNodeNames):
            self.context.logger.log(
                "%s node have been upgrade, can upgrade the remaining nodes."
                 % greyNodeNames)
            raise Exception(ErrorCode.GAUSS_529["GAUSS-52944"])
        elif len(greyNodeNames) == len(self.context.clusterNodes):
            self.context.logger.log(
                "All nodes have been upgrade, no need to upgrade again "
                "by --continue.")
            self.exitWithRetCode(self.action, True)

        if len(greyNodeNames) == len(self.context.clusterInfo.dbNodes):
            self.printPrecommitBanner()
            self.context.logger.debug(
                "The node host in table %s.%s is equal to cluster nodes."
                % (const.UPGRADE_SCHEMA, const.RECORD_NODE_STEP))
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52913"])
        if not self.checkVersion(self.newCommitId, greyNodeNames):
            raise Exception(
                ErrorCode.GAUSS_529["GAUSS_52914"] +
                "Please use the same version to upgrade remain nodes.")

    def checkOptionG(self):
        stepFile = os.path.join(
            self.context.upgradeBackupPath, const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                const.GREY_UPGRADE_STEP_FILE)
            return
        # -g only support 2 loops to upgrade, if has node upgrade,
        # cannot use -g to upgrade other nodes
        greyNodeNames = self.getUpgradedNodeNames()
        if not greyNodeNames:
            self.context.logger.debug("No node has ever been upgraded.")
            return
        else:
            raise Exception("-g only support if no node has ever been upgraded"
                            " ,nodes %s have been upgraded, "
                            "so can use --continue instead of -g to upgrade"
                            " other nodes" % greyNodeNames)

    def backupClusterConfig(self):
        """
        function: Backup the cluster config
        input : NA
        output: NA
        """
        # backup list:
        #    cluster_static_config
        #    cluster_dynamic_config
        #    etc/gscgroup_xxx.cfg
        #    lib/postgresql/pg_plugin
        #    server.key.cipher
        #    server.key.rand
        #    datasource.key.cipher
        #    datasource.key.rand
        #    usermapping.key.cipher
        #    usermapping.key.rand
        #    subscription.key.cipher
        #    subscription.key.rand
        #    utilslib
        #    /share/sslsert/ca.key
        #    /share/sslsert/etcdca.crt
        #    catalog physical files
        #    Data Studio lib files
        #    gds files
        #    javaUDF
        #    postGIS
        #    hadoop_odbc_connector extension files
        #    libsimsearch etc files and lib files
        self.context.logger.log("Backing up cluster configuration.", "addStep")
        try:
            # send cmd to all node and exec
            cmd = "%s -t %s -U %s -V %d --upgrade_bak_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_BACKUP_CONFIG,
                   self.context.user,
                   int(float(self.context.oldClusterNumber) * 1000),
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug("Command for backing up cluster "
                                      "configuration: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

            # backup hotpatch info file
            self.backupHotpatch()
            # backup version file.
            self.backup_version_file()

            if not self.isLargeInplaceUpgrade:
                return
            # backup catalog data files if needed
            self.backupCatalogFiles()

            # backup DS libs and gds file
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_INPLACE_BACKUP,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug(
                "Command for backing up gds file: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.userProfile)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log("Successfully backed up cluster "
                                "configuration.", "constant")

    def backupCatalogFiles(self):
        """
        function: backup  physical files of catalg objects
                  1.check if is inplace upgrade
                  2.get database list
                  3.get catalog objects list
                  4.backup physical files for each database
                  5.backup global folder
        input : NA
        output: NA
        """
        try:
            # send cmd to all node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s " \
                  "--oldcluster_num='%s' -X '%s' -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_BACKUP_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.oldClusterNumber,
                   self.context.xmlFile,
                   self.context.localLog)
            self.context.logger.debug("Command for backing up physical files "
                                      "of catalg objects: %s" % cmd)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool,
                self.context.isSingle,
                self.context.userProfile)
            self.context.logger.debug("Successfully backed up catalog "
                                      "physical files for old cluster.")
        except Exception as e:
            raise Exception(str(e))

    def syncNewGUC(self):
        """
        function: sync newly added guc during inplace upgrade.
                  For now, we only sync guc of cm_agent and cm_server
        input : NA
        output: NA
        """
        self.context.logger.debug("Start to sync new guc.", "addStep")
        try:
            # send cmd to all node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s " \
                  "--new_cluster_app_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_SYNC_CONFIG,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.newClusterAppPath,
                   self.context.localLog,)
            self.context.logger.debug(
                "Command for synchronizing new guc: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            self.context.logger.debug("Failed to synchronize new guc.",
                                      "constant")
            raise Exception(str(e))
        self.context.logger.debug("Successfully synchronized new guc.",
                                  "constant")

    def waitClusterForNormal(self, waitTimeOut=300):
        """
        function: Wait the node become Normal
        input : waitTimeOut
        output: NA
        """
        self.context.logger.log("Waiting for the cluster status to "
                                "become normal.")
        dotCount = 0
        # get the end time
        endTime = datetime.now() + timedelta(seconds=int(waitTimeOut))
        while True:
            time.sleep(5)
            sys.stdout.write(".")
            dotCount += 1
            if dotCount >= 12:
                dotCount = 0
                sys.stdout.write("\n")

            (checkStatus, checkResult) = \
                OMCommand.doCheckStaus(self.context.user, 0)
            if checkStatus == 0:
                if dotCount != 0:
                    sys.stdout.write("\n")
                self.context.logger.log("The cluster status is normal.")
                break

            if datetime.now() >= endTime:
                if dotCount != 0:
                    sys.stdout.write("\n")
                self.context.logger.debug(checkResult)
                raise Exception("Timeout." + "\n" +
                                ErrorCode.GAUSS_516["GAUSS_51602"])

        if checkStatus != 0:
            self.context.logger.debug(checkResult)
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "cluster")

    def create_ca_for_cm(self):
        """
        Create CM CA file
        """
        if self.get_upgrade_cm_strategy() != 1:
            self.context.logger.debug("No need to create CA for CM.")
            return

        new_cluster_config_file = \
            os.path.realpath(os.path.join(self.context.newClusterAppPath,
                                          "bin", "cluster_static_config"))
        self.context.logger.debug("Start create CA for CM.")
        new_cluster_info = dbClusterInfo()
        new_cluster_info.initFromStaticConfig(self.context.user,
                                              new_cluster_config_file)
        local_node = [node for node in new_cluster_info.dbNodes
                      if node.name == NetUtil.GetHostIpOrName()][0]
        agent_component = CM_OLAP()
        agent_component.instInfo = local_node.cmagents[0]
        agent_component.logger = self.context.logger
        agent_component.binPath = os.path.realpath(os.path.join(self.context.newClusterAppPath,
                                                                "bin"))
        agent_component.create_cm_ca(self.context.sshTool)
        self.context.logger.debug("Create CA for CM successfully.")
    
    def createCmCaForRollingUpgrade(self):
        """
        Create CM CA file
        """
        if self.get_upgrade_cm_strategy() != 1:
            self.context.logger.debug("No need to create CA for CM.")
            return
		
        hostList = copy.deepcopy(self.context.nodeNames)
		
        cmd = "%s -t %s -U %s --new_cluster_app_path=%s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_CREATE_CM_CA_FOR_ROLLING_UPGRADE,
               self.context.user,
               self.context.newClusterAppPath,
               self.context.localLog)
        self.context.logger.debug("Command for create ca for cm in rolling upgrade: %s" % cmd)
        self.context.sshTool.executeCommand(cmd, hostList=hostList)
        self.context.logger.debug("Successfully create cm ca for rolling upgrade.")

    def restart_cm_proc(self):
        """kill cm_agent and cm_server process
        """
        if not DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) > 0:
            return
        time.sleep(5)
        self.context.logger.debug("Start to restart cmagent and cmserver")
        kill_cm_proc = "pkill -9 cm_agent -U {user}; " \
            "pkill -9 cm_server -U {user};".format(user=self.context.user)
        host_list = copy.deepcopy(self.context.clusterNodes)
        self.context.logger.debug(f"stopCMProcessesCmd: {kill_cm_proc} on {host_list}")
        self.context.sshTool.getSshStatusOutput(kill_cm_proc, host_list)
        self.context.logger.debug("End to restart cmagent and cmserver")
        
    def reload_cm_proc(self):
        if not DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) > 0:
            return
        self.context.logger.debug("Start to reload cmagent and cmserver")
        kill_cm_proc = "cm_ctl reload --param --server;cm_ctl reload --param --agent"
        _, output = subprocess.getstatusoutput(kill_cm_proc)
        self.context.logger.debug("End to reload cmagent and cmserver, %s" % output)

    def reloadCmAgent(self, is_final=False):
        """
        Run the 'kill -1' command to make the parameters of all cmagent instances take effect.
        :return:
        """
        if not DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) > 0 \
                and not is_final:
            self.context.logger.debug("No need to reload cm configuration.")
            return
        self.context.logger.debug("Start to reload cmagent")
        cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_RELOAD_CMAGENT,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.localLog)
        self.context.logger.debug("reloading all cmagent process: %s" % cmd)
        try:
            hostList = copy.deepcopy(self.context.clusterNodes)
            self.context.execCommandInSpecialNode(cmd, hostList)
            # wait the cluster be normal
            self.waitClusterNormalDegrade()
            self.context.logger.debug("Success to reload cmagent")
        except Exception as er:
            if self.context.action == const.ACTION_INPLACE_UPGRADE or not \
                    self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.debug("Failed to reload cm agent. Warning:{0}".format(str(er)))

    def reload_cmserver(self, is_final=False):
        """
        Run the 'kill -1' command to make the parameters of all cmserver instances take effect.
        :return:
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.oldClusterInfo) == 0 \
                and not is_final:
            self.context.logger.debug("No need to reload cm server configuration.")
            return
        self.context.logger.debug("Start to reload cmserver")
        cm_nodes = []
        # Get all the nodes that contain the CMSERVER instance
        for dbNode in self.context.clusterInfo.dbNodes:
            if len(dbNode.cmservers) > 0:
                cm_nodes.append(dbNode.name)
        cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_RELOAD_CMSERVER,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.localLog)
        self.context.logger.debug("reloading all cmserver process: %s" % cmd)
        try:
            self.context.execCommandInSpecialNode(cmd, cm_nodes)
            # wait the cluster be normal
            self.waitClusterNormalDegrade()
            self.context.logger.debug("Success to reload cmserver")
        except Exception as er:
            if self.context.action == const.ACTION_INPLACE_UPGRADE or \
                    not self.context.forceRollback:
                raise Exception(str(er))
            self.context.logger.debug("Failed to reload cm server. Warning:{0}".format(str(er)))

    def restoreClusterConfig(self, isRollBack=False):
        """
        function: Restore the cluster config
        input : isRollBack
        output: NA
        """
        # restore list:
        #    cluster_dynamic_config
        #    etc/gscgroup_xxx.cfg
        #    lib/postgresql/pg_plugin
        #    server.key.cipher
        #    server.key.rand
        #    datasource.key.cipher
        #    datasource.key.rand
        #    utilslib
        #    /share/sslsert/ca.key
        #    /share/sslsert/etcdca.crt
        #    Data Studio lib files
        #    gds files
        #    javaUDF
        #    postGIS
        #    hadoop_odbc_connector extension files
        #    libsimsearch etc files and lib files
        if isRollBack:
            self.context.logger.log("Restoring cluster configuration.")
        else:
            self.context.logger.log("Restoring cluster configuration.",
                                    "addStep")
        try:
            if isRollBack:
                self.rollbackHotpatch()
            else:
                # restore static configuration
                cmd = "%s -t %s -U %s -V %d --upgrade_bak_path=%s " \
                      "--old_cluster_app_path=%s --new_cluster_app_path=%s " \
                      "-l %s" % (
                    OMCommand.getLocalScript("Local_Upgrade_Utility"),
                    const.ACTION_RESTORE_CONFIG,
                    self.context.user,
                    int(float(self.context.oldClusterNumber) * 1000),
                    self.context.upgradeBackupPath,
                    self.context.oldClusterAppPath,
                    self.context.newClusterAppPath,
                    self.context.localLog)

                self.context.logger.debug("Command for restoring "
                                          "config files: %s" % cmd)
                CmdExecutor.execCommandWithMode(cmd,
                                                self.context.sshTool,
                                                self.context.isSingle,
                                                self.context.mpprcFile)
                if self.isLargeInplaceUpgrade:
                    # backup DS libs and gds file
                    cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                          (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                           const.ACTION_INPLACE_BACKUP,
                           self.context.user,
                           self.context.upgradeBackupPath,
                           self.context.localLog)
                    self.context.logger.debug(
                        "Command for restoreing DS libs and gds file: %s" % cmd)
                    CmdExecutor.execCommandWithMode(
                        cmd,
                        self.context.sshTool,
                        self.context.isSingle,
                        self.context.userProfile)
                # change the owner of application
                cmd = "chown -R %s:%s '%s'" % \
                      (self.context.user, self.context.group,
                       self.context.newClusterAppPath)
                CmdExecutor.execCommandWithMode(
                    cmd,
                    self.context.sshTool, self.context.isSingle,
                    self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        if isRollBack:
            self.context.logger.log("Successfully restored "
                                    "cluster configuration.")
        else:
            self.context.logger.log("Successfully restored cluster "
                                    "configuration.", "constant")

    def checkStaticConfig(self):
        """
        function: Check if static config file exists in bin dir,
                  if not exists, restore it from backup dir
        input : NA
        output: NA
        """
        self.context.logger.log("Checking static configuration files.")
        try:
            # check static configuration path
            staticConfigPath = "%s/bin" % self.context.oldClusterAppPath
            # restore static configuration
            cmd = "(if [ ! -f '%s/cluster_static_config' ];then cp " \
                  "%s/cluster_static_config %s/bin;fi)" % \
                  (staticConfigPath, self.context.upgradeBackupPath,
                   self.context.oldClusterAppPath)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))
        self.context.logger.log("Successfully checked static "
                                "configuration files.")

    def backupNodeVersion(self):
        """
        function: Backup current application and configuration.
                  The function only be used by binary upgrade.
                  To ensure the transaction atomicity,
                  it will be used with checkUpgrade().
        input : NA
        output: NA
        """
        self.context.logger.log("Backing up current application "
                                "and configurations.", "addStep")
        try:
            # back up environment variables
            cmd = "cp '%s' '%s'_gauss" % (self.context.userProfile,
                                          self.context.userProfile)
            self.context.logger.debug(
                "Command for backing up environment file: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

            # back up application and configuration
            cmd = "%s -U %s -P %s -p -b -l %s" % \
                  (OMCommand.getLocalScript("Local_Backup"), self.context.user,
                   self.context.upgradeBackupPath, self.context.localLog)
            self.context.logger.debug(
                "Command for backing up application: %s" % cmd)
            CmdExecutor.execCommandWithMode(
                cmd,
                self.context.sshTool, self.context.isSingle,
                self.context.mpprcFile)

        except Exception as e:
            # delete binary backup directory
            delCmd = g_file.SHELL_CMD_DICT["deleteDir"] % \
                     (self.context.tmpDir, os.path.join(self.context.tmpDir,
                                                        'backupTemp_*'))
            CmdExecutor.execCommandWithMode(delCmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
            raise Exception(str(e))

        self.context.logger.log("Successfully backed up current "
                                "application and configurations.", "constant")

    def restoreNodeVersion(self):
        """
        function: Restore the application and configuration
                  1. restore old version
                  2. restore environment variables
        input : NA
        output: NA
        """
        self.context.logger.log("Restoring application and configurations.")

        try:
            # restore old version
            cmd = "%s -U %s -P %s -p -b -l %s" % \
                  (OMCommand.getLocalScript("Local_Restore"),
                   self.context.user, self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug("Command for restoring "
                                      "old version: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

            # restore environment variables
            cmd = "(if [ -f '%s'_gauss ];then mv '%s'_gauss '%s';fi)" % \
                  (self.context.userProfile, self.context.userProfile,
                   self.context.userProfile)
            self.context.logger.debug("Command for restoring environment file:"
                                      " %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log("Successfully restored application and "
                                "configuration.")

    def modifySocketDir(self):
        """
        function: modify unix socket directory
        input : NA
        output: NA
        """
        self.context.logger.log("Modifying the socket path.", "addStep")
        try:
            # modifying the socket path for all CN/DN instance
            self.setGUCValue("unix_socket_directory",
                             DefaultValue.getTmpDirAppendMppdb(self.context.user), "set")

        except Exception as e:
            raise Exception(str(e))

        self.context.logger.log("Successfully modified socket path.",
                                "constant")

    ###########################################################################
    # Rollback upgrade functions
    ###########################################################################
    def cleanBackupFiles(self):
        """
        function: Clean backup files.
        input : action
        output : NA
        """
        try:
            # clean backup files
            cmd = "(if [ -f '%s/OldDbClusterInfo.py' ]; then rm -f " \
                  "'%s/OldDbClusterInfo.py'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/OldDbClusterInfo.pyc' ]; then rm -f " \
                   "'%s/OldDbClusterInfo.pyc'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -d '%s/script' ]; then rm -rf '%s/script'; " \
                   "fi) &&" %  (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/oldclusterinfo' ]; then rm -f " \
                   "'%s/oldclusterinfo'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/oldclusterGUC' ]; then rm -f " \
                   "'%s/oldclusterGUC'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/cluster_static_config' ]; then rm -f " \
                   "'%s/cluster_static_config'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/c_functionfilelist.dat' ]; then rm -f " \
                   "'%s/c_functionfilelist.dat'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s'_gauss ]; then rm -f '%s'_gauss ; fi) &&" % \
                   (self.context.userProfile, self.context.userProfile)
            cmd += "(if [ -f '%s/oldclusterinfo.json' ]; then rm -f " \
                   "'%s/oldclusterinfo.json'; fi) &&" % \
                   (self.context.tmpDir, self.context.tmpDir)
            cmd += "(if [ -f '%s/%s' ]; then rm -f '%s/%s'; fi) &&" % \
                   (self.context.tmpDir, const.CLUSTER_CNSCONF_FILE,
                    self.context.tmpDir, const.CLUSTER_CNSCONF_FILE)
            cmd += "(rm -f '%s'/gauss_crontab_file_*) &&" % self.context.tmpDir
            cmd += "(if [ -d '%s' ]; then rm -rf '%s'; fi) &&" % \
                   (self.context.upgradeBackupPath,
                    self.context.upgradeBackupPath)
            cmd += "(if [ -f '%s/pg_proc_mapping.txt' ]; then rm -f" \
                   " '%s/pg_proc_mapping.txt'; fi)" % \
                   (self.context.tmpDir, self.context.tmpDir)
            self.context.logger.debug("Command for clean "
                                      "backup files: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

        except Exception as e:
            raise Exception(str(e))

    def cleanBinaryUpgradeBakFiles(self, isRollBack=False):
        """
        function: Clean back up files, include cluster_static_config,
                  cluster_dynamic_config, binary.tar, parameter.tar.
        input : isRollBack
        output: NA
        """
        if (isRollBack):
            self.context.logger.debug("Cleaning backup files.")
        else:
            self.context.logger.debug("Cleaning backup files.", "addStep")

        try:
            # clean backup files
            self.cleanBackupFiles()
            # clean gs_secure_files folder
            if self.context.rollback or self.action == "commit-upgrade":
                self.clean_gs_secure_files()
        except Exception as e:
            raise Exception(str(e))
        if (isRollBack):
            self.context.logger.debug("Successfully cleaned backup files.")
        else:
            self.context.logger.debug("Successfully cleaned backup files.",
                                      "constant")

    ###########################################################################
    # Rollback upgrade functions
    ###########################################################################

    def doHealthCheck(self, checkPosition):
        """
        function: Do health check, if healthy, return 0, else return 1
        input : checkPosition
        output: 0  successfully
                1  failed
        """
        #######################################################################
        # When do binary-upgrade:
        #       const.OPTION_PRECHECK        -> cluster Normal
        #                              -> database can connec
        #       const.OPTION_POSTCHECK       -> cluster Normal
        #                              -> package version Normal
        #                              -> database can connec
        #######################################################################
        self.context.logger.log("Start to do health check.", "addStep")

        status = 0
        output = ""

        if checkPosition == const.OPTION_PRECHECK:
            if (self.checkClusterStatus(checkPosition, True) != 0):
                output += "\n    Cluster status does not match condition."
            if self.checkConnection() != 0:
                output += "\n    Database could not be connected."
        elif checkPosition == const.OPTION_POSTCHECK:
            if len(self.context.nodeNames) != 0:
                checknodes = self.context.nodeNames
            else:
                checknodes = self.context.clusterInfo.getClusterNodeNames()
            if self.checkClusterStatus(checkPosition) != 0:
                output += "\n    Cluster status is Abnormal."
            if not self.checkVersion(
                    self.context.newClusterVersion, checknodes):
                output += "\n    The gaussdb version is inconsistent."
            if self.checkConnection() != 0:
                output += "\n    Database could not be connected."
        else:
            # Invalid check position
            output += "\n    Invalid check position."
        if output != "":
            status = 1
        # all check has been pass, return 0
        self.context.logger.log("Successfully checked cluster status.",
                                "constant")
        return (status, output)

    def checkVersion(self, checkinfo, checknodes):
        """
        function: Check if the node have been upgraded, if gaussdb bin
                  file verison is same on all host, return 0, else retrun 1
        input : checkinfo, checknodes
        output: 0  successfully
                1  failed
        """
        self.context.logger.debug(
            "Start to check gaussdb version consistency.")
        if self.context.isSingle:
            self.context.logger.debug("There is single cluster,"
                                      " no need to check it.")
            return True

        try:
            # checking gaussdb bin file version VxxxRxxxCxx or commitid
            cmd = "source %s;%s -t %s -v %s -U %s -l %s" % \
                  (self.context.userProfile,
                   OMCommand.getLocalScript("Local_Check_Upgrade"),
                   const.ACTION_CHECK_VERSION,
                   checkinfo,
                   self.context.user,
                   self.context.localLog)
            self.context.logger.debug("Command for checking gaussdb version "
                                      "consistency: %s." % cmd)
            (status, output) = \
                self.context.sshTool.getSshStatusOutput(cmd, self.context.nodeNames)
            for node in status.keys():
                failFlag = "Failed to check version information"
                if status[node] != DefaultValue.SUCCESS or \
                        output.find(failFlag) >= 0:
                    raise Exception(ErrorCode.GAUSS_529["GAUSS_52929"] +
                                    "Error: \n%s" % str(output))
            # gaussdb bin file version is same on all host, return 0
            self.context.logger.debug("Successfully checked gaussdb"
                                      " version consistency.")
            return True
        except Exception as e:
            self.context.logger.debug(str(e))
            return False

    def _query_cluster_status(self):
        """
        Query cluster status
        """
        cmd = "source %s;gs_om -t query" % self.context.userProfile
        (status, output) = subprocess.getstatusoutput(cmd)
        if "Cascade Need repair" in output:
            self.context.logger.debug("Cascade node disconnect , "
                                      "check again after 5 seconds.\n{0}".format(output))
            time.sleep(5)
            (status, output) = subprocess.getstatusoutput(cmd)
            self.context.logger.debug("Retry query cluster status finish. "
                                      "Output:\n{0}".format(output))
        return cmd, status, output

    def checkClusterStatus(self, checkPosition=const.OPTION_PRECHECK,
                           doDetailCheck=False):
        """
        function: Check cluster status, if NORMAL, return 0, else return 1
                  For grey upgrade, if have switched to new bin, we will remove
                  abnormal nodes and then return 0, else return 1
        input : checkPosition, doDetailCheck
        output: 0  successfully
                1  failed
        """
        self.context.logger.debug("Start to check cluster status.")
        # build query cmd
        # according to the implementation of the results to determine whether
        # the implementation of success
        cmd, status, output = self._query_cluster_status()

        if status != 0:
            self.context.logger.debug(
                "Failed to execute command %s.\nStatus:%s\nOutput:%s" %
                (cmd, status, output))
            return 1
        self.context.logger.debug(
            "Successfully obtained cluster status information. "
            "Cluster status information:\n%s" % output)
        if output.find("Normal") < 0:
            self.context.logger.debug("The cluster_state is Abnormal.")
            if checkPosition == const.OPTION_POSTCHECK:
                if output.find("Degraded") < 0:
                    self.context.logger.debug("The cluster_state is not "
                                              "Degraded under postcheck.")
                    return 1
            else:
                return 1

        # do more check if required
        if doDetailCheck:
            cluster_state_check = False
            redistributing_check = False
            for line in output.split('\n'):
                if len(line.split(":")) != 2:
                    continue
                (key, value) = line.split(":")
                if key.strip() == "cluster_state" and \
                        value.strip() == "Normal":
                    cluster_state_check = True
                elif key.strip() == "redistributing" and value.strip() == "No":
                    redistributing_check = True
            if cluster_state_check and redistributing_check:
                self.context.logger.debug("Cluster_state must be Normal, "
                                          "redistributing must be No.")
                return 0
            else:
                self.context.logger.debug(
                    "Cluster status information does not meet the upgrade "
                    "condition constraints. When upgrading, cluster_state must"
                    " be Normal, redistributing must be No and balanced"
                    " must be Yes.")
                return 1

        # cluster is NORMAL, return 0
        return 0

    def waitClusterNormalDegrade(self, waitTimeOut=300):
        """
        function: Check if cluster status is Normal for each main step of
                  online upgrade
        input : waitTimeOut, default is 60.
        output : NA
        """
        # get the end time
        self.context.logger.log("Wait for the cluster status normal "
                                "or degrade.")
        endTime = datetime.now() + timedelta(seconds=int(waitTimeOut))
        while True:
            cmd = "source %s;gs_om -t status --detail" % \
                  self.context.userProfile
            (status, output) = subprocess.getstatusoutput(cmd)
            if status == 0 and (output.find("Normal") >= 0 or
                                output.find("Degraded") >= 0):
                self.context.logger.debug(
                    "The cluster status is normal or degrade now.")
                break

            if datetime.now() >= endTime:
                self.context.logger.debug("The cmd is %s " % cmd)
                raise Exception("Timeout." + "\n" +
                                ErrorCode.GAUSS_516["GAUSS_51602"])
            else:
                self.context.logger.debug(
                    "Cluster status has not reach normal. Wait for another 3"
                    " seconds.\n%s" % output)
                time.sleep(3)  # sleep 3 seconds

    def checkConnection(self):
        """
        function: Check if cluster accept connecitons,
                  upder inplace upgrade, all DB should be connected
                  under grey upgrade, makesure all CN in nodes that does not
                  under upgrade process or extracted abnormal nodes can be
                  connected if accpet connection, return 0, else return 1
                  1. find a cn instance
                  2. connect this cn and exec sql cmd
        input : NA
        output: 0  successfully
                1  failed
        """
        self.context.logger.debug("Start to check database connection.")
        mode = True if "dual-standby" in self.context.clusterType else False
        for dbNode in self.context.clusterInfo.dbNodes:
            if len(dbNode.datanodes) == 0 or dbNode.name:
                continue
            for dnInst in dbNode.datanodes:
                # connect this DB and exec sql cmd
                sql = "SELECT 1;"
                (status, output) = \
                    ClusterCommand.remoteSQLCommand(
                        sql, self.context.user, dnInst.hostname, dnInst.port,
                        False, DefaultValue.DEFAULT_DB_NAME,
                        IsInplaceUpgrade=True, maintenance_mode=mode)
                if status != 0 or not output.isdigit():
                    self.context.logger.debug(
                        "Failed to execute SQL on [%s]: %s. Error: \n%s" %
                        (dnInst.hostname, sql, str(output)))
                    return 1

        # all DB accept connection, return 0
        self.context.logger.debug("Successfully checked database connection.")
        return 0

    def createBakPath(self):
        """
        function: create bak path
        input  : NA
        output : NA
        """
        cmd = "(if [ ! -d '%s' ]; then mkdir -p '%s'; fi)" % \
              (self.context.upgradeBackupPath, self.context.upgradeBackupPath)
        cmd += " && (chmod %d -R %s)" % (DefaultValue.KEY_DIRECTORY_MODE,
                                         self.context.upgradeBackupPath)
        self.context.logger.debug("Command for creating directory: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)

    def recordDirFile(self):
        """
        function: record dir file
        input: NA
        output: NA
        """
        self.context.logger.debug("Create the file to record "
                                  "old and new app directory.")
        # write the old cluster number and new cluster number into backup dir
        appDirRecord = os.path.join(self.context.upgradeBackupPath,
                                    const.RECORD_UPGRADE_DIR)
        FileUtil.createFile(appDirRecord, True, DefaultValue.KEY_FILE_MODE)
        FileUtil.writeFile(appDirRecord, [self.context.oldClusterAppPath,
                                        self.context.newClusterAppPath], 'w')
        self.distributeFile(appDirRecord)
        self.context.logger.debug("Successfully created the file to "
                                  "record old and new app directory.")

    def copyBakVersion(self):
        """
        under commit, if we have cleaned old install path, then node disabled,
        we cannot get old version,
        under choseStrategy, we will not pass the check
        :return:NA
        """
        versionFile = os.path.join(self.context.oldClusterAppPath,
                                   "bin/upgrade_version")
        bakVersionFile = os.path.join(self.context.upgradeBackupPath,
                                      "old_upgrade_version")
        cmd = "(if [ -f '%s' ]; then cp -f -p '%s' '%s';fi)" % \
              (versionFile, versionFile, bakVersionFile)
        cmd += " && (chmod %d %s)" % \
               (DefaultValue.KEY_FILE_MODE, bakVersionFile)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)

    def cleanInstallPath(self, cleanNew=const.NEW):
        """
        function: after grey upgrade succeed, clean old install path
        input : cleanNew
        output: NA
        """
        self.context.logger.debug("Cleaning %s install path." % cleanNew,
                                  "addStep")
        # clean old install path
        if cleanNew == const.NEW:
            installPath = self.context.newClusterAppPath
        elif cleanNew == const.OLD:
            installPath = self.context.oldClusterAppPath
        else:
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52937"])

        cmd = "%s -t %s -U %s -R %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               const.ACTION_CLEAN_INSTALL_PATH,
               self.context.user,
               installPath,
               self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for clean %s install path: %s" %
                                  (cleanNew, cmd))
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.log("Successfully cleaned %s install path." %
                                cleanNew, "constant")

    def installNewBin(self):
        """
        function: install new binary in a new directory
                  1. get env GAUSSLOG
                  2. get env PGHOST
                  3. install new bin file
                  4. sync old config to new bin path
                  5. update env
        input: none
        output: none
        """
        try:
            self.context.logger.log("Installing new binary.", "addStep")

            # install new bin file
            cmd = "%s -t 'install_cluster' -U %s:%s -R '%s' -P %s -c %s" \
                  " -l '%s' -X '%s' -T -u" % \
                  (OMCommand.getLocalScript("Local_Install"),
                   self.context.user,
                   self.context.group,
                   self.context.newClusterAppPath,
                   self.context.tmpDir,
                   self.context.clusterInfo.name,
                   self.context.localLog,
                   self.context.xmlFile)
            self.context.logger.debug(
                "Command for installing new binary: %s." % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
            self.context.logger.debug(
                "Successfully installed new binary files.")
        except Exception as e:
            self.context.logger.debug("Failed to install new binary files.")
            raise Exception(str(e))

    def backupHotpatch(self):
        """
        function: backup hotpatch config file patch.info in xxx/data/hotpatch
        input : NA
        output: NA
        """
        self.context.logger.debug("Start to backup hotpatch.")
        try:
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s " \
                  "--new_cluster_app_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_BACKUP_HOTPATCH,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            raise Exception(" Failed to backup hotpatch config file." + str(e))
        self.context.logger.log("Successfully backup hotpatch config file.")

    def rollbackHotpatch(self):
        """
        function: backup hotpatch config file patch.info in xxx/data/hotpatch
        input : NA
        output: NA
        """
        self.context.logger.debug("Start to rollback hotpatch.")
        try:
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s -X '%s'" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_ROLLBACK_HOTPATCH,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog,
                   self.context.xmlFile)
            if self.context.forceRollback:
                cmd += " --force"
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
        except Exception as e:
            raise Exception(" Failed to rollback hotpatch config file."
                            + str(e))
        self.context.logger.log("Successfully rollback hotpatch config file.")

    def backup_version_file(self):
        """
        Backup the old version file.
        """
        oldVersionFile = "%s/bin/%s" % \
                         (self.context.oldClusterAppPath,
                          DefaultValue.DEFAULT_DISABLED_FEATURE_FILE_NAME)
        oldLicenseFile = "%s/bin/%s" % (self.context.oldClusterAppPath,
                                        DefaultValue.DEFAULT_LICENSE_FILE_NAME)

        cmd = "(if [ -d %s ] && [ -f %s ]; then cp -f %s %s; fi) && " % \
              (self.context.upgradeBackupPath, oldVersionFile, oldVersionFile,
               self.context.upgradeBackupPath)
        cmd += "(if [ -d %s ] && [ -f %s ]; then cp -f %s %s; fi)" % \
               (self.context.upgradeBackupPath, oldLicenseFile, oldLicenseFile,
                self.context.upgradeBackupPath)

        self.context.logger.debug(
            "Execute command to backup the product version file and the "
            "license control file: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)

    def getTimeFormat(self, seconds):
        """
        format secends to h-m-s
        input:int
        output:int
        """
        seconds = int(seconds)
        if seconds == 0:
            return 0
        # Converts the seconds to standard time
        hour = seconds / 3600
        minute = (seconds - hour * 3600) / 60
        s = seconds % 60
        resultstr = ""
        if hour != 0:
            resultstr += "%dh" % hour
        if minute != 0:
            resultstr += "%dm" % minute
        return "%s%ds" % (resultstr, s)

    def CopyCerts(self):
        """
        function: copy certs
        input  : NA
        output : NA
        """
        self.context.logger.log("copy certs from %s to %s." % (
            self.context.oldClusterAppPath, self.context.newClusterAppPath))
        try:
            cmd = "%s -t %s -U %s --old_cluster_app_path=%s " \
                  "--new_cluster_app_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_COPY_CERTS,
                   self.context.user,
                   self.context.oldClusterAppPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            self.context.logger.debug("Command for copy certs: '%s'." % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)

        except Exception as e:
            self.context.logger.log("Failed to copy certs from %s to %s." %
                                    (self.context.oldClusterAppPath,
                                     self.context.newClusterAppPath))
            raise Exception(str(e))
        time.sleep(10)
        self.context.logger.log("Successfully copy certs from %s to %s." %
                                (self.context.oldClusterAppPath,
                                 self.context.newClusterAppPath),
                                "constant")

    def clean_cm_instance(self):
        """
        Clean CM instance directory
        """
        self.context.logger.log("Start roll back CM instance.")
        cm_strategy = self.get_upgrade_cm_strategy()
        if cm_strategy == 1:
            self.context.logger.debug("Rollback need clean cm directory")
            cmd = "%s -t %s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_CLEAN_CM,
                   self.context.localLog)
            self.context.logger.debug("Roll back CM install command: {0}".format(cmd))
            self.context.sshTool.executeCommand(cmd, hostList=self.context.nodeNames)
            self.context.logger.debug("Clean cm directory successfully.")
        else:
            self.context.logger.debug("No need clean CM instance directory.")




    def switchBin(self, switchTo=const.OLD):
        """
        function: switch bin
        input  : switchTo
        output : NA
        """
        self.context.logger.log("Switch symbolic link to %s binary directory."
                                % switchTo, "addStep")
        try:
            cmd = "%s -t %s -U %s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_SWITCH_BIN,
                   self.context.user,
                   self.context.localLog)
            if switchTo == const.NEW:
                cmd += " -R '%s'" % self.context.newClusterAppPath
            else:
                cmd += " -R '%s'" % self.context.oldClusterAppPath
            if self.context.forceRollback:
                cmd += " --force"
            self.context.logger.debug("Command for switching binary directory:"
                                      " '%s'." % cmd)
            if self.context.is_grey_upgrade:
                CmdExecutor.execCommandWithMode(cmd,
                                                self.context.sshTool,
                                                self.context.isSingle,
                                                self.context.mpprcFile,
                                                self.context.nodeNames)
            else:
                CmdExecutor.execCommandWithMode(cmd,
                                                self.context.sshTool,
                                                self.context.isSingle,
                                                self.context.mpprcFile)

        except Exception as e:
            self.context.logger.log("Failed to switch symbolic link to %s "
                                    "binary directory." % switchTo)
            raise Exception(str(e))
        time.sleep(10)
        self.context.logger.log("Successfully switch symbolic link to %s "
                                "binary directory." % switchTo, "constant")

    def clearOtherToolPackage(self, action=""):
        """
        function: clear other tool package
        input  : action
        output : NA
        """
        if action == const.ACTION_AUTO_ROLLBACK:
            self.context.logger.debug("clean other tool package files.")
        else:
            self.context.logger.debug(
                "clean other tool package files.", "addStep")
        try:
            commonPart = PackageInfo.get_package_back_name().rsplit("_", 1)[0]
            gphomePath = \
                os.listdir(ClusterDir.getClusterToolPath(self.context.user))
            commitId = self.newCommitId
            if action == const.ACTION_AUTO_ROLLBACK:
                commitId = self.oldCommitId
            for filePath in gphomePath:
                if commonPart in filePath and commitId not in filePath:
                    toDeleteFilePath = os.path.join(
                        ClusterDir.getClusterToolPath(self.context.user),
                        filePath)
                    deleteCmd = "(if [ -f '%s' ]; then rm -rf '%s'; fi) " % \
                                  (toDeleteFilePath, toDeleteFilePath)
                    CmdExecutor.execCommandWithMode(
                        deleteCmd,
                        self.context.sshTool,
                        self.context.isSingle,
                        self.context.mpprcFile)
        except Exception as e:
            self.context.logger.log(
                "Failed to clean other tool package files.")
            raise Exception(str(e))
        if action == const.ACTION_AUTO_ROLLBACK:
            self.context.logger.debug(
                "Success to clean other tool package files.")
        else:
            self.context.logger.debug(
                "Success to clean other tool package files.", "constant")

    def createGphomePack(self):
        """
        function: create Gphome pack
        input  : NA
        output : NA
        """
        try:
            cmd = "(if [ ! -d '%s' ]; then mkdir -p '%s'; fi)" % \
                  (ClusterDir.getClusterToolPath(self.context.user),
                   ClusterDir.getClusterToolPath(self.context.user))
            cmd += " && (chmod %d -R %s)" % \
                   (DefaultValue.KEY_DIRECTORY_MODE,
                    ClusterDir.getClusterToolPath(self.context.user))
            self.context.logger.debug(
                "Command for creating directory: %s" % cmd)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.context.sshTool,
                                            self.context.isSingle,
                                            self.context.mpprcFile)
            oldPackName = "%s-Package-bak_%s.tar.gz" % \
                          (VersionInfo.PRODUCT_NAME_PACKAGE, self.oldCommitId)
            packFilePath = "%s/%s" % (ClusterDir.getClusterToolPath(
                self.context.user), oldPackName)
            copyNode = ""
            cmd = "if [ -f '%s' ]; then echo 'GetFile'; " \
                  "else echo 'NoThisFile'; fi" % packFilePath
            self.context.logger.debug("Command for checking file: %s" % cmd)
            (status, output) = self.context.sshTool.getSshStatusOutput(
                cmd, self.context.clusterNodes, self.context.mpprcFile)
            outputMap = self.context.sshTool.parseSshOutput(
                self.context.clusterNodes)
            self.context.logger.debug("Output: %s" % output)
            for node in self.context.clusterNodes:
                if status[node] == DefaultValue.SUCCESS:
                    if 'GetFile' in outputMap[node]:
                        copyNode = node
                        break
            if copyNode:
                self.context.logger.debug("Copy the file %s from node %s." %
                                          (packFilePath, copyNode))
                for node in self.context.clusterNodes:
                    if status[node] == DefaultValue.SUCCESS:
                        if 'NoThisFile' in outputMap[node]:
                            cmd = LocalRemoteCmd.getRemoteCopyCmd(
                                packFilePath,
                                ClusterDir.getClusterToolPath(
                                    self.context.user),
                                str(copyNode), False, 'directory', node)
                            self.context.logger.debug(
                                "Command for copying directory: %s" % cmd)
                            CmdExecutor.execCommandLocally(cmd)
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] %
                                packFilePath)
        except Exception as e:
            raise Exception(str(e))

    def getPrimaryDN(self, checkNormal):
        """
        find primary dn in centralized cluster, which we can execute SQL commands
        """
        try:
            self.context.logger.debug("start to get primary dn. \n"
                                      "checkNormal is {0}.".format(checkNormal))
            if self.context.standbyCluster or self.context.forceRollback:
                checkNormal = False
            primaryDn = None
            if not checkNormal:
                clusterNodes = self.context.oldClusterInfo.dbNodes
                for dbNode in clusterNodes:
                    if len(dbNode.datanodes) == 0:
                        continue
                    primaryDn = dbNode.datanodes[0]
                    break
                self.primaryDn = primaryDn
            else:
                primaryList, _ = DefaultValue.getPrimaryNode(self.context.userProfile, self.context.logger)
                if primaryList:
                    primaryDn = primaryList[0]
                if not primaryDn:
                    raise Exception(ErrorCode.GAUSS_526["GAUSS_52635"])
                for dbNode in self.context.clusterInfo.dbNodes:
                    for dn in dbNode.datanodes:
                        if dn.hostname == primaryDn:
                            self.primaryDn = dn
            self.context.logger.debug("Successfully get primary DN from "
                                      "{0}.".format(self.primaryDn.hostname))
        except Exception as er:
            self.context.logger.debug("Failed to get Primary dn. Error: %s" % str(er))
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] % "primary dn")

    def getPrimaryNode(self, instanceType):
        """

        :param instanceType:
        :return:
        """
        try:
            self.waitClusterNormalDegrade(waitTimeOut=120)
            self.context.logger.debug("Start to get primary node.")
            postSplit = ""
            primaryFlag = "Primary"
            count = 0
            cmd, status, output = "", 0, ""
            while count < 60:
                cmd = "source {0} && cm_ctl query -Cv".format(self.context.userProfile)
                (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 5)
                # no need to retry under force upgrade
                if status == 0:
                    break
                time.sleep(2)
                count += 1
            if status != 0:
                raise Exception(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % "%s. Error:\n%s" % (cmd, output))
            self.context.logger.debug("the result of query is {0}, "
                                      "instanceType is {1}.".format(output, instanceType))
            targetString = output.split(instanceType)[1]
            if instanceType == "Datanode":
                dnPrimary = [x for x in re.split(r"[|\n]", targetString) if primaryFlag in x
                             or "Main" in x]
                primaryList = []
                for dn in dnPrimary:
                    primaryList.append(list(filter(None, dn.split(" ")))[1])
                return primaryList
            if instanceType == "ETCD":
                postSplit = "Cluster"
                primaryFlag = "StateLeader"
            elif instanceType == "CMServer":
                postSplit = "ETCD"
            elif instanceType == "GTM":
                postSplit = "Datanode"
            elif instanceType == "Coordinator":
                return ""
            if postSplit not in targetString:
                return ""
            primaryInfo = [x for x in re.split(r"[|\n]", targetString.split(postSplit)[0]) if
                           primaryFlag in x]
            if primaryInfo == "" or primaryInfo == []:
                return ""
            primary = list(filter(None, primaryInfo[0].split(" ")))[1]
            self.context.logger.debug("get node {0}".format(primary))
            return primary
        except Exception as er:
            self.context.logger.debug("Failed to get primary node." + str(er))
            raise Exception(str(er))

    def isGucContainDesignatedVal(self, gucName, result):
        """
        The guc value contains the designated string.
        :return:
        """
        sql = "show {0};".format(gucName)
        self.getPrimaryDN(True)
        mode = "primary"
        is_disaster = DefaultValue.cm_exist_and_is_disaster_cluster(self.context.clusterInfo,
                                                                    self.context.logger)
        if is_disaster:
            mode = "standby"
        (_, output) = self.execSqlCommandInPrimaryDN(sql, mode=mode)
        if result in output:
            return True
        else:
            return False

    def execSqlCommandInPrimaryDN(self, sql, retryTime=3, execHost=None, mode="primary"):
        """
        execute sql on primary dn
        :return:
        """
        self.context.logger.debug("Start to exec sql {0}.".format(sql))
        count = 0
        status, output = 1, ""
        mode = True if "dual-standby" in self.context.clusterType or mode == "standby" else False
        while count < retryTime:
            if not execHost:
                self.getPrimaryDN(checkNormal=True)
                execHost = self.primaryDn
            self.context.logger.debug("Exec sql in dn node {0}".format(execHost.hostname))
            (status, output) = ClusterCommand.remoteSQLCommand(sql, self.context.user,
                                                               execHost.hostname, execHost.port,
                                                               False,
                                                               DefaultValue.DEFAULT_DB_NAME,
                                                               IsInplaceUpgrade=True,
                                                               maintenance_mode=mode)
            self.context.logger.debug("Exec sql result "
                                      "is, status:{0}, output is {1}"
                                      "".format(status, output).replace("ERROR", "Log"))
            if status != 0 or SqlResult.findErrorInSql(output):
                count += 1
                continue
            else:
                break
        return status, output

    def initClusterType(self):
        """
        If it is a dual cluster, initialize whether the current cluster
        is the primary cluster or the standby cluster

        :return:
        """
        streaming_cabin = os.path.realpath(os.path.join(EnvUtil.getTmpDirFromEnv(), "streaming_cabin"))
        # The value of replconninfo1 must contain 'iscascade' in the DR cluster.
        isStrDRCluster = self.isGucContainDesignatedVal("replconninfo1", "iscascade")
        if isStrDRCluster and os.path.isdir(streaming_cabin):
            suffix = "-streamDR"
        else:
            self.context.logger.debug("Current cluster is not dual cluster.")
            return

        if self.context.is_inplace_upgrade and self.context.action \
                not in ["commit-upgrade", "auto-rollback", "chose-strategy"]:
            raise Exception("Dual cluster does not support in-place upgrade")

        if self.checkGucValIsInValGiven(const.DISASTER_RECOVERY_GUC, ["2"], fromFile=True):
            self.context.standbyCluster = True
            self.context.clusterType = "dual-standby" + suffix

        elif self.checkGucValIsInValGiven(const.DISASTER_RECOVERY_GUC, ["0"], fromFile=True):
            self.context.clusterType = "dual-primary" + suffix

        self.context.logger.log("NOTICE: the clusterType is {0}".format(self.context.clusterType))

        if not self.context.is_inplace_upgrade:
            self.backup_disaster_user_file()

        if self.context.forceRollback:
            return
        self.copyStandbyClusterUpgradeFile()

        upgradeInfoTmp = self.context.getDualUpgradeInfo(self.context.upgradePhaseInfoPath, 0)
        if upgradeInfoTmp is not None:
            if "dual-standby" in self.context.clusterType:
                self.context.dualUpgradeShareInfo.masterVersion = upgradeInfoTmp.masterVersion
                self.context.dualUpgradeShareInfo.masterUpgradeStatus = \
                    upgradeInfoTmp.masterUpgradeStatus
            else:
                self.context.dualUpgradeShareInfo.standbyVersion = upgradeInfoTmp.standbyVersion
                self.context.dualUpgradeShareInfo.standbyUpgradeStatus = \
                    upgradeInfoTmp.standbyUpgradeStatus

        self.context.updateDualUpgradeInfo(self.context.dualUpgradeShareInfo,
                                           filePath=self.context.upgradePhaseInfoPath,
                                           startPost=0)

    def checkGucValIsInValGiven(self, gucName, valList, fromFile=False):
        """
        Checks whether a given parameter is a given value list in a given instance list.
        """
        self.context.logger.debug("checks whether the parameter:{0} is "
                                  "the value:{1}.".format(gucName, valList))
        gucStr = "{0}:{1}".format(gucName, ",".join(valList))
        try:
            self.checkParam(gucStr, fromFile)
            self.context.logger.debug("Success to check the parameter:{0} value is "
                                      "in the value:{1}.".format(gucName, valList))
            return True
        except Exception as _:
            return False

    def copyStandbyClusterUpgradeFile(self):
        """
        From the data directory of the standby cluster, copy the upgrade_phase_info file
        to the designated instance directory of the primary cluster, and distribute it
        to the upgrade backup directory of all nodes
        """
        hardUser, hardUserPwd = self.getDisasterRecoveryUser()
        if hardUser is None or hardUser == "" or hardUserPwd is None or hardUserPwd == "":
            raise Exception("Failed to obtain the streaming disaster build user")
        dnInstance = None
        for x in range(1, 9):
            localRemoteInfo = self.getLocalRemoteHostIpAndPort("{0}{1}".format(
                const.REMOTE_INFO_GUC[self.context.clusterType], x))
            for dbNode in self.context.clusterInfo.dbNodes:
                for dnInst in dbNode.datanodes:
                    self.context.logger.debug("The instance is {0}".format(dnInst.__dict__))
                    if "-streamDR" in self.context.clusterType:
                        dataIp = DefaultValue.get_data_ip_info(dnInst, self.context.logger)
                        if localRemoteInfo.get("localhost") in dataIp and \
                                localRemoteInfo.get("localport") == str(dnInst.haPort).strip():
                            dnInstance = copy.deepcopy(dnInst)
                            break
            if dnInstance is not None:
                try:
                    self.copyAndDistributeUpgradeFile(dnInstance, localRemoteInfo)
                except Exception as err:
                    self.context.logger.error("Cope file failed msg:%s." % err)
                    dnInstance = None
                    continue
                break
        if dnInstance is None:
            raise Exception("Unable to find a DN to connect to the standby cluster node")

    def checkDualClusterUpgrade(self):
        """
         Double cluster check whether it can be upgrade

        :return:
        """
        if "dual-standby-streamDR" not in self.context.clusterType or \
                self.context.action == const.ACTION_SMALL_UPGRADE:
            return
        self.context.logger.debug("The status of the dual-cluster standby status is {0}, version "
                                  "is {1}. The status of the dual-cluster master status is {2}, "
                                  "version is {3}".format(
                                  self.context.dualUpgradeShareInfo.standbyUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.standbyVersion,
                                  self.context.dualUpgradeShareInfo.masterUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.masterVersion))

        if self.context.dualUpgradeShareInfo.masterUpgradeStatus < 2 or \
                self.context.dualUpgradeShareInfo.masterVersion != self.newCommitId:
            raise Exception("The status of the dual-cluster master is {0}. "
                            "the standby cluster cannot be upgrade."
                            .format(self.context.dualUpgradeShareInfo.masterUpgradeStatus))

    def recordDualClusterStage(self, commitVersion, upgradeStage):
        """
        Record the upgrade information of the dual cluster

        :param commitVersion:
        :param upgradeStage:
        :return:
        """
        if "dual-primary" in self.context.clusterType:
            self.context.dualUpgradeShareInfo.masterVersion = commitVersion
            self.context.dualUpgradeShareInfo.masterUpgradeStatus = upgradeStage
        elif "dual-standby" in self.context.clusterType:
            self.context.dualUpgradeShareInfo.standbyVersion = commitVersion
            self.context.dualUpgradeShareInfo.standbyUpgradeStatus = upgradeStage
        else:
            return
        self.context.updateDualUpgradeInfo(self.context.dualUpgradeShareInfo,
                                           filePath=self.context.upgradePhaseInfoPath, startPost=0)

    def checkDualClusterRollback(self):
        """
         Double cluster check whether it can be rollback

        :return:
        """
        if "dual-standby" in self.context.clusterType or \
                "dual-" not in self.context.clusterType:
            return
        self.context.logger.debug("The status of the dual-cluster standby status is {0}, version "
                                  "is {1}. The status of the dual-cluster master status is {2}, "
                                  "version is {3}".format(
                                  self.context.dualUpgradeShareInfo.standbyUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.standbyVersion,
                                  self.context.dualUpgradeShareInfo.masterUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.masterVersion))
        if not self.context.rollback or \
                "dual-primary" in self.context.clusterType or \
                self.context.action == const.ACTION_SMALL_UPGRADE or self.context.forceRollback:
            return
        # master cluster
        if "dual-primary" in self.context.clusterType:
            if (self.context.dualUpgradeShareInfo.standbyUpgradeStatus > 2 or
                    self.context.dualUpgradeShareInfo.standbyUpgradeStatus == 0) and \
                    self.context.dualUpgradeShareInfo.standbyVersion == self.newCommitId:
                raise Exception("The status of the dual-cluster standby is {0}. "
                                "the master cluster cannot be rolled back."
                                .format(self.context.dualUpgradeShareInfo.standbyUpgradeStatus))

    def checkDualClusterCommit(self):
        """
        Double cluster check whether it can be submitted

        :return:
        """
        if "dual-" not in self.context.clusterType:
            return
        if self.context.action == const.ACTION_SMALL_UPGRADE:
            return
        self.context.logger.debug("The status of the dual-cluster standby status is {0}, version "
                                  "is {1}. The status of the dual-cluster master status is {2}, "
                                  "version is {3}".format(
                                  self.context.dualUpgradeShareInfo.standbyUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.standbyVersion,
                                  self.context.dualUpgradeShareInfo.masterUpgradeStatus,
                                  self.context.dualUpgradeShareInfo.masterVersion))
        # master cluster
        if "dual-primary" in self.context.clusterType:
            if self.context.dualUpgradeShareInfo.standbyUpgradeStatus != 0 or \
                    self.context.dualUpgradeShareInfo.standbyVersion != self.newCommitId:
                raise Exception("The status of the dual-cluster standby status is {0}, "
                                "version is {1}. the master cluster cannot be commit."
                                .format(self.context.dualUpgradeShareInfo.standbyUpgradeStatus,
                                        self.context.dualUpgradeShareInfo.standbyVersion))
        if "dual-standby" in self.context.clusterType:
            if self.context.dualUpgradeShareInfo.masterUpgradeStatus != 2 or \
                    self.context.dualUpgradeShareInfo.masterVersion != self.newCommitId:
                raise Exception("The status of the dual-cluster master status is {0}, "
                                "version is {1}. The standby cluster cannot be commit."
                                .format(self.context.dualUpgradeShareInfo.masterUpgradeStatus,
                                        self.context.dualUpgradeShareInfo.masterVersion))

    def copyDirFromRemoteNode(self, remoteHost, remoteDir, targetHost, targetDir):
        """
        SSH to the remote node, copy dir from the remote node to the specified node

        :param remoteHost:
        :param remoteDir:
        :param targetHost:
        :param targetDir:
        :return:
        """
        scpcmd = "pssh -s -H {0} 'source {5}; if [ -d '{1}' ];" \
                 "then  pscp -r -H {2} {3} {4}; fi' ".format(remoteHost, remoteDir, targetHost,
                                                             remoteDir, targetDir,
                                                             self.context.userProfile)
        (status, output) = CmdUtil.retryGetstatusoutput(scpcmd, 2, 5)
        if status != 0:
            raise Exception("File copy failed. Output: {0}".format(output))

    def getLocalRemoteHostIpAndPort(self, gucName):
        """
        Get the DN instance and the corresponding standby cluster host and port through the
        cross_cluster_replconninfo parameter
        :param gucName: cross_cluster_replconninfo parameter name
        :return: {"localhost":"", "localport":"", "remotehost":"", "remoteport":""}
        """
        isLocal = False
        localRemoteInfo = dict()
        sql = "show {0};".format(gucName)
        self.getPrimaryDN(False)
        (status, output) = self.execSqlCommandInPrimaryDN(sql)
        if status != 0 or output == "":
            raise Exception("Failed to get GUC parameter: {0} value. Output: {1}".format(gucName,
                                                                                         output))
        localIp = output.split("localhost=")[1].split("localport=")[0].strip()
        remoteIp = output.split("remotehost=")[1].split("remoteport=")[0].strip()

        self.context.logger.debug("Success get the output {0}".format(output))

        if "-streamDR" in self.context.clusterType:
            localPort = output.split("localport=")[1].split("localheartbeatport=")[0].strip()
            remotePort = output.split("remoteport=")[1].split("remoteheartbeatport=")[0].strip()

        for dbNode in self.context.clusterInfo.dbNodes:
            if isLocal:
                break
            for dnInst in dbNode.datanodes:
                if remoteIp in dnInst.listenIps or remoteIp in dnInst.hostname:
                    isLocal = True
                    break
        self.context.logger.debug("The local flag is  {0}".format(isLocal))

        if isLocal:
            localRemoteInfo.setdefault("localhost", "no find remote host")
        else:
            localRemoteInfo.setdefault("localhost", localIp)

        localRemoteInfo.setdefault("localport", localPort)
        localRemoteInfo.setdefault("remotehost", remoteIp)
        localRemoteInfo.setdefault("remoteport", remotePort)
        return localRemoteInfo

    def copyAndDistributeUpgradeFile(self, dnInstance, localRemoteInfo):
        """
        copy upgrade file
        :return:
        """
        hardUser, hardUserPwd = self.getDisasterRecoveryUser()
        cmd_remote = 'pssh -s -H {0} \'source {8}; gs_ctl build -D {1} -b copy_upgrade_file ' \
                     '-Z datanode -U {2} -P "{3}" -C "localhost={4} localport={5} remotehost={6} ' \
                     'remoteport={7}"\''.format(dnInstance.hostname,
                                                dnInstance.datadir,
                                                hardUser,
                                                hardUserPwd,
                                                localRemoteInfo.get("localhost"),
                                                localRemoteInfo.get("localport"),
                                                localRemoteInfo.get("remotehost"),
                                                localRemoteInfo.get("remoteport"),
                                                self.context.userProfile)

        cmd_remote = cmd_remote.replace(" -Z datanode", "")

        self.context.logger.debug("Copy upgrade file with cmd: {0}.".
                                  format(cmd_remote.replace(hardUserPwd, "***")))
        status, output = DefaultValue.getstatusoutput_hide_pass(cmd_remote)
        if status == 0:
            self.context.logger.debug("Successfully copy upgrade file")
        else:
            raise Exception("Failed to copy files from the standby cluster. "
                            "Ensure that the standby cluster version supports this function. "
                            "Output: {0}".format(output))

        remoteUpgradeInfoPath = os.path.join(dnInstance.datadir, const.UPGRADE_PHASE_INFO)
        self.copyFileFromRemoteNode(dnInstance.hostname, remoteUpgradeInfoPath,
                                    NetUtil.GetHostIpOrName(),
                                    self.context.upgradePhaseInfoPath)
        if not os.path.exists(self.context.upgradePhaseInfoPath):
            FileUtil.createFile(self.context.upgradePhaseInfoPath,
                                mode=DefaultValue.KEY_FILE_MODE)
            self.context.updateDualUpgradeInfo(self.context.dualUpgradeShareInfo,
                                               filePath=self.context.upgradePhaseInfoPath,
                                               startPost=0)

        self.context.sshTool.scpFiles(self.context.upgradePhaseInfoPath,
                                      self.context.tmpDir,
                                      hostList=self.context.clusterNodes)

    def getDisasterRecoveryUser(self):
        """
        Obtain special users of the streaming disaster recovery cluster for building
        :return: user name
        """
        mode = True if "dual-standby" in self.context.clusterType else False
        user_str = DefaultValue.obtain_hadr_user_encrypt_str(
            self.context.clusterInfo, self.context.user, self.context.logger, mode)
        rand_pwd = DefaultValue.decrypt_hadr_rand_pwd(self.context.logger)
        params = rand_pwd, user_str, self.context.clusterInfo, self.context.user, \
                 self.context.logger, mode
        hardUser, hardUserPwd = DefaultValue.decrypt_hadr_user_info(params)
        return hardUser, hardUserPwd

    def copyFileFromRemoteNode(self, remoteHost, remoteFile, targetHost, targetFile):
        """
        SSH to the remote node, copy files from the remote node to the specified node

        :param remoteHost:
        :param remoteFile:
        :param targetHost:
        :param targetFile:
        :return:
        """
        scpcmd = "pssh -s -H {0} 'source {5}; if [ -f '{1}' ];" \
                 "then pscp -H {2} {3} {4}; fi' ".format(remoteHost, remoteFile, targetHost,
                                                          remoteFile, targetFile,
                                                          self.context.userProfile)
        (status, output) = CmdUtil.retryGetstatusoutput(scpcmd, 2, 5)
        if status != 0:
            raise Exception("File copy failed. Output: {0}".format(output))

    def clean_gs_secure_files(self):
        """
        delete gs_secure_files during rollback or commit
        """
        try:
            self.context.logger.debug(
                "Starting to clean gs_secure_files folder in the dn data catalog.")
            cmd = "%s -t %s -U %s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   const.ACTION_CLEAN_GS_SECURE_FILES,
                   self.context.user,
                   self.context.localLog)
            self.context.logger.debug("clean gs_secure_files folder:{0}".format(cmd))
            host_list = copy.deepcopy(self.context.clusterNodes)
            self.context.execCommandInSpecialNode(cmd, host_list)
        except Exception as er:
            raise Exception(str(er))
        self.context.logger.debug(
            "Successfully to clean gs_secure_files folder in the dn data catalog.")
