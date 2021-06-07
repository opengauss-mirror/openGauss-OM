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
import re
import csv
import traceback
import copy
import random

from datetime import datetime, timedelta
from gspylib.common.Common import DefaultValue, ClusterCommand, \
    ClusterInstanceConfig
from gspylib.common.DbClusterInfo import instanceInfo, \
    dbNodeInfo, dbClusterInfo, compareObject
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.SshTool import SshTool
from gspylib.common.VersionInfo import VersionInfo
from gspylib.common.DbClusterStatus import DbClusterStatus
from gspylib.os.gsplatform import g_Platform
from gspylib.os.gsfile import g_file
from gspylib.os.gsOSlib import g_OSlib
from gspylib.inspection.common import SharedFuncs
from impl.upgrade.UpgradeConst import GreyUpgradeStep
import impl.upgrade.UpgradeConst as Const


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
        self.context = upgrade
        self.newCommitId = ""
        self.oldCommitId = ""
        self.isLargeInplaceUpgrade = False
        self.__upgrade_across_64bit_xid = False
        self.action = upgrade.action

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
            if action == Const.ACTION_AUTO_ROLLBACK:
                retCode = 3
            else:
                retCode = 1
        elif action in [Const.ACTION_SMALL_UPGRADE,
                        Const.ACTION_LARGE_UPGRADE,
                        Const.ACTION_INPLACE_UPGRADE]:
            retCode = 0
        elif action == Const.ACTION_AUTO_ROLLBACK:
            retCode = 2
        elif action == Const.ACTION_CHOSE_STRATEGY:
            retCode = 4
        elif action == Const.ACTION_COMMIT_UPGRADE:
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
        self.initClusterConfig()
        self.context.logger.debug("Successfully init global infos", "constant")

    def setClusterDetailInfo(self):
        """
        function: set cluster detail info
        input  : NA
        output : NA
        """
        for dbNode in self.context.clusterInfo.dbNodes:
            dbNode.setDnDetailNum()
        #self.context.clusterInfo.setClusterDnCount()

    def checkExistsProcess(self, greyNodeNames):
        """
        function: check exists process
        input  : greyNodeNames
        output : NA
        """
        pass

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
        DefaultValue.execCommandWithMode(cmd,
                                         "remove om rollback "
                                         "record progress file",
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
        self.context.tmpDir = DefaultValue.getTmpDirFromEnv(self.context.user)
        if self.context.tmpDir == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
        self.context.upgradeBackupPath = \
            "%s/%s" % (self.context.tmpDir, "binary_upgrade")
        try:
            self.initGlobalInfos()
            self.removeOmRollbackProgressFile()
            self.commonCheck()

            # 4. get upgrade type
            # After choseStrategy, it will assign action to self.context.action
            # to do full-upgrade or binary-upgrade
            if self.context.action == Const.ACTION_AUTO_UPGRADE:
                self.context.action = self.choseStrategy()
                self.context.logger.debug(
                    "%s execution takes %s steps in total" % (
                        Const.GS_UPGRADECTL, ClusterCommand.countTotalSteps(
                            Const.GS_UPGRADECTL, self.context.action)))
                # If get upgrade strategy failed,
                # then try to get rollback strategy.
                # Set strategyFlag as True to check
                # upgrade parameter is correct or not
                if self.context.action in [Const.ACTION_LARGE_UPGRADE,
                                           Const.ACTION_SMALL_UPGRADE]:
                    self.doGreyBinaryUpgrade()
                else:
                    self.doInplaceBinaryUpgrade()
            # After choseStrategy, it will assign action to self.context.action
            elif self.context.action == Const.ACTION_AUTO_ROLLBACK:
                # because if we rollback with auto rollback,
                # we will rollback all the nodes,
                # but if we rollback under upgrade,
                # we will only rollback specified nodes
                self.context.action = self.choseStrategy()
                self.context.rollback = True
                if self.context.action == Const.ACTION_INPLACE_UPGRADE:
                    self.exitWithRetCode(Const.ACTION_AUTO_ROLLBACK,
                                         self.doInplaceBinaryRollback())
                else:
                    self.exitWithRetCode(Const.ACTION_AUTO_ROLLBACK,
                                         self.doGreyBinaryRollback(
                                             Const.ACTION_AUTO_ROLLBACK))
            elif self.context.action == Const.ACTION_COMMIT_UPGRADE:
                self.context.action = self.choseStrategy()
                if self.context.action == Const.ACTION_INPLACE_UPGRADE:
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
            if action == Const.ACTION_AUTO_ROLLBACK and \
                    self.checkBakPathNotExists():
                self.context.logger.log("No need to rollback.")
                self.exitWithRetCode(action, True)
            else:
                self.context.logger.error(str(e))
                self.exitWithRetCode(action, False, str(e))

    def commonCheck(self):
        """
        Check in the common process.
        :return:
        """
        self.checkReadOnly()
        if self.context.is_grey_upgrade:
            self.checkUpgradeMode()

    def checkReadOnly(self):
        """
        check if in read only mode under grey upgrade, grey upgrade commit or
         grey upgrade rollback if not in read only, then record the value of
          enable_transaction_read_only and set it to off
        """
        try:
            self.context.logger.debug("Check if in read only mode.")
            greyUpgradeFlagFile = os.path.join(self.context.upgradeBackupPath,
                                               Const.GREY_UPGRADE_STEP_FILE)
            # only used under grey upgrade, grey upgrade commit or grey upgrade
            #  rollback if under grey upgrade, the flag file
            # greyUpgradeFlagFile has not been created
            # so we use is_inplace_upgrade to judge the mode
            if (self.context.action == Const.ACTION_AUTO_UPGRADE and
                    not self.context.is_inplace_upgrade or
                    (os.path.isfile(greyUpgradeFlagFile) and
                     self.context.action in [Const.ACTION_AUTO_ROLLBACK,
                                             Const.ACTION_COMMIT_UPGRADE])):
                if self.unSetClusterReadOnlyMode() != 0:
                    raise Exception("NOTICE: "
                                    + ErrorCode.GAUSS_529["GAUSS_52907"])
        except Exception as e:
            raise Exception(str(e))

    def checkUpgradeMode(self):
        """
        used to check if upgrade_mode is 0 under before upgrade
        if not, we set it to 0
        """
        tempPath = self.context.upgradeBackupPath
        filePath = os.path.join(tempPath, Const.INPLACE_UPGRADE_STEP_FILE)
        if self.context.action == Const.ACTION_AUTO_UPGRADE \
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
            if self.context.action in [Const.ACTION_SMALL_UPGRADE,
                                       Const.ACTION_LARGE_UPGRADE]:
                self.exitWithRetCode(Const.ACTION_CHOSE_STRATEGY,
                                     True,
                                     "Upgrade strategy: %s."
                                     % self.context.action)
            # Use inplace upgrade under special case
            else:
                self.exitWithRetCode(Const.ACTION_CHOSE_STRATEGY,
                                     True,
                                     "Upgrade strategy: %s."
                                     % self.context.action)
        except Exception as e:
            self.exitWithRetCode(Const.ACTION_CHOSE_STRATEGY, False, str(e))
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
            gaussHome = DefaultValue.getInstallDir(self.context.user)
            if gaussHome == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"]
                                % "$GAUSSHOME")
            if not os.path.islink(gaussHome):
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52915"])
            newPath = gaussHome + "_%s" % newCommitId
            # new app dir should exist after preinstall,
            # then we can use chose strategy
            if not os.path.exists(newPath):
                if self.context.action != Const.ACTION_AUTO_ROLLBACK:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                                    % newPath)
            self.context.logger.debug(
                "Successfully obtained version information"
                " of new clusters by %s." % newVersionFile)

            # get the old cluster info, if binary_upgrade does not exists,
            # try to copy from other nodes
            oldPath = self.getClusterAppPath(Const.OLD)
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
                    upgradeAction = Const.ACTION_INPLACE_UPGRADE
                else:
                    upgradeAction = Const.ACTION_SMALL_UPGRADE
            else:
                if int(float(newClusterNumber)) > int(float(oldClusterNumber)):
                    raise Exception(ErrorCode.GAUSS_529["GAUSS_52904"]
                                    + "This cluster version is "
                                      "not supported upgrade.")
                elif ((float(newClusterNumber) - int(float(newClusterNumber)))
                      > (float(oldClusterNumber) -
                         int(float(oldClusterNumber)))):
                    if self.context.is_inplace_upgrade:
                        upgradeAction = Const.ACTION_INPLACE_UPGRADE
                        self.isLargeInplaceUpgrade = True
                    else:
                        upgradeAction = Const.ACTION_LARGE_UPGRADE
                else:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51629"]
                                    % newClusterNumber)
            self.context.logger.debug("The matched upgrade strategy is: %s."
                                      % upgradeAction)
            self.context.newClusterVersion = newClusterVersion
            self.context.newClusterNumber = newClusterNumber
            self.context.oldClusterVersion = oldClusterVersion
            self.context.oldClusterNumber = oldClusterNumber
            self.context.newClusterAppPath = newPath
            self.context.oldClusterAppPath = oldPath
            self.newCommitId = newCommitId
            self.oldCommitId = oldCommitId
            return upgradeAction
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52900"] % str(e)
                            + " Do nothing this time.")

    def canDoRollbackOrCommit(self):
        """
        Check whether rollback or commit is required.
        :return:
        """
        try:
            if self.context.action == Const.ACTION_AUTO_ROLLBACK or \
                    self.context.action == Const.ACTION_COMMIT_UPGRADE:
                inplaceUpgradeFlagFile = os.path.join(
                    self.context.upgradeBackupPath,
                    Const.INPLACE_UPGRADE_FLAG_FILE)
                grayUpgradeFlagFile = os.path.join(
                    self.context.upgradeBackupPath,
                    Const.GREY_UPGRADE_STEP_FILE)
                self.context.is_inplace_upgrade = False
                # we do rollback by the backup directory
                if os.path.isfile(inplaceUpgradeFlagFile):
                    self.context.logger.debug("inplace upgrade flag exists, "
                                              "use inplace rollback or commit.")
                    self.context.is_inplace_upgrade = True
                if os.path.isfile(grayUpgradeFlagFile):
                    self.context.logger.debug("grey upgrade flag exists, "
                                              "use grey rollback or commit.")
                    self.context.isGreyUpgrade = True
                if not (self.context.is_inplace_upgrade or
                        self.context.isGreyUpgrade):
                    if self.context.action == Const.ACTION_AUTO_ROLLBACK \
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
        if self.context.action == Const.ACTION_AUTO_UPGRADE:
            stepFile = os.path.join(self.context.upgradeBackupPath,
                                    Const.GREY_UPGRADE_STEP_FILE)
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
                            % Const.GREY_UPGRADE_STEP_FILE \
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
        elif self.context.action == Const.ACTION_AUTO_ROLLBACK or \
                self.context.action == Const.ACTION_COMMIT_UPGRADE:
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
        if not self.existTable(Const.RECORD_NODE_STEP):
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
        newPath = self.getClusterAppPath(Const.NEW)
        if newPath != "":
            LastNewCommitId = newPath[-8:]
            # When repeatedly run gs_upgradectl script,
            # this time upgrade version should be same
            # with last record upgrade version
            if newCommitId != LastNewCommitId:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52935"])

    def checkOldClusterVersion(self, gaussdbPath, oldClusterVersionFile):
        """
        check old cluster version
        input : gaussdbPath, oldClusterVersionFile
        output:
            1. (0,"V100R00XCXX")
            2. (999,"NAC00Version")
            3. (1, errorMsg)
        otherwise raise exception
        """
        if os.path.isfile(oldClusterVersionFile):
            cmd = "cat %s" % oldClusterVersionFile
        else:
            gaussdbFile = "%s/gaussdb" % gaussdbPath
            if not os.path.exists(gaussdbFile):
                self.context.logger.debug("The %s does not exist."
                                          " Cannot obtain old cluster"
                                          " version." % gaussdbFile)
                return 1, " The %s does not exist. Cannot " \
                          "obtain old cluster version" % gaussdbFile
            if not os.path.isfile(gaussdbFile):
                self.context.logger.debug("The %s is not a file. "
                                          "Cannot obtain old cluster"
                                          " version." % gaussdbFile)
                return 1, " The %s is not a file. Cannot " \
                          "obtain old cluster version" % gaussdbFile
            # get old cluster version by gaussdb
            # the information of gaussdb like this:
            #    gaussdb Gauss200 V100R00XCXX build xxxx
            #    compiled at xxxx-xx-xx xx:xx:xx
            cmd = "export LD_LIBRARY_PATH=%s/lib:$LD_LIBRARY_PATH;%s " \
                  "--version" % (os.path.dirname(gaussdbPath), gaussdbFile)

        self.context.logger.debug("Command for getting old"
                                  " cluster version:%s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0 and re.compile(r'V[0-9]{3}R[0-9]{3}C[0-9]{2}'
                                      ).search(str(output)) is not None:
            return 0, re.compile(
                r'V[0-9]{3}R[0-9]{3}C[0-9]{2}').search(str(output)).group()
        else:
            self.context.logger.debug("Failed to obtain old cluster"
                                      " version. Error: \n%s" % str(output))
            return 999, "NAC00Version"

    def setGUCValue(self, gucKey, gucValue, actionType="reload"):
        """
        function: do gs_guc
        input : gucKey - parameter name
                gucValue - parameter value
                actionType - guc action type(set/reload). default is 'reload'
        """
        userProfile = DefaultValue.getMpprcFile()
        if gucValue != "":
            gucStr = "%s='%s'" % (gucKey, gucValue)
        else:
            gucStr = "%s" % gucKey

        cmd = "source %s ;" % userProfile
        cmd += "gs_guc %s -N all -I all -c \"%s\"" % (actionType, gucStr)
        self.context.logger.debug("Command for setting "
                                  "GUC parameter %s: %s" % (gucKey, cmd))
        (status, output) = DefaultValue.retryGetstatusoutput(cmd)
        return status, output

    def setClusterReadOnlyMode(self):
        """
        function: set cluster read only mode
        input  : NA
        output : int
        """
        self.context.logger.debug("Setting up the cluster read-only mode.")
        (status, output) = self.setGUCValue("default_transaction_read_only",
                                            "true")
        if status == 0:
            self.context.logger.debug("successfully set the "
                                      "cluster read-only mode.")
            return 0
        else:
            self.context.logger.debug(
                "Failed to set default_transaction_read_only parameter."
                + " Error: \n%s" % str(output))
            return 1

    def unSetClusterReadOnlyMode(self):
        """
        function: Canceling the cluster read-only mode
        input : NA
        output: 0  successfully
                1  failed
        """
        self.context.logger.debug("Canceling the cluster read-only mode.")
        # un set cluster read only mode
        (status, output) = self.setGUCValue("default_transaction_read_only",
                                            "false")
        if status == 0:
            self.context.logger.debug("Successfully cancelled the"
                                      " cluster read-only mode.")
            return 0
        else:
            self.context.logger.debug(
                "Failed to set default_transaction_read_only parameter."
                + " Error: \n%s" % str(output))
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
            Const.UPGRADE_TIMEOUT_CLUSTER_STOP)
        self.context.logger.debug("Command for stop cluster: %s" % cmd)
        DefaultValue.execCommandWithMode(
            cmd, "Stop cluster", self.context.sshTool,
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
                Const.UPGRADE_TIMEOUT_CLUSTER_START, number)
        else:
            cmd = "%s -U %s -R %s -t %s" % (
                OMCommand.getLocalScript("Local_StartInstance"),
                self.context.user, self.context.clusterInfo.appPath,
                Const.UPGRADE_TIMEOUT_CLUSTER_START)
        DefaultValue.execCommandWithMode(
            cmd, "Start cluster", self.context.sshTool,
            self.context.isSingle or self.context.localMode,
            self.context.mpprcFile)
        self.context.logger.log("Successfully started cluster.")

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
            DefaultValue.execCommandWithMode(cmd,
                                             "create commit flag file",
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
            g_file.createFile(inplace_upgrade_flag_file)
            g_file.writeFile(inplace_upgrade_flag_file,
                             ["newClusterNumber:%s" % newClusterNumber], 'a')
            g_file.writeFile(inplace_upgrade_flag_file,
                             ["oldClusterNumber:%s" % oldClusterNumber], 'a')
            if (not self.context.isSingle):
                self.context.sshTool.scpFiles(inplace_upgrade_flag_file,
                                              self.context.upgradeBackupPath)
            if float(self.context.oldClusterNumber) <= float(
                    Const.UPGRADE_VERSION_64bit_xid) < \
                    float(self.context.newClusterNumber):
                self.__upgrade_across_64bit_xid = True

            self.context.logger.debug("Successfully created inplace"
                                      " upgrade flag file.")
        except Exception as e:
            raise Exception(str(e))

    def setUpgradeMode(self, mode):
        """
        function: set upgrade_mode parameter
        Input : mode
        output : NA
        """
        try:
            self.setUpgradeModeGuc(mode)
        except Exception as e:
            if self.context.action == Const.ACTION_INPLACE_UPGRADE or \
                    not self.context.forceRollback:
                raise Exception(str(e))
            try:
                self.setUpgradeModeGuc(mode, "set")
            except Exception as e:
                self.context.logger.log("Failed to set upgrade_mode,"
                                        " please set it manually.")

    def setUpgradeModeGuc(self, mode, setType="reload"):
        """
        function: set upgrade mode guc
        input  : mode, setType
        output : NA
        """
        self.context.logger.debug("Set upgrade_mode guc parameter.")
        cmd = "gs_guc %s -I all -c 'upgrade_mode=%d'" % (
            setType, mode)
        self.context.logger.debug("Command for setting database"
                                  " node parameter: %s." % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.context.logger.debug("Set upgrade_mode parameter "
                                      "failed. cmd:%s\nOutput:%s"
                                      % (cmd, str(output)))
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                            + "Error: \n%s" % str(output))
        gucStr = "upgrade_mode:%d" % mode
        self.checkParam(gucStr)
        self.context.logger.debug("Successfully set "
                                  "upgrade_mode to %d." % mode)

    def checkParam(self, gucStr):
        """
        function: check the cmagent guc value
        Input : gucStr the guc key:value string
        output : NA
        """
        self.context.logger.debug("Start to check GUC value %s." % gucStr)
        try:
            # send cmd to that node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s" \
                  " --guc_string=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   Const.ACTION_CHECK_GUC,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   gucStr,
                   self.context.localLog)
            self.context.logger.debug("Command for checking"
                                      " parameter: %s." % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "check GUC value",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)
            self.context.logger.debug("Successfully checked guc value.")
        except Exception as e:
            raise Exception(str(e))

    def floatMoreThan(self, numOne, numTwo):
        """
        function: float more than
        input  : numOne, numTwo
        output : True/False
        """
        if float(numOne) - float(numTwo) > float(Const.DELTA_NUM):
            return True
        return False

    def floatLessThan(self, numOne, numTwo):
        """
        function: float less than
        input: numOne, numTwo
        output: True/False
        """
        if float(numOne) - float(numTwo) < float(-Const.DELTA_NUM):
            return True
        return False

    def floatEqualTo(self, numOne, numTwo):
        """
        function: float equal to
        input: numOne, numTwo
        output: True/False
        """
        if float(-Const.DELTA_NUM) < (float(numOne) - float(numTwo)) \
                < float(Const.DELTA_NUM):
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
        (status, output) = self.setGUCValue("vacuum_defer_cleanup_age",
                                            "100000", "reload")
        if status != 0:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] % "GUC" +
                            " Error: \n%s" % str(output))

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
            # 4. check the cluster pressure
            self.HASyncReplayCheck()
            # 5. before do grey binary upgrade, we must make sure the
            # cluster is Normal and the database could be
            # connected, if not, exit.
            (status, output) = self.doHealthCheck(Const.OPTION_PRECHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] %
                                "cluster" + "Detail: " + output)
            # 6.chose the node name list that satisfy the condition as
            # upgrade nodes
            self.chooseUpgradeNodes()
            # check if it satisfy upgrade again, if it is the second loop to
            # upgrade, it can go go upgrade again branch
            upgradeAgain = self.canUpgradeAgain()
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
                    self.exitWithRetCode(Const.ACTION_AUTO_ROLLBACK, False)
                self.removeOmRollbackProgressFile()
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
                #self.createGrpcCA()
                #self.prepareServerKey()
                #self.prepareRoachServerKey()
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
                if self.context.action == Const.ACTION_LARGE_UPGRADE:
                    self.updateCatalog()
                self.recordNodeStep(GreyUpgradeStep.STEP_SWITCH_NEW_BIN)

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
                self.greySyncGuc()
                self.greyUpgradeSyncOldConfigToNew()
                # 11. switch the cluster version to new version
                self.switchBin(Const.NEW)
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
            (status, output) = self.doHealthCheck(Const.OPTION_POSTCHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] %
                                "cluster" + output)
            if self.isNodeSpecifyStep(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG):
                # 14. exec post upgrade script
                if self.context.action == Const.ACTION_LARGE_UPGRADE:
                    self.waitClusterForNormal()
                    self.prepareSql("rollback-post")
                    self.execRollbackUpgradedCatalog(scriptType="rollback-post")
                    self.prepareSql("upgrade-post")
                    self.execRollbackUpgradedCatalog(scriptType="upgrade-post")
                    self.getLsnInfo()
                hosts = copy.deepcopy(self.context.clusterNodes)
                self.recordNodeStep(
                    GreyUpgradeStep.STEP_PRE_COMMIT, nodes=hosts)
                self.printPrecommitBanner()
        except Exception as e:
            hintInfo = "Nodes are new version. " \
                       "Please check the cluster status. ERROR: \n"
            self.context.logger.log(hintInfo + str(e))
            self.context.logger.debug(traceback.format_exc())
            self.exitWithRetCode(self.context.action, False, hintInfo + str(e))
        self.context.logger.log("Successfully upgrade nodes.")
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
                                    Const.GREY_UPGRADE_STEP_FILE)
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
               Const.ACTION_GREY_SYNC_GUC,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.localLog)
        self.context.logger.debug("Command for sync GUC in upgrade: %s" % cmd)
        hostList = copy.deepcopy(self.context.nodeNames)
        self.context.sshTool.executeCommand(cmd, "", hostList=hostList)
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
                   Const.ACTION_GREY_UPGRADE_CONFIG_SYNC,
                   self.context.user,
                   int(float(self.context.oldClusterNumber) * 1000),
                   self.context.oldClusterAppPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            self.context.logger.debug("Command for syncing config files: %s"
                                      % cmd)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, "", hostList=hostList)

            # change the owner of application
            cmd = "chown -R %s:%s '%s'" % \
                  (self.context.user, self.context.group,
                   self.context.newClusterAppPath)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, "", hostList=hostList)
        except Exception as e:
            raise Exception(str(e) + " Failed to sync configuration.")
        self.context.logger.log("Successfully synced cluster configuration.")

    def switchExistsProcess(self, isRollback=False):
        """
        switch all the process
        :param isRollback:
        :return:
        """
        self.context.logger.log("Switching all db processes.", "addStep")
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
            self.context.logger.debug("Create checkpoint before switching.")
            start_time = timeit.default_timer()
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

    def switchDn(self, isRollback):
        self.context.logger.debug("Switching DN processes.")
        start_time = timeit.default_timer()
        # under upgrade, kill the process from old cluster app path,
        # rollback: kill from new cluster app path
        cmd = "%s -t %s -U %s -V %d --old_cluster_app_path=%s " \
              "--new_cluster_app_path=%s -X '%s' -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               Const.ACTION_SWITCH_DN,
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
        self.context.logger.debug(
            "Command for switching DN processes: %s" % cmd)
        hostList = copy.deepcopy(self.context.nodeNames)
        self.context.sshTool.executeCommand(cmd, "", hostList=hostList)
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
        cmd = "gs_om -t start"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            "Command:%s. Error:\n%s" % (cmd, output))

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
                                    Const.GREY_UPGRADE_STEP_FILE)
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
                   Const.ACTION_GET_LSN_INFO,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug("Command for geting lsn info: %s." % cmd)
            self.context.sshTool.executeCommand(cmd, "", hostList=execHosts)
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
                                    Const.GREY_UPGRADE_STEP_FILE)
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
                  Const.UPGRADE_SCHEMA, relname)
            self.context.logger.debug("Sql to query if has the table: %s" % sql)
            (status, output) = self.execSqlCommandInPrimaryDN(sql)
            if status != 0 or ClusterCommand.findErrorInSql(output):
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] %
                                sql + " Error: \n%s" % str(output))
            if output == '0':
                self.context.logger.debug("Table does not exist.")
                return False
            self.context.logger.debug("Table exists.")
            return True
        except Exception as e:
            raise Exception(str(e))

    def findOneMatchedCombin(self, clusterNodes):
        """
        function: if the node number is less than const.COMBIN_NUM, we will
        try all possiblity combination to get one
        matched combination, otherwise, we will use a strategy to find the
        node with less instance(cms, gtm, etc.)
        input : check the score or return the first match combination
        output: one match best node
        """
        combinNodes = clusterNodes
        # combin is node name list
        randomNodes = random.sample(combinNodes, self.context.nodesNum)
        self.context.logger.log("Not match the condition, "
                                "choose nodes %s" % randomNodes)
        return randomNodes

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
                                   Const.GREY_UPGRADE_STEP_FILE + "_bak")
        self.context.logger.debug("Create and init the file %s." % bakStepFile)
        g_file.createFile(bakStepFile, True, DefaultValue.KEY_FILE_MODE)
        header = ["node_host", "upgrade_action", "step"]
        g_file.createFileInSafeMode(bakStepFile)
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
                                     Const.GREY_UPGRADE_STEP_FILE)
        g_file.rename(bakStepFile, finalStepFile)
        # so if we can get the step file, we can get the step information
        self.context.logger.debug("Rename the file %s to %s." % (
            bakStepFile, finalStepFile))
        self.distributeFile(finalStepFile)
        self.context.logger.debug("Successfully inited the file %s and "
                                  "send it to each node." % finalStepFile)

    def initUpgradeProcessStatus(self):
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                Const.INPLACE_UPGRADE_STEP_FILE)
        self.context.logger.debug("Create and init the file %s" % stepFile)
        g_file.removeFile(stepFile, "python")
        g_file.createFile(stepFile, True, DefaultValue.KEY_FILE_MODE)
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
                                Const.GREY_UPGRADE_STEP_FILE)
        stepTempFile = os.path.join(self.context.upgradeBackupPath,
                                    "upgrade_step_temp.csv")
        g_file.createFileInSafeMode(stepTempFile)
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

        g_file.removeFile(stepFile)
        g_file.rename(stepTempFile, stepFile)
        g_file.changeMode(DefaultValue.KEY_FILE_MODE, stepFile)
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
            self.exitWithRetCode(Const.ACTION_AUTO_ROLLBACK, False)
        try:
            self.checkUpgrade()

            # 3. before do binary upgrade, we must make sure the cluster is
            # Normal and the database could be connected
            #    if not, exit.
            self.startCluster()

            # uninstall kerberos if has already installed
            pghost_path = DefaultValue.getEnvironmentParameterValue(
                'PGHOST', self.context.user)
            kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
            if os.path.exists(kerberosflagfile):
                self.stopCluster()
                self.context.logger.log("Starting uninstall Kerberos.",
                                        "addStep")
                cmd = "source %s && " % self.context.userProfile
                cmd += "%s -m uninstall -U %s" % (OMCommand.getLocalScript(
                    "Local_Kerberos"), self.context.user)
                self.context.sshTool.executeCommand(cmd, "")
                self.context.logger.log("Successfully uninstall Kerberos.")
                self.startCluster()
            if self.unSetClusterReadOnlyMode() != 0:
                raise Exception("NOTICE: "
                                + ErrorCode.GAUSS_529["GAUSS_52907"])
            self.recordNodeStepInplace(Const.ACTION_INPLACE_UPGRADE,
                                       Const.BINARY_UPGRADE_STEP_INIT_STATUS)

            (status, output) = self.doHealthCheck(Const.OPTION_PRECHECK)
            if status != 0:
                self.exitWithRetCode(Const.ACTION_INPLACE_UPGRADE, False,
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
            self.recordNodeStepInplace(Const.ACTION_INPLACE_UPGRADE,
                                       Const.BINARY_UPGRADE_STEP_STOP_NODE)
            self.context.logger.debug("Start to stop all instances"
                                      " on the node.", "addStep")
            self.stopCluster()
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
                Const.ACTION_INPLACE_UPGRADE,
                Const.BINARY_UPGRADE_STEP_BACKUP_VERSION)
            self.backupClusterConfig()

            # 10. Upgrade application on node
            #     install new bin file
            self.recordNodeStepInplace(Const.ACTION_INPLACE_UPGRADE,
                                       Const.BINARY_UPGRADE_STEP_UPGRADE_APP)
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
            self.restoreClusterConfig()
            self.syncNewGUC()
            # unset cluster readonly
            self.startCluster()
            if self.unSetClusterReadOnlyMode() != 0:
                raise Exception("NOTICE: "
                                + ErrorCode.GAUSS_529["GAUSS_52907"])
            # flush new app dynamic configuration
            dynamicConfigFile = "%s/bin/cluster_dynamic_config" % \
                                self.context.newClusterAppPath
            if os.path.exists(dynamicConfigFile) \
                    and self.isLargeInplaceUpgrade:
                self.refresh_dynamic_config_file()
                self.context.logger.debug(
                    "Successfully refresh dynamic config file")
            self.stopCluster()
            if os.path.exists(dynamicConfigFile) \
                    and self.isLargeInplaceUpgrade:
                self.restore_dynamic_config_file()
            # 12. modify GUC parameter unix_socket_directory
            self.modifySocketDir()
            # 13. start new cluster
            self.recordNodeStepInplace(Const.ACTION_INPLACE_UPGRADE,
                                       Const.BINARY_UPGRADE_STEP_START_NODE)
            self.context.logger.debug("Start to start all instances"
                                      " on the node.", "addStep")

            # update catalog
            # start cluster in normal mode
            if self.isLargeInplaceUpgrade:
                self.touchRollbackCatalogFlag()
                self.updateCatalog()
            self.CopyCerts()
            self.context.createGrpcCa()
            self.context.logger.debug("Successfully createGrpcCa.")

            self.switchBin(Const.NEW)
            self.startCluster()
            if self.isLargeInplaceUpgrade:
                self.modifyPgProcIndex()
                self.context.logger.debug("Start to exec post upgrade script")
                self.doUpgradeCatalog(self.context.oldClusterNumber,
                                      postUpgrade=True)
                self.context.logger.debug(
                    "Successfully exec post upgrade script")
            self.context.logger.debug("Successfully start all "
                                      "instances on the node.", "constant")
            if self.setClusterReadOnlyMode() != 0:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52908"])
            # 14. check the cluster status
            (status, output) = self.doHealthCheck(Const.OPTION_POSTCHECK)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"]
                                % "cluster" + output)

            # 15. record precommit step status
            self.recordNodeStepInplace(Const.ACTION_INPLACE_UPGRADE,
                                       Const.BINARY_UPGRADE_STEP_PRE_COMMIT)
            self.printPrecommitBanner()
        except Exception as e:
            self.context.logger.error(str(e))
            self.context.logger.log("Binary upgrade failed. Rollback"
                                    " to the original cluster.")
            # do rollback
            self.exitWithRetCode(Const.ACTION_AUTO_ROLLBACK,
                                 self.doInplaceBinaryRollback())
        self.exitWithRetCode(Const.ACTION_INPLACE_UPGRADE, True)

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
        if self.getNodeStepInplace() != Const.BINARY_UPGRADE_STEP_PRE_COMMIT:
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52916"]
                            + " Please check if previous upgrade"
                              " operation was successful or if"
                              " upgrade has already been committed.")
        # create commit flag file
        self.createCommitFlagFile()

        # variable to indicate whether we should keep step file
        # and cleanup list file for re-entry
        cleanUpSuccess = True

        # drop table and index after large upgrade
        if self.isLargeInplaceUpgrade:
            if self.check_upgrade_mode():
                self.drop_table_or_index()
        # 1.unset read-only
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
        time.sleep(10)
        # 3. clean backup catalog physical files if doing inplace upgrade
        if self.cleanBackupedCatalogPhysicalFiles() != 0:
            self.context.logger.debug(
                "Failed to clean backup files in directory %s. "
                % self.context.upgradeBackupPath)

        if not cleanUpSuccess:
            self.context.logger.log("NOTICE: Cleanup is incomplete during"
                                    " commit. Please re-commit upgrade once"
                                    " again or cleanup manually")
            self.exitWithRetCode(Const.ACTION_INPLACE_UPGRADE, False)
        else:
            # 8. clean up other upgrade tmp files
            # and uninstall inplace upgrade support functions
            self.cleanInstallPath(Const.OLD)
            self.cleanBinaryUpgradeBakFiles()
            if self.isLargeInplaceUpgrade:
                self.stopCluster()
                self.startCluster()

            # install Kerberos
            self.install_kerberos()
            self.context.logger.log("Commit binary upgrade succeeded.")
            self.exitWithRetCode(Const.ACTION_INPLACE_UPGRADE, True)

    def install_kerberos(self):
        """
        install kerberos after upgrade
        :return:NA
        """
        pghost_path = DefaultValue.getEnvironmentParameterValue(
            'PGHOST', self.context.user)
        kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
        if os.path.exists(kerberosflagfile):
            # install kerberos
            cmd = "source %s &&" % self.context.userProfile
            cmd += "gs_om -t stop && "
            cmd += "%s -m install -U %s --krb-server" % (
                OMCommand.getLocalScript("Local_Kerberos"),
                self.context.user)
            (status, output) = DefaultValue.retryGetstatusoutput(cmd, 3, 5)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                "Command:%s. Error:\n%s" % (cmd, output))
            cmd = "source %s && " % self.context.userProfile
            cmd += "%s -m install -U %s --krb-client " % (
            OMCommand.getLocalScript("Local_Kerberos"), self.context.user)
            self.context.sshTool.executeCommand(
                cmd, "", hostList=self.context.clusterNodes)
            self.context.logger.log("Successfully install Kerberos.")
            cmd = "source %s && gs_om -t start" % self.context.userProfile
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0 and not self.context.ignoreInstance:
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
                  Const.ACTION_RESTORE_DYNAMIC_CONFIG_FILE,
                  self.context.user,
                  int(float(self.context.oldClusterNumber) * 1000),
                  self.context.upgradeBackupPath,
                  self.context.oldClusterAppPath,
                  self.context.newClusterAppPath,
                  self.context.localLog)

        self.context.logger.debug("Command for restoring "
                                  "config files: %s" % cmd)
        DefaultValue.execCommandWithMode(cmd,
                                         "restore config files",
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
                g_file.removeFile(pg_proc_csv_path)
            if os.path.exists(new_pg_proc_csv_path):
                g_file.removeFile(new_pg_proc_csv_path)

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
                cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                      (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                       Const.ACTION_CLEAN_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.localLog)
                if isRollBack:
                    cmd += " --rollback --oldcluster_num='%s'" % \
                           self.context.oldClusterNumber
                self.context.logger.debug(
                    "Command for cleaning up physical catalog files: %s." % cmd)
                DefaultValue.execCommandWithMode(
                    cmd,
                    "clean backuped physical files of catalog objects",
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
            g_file.createFile(lcgroupfile)
            g_file.changeOwner(self.context.user, lcgroupfile)
            g_file.changeMode(DefaultValue.KEY_FILE_MODE, lcgroupfile)
            # write result to file
            with open(lcgroupfile, "w") as fp_json:
                json.dump({"lcgroupnamelist": lcgroupnames}, fp_json)
            # send file to remote nodes
            self.context.sshTool.scpFiles(lcgroupfile, self.context.tmpDir)
            self.context.logger.debug(
                "Successfully to write and send logical cluster info file.")
            return 0
        except Exception as e:
            cmd = "(if [ -f '%s' ]; then rm -f '%s'; fi)" % (
                lcgroupfile, lcgroupfile)
            DefaultValue.execCommandWithMode(cmd,
                                             "clean lcgroup name list file",
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
        if self.context.action == Const.ACTION_INPLACE_UPGRADE:
            hostName = DefaultValue.GetHostIpOrName()
            hosts = [hostName]
        else:
            hosts = self.context.clusterNodes
        cmd = "%s -t %s -U %s --upgrade_bak_path=%s -X %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               Const.ACTION_UPGRADE_SQL_FOLDER,
               self.context.user,
               self.context.upgradeBackupPath,
               self.context.xmlFile,
               self.context.localLog)
        DefaultValue.execCommandWithMode(cmd,
                                         "prepare upgrade_sql",
                                         self.context.sshTool,
                                         self.context.isSingle,
                                         self.context.userProfile,
                                         hosts)

    def HASyncReplayCheck(self):
        """
        function: Wait and check if all standbys have replayed upto flushed
                  xlog positions of primaries.We record primary xlog flush
                  position at start of the check and wait until standby replay
                  upto that point.
                  Attention: If autovacuum is turned on, primary xlog flush
                  position may increase during the check.We do not check such
                   newly added xlog because they will not change catalog
                   physical file position.
        Input: NA
        output : NA
        """
        self.context.logger.debug("Start to wait and check if all the standby"
                                  " instances have replayed all xlogs.")
        self.doReplay()
        self.context.logger.debug("Successfully performed the replay check "
                                  "of the standby instance.")

    def doReplay(self):
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
                self.dnInst.hostname,
                self.dnInst.port,
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
                    self.dnInst.hostname,
                    self.dnInst.port,
                    False,
                    DefaultValue.DEFAULT_DB_NAME,
                    IsInplaceUpgrade=True)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] % refreshsql +
                        "Error: \n%s" % str(output))

            if datetime.now() > EndTime and NeedReplay:
                self.context.logger.log("WARNING: " + ErrorCode.GAUSS_513[
                    "GAUSS_51300"] % sql + " Timeout while waiting for "
                                           "standby replay.")
                return
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
        tmpFile = os.path.join(DefaultValue.getTmpDirFromEnv(
            self.context.user), Const.TMP_DYNAMIC_DN_INFO)
        try:
            self.context.logger.debug("Start to backup old cluster database"
                                      " and relation information.")
            # prepare backup path
            backup_path = os.path.join(
                self.context.upgradeBackupPath, "oldClusterDBAndRel")
            cmd = "rm -rf '%s' && mkdir '%s' -m '%s' " % \
                  (backup_path, backup_path, DefaultValue.KEY_DIRECTORY_MODE)
            hostList = copy.deepcopy(self.context.clusterNodes)
            self.context.sshTool.executeCommand(cmd, "", hostList=hostList)
            # prepare dynamic cluster info file in every node
            self.generateDynamicInfoFile(tmpFile)
            # get dn primary hosts
            dnPrimaryNodes = self.getPrimaryDnListFromDynamicFile()
            execHosts = list(set(dnPrimaryNodes))

            # send cmd to all node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   Const.ACTION_BACKUP_OLD_CLUSTER_DB_AND_REL,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug(
                "Command for backing up old cluster database and "
                "relation information: %s." % cmd)
            self.context.sshTool.executeCommand(cmd, "", hostList=execHosts)
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
                    deleteCmd, "", hostList=hostList)

    def generateDynamicInfoFile(self, tmpFile):
        """
        generate dynamic info file and send to every node
        :return:
        """
        self.context.logger.debug(
            "Start to generate dynamic info file and send to every node.")
        try:
            cmd = ClusterCommand.getQueryStatusCmd(
                self.context.user, outFile=tmpFile)
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
            tmpFile = os.path.join(DefaultValue.getTmpDirFromEnv(
                self.context.user), Const.TMP_DYNAMIC_DN_INFO)
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
        DefaultValue.execCommandWithMode(cmd,
                                         "create init flag file",
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
            self.doUpgradeCatalog(self.context.oldClusterNumber)
        except Exception as e:
            raise Exception(
                "Failed to execute update sql file. Error: %s" % str(e))

    def doUpgradeCatalog(self, oldClusterNumber, postUpgrade=False):
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
        try:
            if self.context.action == Const.ACTION_INPLACE_UPGRADE:
                if not postUpgrade:
                    self.startCluster()
                    self.setUpgradeMode(1)
                    self.touchInitFile()
            elif not postUpgrade:
                # the guc parameter upgrade_from need to restart
                # cmagent to take effect
                self.setUpgradeMode(2)
                # kill snapshot thread in kernel
                self.context.killKernalSnapshotThread(self.dnInst)
            # if we use --force to forceRollback last time,
            # it may has remaining last catalog
            if postUpgrade:
                self.waitClusterForNormal()
                self.execRollbackUpgradedCatalog(scriptType="rollback-post")
                self.execRollbackUpgradedCatalog(scriptType="upgrade-post")
            else:
                self.execRollbackUpgradedCatalog(scriptType="rollback")
                self.execRollbackUpgradedCatalog(scriptType="upgrade")
                self.pgxcNodeUpdateLocalhost("upgrade")
            self.getLsnInfo()
            if self.context.action == \
                    Const.ACTION_INPLACE_UPGRADE and not postUpgrade and not \
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
            Const.ACTION_CREATE_NEW_CSV_FILE,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        self.context.logger.debug(
            "Command for create new csv file: %s." % cmd)
        self.context.sshTool.executeCommand(cmd, "", hostList=execHosts)
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
            Const.ACTION_CREATE_PG_PROC_MAPPING_FILE,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        DefaultValue.execCommandWithMode(
            cmd,
            "create file to save mapping between pg_proc file path and "
            "pg_proc_temp_oids file path",
            self.context.sshTool,
            self.context.isSingle,
            self.context.userProfile)
        self.context.logger.debug(
            "Successfully created file to save mapping between pg_proc file "
            "path and pg_proc_temp_oids file path.")
        # stop cluster
        self.stopCluster()
        # replace pg_proc data file by pg_proc_temp data file
        # send cmd to all node and exec
        cmd = "%s -t %s -U %s -R '%s' -l %s" % (
            OMCommand.getLocalScript("Local_Upgrade_Utility"),
            Const.ACTION_REPLACE_PG_PROC_FILES,
            self.context.user,
            self.context.tmpDir,
            self.context.localLog)
        DefaultValue.execCommandWithMode(
            cmd,
            "replace pg_proc data file by pg_proc_temp data files",
            self.context.sshTool,
            self.context.isSingle,
            self.context.userProfile)
        self.context.logger.debug(
            "Successfully replaced pg_proc data files.")

    def copy_and_modify_tableinfo_to_csv(self, old_csv_path, new_csv_path):
        """
        1. copy pg_proc info to csv file
        2. modify csv file
        3. create new table and get info by csv file
        :return:
        """
        sql =\
            """copy pg_proc( proname, pronamespace, proowner, prolang, 
            procost, prorows, provariadic, protransform, prosecdef, 
            proleakproof, proisstrict, proretset, provolatile, pronargs, 
            pronargdefaults, prorettype, proargtypes, proallargtypes, 
            proargmodes, proargnames, proargdefaults, prosrc, probin, 
            proconfig, proacl, prodefaultargpos, fencedmode, proshippable, 
            propackage,prokind) WITH OIDS to '%s' delimiter ',' 
            csv header;""" % old_csv_path
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql, self.context.user,
            self.dnInst.hostname, self.dnInst.port, False,
            DefaultValue.DEFAULT_DB_NAME, IsInplaceUpgrade=True)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                            " Error: \n%s" % str(output))
        pg_proc_csv_reader = csv.reader(open(old_csv_path, 'r'))
        pg_proc_csv_data = list(pg_proc_csv_reader)
        header = pg_proc_csv_data[0]
        header.insert(header.index('protransform') + 1, 'proisagg')
        header.insert(header.index('protransform') + 2, 'proiswindow')
        new_pg_proc_csv_data = []
        new_pg_proc_csv_data.append(header)
        pg_proc_data_info = pg_proc_csv_data[1:]
        for i in range(2):
            for info in pg_proc_data_info:
                info.insert(header.index('protransform') + 2, 'True')
        for info in pg_proc_data_info:
            new_pg_proc_csv_data.append(info)
        f = open(new_csv_path, 'w')
        new_pg_proc_csv_writer = csv.writer(f)
        for info in new_pg_proc_csv_data:
            new_pg_proc_csv_writer.writerow(info)
        f.close()

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
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql, self.context.user,
            self.dnInst.hostname, self.dnInst.port, False,
            DefaultValue.DEFAULT_DB_NAME, IsInplaceUpgrade=True)
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
        sql = 'CHECKPOINT;'
        for eachdb in database_list:
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                eachdb, IsInplaceUpgrade=True)
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
            dnNodeName = self.dnInst.hostname
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
                g_OSlib.scpFile(dnNodeName, check_upgrade_sql,
                                self.context.upgradeBackupPath)
            if not os.path.isfile(maindb_sql):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % maindb_sql)
            if not os.path.isfile(otherdb_sql):
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50210"] % otherdb_sql)
            g_OSlib.scpFile(dnNodeName, maindb_sql,
                            self.context.upgradeBackupPath)
            g_OSlib.scpFile(dnNodeName, otherdb_sql,
                            self.context.upgradeBackupPath)
            self.context.logger.debug(
                "Scp {0} file and {1} file to nodes {2}".format(
                    maindb_sql, otherdb_sql, dnNodeName))
            # send cmd to that node and exec
            cmd = "%s -t %s -U %s --upgrade_bak_path=%s --script_type=%s -l " \
                  "%s" % (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   Const.ACTION_UPDATE_CATALOG,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   scriptType,
                   self.context.localLog)
            self.context.logger.debug(
                "Command for executing {0} catalog.".format(scriptType))
            DefaultValue.execCommandWithMode(cmd,
                                             "{0} catalog".format(scriptType),
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
                    sql += "SET %s = on;" % Const.ON_INPLACE_UPGRADE
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
                       Const.ACTION_TOUCH_INIT_FILE,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.localLog)
                DefaultValue.execCommandWithMode(cmd,
                                                 "create upgrade init file",
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
            g_file.createFile(writeFile)
            g_file.writeFile(writeFile, header, 'w')

            with open(writeFile, 'a') as sqlFile:
                for each_file in fileNameList:
                    each_file_with_path = "%s/%s" % (filePath, each_file)
                    self.context.logger.debug("Handling file: %s" %
                                              each_file_with_path)
                    with open(each_file_with_path, 'r') as fp:
                        for line in fp:
                            sqlFile.write(line)
                    sqlFile.write(os.linesep)
            g_file.writeFile(writeFile, ["COMMIT;"], 'a')
            self.context.logger.debug(
                "Success to together {0} file".format(writeFile))
            if not os.path.isfile(writeFile):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % writeFile)
        except Exception as e:
            raise Exception("Failed to write {0} sql file. ERROR: {1}".format(
                writeFile, str(e)))

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
        drop index pg_proc_proname_args_nsp_index;SET LOCAL 
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
        self.stopCluster()
        # start cluster
        self.startCluster()
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
                                Const.GREY_UPGRADE_STEP_FILE)
        self.context.logger.debug("Get the action from file %s." % stepFile)
        if not (os.path.exists(stepFile) or os.path.isfile(stepFile)):
            self.context.logger.debug("Step file does not exists or not file,"
                                      " cannot get action from it. "
                                      "Set it to large upgrade.")
            self.context.action = Const.ACTION_LARGE_UPGRADE
            return
        with open(stepFile, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                self.context.action = row['upgrade_action']
                break
        self.context.logger.debug("Set the action to %s"
                                  % self.context.action)

    def getClusterAppPath(self, mode=Const.OLD):
        """
        if cannot get path from table, try to get from the backup file
        :param mode:
        :return:
        """
        self.context.logger.debug("Get the install path from table or file.")
        path = self.getClusterAppPathFromFile(mode)
        return path

    def getClusterAppPathFromFile(self, mode=Const.OLD):
        """
        get the app path from backup dir, mode is new or old,
        :param mode: 'old', 'new'
        :return: the real path of appPath
        """
        dirFile = "%s/%s" % (self.context.upgradeBackupPath,
                             Const.RECORD_UPGRADE_DIR)
        self.context.logger.debug("Get the %s app path from file %s"
                                  % (mode, dirFile))
        if mode not in [Const.OLD, Const.NEW]:
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
                    g_file.createDirectory(
                        self.context.upgradeBackupPath, True,
                        DefaultValue.KEY_DIRECTORY_MODE)
                self.context.logger.debug("Copy the directory %s from node %s."
                                          % (self.context.upgradeBackupPath,
                                             copyNode))
                cmd = g_Platform.getRemoteCopyCmd(
                    self.context.upgradeBackupPath, self.context.tmpDir,
                    str(copyNode), False, 'directory')
                self.context.logger.debug("Command for copying "
                                          "directory: %s" % cmd)
                DefaultValue.execCommandLocally(cmd)
            else:
                # binary_upgrade exists, but no step file
                return ""
        if not os.path.isfile(dirFile):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % dirFile)
        with open(dirFile, 'r') as fp:
            retLines = fp.readlines()
        if len(retLines) != 2:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] % dirFile)
        if mode == Const.OLD:
            path = retLines[0].strip()
        else:
            path = retLines[1].strip()
        # if can get the path from file, the path must be valid,
        # otherwise the file is damaged accidentally
        DefaultValue.checkPathVaild(path)
        if not os.path.exists(path):
            if mode == Const.NEW and \
                    self.context.action == Const.ACTION_AUTO_ROLLBACK:
                self.context.logger.debug("Under rollback, the new "
                                          "cluster app path does not exists.")
            elif mode == Const.OLD and \
                    self.context.action == Const.ACTION_COMMIT_UPGRADE:
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
        try:
            (status, output) = self.doHealthCheck(Const.OPTION_POSTCHECK)
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
            if self.existTable(Const.RECORD_NODE_STEP):
                self.recordNodeStep(GreyUpgradeStep.STEP_BEGIN_COMMIT)
            self.setActionFile()
            # self.restoreOriginalState()
            if self.context.action == Const.ACTION_LARGE_UPGRADE:
                self.setUpgradeMode(0)
            time.sleep(10)
            if self.dropPMKSchema() != 0:
                raise Exception(ErrorCode.GAUSS_529["GAUSS_52917"])

            self.clearOtherToolPackage()
            self.cleanInstallPath(Const.OLD)
            self.dropSupportSchema()
            self.cleanBinaryUpgradeBakFiles()
            self.cleanConfBakOld()
            self.context.logger.log("Commit upgrade succeeded.")
        except Exception as e:
            self.exitWithRetCode(Const.ACTION_COMMIT_UPGRADE, False, str(e))
        self.exitWithRetCode(Const.ACTION_COMMIT_UPGRADE, True)

    def dropPMKSchema(self):
        """
        function: Notice: the pmk schema on database postgres
        input : NA
        output: return 0, if the operation is done successfully.
                return 1, if the operation failed.
        """
        try:
            self.context.logger.debug("Start to drop schema PMK.")
            # execute drop commands by the CN instance
            sql = "DROP SCHEMA IF EXISTS pmk CASCADE; "
            retry_times = 0
            while True:
                (status, output) = self.execSqlCommandInPrimaryDN(sql)
                if status != 0 or ClusterCommand.findErrorInSql(output):
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

    def cleanConfBakOld(self):
        """
        clean conf.bak.old files in all instances
        input : NA
        output : NA
        """
        try:
            cmd = "%s -t %s -U %s -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   Const.ACTION_CLEAN_CONF_BAK_OLD,
                   self.context.user,
                   self.context.localLog)
            hostList = copy.deepcopy(self.context.nodeNames)
            self.context.sshTool.executeCommand(cmd, "", hostList=hostList)
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
            if action == Const.ACTION_AUTO_ROLLBACK:
                self.clearOtherToolPackage(action)
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
            # if -2, it means there is no need to exec rollback
            # if under upgrade continue mode, it will do upgrade not rollback,
            #  it can enter the upgrade process
            # when the binary_upgrade bak dir has some files
            if maxStep == Const.BINARY_UPGRADE_NO_NEED_ROLLBACK:
                self.cleanBinaryUpgradeBakFiles(True)
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
            if maxStep == GreyUpgradeStep.STEP_UPDATE_POST_CATALOG:
                self.context.logger.debug(
                    "Record the step %d to mark it has leaved pre-commit"
                    " status." % GreyUpgradeStep.STEP_UPDATE_POST_CATALOG)
                try:
                    if self.context.action == Const.ACTION_LARGE_UPGRADE\
                            and \
                            self.isNodeSpecifyStep(
                                GreyUpgradeStep.STEP_UPDATE_POST_CATALOG):
                        self.prepareUpgradeSqlFolder()
                        self.prepareSql("rollback-post")
                        self.setUpgradeMode(2)
                        self.execRollbackUpgradedCatalog(
                            scriptType="rollback-post")
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
                self.switchBin(Const.OLD)
                self.greyRestoreGuc()
                if needSwitchProcess:
                    self.rollbackHotpatch()
                    self.switchExistsProcess(True)
                self.recordNodeStep(GreyUpgradeStep.STEP_UPDATE_CATALOG)
            if maxStep >= GreyUpgradeStep.STEP_UPDATE_CATALOG and\
                    self.context.action == Const.ACTION_LARGE_UPGRADE:
                self.rollbackCatalog()
                self.recordNodeStep(GreyUpgradeStep.STEP_INIT_STATUS)

            if maxStep >= GreyUpgradeStep.STEP_INIT_STATUS:
                # clean on all the node, because the binary_upgrade temp
                #  dir will create in every node
                self.cleanInstallPath(Const.NEW)
                self.dropSupportSchema()
                self.initOmRollbackProgressFile()
                self.cleanBinaryUpgradeBakFiles(True)
        except Exception as e:
            self.context.logger.debug(str(e))
            self.context.logger.debug(traceback.format_exc())
            self.context.logger.log("Rollback failed. Error: %s" % str(e))
            return False
        self.context.logger.log("Rollback succeeded.")
        return True

    def setReadStepFromFile(self):
        readFromFileFlag = os.path.join(self.context.upgradeBackupPath,
                                        Const.READ_STEP_FROM_FILE_FLAG)
        self.context.logger.debug("Under force rollback mode.")
        g_file.createFile(readFromFileFlag, True, DefaultValue.KEY_FILE_MODE)
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
            return Const.BINARY_UPGRADE_NO_NEED_ROLLBACK
        if not os.path.isdir(self.context.upgradeBackupPath):
            raise Exception(ErrorCode.GAUSS_513["GAUSS_50211"] %
                            self.context.upgradeBackupPath)
        # because the binary_upgrade dir is used to block expand,
        # so we should clean the dir when rollback
        fileList = os.listdir(self.context.upgradeBackupPath)
        if not fileList:
            return GreyUpgradeStep.STEP_INIT_STATUS
        stepFile = os.path.join(self.context.upgradeBackupPath,
                                Const.GREY_UPGRADE_STEP_FILE)
        if not os.path.exists(stepFile):
            self.context.logger.debug(
                "No need to rollback. File %s does not exist." % stepFile)
            return Const.BINARY_UPGRADE_NO_NEED_ROLLBACK

        self.context.logger.debug("Get the node step from file %s." % stepFile)
        with open(stepFile, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            maxStep = Const.INVALID_UPRADE_STEP
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

    def execSqlCommandInPrimaryDN(self, sql, retryTime=3):
        self.context.logger.debug("Start to exec sql {0}.".format(sql))
        count = 0
        status, output = 1, ""
        while count < retryTime:
            self.getOneDNInst(checkNormal=True)
            self.context.logger.debug(
                "Exec sql in dn node {0}".format(self.dnInst.hostname))
            (status, output) = ClusterCommand.remoteSQLCommand(
                sql, self.context.user,
                self.dnInst.hostname, self.dnInst.port, False,
                DefaultValue.DEFAULT_DB_NAME, IsInplaceUpgrade=True)
            self.context.logger.debug(
                "Exec sql result is, status:{0}, output is {1}".format(
                    status, output))
            if status != 0 or ClusterCommand.findErrorInSql(output):
                count += 1
                continue
            else:
                break
        return status, output

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
                                    Const.GREY_UPGRADE_STEP_FILE)
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
                                Const.GREY_UPGRADE_STEP_FILE)
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
            Const.ACTION_GREY_RESTORE_CONFIG,
            self.context.user,
            self.context.oldClusterAppPath,
            self.context.newClusterAppPath,
            self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for restoring config: %s" % cmd)
        rollbackList = copy.deepcopy(self.context.clusterNodes)
        self.context.sshTool.executeCommand(cmd, "", hostList=rollbackList)
        self.context.logger.debug("Successfully restore config.")

    def greyRestoreGuc(self):
        """
        restore the old guc in rollback
        :return: NA
        """
        cmd = "%s -t %s -U %s --old_cluster_app_path=%s -X %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               Const.ACTION_GREY_RESTORE_GUC,
               self.context.user,
               self.context.oldClusterAppPath,
               self.context.xmlFile,
               self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for restoring GUC: %s" % cmd)
        rollbackList = copy.deepcopy(self.context.clusterNodes)
        self.context.sshTool.executeCommand(cmd, "", hostList=rollbackList)
        self.context.logger.debug("Successfully restore guc.")

    def dropSupportSchema(self):
        self.context.logger.debug("Drop schema.")
        sql = "DROP SCHEMA IF EXISTS %s CASCADE;" % Const.UPGRADE_SCHEMA
        retryTime = 0
        try:
            while retryTime < 5:
                (status, output) = self.execSqlCommandInPrimaryDN(sql)
                if status != 0 or ClusterCommand.findErrorInSql(output):
                    retryTime += 1
                    self.context.logger.debug(
                        "Failed to execute SQL: %s. Error: \n%s. retry" % (
                            sql, str(output)))
                else:
                    break
            if status != 0 or ClusterCommand.findErrorInSql(output):
                self.context.logger.debug(
                    "Failed to execute SQL: %s. Error: \n%s" % (
                        sql, str(output)))
                raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % sql +
                                " Please drop manually with this command.")
            self.context.logger.debug("Successfully drop schema %s cascade." %
                                      Const.UPGRADE_SCHEMA)
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
        # Const.BINARY_UPGRADE_NO_NEED_ROLLBACK value is -2
        # Const.INVALID_UPRADE_STEP value is -1
        # Const.BINARY_UPGRADE_STEP_INIT_STATUS value is 0
        # Const.BINARY_UPGRADE_STEP_BACKUP_STATUS value is 1
        # Const.BINARY_UPGRADE_STEP_STOP_NODE value is 2
        # Const.BINARY_UPGRADE_STEP_BACKUP_VERSION value is 3
        # Const.BINARY_UPGRADE_STEP_UPGRADE_APP value is 4
        # Const.BINARY_UPGRADE_STEP_START_NODE value is 5
        # Const.BINARY_UPGRADE_STEP_PRE_COMMIT value is 6
        self.distributeXml()
        step = self.getNodeStepInplace()
        if step == Const.BINARY_UPGRADE_NO_NEED_ROLLBACK:
            self.context.logger.log("Rollback succeeded.")
            return True

        # if step <= -1, it means the step file is broken, exit.
        if step <= Const.INVALID_UPRADE_STEP:
            self.context.logger.debug("Invalid upgrade step: %s." % str(step))
            return False

        # if step value is Const.BINARY_UPGRADE_STEP_PRE_COMMIT
        # and find commit flag file,
        # means user has commit upgrade, then can not do rollback
        if step == Const.BINARY_UPGRADE_STEP_PRE_COMMIT:
            if not self.checkCommitFlagFile():
                self.context.logger.log(
                    "Upgrade has already been committed, "
                    "can not execute rollback command any more.")
                return False

        try:
            self.checkStaticConfig()
            self.startCluster()
            # Mark that we leave pre commit status,
            # so that if we fail at the first few steps,
            # we won't be allowed to commit upgrade any more.
            if step == Const.BINARY_UPGRADE_STEP_PRE_COMMIT:
                self.recordNodeStepInplace(
                    Const.ACTION_INPLACE_UPGRADE,
                    Const.BINARY_UPGRADE_STEP_START_NODE)

            if step >= Const.BINARY_UPGRADE_STEP_START_NODE:
                # drop table and index after large upgrade
                if self.isLargeInplaceUpgrade:
                    if self.check_upgrade_mode():
                        self.drop_table_or_index()
                self.restoreClusterConfig(True)
                self.switchBin(Const.OLD)
                if self.isLargeInplaceUpgrade:
                    touchInitFlagFile = os.path.join(
                        self.context.upgradeBackupPath, "touch_init_flag")
                    if os.path.exists(touchInitFlagFile):
                        self.rollbackCatalog()
                        self.cleanCsvFile()
                    else:
                        self.setUpgradeMode(0)
                else:
                    self.stopCluster()
                self.recordNodeStepInplace(
                    Const.ACTION_INPLACE_UPGRADE,
                    Const.BINARY_UPGRADE_STEP_UPGRADE_APP)

            if step >= Const.BINARY_UPGRADE_STEP_UPGRADE_APP:
                self.restoreNodeVersion()
                self.restoreClusterConfig(True)
                self.recordNodeStepInplace(
                    Const.ACTION_INPLACE_UPGRADE,
                    Const.BINARY_UPGRADE_STEP_BACKUP_VERSION)

            if step >= Const.BINARY_UPGRADE_STEP_BACKUP_VERSION:
                self.cleanBackupedCatalogPhysicalFiles(True)
                self.recordNodeStepInplace(
                    Const.ACTION_INPLACE_UPGRADE,
                    Const.BINARY_UPGRADE_STEP_STOP_NODE)

            if step >= Const.BINARY_UPGRADE_STEP_STOP_NODE:
                self.startCluster()
                self.recordNodeStepInplace(
                    Const.ACTION_INPLACE_UPGRADE,
                    Const.BINARY_UPGRADE_STEP_INIT_STATUS)

            if step >= Const.BINARY_UPGRADE_STEP_INIT_STATUS:
                if self.unSetClusterReadOnlyMode() != 0:
                    raise Exception("NOTICE: " +
                                    ErrorCode.GAUSS_529["GAUSS_52907"])
                self.cleanBinaryUpgradeBakFiles(True)
                self.cleanInstallPath(Const.NEW)
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
        sql = "select count(*) from pg_class where relname = '%s';" % name
        (status, output) = ClusterCommand.remoteSQLCommand(
            sql, self.context.user,
            self.dnInst.hostname, self.dnInst.port, False,
            eachdb, IsInplaceUpgrade=True)
        if status != 0 or ClusterCommand.findErrorInSql(output):
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
            if self.context.action == Const.ACTION_INPLACE_UPGRADE and int(
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
            if self.context.action == Const.ACTION_INPLACE_UPGRADE:
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
        if self.context.action == Const.ACTION_INPLACE_UPGRADE:
            self.startCluster()
            self.setUpgradeMode(1)
        else:
            self.setUpgradeMode(2)
        self.execRollbackUpgradedCatalog(scriptType="rollback")
        self.pgxcNodeUpdateLocalhost("rollback")
        if self.context.action == Const.ACTION_INPLACE_UPGRADE:
            self.stopCluster()
        self.setUpgradeMode(0)

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
            self.startCluster()
            self.setUpgradeMode(0)
            self.stopCluster()
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
                      "--oldcluster_num='%s' -l %s" % \
                      (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                       Const.ACTION_RESTORE_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                       self.context.user,
                       self.context.upgradeBackupPath,
                       self.context.oldClusterNumber,
                       self.context.localLog)
                self.context.logger.debug(
                    "Command for restoring physical catalog files: %s." % cmd)
                DefaultValue.execCommandWithMode(
                    cmd,
                    "restore physical files of catalog objects",
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
        header.append("SET %s = on;" % Const.ON_INPLACE_UPGRADE)
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
            DefaultValue.getEnvironmentParameterValue("GAUSSHOME",
                                                      self.context.user)
        # $GAUSSHOME must has available value.
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
        (appPath, appPathName) = os.path.split(gaussHome)
        commonDbClusterInfoModule = \
            "%s/bin/script/gspylib/common/DbClusterInfo.py" % gaussHome
        commonStaticConfigFile = "%s/bin/cluster_static_config" % gaussHome
        try:
            if self.context.action == Const.ACTION_INPLACE_UPGRADE:

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
                logPathWithUser = DefaultValue.getEnv("GAUSSLOG")
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
            elif (self.context.action == Const.ACTION_CHOSE_STRATEGY
                  or self.context.action == Const.ACTION_COMMIT_UPGRADE):
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
                  [Const.ACTION_SMALL_UPGRADE, Const.ACTION_AUTO_UPGRADE,
                   Const.ACTION_LARGE_UPGRADE, Const.ACTION_AUTO_ROLLBACK]):
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
                        self.context.action == Const.ACTION_AUTO_ROLLBACK:
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
                    self.context.action == Const.ACTION_AUTO_UPGRADE \
                    and self.context.is_grey_upgrade:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50200"] % "kerberos")
            if os.path.exists(xmlfile) and self.context.is_inplace_upgrade:
                pghost_path = DefaultValue.getEnvironmentParameterValue(
                    'PGHOST', self.context.user)
                destfile = "%s/krb5.conf" % os.path.dirname(
                    self.context.userProfile)
                kerberosflagfile = "%s/kerberos_upgrade_flag" % pghost_path
                cmd = "cp -rf %s %s " % (destfile, kerberosflagfile)
                (status, output) = DefaultValue.retryGetstatusoutput(cmd, 3, 5)
                if status != 0:
                    raise Exception(
                        ErrorCode.GAUSS_502["GAUSS_50206"] % kerberosflagfile
                        + " Error: \n%s" % output)
                self.context.logger.debug(
                    "Successful back up kerberos config file.")
        except Exception as e:
            self.context.logger.debug(traceback.format_exc())
            self.exitWithRetCode(self.context.action, False, str(e))

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
                self.context.userProfile)
            self.context.logger.debug(
                "Cluster status information is %s;The primaryDnNode is %s" % (
                    output, primaryDnNode))
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
                        OMCommand.getClusterStatus(self.context.user)
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
            hosts.remove(DefaultValue.GetHostIpOrName())

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
            filePath = os.path.join(tempPath, Const.INPLACE_UPGRADE_STEP_FILE)
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
        hosts.remove(DefaultValue.GetHostIpOrName())
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
            filePath = os.path.join(tempPath, Const.INPLACE_UPGRADE_STEP_FILE)
            if not os.path.exists(filePath):
                self.context.logger.debug("The cluster status is Normal. "
                                          "No need to rollback.")
                return Const.BINARY_UPGRADE_NO_NEED_ROLLBACK

            # read and check record format
            stepInfo = g_file.readFile(filePath)[0]
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
                    Const.BINARY_UPGRADE_STEP_PRE_COMMIT or \
                    int(recordStep) < Const.INVALID_UPRADE_STEP:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51633"] %
                                recordStep)
        except Exception as e:
            self.context.logger.error(str(e))
            return Const.INVALID_UPRADE_STEP
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
                int(step) < Const.INVALID_UPRADE_STEP:
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
            DefaultValue.execCommandWithMode(cmd,
                                             "check upgrade environment",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)
        except Exception as e:
            self.context.logger.log("Failed to check upgrade environment.",
                                    "constant")
            raise Exception(str(e))
        if not self.context.forceRollback:
            if self.context.oldClusterNumber >= \
                    Const.ENABLE_STREAM_REPLICATION_VERSION:
                self.check_gucval_is_inval_given(
                    Const.ENABLE_STREAM_REPLICATION_NAME, Const.VALUE_ON)
        try:
            if self.context.action == Const.ACTION_INPLACE_UPGRADE:
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
        gaussHome = DefaultValue.getInstallDir(self.context.user)
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
            self.context.upgradeBackupPath, Const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                Const.GREY_UPGRADE_STEP_FILE)
            return
        grey_node_names = self.getUpgradedNodeNames()
        if grey_node_names:
            self.context.logger.log(
                "All nodes have been upgrade, no need to upgrade again.")
            self.exitWithRetCode(self.action, True)

    def checkOptionH(self):
        self.checkNodeNames()
        stepFile = os.path.join(
            self.context.upgradeBackupPath, Const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                Const.GREY_UPGRADE_STEP_FILE)
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
                self.context.upgradeBackupPath, Const.GREY_UPGRADE_STEP_FILE)
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
            self.context.upgradeBackupPath, Const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52920"] +
                            "Need to upgrade some nodes first.")
        greyNodeNames = self.getUpgradedNodeNames()
        # the nodes that have upgraded that should reached to precommit
        if not self.isNodeSpecifyStep(GreyUpgradeStep.STEP_UPDATE_POST_CATALOG,
                                      greyNodeNames):
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52912"])
        if len(greyNodeNames) == len(self.context.clusterInfo.dbNodes):
            self.printPrecommitBanner()
            self.context.logger.debug(
                "The node host in table %s.%s is equal to cluster nodes."
                % (Const.UPGRADE_SCHEMA, Const.RECORD_NODE_STEP))
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52913"])
        if not self.checkVersion(self.newCommitId, greyNodeNames):
            raise Exception(
                ErrorCode.GAUSS_529["GAUSS_52914"] +
                "Please use the same version to upgrade remain nodes.")

    def checkOptionG(self):
        stepFile = os.path.join(
            self.context.upgradeBackupPath, Const.GREY_UPGRADE_STEP_FILE)
        if not os.path.isfile(stepFile):
            self.context.logger.debug(
                "File %s does not exists. No need to check." %
                Const.GREY_UPGRADE_STEP_FILE)
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
                   Const.ACTION_BACKUP_CONFIG,
                   self.context.user,
                   int(float(self.context.oldClusterNumber) * 1000),
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug("Command for backing up cluster "
                                      "configuration: %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "backup config files",
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
                   Const.ACTION_INPLACE_BACKUP,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog)
            self.context.logger.debug(
                "Command for backing up gds file: %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "backup DS libs and gds file",
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
                  "--oldcluster_num='%s' -l %s" % \
                  (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                   Const.ACTION_BACKUP_OLD_CLUSTER_CATALOG_PHYSICAL_FILES,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.oldClusterNumber,
                   self.context.localLog)
            self.context.logger.debug("Command for backing up physical files "
                                      "of catalg objects: %s" % cmd)
            DefaultValue.execCommandWithMode(
                cmd,
                "backup  physical files of catalg objects",
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
                   Const.ACTION_SYNC_CONFIG,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.newClusterAppPath,
                   self.context.localLog,)
            self.context.logger.debug(
                "Command for synchronizing new guc: %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "sync new guc",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)
        except Exception as e:
            self.context.logger.debug("Failed to synchronize new guc.",
                                      "constant")
            raise Exception(str(e))
        self.context.logger.debug("Successfully synchronized new guc.",
                                  "constant")

    def cleanExtensionFiles(self):
        """
        function: clean extension library and config files
        input: NA
        output: 0 / 1
        """
        try:
            # clean extension library and config files
            hadoop_odbc_connector = "%s/lib/postgresql/" \
                                    "hadoop_odbc_connector.so" % \
                                    self.context.oldClusterInfo.appPath
            extension_config01 = "%s/share/postgresql/extension/" \
                                 "hadoop_odbc_connector--1.0.sql" % \
                                 self.context.oldClusterInfo.appPath
            extension_config02 = "%s/share/postgresql/extension/" \
                                 "hadoop_odbc_connector.control" % \
                                 self.context.oldClusterInfo.appPath
            extension_config03 = "%s/share/postgresql/extension/hadoop_odbc_" \
                                 "connector--unpackaged--1.0.sql" % \
                                 self.context.oldClusterInfo.appPath

            cmd = "(if [ -f '%s' ];then rm -f '%s';fi)" % \
                  (hadoop_odbc_connector, hadoop_odbc_connector)
            cmd += " && (if [ -f '%s' ];then rm -f '%s';fi)" % \
                   (extension_config01, extension_config01)
            cmd += " && (if [ -f '%s' ];then rm -f '%s';fi)" % \
                   (extension_config02, extension_config02)
            cmd += " && (if [ -f '%s' ];then rm -f '%s';fi)" % \
                   (extension_config03, extension_config03)
            self.context.logger.debug("Command for cleaning extension "
                                      "library and config files: %s" % cmd)
            DefaultValue.execCommandWithMode(
                cmd, "clean extension library and config files",
                self.context.sshTool, self.context.isSingle,
                self.context.mpprcFile)
            self.context.logger.debug("Command for cleaning extension "
                                      "library and config files: %s" % cmd)
            return 0
        except Exception as e:
            self.context.logger.debug("Fail to clean extension library and "
                                      "config files.output:%s" % str(e))
            return 1

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

    def getLcgroupnameList(self, jsonFile):
        """
        function: get Lc group name list
        input: jsonFile
        output: []
        """
        para = {}
        lcgroupnamelist = []
        try:
            with open(jsonFile, "r") as fp_json:
                para = json.load(fp_json)
        except Exception as e:
            raise Exception(str(e))
        if (para):
            lcgroupnamelist = para['lcgroupnamelist']
            while '' in lcgroupnamelist:
                lcgroupnamelist.remove('')
        return lcgroupnamelist

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
                    Const.ACTION_RESTORE_CONFIG,
                    self.context.user,
                    int(float(self.context.oldClusterNumber) * 1000),
                    self.context.upgradeBackupPath,
                    self.context.oldClusterAppPath,
                    self.context.newClusterAppPath,
                    self.context.localLog)

                self.context.logger.debug("Command for restoring "
                                          "config files: %s" % cmd)
                DefaultValue.execCommandWithMode(cmd,
                                                 "restore config files",
                                                 self.context.sshTool,
                                                 self.context.isSingle,
                                                 self.context.mpprcFile)
                if self.isLargeInplaceUpgrade:
                    # backup DS libs and gds file
                    cmd = "%s -t %s -U %s --upgrade_bak_path=%s -l %s" % \
                          (OMCommand.getLocalScript("Local_Upgrade_Utility"),
                           Const.ACTION_INPLACE_BACKUP,
                           self.context.user,
                           self.context.upgradeBackupPath,
                           self.context.localLog)
                    self.context.logger.debug(
                        "Command for restoreing DS libs and gds file: %s" % cmd)
                    DefaultValue.execCommandWithMode(
                        cmd,
                        "restore DS libs and gds file",
                        self.context.sshTool,
                        self.context.isSingle,
                        self.context.userProfile)
                # change the owner of application
                cmd = "chown -R %s:%s '%s'" % \
                      (self.context.user, self.context.group,
                       self.context.newClusterAppPath)
                DefaultValue.execCommandWithMode(
                    cmd, "change the owner of application",
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
            DefaultValue.execCommandWithMode(cmd,
                                             "restore static configuration",
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
            DefaultValue.execCommandWithMode(cmd,
                                             "back up environment variables",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)

            # back up application and configuration
            cmd = "%s -U %s -P %s -p -b -l %s" % \
                  (OMCommand.getLocalScript("Local_Backup"), self.context.user,
                   self.context.upgradeBackupPath, self.context.localLog)
            self.context.logger.debug(
                "Command for backing up application: %s" % cmd)
            DefaultValue.execCommandWithMode(
                cmd, "back up application and configuration",
                self.context.sshTool, self.context.isSingle,
                self.context.mpprcFile)

        except Exception as e:
            # delete binary backup directory
            delCmd = g_file.SHELL_CMD_DICT["deleteDir"] % \
                     (self.context.tmpDir, os.path.join(self.context.tmpDir,
                                                        'backupTemp_*'))
            DefaultValue.execCommandWithMode(delCmd,
                                             "delete binary backup directory",
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
            DefaultValue.execCommandWithMode(cmd,
                                             "restore old version",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)

            # restore environment variables
            cmd = "(if [ -f '%s'_gauss ];then mv '%s'_gauss '%s';fi)" % \
                  (self.context.userProfile, self.context.userProfile,
                   self.context.userProfile)
            self.context.logger.debug("Command for restoring environment file:"
                                      " %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "restore environment variables",
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
            (status, output) = self.setGUCValue(
                "unix_socket_directory",
                DefaultValue.getTmpDirAppendMppdb(self.context.user), "set")
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] % "GUC" +
                                " Error: \n%s" % str(output))

            userProfile = DefaultValue.getMpprcFile()
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
                   (self.context.tmpDir, Const.CLUSTER_CNSCONF_FILE,
                    self.context.tmpDir, Const.CLUSTER_CNSCONF_FILE)
            cmd += "(rm -f '%s'/gauss_crontab_file_*) &&" % self.context.tmpDir
            cmd += "(if [ -d '%s' ]; then rm -rf '%s'; fi) &&" % \
                   (self.context.upgradeBackupPath,
                    self.context.upgradeBackupPath)
            cmd += "(if [ -f '%s/pg_proc_mapping.txt' ]; then rm -f" \
                   " '%s/pg_proc_mapping.txt'; fi)" % \
                   (self.context.tmpDir, self.context.tmpDir)
            self.context.logger.debug("Command for clean "
                                      "backup files: %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "clean backup files",
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
        #       Const.OPTION_PRECHECK        -> cluster Normal
        #                              -> database can connec
        #       Const.OPTION_POSTCHECK       -> cluster Normal
        #                              -> package version Normal
        #                              -> database can connec
        #######################################################################
        self.context.logger.log("Start to do health check.", "addStep")

        status = 0
        output = ""

        if (checkPosition == Const.OPTION_PRECHECK):
            if (self.checkClusterStatus(checkPosition, True) != 0):
                output += "\n    Cluster status does not match condition."
            if (self.checkConnection() != 0):
                output += "\n    Database could not be connected."
        elif (checkPosition == Const.OPTION_POSTCHECK):
            if (self.checkClusterStatus(checkPosition) != 0):
                output += "\n    Cluster status is Abnormal."
            if not self.checkVersion(
                    self.context.newClusterVersion,
                    self.context.clusterInfo.getClusterNodeNames()):
                output += "\n    The gaussdb version is inconsistent."
            if (self.checkConnection() != 0):
                output += "\n    Database could not be connected."
        else:
            # Invalid check position
            output += "\n    Invalid check position."
        if (output != ""):
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
                   Const.ACTION_CHECK_VERSION,
                   checkinfo,
                   self.context.user,
                   self.context.localLog)
            self.context.logger.debug("Command for checking gaussdb version "
                                      "consistency: %s." % cmd)
            (status, output) = \
                self.context.sshTool.getSshStatusOutput(cmd, checknodes)
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

    def checkClusterStatus(self, checkPosition=Const.OPTION_PRECHECK,
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
        cmd = "source %s;gs_om -t query" % self.context.userProfile
        (status, output) = subprocess.getstatusoutput(cmd)
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
            if checkPosition == Const.OPTION_POSTCHECK:
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
                        IsInplaceUpgrade=True)
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
        DefaultValue.execCommandWithMode(cmd,
                                         "create binary_upgrade path",
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
                                    Const.RECORD_UPGRADE_DIR)
        g_file.createFile(appDirRecord, True, DefaultValue.KEY_FILE_MODE)
        g_file.writeFile(appDirRecord, [self.context.oldClusterAppPath,
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
        DefaultValue.execCommandWithMode(cmd,
                                         "copy upgrade_version file",
                                         self.context.sshTool,
                                         self.context.isSingle,
                                         self.context.mpprcFile)

    def cleanInstallPath(self, cleanNew=Const.NEW):
        """
        function: after grey upgrade succeed, clean old install path
        input : cleanNew
        output: NA
        """
        self.context.logger.debug("Cleaning %s install path." % cleanNew,
                                  "addStep")
        # clean old install path
        if cleanNew == Const.NEW:
            installPath = self.context.newClusterAppPath
        elif cleanNew == Const.OLD:
            installPath = self.context.oldClusterAppPath
        else:
            raise Exception(ErrorCode.GAUSS_529["GAUSS_52937"])

        cmd = "%s -t %s -U %s -R %s -l %s" % \
              (OMCommand.getLocalScript("Local_Upgrade_Utility"),
               Const.ACTION_CLEAN_INSTALL_PATH,
               self.context.user,
               installPath,
               self.context.localLog)
        if self.context.forceRollback:
            cmd += " --force"
        self.context.logger.debug("Command for clean %s install path: %s" %
                                  (cleanNew, cmd))
        DefaultValue.execCommandWithMode(cmd,
                                         "clean %s install path" % cleanNew,
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
            DefaultValue.execCommandWithMode(cmd,
                                             "install new application",
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
                   Const.ACTION_BACKUP_HOTPATCH,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            DefaultValue.execCommandWithMode(cmd,
                                             "backup hotpatch files",
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
                   Const.ACTION_ROLLBACK_HOTPATCH,
                   self.context.user,
                   self.context.upgradeBackupPath,
                   self.context.localLog,
                   self.context.xmlFile)
            if self.context.forceRollback:
                cmd += " --force"
            DefaultValue.execCommandWithMode(cmd,
                                             "rollback hotpatch",
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
        DefaultValue.execCommandWithMode(cmd,
                                         "Backup old gaussdb.version file.",
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
                   Const.ACTION_COPY_CERTS,
                   self.context.user,
                   self.context.oldClusterAppPath,
                   self.context.newClusterAppPath,
                   self.context.localLog)
            self.context.logger.debug("Command for copy certs: '%s'." % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "Command for copy certs",
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

    def switchBin(self, switchTo=Const.OLD):
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
                   Const.ACTION_SWITCH_BIN,
                   self.context.user,
                   self.context.localLog)
            if switchTo == Const.NEW:
                cmd += " -R '%s'" % self.context.newClusterAppPath
            else:
                cmd += " -R '%s'" % self.context.oldClusterAppPath
            if self.context.forceRollback:
                cmd += " --force"
            self.context.logger.debug("Command for switching binary directory:"
                                      " '%s'." % cmd)
            if self.context.is_grey_upgrade:
                DefaultValue.execCommandWithMode(cmd,
                                                 "Switch the binary directory",
                                                 self.context.sshTool,
                                                 self.context.isSingle,
                                                 self.context.mpprcFile,
                                                 self.context.nodeNames)
            else:
                DefaultValue.execCommandWithMode(cmd,
                                                 "Switch the binary directory",
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
        if action == Const.ACTION_AUTO_ROLLBACK:
            self.context.logger.debug("clean other tool package files.")
        else:
            self.context.logger.debug(
                "clean other tool package files.", "addStep")
        try:
            commonPart = DefaultValue.get_package_back_name().rsplit("_", 1)[0]
            gphomePath = \
                os.listdir(DefaultValue.getClusterToolPath(self.context.user))
            commitId = self.newCommitId
            if action == Const.ACTION_AUTO_ROLLBACK:
                commitId = self.oldCommitId
            for filePath in gphomePath:
                if commonPart in filePath and commitId not in filePath:
                    toDeleteFilePath = os.path.join(
                        DefaultValue.getClusterToolPath(self.context.user),
                        filePath)
                    deleteCmd = "(if [ -f '%s' ]; then rm -rf '%s'; fi) " % \
                                  (toDeleteFilePath, toDeleteFilePath)
                    DefaultValue.execCommandWithMode(
                        deleteCmd,
                        "clean tool package files",
                        self.context.sshTool,
                        self.context.isSingle,
                        self.context.mpprcFile)
        except Exception as e:
            self.context.logger.log(
                "Failed to clean other tool package files.")
            raise Exception(str(e))
        if action == Const.ACTION_AUTO_ROLLBACK:
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
                  (DefaultValue.getClusterToolPath(self.context.user),
                   DefaultValue.getClusterToolPath(self.context.user))
            cmd += " && (chmod %d -R %s)" % \
                   (DefaultValue.KEY_DIRECTORY_MODE,
                    DefaultValue.getClusterToolPath(self.context.user))
            self.context.logger.debug(
                "Command for creating directory: %s" % cmd)
            DefaultValue.execCommandWithMode(cmd,
                                             "create gphome path",
                                             self.context.sshTool,
                                             self.context.isSingle,
                                             self.context.mpprcFile)
            oldPackName = "%s-Package-bak_%s.tar.gz" % \
                          (VersionInfo.PRODUCT_NAME_PACKAGE, self.oldCommitId)
            packFilePath = "%s/%s" % (DefaultValue.getClusterToolPath(
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
                            cmd = g_Platform.getRemoteCopyCmd(
                                packFilePath,
                                DefaultValue.getClusterToolPath(
                                    self.context.user),
                                str(copyNode), False, 'directory', node)
                            self.context.logger.debug(
                                "Command for copying directory: %s" % cmd)
                            DefaultValue.execCommandLocally(cmd)
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] %
                                packFilePath)
        except Exception as e:
            raise Exception(str(e))
