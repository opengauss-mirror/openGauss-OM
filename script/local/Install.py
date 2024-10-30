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
# Description  : Install.py is a utility to do gs_install.
#############################################################################

import getopt
import os
import sys
import subprocess
import traceback

sys.path.append(sys.path[0] + "/../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue, CmPackageException
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.LocalBaseOM import LocalBaseOM
from gspylib.common.DbClusterInfo import dbClusterInfo
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.cluster_file.cluster_log import ClusterLog
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.package_info import PackageInfo
from domain_utils.cluster_file.profile_file import ProfileFile
from domain_utils.cluster_file.version_info import VersionInfo
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_diff.comm_constants import CommConstants

#################################################################
ACTION_INSTALL_CLUSTER = "install_cluster"
ACTION_INIT_INSTNACE = "init_instance"
ACTION_CONFIG_CLUSTER = "config_cluster"
ACTION_START_CLUSTER = "start_cluster"
ACTION_CLEAN_TEMP_FILE = "clean_temp_file"
ACTION_PREPARE_CONFIG_CLUSTER = "prepare_config_cluster"
ACTION_BUILD_STANDBY = "build_standby"
ACTION_BUILD_CASCADESTANDBY = "build_cascadestandby"
#################################################################
g_opts = None


#################################################################

class CmdOptions():
    """
    class: cmdOptions
    """

    def __init__(self):
        """
        Constructor
        """
        self.action = ""
        self.installPath = ""
        self.logPath = ""
        self.tmpPath = ""
        self.user = ""
        self.group = ""
        self.clusterName = ""
        self.clusterConfig = ""
        self.mpprcFile = ""
        self.static_config_file = ""
        self.installflag = False
        self.logFile = ""
        self.alarmComponent = ""
        self.dws_mode = False
        self.upgrade = False
        self.productVersion = None
        # License mode
        self.licenseMode = None
        self.time_out = None
        self.logger = None


def usage():
    """
Usage:
  python3 --help | -?
  python3 Install.py -t action -U username:groupname -X xmlfile
  [--alarm=ALARMCOMPONENT]
  [-l logfile]
  [--dws-mode]
  [-R installPath]
  [-c clusterName]
  [-M logPath]
  [-P tmpPath]
  [-f staticConfigFile]
Common options:
  -t                                The type of action.
  -U                                The user and group name.
  -X --xmlfile = xmlfile            Cluster config file.
     --alarm = ALARMCOMPONENT       alarm component path.
     --dws-mode                     dws mode.
  -l --log-file=logfile             The path of log file.
  -R                                Install path.
  -c                                Cluster name.
  -M                                The directory of log file.
  -P                                The tmp path.
  -f                                The static_config_file.
  -? --help                         Show this help screen.
    """
    print(usage.__doc__)

def check_parameter(opts, parameter_keys, parameter_map):
    """
    function: check parameter
    input : NA
    output: NA
    """
    for key, value in opts:
        if key == "-U":
            strTemp = value
            strList = strTemp.split(":")
            if len(strList) != 2:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "U")
            if strList[0] == "" or strList[1] == "":
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "U")
            g_opts.user = strList[0]
            g_opts.group = strList[1]
        elif key in parameter_keys:
            parameter_map[key] = value
        elif key == "-t":
            g_opts.action = value
        elif key == "--dws-mode":
            g_opts.dws_mode = True
        elif key == "-u":
            g_opts.upgrade = True
        elif key == "-T":
            g_opts.installflag = True
        else:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % value)
        Parameter.checkParaVaild(key, value)
        if key in ["-c", "--alarm", "--product", "--licensemode"]:
            Parameter.check_parse(key, value)

    return parameter_map

def parseCommandLine():
    """
    function: parse input parameters
    input : NA
    output: NA
    """
    try:
        # option '-M' specify the environment parameter GAUSSLOG
        # option '-P' specify the environment parameter PGHOST|GAUSSTMP
        # option '-u' install new binary for upgrade
        opts, args = getopt.getopt(sys.argv[1:], "t:U:X:R:M:P:i:l:c:f:Tu",
                                   ["alarm=", "dws-mode", "time_out=",
                                    "product=", "licensemode="])
    except getopt.GetoptError as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(e))

    if len(args) > 0:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    parameter_map = {"-X": g_opts.clusterConfig, "-R": g_opts.installPath,
                     "-l": g_opts.logFile, "-c": g_opts.clusterName,
                     "-M": g_opts.logPath, "-P": g_opts.tmpPath,
                     "-f": g_opts.static_config_file,
                     "--alarm": g_opts.alarmComponent,
                     "--licensemode": g_opts.licenseMode,
                     "--time_out": g_opts.time_out}
    parameter_keys = parameter_map.keys()
    parameter_map = check_parameter(opts, parameter_keys, parameter_map)

    g_opts.clusterConfig = parameter_map["-X"]
    g_opts.installPath = parameter_map["-R"]
    g_opts.logFile = parameter_map["-l"]
    g_opts.clusterName = parameter_map["-c"]
    g_opts.logPath = parameter_map["-M"]
    g_opts.tmpPath = parameter_map["-P"]
    g_opts.static_config_file = parameter_map["-f"]
    g_opts.alarmComponent = parameter_map["--alarm"]
    g_opts.licenseMode = parameter_map["--licensemode"]
    g_opts.time_out = parameter_map["--time_out"]


def checkParameterEmpty(parameter, parameterName):
    """
    function: check parameter empty
    input : parameter, parameterName
    output: NA
    """
    if parameter == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                               % parameterName + ".")


def checkParameter():
    """
    function: check install parameter
    input : NA
    output: NA
    """
    if g_opts.action == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + '.')

    if (g_opts.action != ACTION_INSTALL_CLUSTER
            and g_opts.action != ACTION_PREPARE_CONFIG_CLUSTER
            and g_opts.action != ACTION_INIT_INSTNACE
            and g_opts.action != ACTION_CONFIG_CLUSTER
            and g_opts.action != ACTION_START_CLUSTER
            and g_opts.action != ACTION_CLEAN_TEMP_FILE
            and g_opts.action != ACTION_BUILD_STANDBY
            and g_opts.action != ACTION_BUILD_CASCADESTANDBY):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "t")

    if (g_opts.clusterConfig != "" and
            not os.path.exists(g_opts.clusterConfig)):
        GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50201"]
                               % g_opts.clusterConfig)

    if (g_opts.logPath != "" and not os.path.exists(g_opts.logPath)
            and not os.path.isabs(g_opts.logPath)):
        GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50219"]
                               % g_opts.logPath)

    if (g_opts.static_config_file != "" and
            not os.path.isfile(g_opts.static_config_file)):
        GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50219"]
                               % g_opts.static_config_file)

    # check mpprc file path
    g_opts.mpprcFile = EnvUtil.getMpprcFile()
    g_opts.logger = GaussLog(g_opts.logFile)
    checkParameterEmpty(g_opts.user, "U")
    g_opts.installPath = os.path.normpath(g_opts.installPath)
    g_opts.installPath = os.path.realpath(g_opts.installPath)
    g_opts.logger.log("Using " + g_opts.user + ":" + g_opts.group
                      + " to install database.")
    g_opts.logger.log("Using installation program path : "
                      + g_opts.installPath)

    if g_opts.logFile == "":
        g_opts.logFile = ClusterLog.getOMLogPath(
            ClusterConstants.LOCAL_LOG_FILE, g_opts.user, "",
            g_opts.clusterConfig)

    if g_opts.alarmComponent == "":
        g_opts.alarmComponent = DefaultValue.ALARM_COMPONENT_PATH


def createLinkToApp():
    """
    function: create link to app
    input  : NA
    output : NA
    """
    if g_opts.upgrade:
        g_opts.logger.log("Under upgrade process,"
                          " no need to create symbolic link.")
        return
    g_opts.logger.debug("Created symbolic link to $GAUSSHOME with commitid.")
    gaussHome = ClusterDir.getInstallDir(g_opts.user)
    if gaussHome == "":
        raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GAUSSHOME")
    versionFile = VersionInfo.get_version_file()
    commitid = VersionInfo.get_version_info(versionFile)[2]
    actualPath = gaussHome + "_" + commitid
    if os.path.exists(gaussHome):
        if not os.path.islink(gaussHome):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50200"] % gaussHome
                            + " Cannot create symbolic link,"
                              " please rename or delete it.")
        else:
            if os.path.realpath(gaussHome) == actualPath:
                g_opts.logger.log("$GAUSSHOME points to %s, no need to create"
                                  " symbolic link." % actualPath)
                return

    cmd = "ln -snf %s %s" % (actualPath, gaussHome)
    g_opts.logger.log("Command for creating symbolic link: %s." % cmd)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_opts.logger.log(output)
        g_opts.logger.logExit(ErrorCode.GAUSS_501["GAUSS_50107"] % "app.")
    g_opts.logger.debug("Successfully created symbolic link to"
                        " $GAUSSHOME with commitid.")


class Install(LocalBaseOM):
    """
    class: install
    """

    def __init__(self, logFile, user, clusterConf, dwsMode=False,
                 mpprcFile="", installPath="", alarmComponent="",
                 upgrade=False):
        """
        function: Constructor
        input : logFile, user, clusterConf, dwsMode, mpprcFile, installPath
                alarmComponent, upgrade
        output: NA
        """
        LocalBaseOM.__init__(self, logFile, user, clusterConf, dwsMode)

        if self.clusterConfig == "":
            # Read config from static config file
            self.readConfigInfo()
        else:
            self.clusterInfo = dbClusterInfo()
            self.clusterInfo.initFromXml(self.clusterConfig)
            hostName = NetUtil.GetHostIpOrName()
            self.dbNodeInfo = self.clusterInfo.getDbNodeByName(hostName)
            if self.dbNodeInfo is None:
                self.logger.logExit(ErrorCode.GAUSS_516["GAUSS_51619"]
                                    % hostName)
        # get user info
        self.getUserInfo()
        if user != "" and self.user != user.strip():
            self.logger.debug("User parameter : %s." % user)
            self.logger.logExit(ErrorCode.GAUSS_503["GAUSS_50315"]
                                % (self.user, self.clusterInfo.appPath))
        # init every component
        self.initComponent()

        self.mpprcFile = mpprcFile
        self.installPath = installPath
        self.alarmComponent = alarmComponent
        self.upgrade = upgrade
        # This script will be not validating the parameters.
        # Because this should be detected by which instance call
        #  this local script.
        self.productVersion = None
        self.time_out = None

    def check_clib_bin(self, clib_bin, bin_file):
        """
        Check perctrl in GPHOME clib path.
        If not in, copy if from installPath
        """
        if os.path.exists(clib_bin):
            return
        tmp_path = os.path.realpath(os.path.join(EnvUtil.getTmpDirFromEnv(g_opts.user), f'dss_app_{VersionInfo.getCommitid()}'))
        if not os.path.isdir(tmp_path):
            raise Exception(f"Cannot get {clib_bin}, no such file.")
        mv_cmd = f"mv {tmp_path}/{bin_file} {clib_bin}"
        status, output = subprocess.getstatusoutput(mv_cmd)
        if status != 0:
            self.logger.logExit(f"Failed to copy {bin_file} from {tmp_path}. Error: \n{str(output)}")
        self.logger.log(f"Successfully copy {bin_file} from {tmp_path}.")

    def link_dss_bin(self):
        '''
        The install user doesn't have the root permissions.
        Therefore, privileges escaation is not supported.
        In the preinstall process, the binary privileges is
        escalated and is linked during the install process.
        '''
        clib_app = os.path.realpath(
            os.path.join(
                EnvUtil.getEnvironmentParameterValue("GPHOME", self.user),
                'script/gspylib/clib', f'dss_app_{VersionInfo.getCommitid()}'))
        dss_app = os.path.realpath(
            os.path.join(os.path.dirname(self.installPath),
                         f'dss_app_{VersionInfo.getCommitid()}'))

        bin_path = os.path.realpath(os.path.join(self.installPath, 'bin'))
        if not os.path.isdir(bin_path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % bin_path)
        if not os.path.isdir(dss_app):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % dss_app)

        sudo_bin = ['perctrl']
        for bin_ in sudo_bin:
            clib_bin = os.path.realpath(os.path.join(clib_app, bin_))
            self.check_clib_bin(clib_bin, bin_)
            app_bin = os.path.realpath(os.path.join(dss_app, bin_))
            if os.path.isfile(clib_bin):
                mv_cmd = r'\mv {0} {1}'.format(clib_bin, app_bin)
                status, output = subprocess.getstatusoutput(mv_cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % mv_cmd +
                                    "Error:\n%s" % output)

        link_cmd = 'ln -snf {0}/perctrl {1}'.format(dss_app, bin_path)
        self.logger.debug(f"The cmd of the link: {link_cmd}.")
        status, output = subprocess.getstatusoutput(link_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % link_cmd +
                            "Error:\n%s." % output)
        self.logger.log("Successfully generated the soft link.")

    def decompress_cm_package(self):
        """
        Decompress CM package
        """
        cm_package = os.path.join(EnvUtil.getEnvironmentParameterValue(
            "GPHOME", self.user), PackageInfo.getPackageFile(
            "CM"))
        if DefaultValue.get_cm_server_num_from_static(self.clusterInfo) == 0 and \
                not os.path.isfile(cm_package):
            self.logger.log("No need to decompress cm package.")
            return

        if not DefaultValue.check_cm_package(self.clusterInfo, cm_package, self.logger):
            raise CmPackageException()
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, cm_package)
        tar_cmd = "export LD_LIBRARY_PATH=$GPHOME/script/gspylib/clib:" \
                  "$LD_LIBRARY_PATH && "
        # decompress tar file.
        decompress_cmd = tar_cmd + "tar -zxf \"" + cm_package + "\" -C \"" + \
                         self.installPath + "\""
        self.logger.log("Decompress CM package command: " + decompress_cmd)
        status, output = subprocess.getstatusoutput(decompress_cmd)
        if status != 0:
            self.logger.log("Decompress CM package failed. Output: %s" % output)
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50217"]
                                % cm_package + " Error: \n%s" % str(output))
        self.logger.log("Decompress CM package successfully.")

    def generate_dss_path(self):
        """
        Generate dss path
        """
        dss_app_path = os.path.realpath(
            os.path.join(os.path.dirname(self.installPath), f'dss_app_{VersionInfo.getCommitid()}'))
        if os.path.isdir(dss_app_path):
            self.logger.debug(f"{dss_app_path} is normal. No need to generate dss app directory.")
            return
        self.logger.debug("Try to create new dss app path.")
        FileUtil.createDirectory(dss_app_path, True, DefaultValue.KEY_DIRECTORY_MODE)
        self.logger.debug("Create dss app path successfully.")


    def generate_install_path(self):
        """
        Generate install path
        """
        if self.clusterInfo.enable_dss == "on":
            self.generate_dss_path()
        if os.path.isdir(self.installPath):
            self.logger.debug("[{0}] is normal. "
                              "No need to generate install directory.".format(self.installPath))
            return
        self.logger.debug("Try to create new app path.")
        FileUtil.createDirectory(self.installPath, True, DefaultValue.KEY_DIRECTORY_MODE)
        self.logger.debug("Try to create new app path successfully.")

    def __decompressBinPackage(self):
        """
        function: Install database binary file.
        input : NA
        output: NA
        """
        self.logger.log("Decompressing bin file.")
        tar_file = PackageInfo.getPackageFile(CommConstants.PKG_SERVER)
        # let bin executable
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, tar_file)

        cmd = "export LD_LIBRARY_PATH=$GPHOME/script/gspylib/clib:" \
              "$LD_LIBRARY_PATH && "
        # decompress tar file.
        self.generate_install_path()
        str_cmd = cmd + "tar -xpf \"" + tar_file + "\" -C \"" + \
                 self.installPath + "\""
        self.logger.debug("Decompress cmd is: %s" % str_cmd)
        status, output = subprocess.getstatusoutput(str_cmd)
        if status != 0:
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50217"]
                                % tar_file + " Error: \n%s" % str(output))

        # mv $GPHOME/script/transfer.py to $GAUSSHOME/bin/
        dirName = os.path.dirname(os.path.realpath(__file__))
        transferFile = dirName + "/../../script/transfer.py"
        if os.path.exists(transferFile):
            FileUtil.cpFile(transferFile, self.installPath + "/bin/")
            FileUtil.removeFile(transferFile)
        # cp $GPHOME/script to $GAUSSHOME/bin/
        FileUtil.cpFile(dirName + "/../../script",
                      self.installPath + "/bin/")

        # cp $GAUSSHOME/bin/script/gspylib/etc/sql/pmk to /share/postgresql
        destPath = self.installPath + "/share/postgresql/"
        pmkPath = self.installPath + "/bin/script/gspylib/etc/sql/"
        pmkFile = pmkPath + "pmk_schema.sql"
        if os.path.exists(pmkFile):
            FileUtil.cpFile(pmkFile, destPath)

        pmk_singe_inst_file = pmkPath + "pmk_schema_single_inst.sql"
        if os.path.exists(pmk_singe_inst_file):
            FileUtil.cpFile(pmk_singe_inst_file, destPath)

        # decompress CM package
        self.decompress_cm_package()

        # change owner for tar file.
        FileUtil.changeOwner(self.user, self.installPath, True)

        # link bin with cap on dss mode
        if self.clusterInfo.enable_dss == 'on':
            self.link_dss_bin()

        self.logger.log("Successfully decompressed bin file.")

    def __saveUpgradeVerionInfo(self):
        """
        function: save upgrade version info
        input: NA
        output: NA
        """
        if self.dws_mode:
            versionCfgFile = "%s/version.cfg" % DefaultValue.DWS_PACKAGE_PATH
            upgradeVersionFile = "%s/bin/upgrade_version" % self.installPath
        else:
            dirName = os.path.dirname(os.path.realpath(__file__))
            versionCfgFile = "%s/../../version.cfg" % dirName
            upgradeVersionFile = "%s/bin/upgrade_version" % self.installPath

        if not os.path.exists(versionCfgFile):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % versionCfgFile)
        if not os.path.isfile(versionCfgFile):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50210"]
                                % versionCfgFile)

        try:
            # read version info from version.cfg file
            (newClusterVersion, newClusterNumber, commitId) = \
                VersionInfo.get_version_info(versionCfgFile)
            # save version info to upgrade_version file
            if os.path.isfile(upgradeVersionFile):
                os.remove(upgradeVersionFile)

            FileUtil.createFile(upgradeVersionFile)
            FileUtil.writeFile(upgradeVersionFile,
                             [newClusterVersion, newClusterNumber, commitId])
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, upgradeVersionFile)
        except Exception as e:
            self.logger.logExit(str(e))

    def __modifyAlarmItemConfFile(self):
        """
        function: modify alarm item conf file
        input: NA
        output: NA
        """
        # modify alarmItem.conf file
        alarmItemConfigFile = "%s/bin/alarmItem.conf" % self.installPath
        if not os.path.exists(alarmItemConfigFile):
            self.logger.log("Alarm's configuration file %s does not exist."
                            % alarmItemConfigFile)
            return

        self.logger.log("Modifying Alarm configuration.")
        FileUtil.replaceFileLineContent("^.*\(alarm_component.*=.*\)", "#\\1",
                                      alarmItemConfigFile)
        FileUtil.writeFile(alarmItemConfigFile, ['    '])
        FileUtil.writeFile(alarmItemConfigFile, ['alarm_component = %s'
                                               % self.alarmComponent])

    def __set_manual_start(self):
        """
        function: Set manual start:
                  1.set cluster_manual_start
                  2.set etcd_manual_start
        input : NA
        output: NA
        """
        if self.upgrade:
            return
        cluster_manual_start_file = "'%s'/bin/cluster_manual_start" % self.installPath
        FileUtil.createFile(cluster_manual_start_file)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, cluster_manual_start_file)

    def __createStaticConfig(self):
        """
        function: Save cluster info to static config
        input : NA
        output: NA
        """
        staticConfigPath = "%s/bin/cluster_static_config" % self.installPath
        # save static config
        nodeId = self.dbNodeInfo.id
        self.clusterInfo.saveToStaticConfig(staticConfigPath, nodeId)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, staticConfigPath)
        FileUtil.changeOwner(self.user, staticConfigPath, False)

    def __bakInstallPackage(self):
        """
        function: backup install package for replace
        input : NA
        output: NA
        """
        dirName = os.path.dirname(os.path.realpath(__file__))
        packageFile = "%s/%s" % (os.path.join(dirName, "./../../"),
                                 PackageInfo.get_package_back_name())
        # Check if MPPDB package exist
        if not os.path.exists(packageFile):
            self.logger.logExit(ErrorCode.GAUSS_502["GAUSS_50201"]
                                % 'MPPDB package' + " Can not back up.")
        # Save MPPDB package to bin path
        destPath = "'%s'/bin/" % self.installPath
        FileUtil.cpFile(packageFile, destPath)

    def __fixInstallPathPermission(self):
        """
        function: fix the whole install path's permission
        input : NA
        output: NA
        """
        installPathFileTypeDict = {}
        try:
            # get files type
            installPathFileTypeDict = FileUtil.getFilesType(self.installPath)
        except Exception as e:
            self.logger.logExit(str(e))

        for key in installPathFileTypeDict:
            if not os.path.exists(key):
                self.logger.debug("[%s] does not exist. Please skip it."
                                  % key)
                continue
            if os.path.islink(key):
                self.logger.debug("[%s] is a link file. Please skip it."
                                  % key)
                continue
            # skip DbClusterInfo.pyc
            if os.path.basename(key) == "DbClusterInfo.pyc":
                continue
            if (installPathFileTypeDict[key].find("executable") >= 0 or
                    installPathFileTypeDict[key].find("ELF") >= 0 or
                    installPathFileTypeDict[key].find("directory") >= 0):
                FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, key, True)
            else:
                FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, key)

    def __setCgroup(self):
        """
        function: copy cgroup config file to gausshome which generated at
                  preinstall step.
        input : NA
        output: NA
        """
        self.logger.log("Set Cgroup config file to appPath.")

        source_path = os.path.join(os.getenv("GPHOME"),
            self.user, "etc")
        target_path = os.path.join(self.installPath, "etc")
        cmd = "cp %s/* %s" % (source_path, target_path)
        self.logger.debug("set cgroup at install step cmd: %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.debug("set cgroup at install step result: %s" % output)

        self.logger.log("Successfully Set Cgroup.")

    def __changeEnv(self):
        """
        function: Change GAUSS_ENV
        input : NA
        output: NA
        """
        # modified user's environmental variable $GAUSS_ENV
        self.logger.log("Modifying user's environmental variable $GAUSS_ENV.")
        ProfileFile.updateUserEnvVariable(self.mpprcFile, "GAUSS_ENV", "2")
        ProfileFile.updateUserEnvVariable(self.mpprcFile, "GS_CLUSTER_NAME",
                                           g_opts.clusterName)
        self.logger.log("Successfully modified user's environmental"
                        " variable $GAUSS_ENV.")

    def __fixFilePermission(self):
        """
        function: modify permission for app path
        input: NA
        ouput: NA
        """
        self.logger.log("Fixing file permission.")
        binPath = "'%s'/bin" % self.installPath
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, binPath, True)
        libPath = "'%s'/lib" % self.installPath
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, libPath, True)
        sharePath = "'%s'/share" % self.installPath
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, sharePath, True)
        etcPath = "'%s'/etc" % self.installPath
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, etcPath, True)
        includePath = "'%s'/include" % self.installPath
        FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, includePath, True)

        tarFile = "'%s'/bin/'%s'" % (self.installPath,
                                     PackageInfo.get_package_back_name())
        if (os.path.isfile(tarFile)):
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, tarFile)

        # ./script/util/*.conf *.service
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/script/gspylib/etc/conf/check_list.conf"
                          % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/script/gspylib/etc/conf/"
                          "check_list_dws.conf" % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/script/gspylib/etc/conf/gs-OS-set.service"
                          % self.installPath)
        # bin config file
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/alarmItem.conf" % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/cluster_guc.conf" % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/upgrade_version" % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/retry_errcodes.conf" % self.installPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/bin/cluster_static_config" % self.installPath)

        # ./script/local/*.sql
        cmd = "find '%s'/bin/script -type f -name \"*.sql\" -exec" \
              " chmod 600 {} \\;" % self.installPath
        # ./lib files
        cmd += " && find '%s'/lib/ -type f -exec chmod 600 {} \\;" \
               % self.installPath
        # ./share files
        cmd += " && find '%s'/share/ -type f -exec chmod 600 {} \\;" \
               % self.installPath
        self.logger.debug("Command: %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.log(output)
            self.logger.logExit(ErrorCode.GAUSS_501["GAUSS_50107"] % "app.")

    def installCluster(self):
        """
        function: install application
        input : NA
        output: NA
        """
        self.__decompressBinPackage()
        self.__saveUpgradeVerionInfo()
        self.__modifyAlarmItemConfFile()
        self.__set_manual_start()
        self.__createStaticConfig()
        if not self.dws_mode:
            self.__bakInstallPackage()
        self.__fixInstallPathPermission()
        self.__changeEnv()
        self.__fixFilePermission()
        self.__setCgroup()

    def startCluster(self):
        """
        function: start cluster
        input: NA
        output: NA
        """
        for dn in self.dnCons:
            dn.start(self.time_out)

    def buildStandby(self):
        """
        function: build standby
        input: NA
        output: NA
        """
        for dn in self.dnCons:
            if dn.instInfo.instanceType == DefaultValue.STANDBY_INSTANCE:
                dn.build()

    def buildCascadeStandby(self):
        """
        function: build standby
        input: NA
        output: NA
        """
        for dn in self.dnCons:
            if dn.instInfo.instanceType == DefaultValue.CASCADE_STANDBY:
                dn.build_cascade()

    def cleanTempFile(self):
        """
        function: clean temp file
        input: NA
        output: NA
        """
        filename = "/tmp/temp.%s" % self.user
        try:
            if os.path.isfile(filename):
                FileUtil.removeFile(filename)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"]
                            % ("file [%s]" % filename))


if __name__ == '__main__':
    ##########################################################################
    # This is the main install flow.
    ##########################################################################
    """
    function: install the cluster
    input : NA
    output: NA
    """
    try:
        # Initialize self and Parse command line and save to global variable
        parseCommandLine()
        # check the parameters is not OK
        checkParameter()
        createLinkToApp()
        # Initialize globals parameters
        installer = Install(g_opts.logFile, g_opts.user, g_opts.clusterConfig,
                            g_opts.dws_mode, g_opts.mpprcFile,
                            g_opts.installPath, g_opts.alarmComponent,
                            g_opts.upgrade)
        installer.productVersion = g_opts.productVersion
        installer.time_out = g_opts.time_out
        try:
            functionDict = {ACTION_INSTALL_CLUSTER: installer.installCluster,
                            ACTION_START_CLUSTER: installer.startCluster,
                            ACTION_CLEAN_TEMP_FILE: installer.cleanTempFile,
                            ACTION_BUILD_STANDBY: installer.buildStandby,
                            ACTION_BUILD_CASCADESTANDBY:
                                installer.buildCascadeStandby}
            functionKeys = functionDict.keys()

            if g_opts.action in functionKeys:
                functionDict[g_opts.action]()
            else:
                g_opts.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50004"] % 't'
                                      + " Value: %s." % g_opts.action)
        except Exception as e:
            g_opts.logger.log(traceback.format_exc())
            g_opts.logger.logExit(str(e))

        # close the log file
        g_opts.logger.closeLog()
    except Exception as e:
        GaussLog.exitWithError(str(e))

    sys.exit(0)
