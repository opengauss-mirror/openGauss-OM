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
# Description  : gs_install is a utility to deploy a Gauss200 server.
#############################################################################
import subprocess
import os
import sys
import re

sys.path.append(sys.path[0] + "/../../../")
from gspylib.common.Common import DefaultValue
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.os.gsfile import g_file
from impl.install.InstallImpl import InstallImpl
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from domain_utils.cluster_file.version_info import VersionInfo
from gspylib.component.DSS.dss_checker import DssConfig
from base_utils.os.cmd_util import CmdUtil
from gspylib.component.DSS.dss_comp import UdevContext

ROLLBACK_FAILED = 3

# Action type
ACTION_INSTALL_CLUSTER = "install_cluster"


class InstallImplOLAP(InstallImpl):
    """
    The class is used to do perform installation
    """
    """
    init the command options
    save command line parameter values
    """

    def __init__(self, install):
        """
        function: constructor
        """
        super(InstallImplOLAP, self).__init__(install)

    def checkTimeout(self):
        """
        function: check timeout
        input: NA
        output: NA
        """
        if (self.context.time_out is None):
            # if --time-out is null
            self.context.time_out = DefaultValue.TIMEOUT_CLUSTER_START
        else:
            if (not str(self.context.time_out).isdigit()):
                # --time-out is not a digit
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50003"] % (
                    "-time-out", "a nonnegative integer"))
            self.context.time_out = int(self.context.time_out)
            if (
                    self.context.time_out <= 0
                    or self.context.time_out >= 2147483647):
                # --time-out is not a int
                raise Exception(
                    ErrorCode.GAUSS_500["GAUSS_50004"] % "-time-out")

    def deleteTempFileForUninstall(self):
        """
        function: Rollback install ,delete temporary file
        input : NA
        output: NA
        """
        # Deleting temporary file
        self.context.logger.debug("Deleting temporary file.")
        tmpFile = "/tmp/temp.%s" % self.context.user
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (tmpFile, tmpFile)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.debug("Successfully deleted temporary file.")

    def prepareInstallCluster(self):
        """
         function: prepared install cluster
                 AP: distribute package
                 and Check installation environment on all nodes
                 TP: skip
        """
        if (not self.context.dws_mode and not self.context.isSingle):
            # distribute package to every host
            self.context.distributeFiles()
        self.checkNodeInstall()

    def getCommandOptions(self):
        """
        function: get command options
        input: NA
        output: NA
        """
        opts = ""
        if self.context.alarm_component != "":
            opts += " --alarm=%s " % self.context.alarm_component
        if self.context.time_out is not None:
            opts += " --time_out=%d " % self.context.time_out
        return opts

    def prepareConfigCluster(self):
        """
        function: install cluster instance
        input : NA
        output: NA
        """
        self.context.cleanNodeConfig()
        is_dss_mode = self.context.clusterInfo.enable_dss == 'on'
        self.reset_lun_device(is_dss_mode)
        self.create_dss_vg(is_dss_mode)
        self.checkNodeConfig()

    def checkNodeConfig(self):
        """
        function: Check node config on all nodes
        input : NA
        output: NA
        """
        self.context.logger.log("Checking node configuration on all nodes.")
        # Check node config on all nodes
        cmdParam = ""
        for param in self.context.dataGucParam:
            cmdParam += " -D \\\"%s\\\"" % param

        cmd = "source %s;" % self.context.mpprcFile
        cmd += "%s -U %s -l %s %s" % (
            OMCommand.getLocalScript("Local_Check_Config"), self.context.user,
            self.context.localLog, cmdParam)
        self.context.logger.debug(
            "Command for checking node configuration: %s." % cmd)

        cmd = self.singleCmd(cmd)

        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.debug("Successfully checked node configuration.")

    def checkNodeInstall(self):
        """
        function: check node install
        input: NA
        output: NA
        """
        self.context.logger.debug("Checking node's installation.", "constant")
        # Checking node's installation
        self.context.logger.log(
            "Checking the installation environment on all nodes.", "constant")
        # Checking the installation environment
        cmd = "source %s;" % self.context.mpprcFile
        cmd += "%s -U %s -R %s -l %s -X %s" % (
            OMCommand.getLocalScript("Local_Check_Install"),
            self.context.user + ":" + self.context.group,
            self.context.clusterInfo.appPath,
            self.context.localLog, self.context.xmlFile)
        self.context.logger.debug(
            "Command for checking installation: %s." % cmd)

        cmd = self.singleCmd(cmd)

        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.debug("Successfully checked node's installation.",
                                  "constant")

    def create_dss_vg(self, is_dss_mode=False):
        '''
        Create a VG on the first node.
        '''
        if not is_dss_mode:
            self.context.logger.debug(
                'The mode is non-dss, no need to create the dss vg.')
            return

        self.context.logger.log('Start to create the dss vg.')
        for vgname, dss_disk in UdevContext.get_all_vgname_disk_pair(
                self.context.clusterInfo.dss_shared_disks,
                self.context.clusterInfo.dss_pri_disks,
                self.context.user).items():
            au_size = '4096'
            if dss_disk.find('shared') == -1:
                au_size = '65536'
            source_cmd = "source %s; " % self.context.mpprcFile
            show_cmd = source_cmd + f'dsscmd showdisk -g {vgname} -s vg_header'
            cv_cmd = source_cmd + f'dsscmd cv -g {vgname} -v {dss_disk} -s {au_size}'
            self.context.logger.debug(
                'The cmd of the showdisk: {}.'.format(show_cmd))
            self.context.logger.debug('The cmd of the cv: {}.'.format(cv_cmd))

            sts, out = subprocess.getstatusoutput(show_cmd)
            if sts == 0:
                if out.find('vg_name = {}'.format(vgname)) > -1:
                    self.context.logger.debug(
                        'volume group {} mounted'.format(dss_disk))
                else:
                    sts, out = CmdUtil.retry_exec_by_popen(cv_cmd)
                    if sts:
                        self.context.logger.debug(
                            'The volume {} is successfully created. Result: {}'.
                            format(dss_disk, str(out)))
                    else:
                        raise Exception(
                            ErrorCode.GAUSS_512['GAUSS_51257'] +
                            "Failed to create the volume: {}".format(str(out)))
            else:
                raise Exception(
                    ErrorCode.GAUSS_512['GAUSS_51257'] +
                    "Failed to query the volume using dsscmd, cmd: {}, Error: {}"
                    .format(show_cmd, out.strip()))
        self.context.logger.log("End to create the dss vg.")

    def reset_lun_device(self, is_dss_mode=False):
        '''
        Low-level user disk with dd
        '''
        if not is_dss_mode:
            self.context.logger.debug(
                'The mode is non-dss, no need to clear the disk.')
            return

        self.context.logger.log("Start to clean up the dss luns.")
        infos = list(
            filter(None, re.split(r':|,',
                                  self.context.clusterInfo.dss_vg_info)))
        dss_devs = list(map(os.path.realpath, infos[1::2]))
        cm_devs = list(
            map(os.path.realpath, [
                self.context.clusterInfo.cm_vote_disk,
                self.context.clusterInfo.cm_share_disk
            ]))

        self.context.logger.debug(
            "The luns are about to be cleared, contains: {}.".format(
                ', '.join(cm_devs + dss_devs)))

        cmd = []
        for ds in dss_devs:
            cmd.append('dd if=/dev/zero bs=64K count=1024 of={}'.format(ds))
        for cs in cm_devs:
            cmd.append('dd if=/dev/zero bs=1M count=256 of={}'.format(cs))
        self.context.logger.debug("Clear lun cmd: {}.".format(' && '.join(cmd)))

        CmdExecutor.execCommandLocally(' && '.join(cmd))
        self.context.logger.log("End to clean up the dss luns.")

    def initNodeInstance(self):
        """
        function: init instance applications
        input : NA
        output: NA
        """
        self.context.logger.log("Initializing instances on all nodes.")
        # init instance applications
        cmdParam = ""
        # get the --gsinit-parameter parameter values
        for param in self.context.dbInitParam:
            cmdParam += " -P \\\"%s\\\"" % param

        cmd = "source %s;" % self.context.mpprcFile
        # init instances on all nodes
        cmd += "%s -U %s %s -l %s" % (
            OMCommand.getLocalScript("Local_Init_Instance"), self.context.user,
            cmdParam, self.context.localLog)

        if self.context.clusterInfo.enable_dcf == 'on':
            cmd += " --paxos_mode"
        elif self.context.clusterInfo.enable_dss == 'on':
            dss_config = DssConfig.get_value_b64_handler(
                'dss_nodes_list', self.context.clusterInfo.dss_config)
            cmd += f" --dss_mode --dss_config={dss_config}"
            if self.context.dorado_cluster_mode != "":
                cmd += f" --dorado_cluster_mode={self.context.dorado_cluster_mode}"
        self.context.logger.debug(
            "Command for initializing instances: %s" % cmd)

        cmd = self.singleCmd(cmd)

        parallelism = False if self.context.clusterInfo.enable_dss == 'on' else True
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        parallelism=parallelism)
        self.context.logger.debug("Successfully initialized node instance.")

    def configInstance(self):
        """
        function: config instance
        input : NA
        output: NA
        """
        # config instance applications
        if self.context.clusterInfo.float_ips:
            self.config_cm_res_json()
        self.updateInstanceConfig()
        self.updateHbaConfig()

    def checkMemAndCores(self):
        """
        function: memCheck and coresCheck
        input  : NA
        output : False/True
        """
        self.context.logger.log(
            "Check consistence of memCheck and coresCheck on database nodes.")
        self.context.logger.debug(
            "Check whether the memory "
            "and CPU cores of database nodes meet the requirements.")
        self.context.logger.debug("If all database nodes meet follows : ")
        self.context.logger.debug("memory=128G and CPU logic_cores=16")
        self.context.logger.debug(
            "Then we don't use default guc set xmlFile : guc_list.xml")
        checkConsistence = False
        data_check_info = {}
        if self.context.isSingle:
            return False
        all_dn = []
        for dataNode in self.context.clusterInfo.dbNodes:
            if len(dataNode.datanodes) > 0:
                all_dn.append(dataNode)
        self.context.logger.debug(
            "Check consistence of memCheck and coresCheck on database node: %s"
            % [node.name for node in all_dn])
        for dbNode in all_dn:
            memCheck = "cat /proc/cpuinfo | grep processor | wc -l"
            coresCheck = "free -g --si | grep 'Mem' | awk -F ' ' '{print \$2}'"
            cmd = "pssh -s -H %s \"%s & %s\"" % (
                dbNode.name, memCheck, coresCheck)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0 or len(output.strip().split()) != 2:
                self.context.logger.debug(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                    + " Error: \n%s" % str(
                        output))
                raise Exception(
                    ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                    + " Error: \n%s" % str(
                        output))
            data_check_info[dbNode.name] = str(output).strip().split()
        self.context.logger.debug(
            "The check info on each node. \nNode : Info(MemSize | CPUCores)")
        for each_node, check_info in data_check_info.items():
            self.context.logger.debug("%s : %s" % (each_node, check_info))
        try:
            if len(set([",".join(value) for value in
                        list(data_check_info.values())])) == 1:
                coresNum = int(list(data_check_info.values())[0][0])
                memSize = int(list(data_check_info.values())[0][1])
                if (coresNum == 16 and memSize >= 124 and memSize <= 132):
                    checkConsistence = True
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53023"] % str(e))
        self.context.logger.log(
            "Successful check consistence of memCheck "
            "and coresCheck on all nodes.")
        return checkConsistence

    def updateInstanceConfig(self):
        """
        function: Update instances config on all nodes
        input : NA
        output: NA
        """
        self.context.logger.log(
            "Updating instance configuration on all nodes.")
        # update instances config on all nodes
        cmd_param = ""
        para_list_dn = [param.split('=')[0].strip() for param in
                      self.context.dataGucParam]
        if "autovacuum" not in para_list_dn:
            self.context.dataGucParam.append("autovacuum=on")

        # get the --dn-guc parameter values
        for param in self.context.dataGucParam:
            cmd_param += "*==SYMBOL==*-D*==SYMBOL==*%s" % param
        for param in self.context.cm_server_guc_param:
            cmd_param += "*==SYMBOL==*-S*==SYMBOL==*%s" % param
        # check the --alarm-component parameter
        if self.context.alarm_component != "":
            cmd_param += "*==SYMBOL==*--alarm=%s" % self.context.alarm_component
        if self.context.clusterInfo.enable_dcf == "on":
            cmd_param += "*==SYMBOL==*-D*==SYMBOL==*%s" % (
                    "enable_dcf=" + self.context.clusterInfo.enable_dcf)
            if not self.context.clusterInfo.hasNoCm():
                cmd_param += "*==SYMBOL==*-S*==SYMBOL==*%s" % (
                    "enable_dcf=" + self.context.clusterInfo.enable_dcf)
            cmd_param += "*==SYMBOL==*-D*==SYMBOL==*%s" % (
                    "dcf_config=" + self.context.clusterInfo.dcf_config.replace('"', '\\"'))
            cmd_param += "*==SYMBOL==*-X*==SYMBOL==*%s" % (self.context.xmlFile)
        # create tmp file for guc parameters
        # comm_max_datanode and max_process_memory
        self.context.logger.debug("create tmp_guc file.")
        tmp_guc_path = EnvUtil.getTmpDirFromEnv(self.context.user)
        tmp_guc_file = "%s/tmp_guc" % tmp_guc_path
        cmd = g_file.SHELL_CMD_DICT["createFile"] % (
            tmp_guc_file, DefaultValue.MAX_DIRECTORY_MODE, tmp_guc_file)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Create tmp_guc file successfully.")

        # get the master datanode number
        primary_dn_num = DefaultValue.getPrimaryDnNum(self.context.clusterInfo)
        self.context.logger.debug(
            "get master datanode number : %s" % primary_dn_num)
        # get the physic memory of all node and choose the min one
        physic_memo = DefaultValue.getPhysicMemo(self.context.sshTool,
                                                self.context.isSingle)
        self.context.logger.debug("get physic memory value : %s" % physic_memo)
        # get the datanode number in all nodes and choose the max one
        data_node_num = DefaultValue.getDataNodeNum(self.context.clusterInfo)
        self.context.logger.debug("get min datanode number : %s" % data_node_num)

        # write the value in tmp file
        self.context.logger.debug("Write value in tmp_guc file.")
        guc_value_content = str(primary_dn_num) + "," + str(
            physic_memo) + "," + str(data_node_num)
        cmd = g_file.SHELL_CMD_DICT["overWriteFile"] % (
            guc_value_content, tmp_guc_file)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle,
                                        self.context.mpprcFile)
        self.context.logger.debug("Write tmp_guc file successfully.")

        # update instances config
        cmd = "source %s;" % self.context.mpprcFile
        cmd += "%s " % (OMCommand.getLocalScript("Local_Config_Instance"))
        para_line = \
            "*==SYMBOL==*-U*==SYMBOL==*%s%s*==SYMBOL==*-l*==SYMBOL==*%s" % (
                self.context.user, cmd_param, self.context.localLog)
        # get the --gucXml parameter
        if self.checkMemAndCores():
            para_line += "*==SYMBOL==*--gucXml"
        para_line += "*==SYMBOL==*-X*==SYMBOL==*%s" % self.context.xmlFile
        cmd += DefaultValue.encodeParaline(para_line, DefaultValue.BASE_ENCODE)

        self.context.logger.debug(
            "Command for updating instances configuration: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.debug("Successfully configured node instance.")

    def config_cm_res_json(self):
        """
        Config cm resource json file.
        """
        self.context.logger.log("Configuring cm resource file on all nodes.")
        cmd = "source %s; " % self.context.mpprcFile
        cmd += "%s -t %s -U %s -X '%s' -l '%s' " % (
               OMCommand.getLocalScript("Local_Config_CM_Res"), ACTION_INSTALL_CLUSTER,
               self.context.user, self.context.xmlFile, self.context.localLog)
        self.context.logger.debug(
            "Command for configuring cm resource file: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.log("Successfully configured cm resource file.")

    def updateHbaConfig(self):
        """
        function: config Hba instance
        input : NA
        output: NA
        """
        self.context.logger.log("Configuring pg_hba on all nodes.")

        # Configuring pg_hba
        cmd = "source %s;" % self.context.mpprcFile
        cmd += "%s -U %s -X '%s' -l '%s' " % (
            OMCommand.getLocalScript("Local_Config_Hba"), self.context.user,
            self.context.xmlFile, self.context.localLog)
        self.context.logger.debug(
            "Command for configuring Hba instance: %s" % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.context.sshTool,
                                        self.context.isSingle)
        self.context.logger.debug("Successfully configured HBA.")

    def rollbackInstall(self):
        """
        function: Rollback install
        input : NA
        output: NA
        0 succeed
        1 failed
        2 rollback succeed
        3 rollback failed
        """
        # Rollback install
        self.context.logger.log("Rolling back.")
        try:
            self.deleteTempFileForUninstall()
            # Rollback install
            cmd = "source %s;" % self.context.mpprcFile
            cmd += "%s -U %s -R '%s' -l '%s' -T --delete-static-file" % (
                OMCommand.getLocalScript("Local_Uninstall"), self.context.user,
                os.path.realpath(self.context.clusterInfo.appPath),
                self.context.localLog)
            self.context.logger.debug("Command for rolling back: %s." % cmd)
            # exec the cmd for rollback
            (status, output) = self.context.sshTool.getSshStatusOutput(cmd)
            for ret in list(status.values()):
                if (ret != DefaultValue.SUCCESS):
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                    cmd + "Error:\n%s" % str(output))
            self.context.logger.debug(output)
        except Exception as e:
            # failed to roll back
            self.context.logger.error(str(e))
            sys.exit(ROLLBACK_FAILED)
        # Rollback succeeded
        self.context.logger.log("Rollback succeeded.")

    def checkPgLogFileMode(self):
        """
        function: change pg_log file mode
        input : NA
        output: NA
        """
        try:
            userDir = "%s/%s" % (
                self.context.clusterInfo.logPath, self.context.user)
            # change log file mode
            FileUtil.getchangeFileModeCmd(userDir)
        except Exception as e:
            raise Exception(str(e))

    def checkClusterStatus(self):
        """
        function: Check if cluster is running
        input : NA
        output: NA
        """
        # Check if cluster is running
        self.context.logger.debug("Checking the cluster status.", "addStep")
        try:
            self.context.cmCons[0].queryClusterStatus()
            # You can find the cluster status, indicating that the cluster is installed,
            # and exit the error.
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51625"] + " Can not do install now.")
        except Exception as _:
            self.context.logger.debug("Successfully checked the cluster status.", "constant")

    def check_cm_server_node_number(self):
        """
        Check CM server node number
        """
        cm_server_number = DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo)

        if self.context.clusterInfo.enable_dss == 'on':
            if cm_server_number < 1:
                raise Exception(ErrorCode.GAUSS_527["GAUSS_52708"] %
                                "CM server number" +
                                " CM server number must be more than 0.")
            return

        if 0 < cm_server_number < 2:
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52708"] % "CM server number" +
                "CM server number must be more than 2.")
        elif cm_server_number > 0 and len(self.context.clusterInfo.dbNodes) < 2:
            raise Exception(
                ErrorCode.GAUSS_527["GAUSS_52708"] % "CM server node number" +
                "The number of cluster nodes configured with cm_server instances "
                "cannot be less than 3.")

    def singleCmd(self, cmd):
        """
        function: remove symbol \ if in single mode.
        input : cmd
        output: str
        """
        # remove symbol \ if in single mode.
        if (self.context.isSingle):
            cmd = cmd.replace("\\", "")
        return cmd

    def deleteSymbolicAppPath(self):
        """
        function: delete symbolic app path
        input  : NA
        output : NA
        """
        self.context.logger.debug("Delete symbolic link $GAUSSHOME.")
        versionFile = VersionInfo.get_version_file()
        commitid = VersionInfo.get_version_info(versionFile)[2]
        cmd = "rm -rf %s" % self.context.clusterInfo.appPath
        self.context.clusterInfo.appPath = \
            self.context.clusterInfo.appPath + "_" + commitid
        CmdExecutor.execCommandWithMode(cmd, self.context.sshTool,
                                         self.context.isSingle,
                                         self.context.mpprcFile)
        self.context.logger.debug(
            "Successfully delete symbolic link $GAUSSHOME, cmd: %s." % cmd)

    def create_ca_for_cm(self):
        """
        Create CM CA file
        """
        if DefaultValue.get_cm_server_num_from_static(self.context.clusterInfo) == 0:
            self.context.logger.log("NO cm_server instance, no need to create CA for CM.")
            return
        local_cm = [cm_component for cm_component in self.context.cmCons
                    if cm_component.instInfo.hostname ==
                    NetUtil.GetHostIpOrName()][0]

        local_cm.create_cm_ca(self.context.sshTool)

    def create_ca_for_dss(self):
        '''
        Create DSS CA file
        '''
        dss_mode = True if self.context.clusterInfo.enable_dss == 'on' else False
        dss_ssl_enable = True if self.context.clusterInfo.dss_ssl_enable == 'on' else False

        if dss_mode and dss_ssl_enable and DefaultValue.get_cm_server_num_from_static(
                self.context.clusterInfo) > 0:
            local_cm = [
                cm_component for cm_component in self.context.cmCons
                if cm_component.instInfo.hostname == NetUtil.GetHostIpOrName()
            ][0]

            local_cm.create_cm_ca(self.context.sshTool, ca_org='dss')
        elif dss_mode and dss_ssl_enable and DefaultValue.get_cm_server_num_from_static(
                self.context.clusterInfo) == 0:
            raise Exception(
                'The DSS mode does not support cluster installation without cm.'
            )
        elif not dss_ssl_enable:
            self.context.logger.log(
                "Non-dss_ssl_enable, no need to create CA for DSS")
