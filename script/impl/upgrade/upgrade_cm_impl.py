# -*- coding:utf-8 -*-
import subprocess
import sys
import os
import time

sys.path.append(sys.path[0] + "/../../")
import impl.upgrade.UpgradeConst as Const
from impl.upgrade.UpgradeImpl import UpgradeImpl
from base_utils.os.env_util import EnvUtil

from gspylib.os.gsfile import g_file
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.OMCommand import OMCommand
from gspylib.common.Common import DefaultValue


class UpgradeCmImpl(UpgradeImpl):
    """
    Upgrade CM component implement
    """
    def __init__(self, upgrade_context):
        super(UpgradeCmImpl, self).__init__(upgrade_context)
        self.upgrade_context = upgrade_context
        self.logger = self.upgrade_context.logger
        self.cluster_info = None
        self.ssh_tool = None
        self.dest_package_path = ""
        self.origin_cluster_state = ""
        self.package_random_number = ""

    def check_upgrade_cm_parameter(self):
        """
        Check upgrade parameter
        """
        if not self.upgrade_context.upgrade_package:
            self.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50001"] % "--package-package")
        if not os.path.isfile(self.upgrade_context.upgrade_package):
            self.logger.logExit(ErrorCode.GAUSS_500["GAUSS_50004"] % "--package-package" + 
                                "File [%s] not exist." % self.upgrade_context.upgrade_package)

    def get_cm_current_version(self):
        """
        Get CM current version
        """
        cmd = "source {0}; cm_ctl -V".format(EnvUtil.getMpprcFile())
        status, output = subprocess.getstatusoutput(cmd)
        self.logger.debug("Get CM version result: {0}".format(output))
        if status != 0 or "build" not in output or "openGauss" not in output:
            self.logger.warn("cm_ctl error: {0}".format(output))
            return "no_version"
        return output.strip().split("build")[1].split(")")[0].strip()

    def init_global(self):
        """
        Initialize global value
        """
        self.upgrade_context.initClusterInfoFromStaticFile(self.upgrade_context.user)
        self.upgrade_context.initSshTool(self.upgrade_context.clusterInfo.getClusterNodeNames(),
                                         timeout=300)
        self.cluster_info = self.upgrade_context.clusterInfo
        self.ssh_tool = self.upgrade_context.sshTool
        tmp_path = EnvUtil.getEnv("PGHOST")
        version = self.get_cm_current_version()
        version = version if version else "empty_version"
        time_stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(time.time()))

        pkg_name_list = os.path.basename(self.upgrade_context.upgrade_package).split(".")
        package_perfix = [real_name.strip() for real_name in pkg_name_list if real_name.strip()][0]
        self.package_random_number = "{0}-{1}".format(version, time_stamp)
        upgrade_package_name = "{0}-{1}.tar.gz".format(package_perfix, time_stamp)

        self.dest_package_path = os.path.join(tmp_path, upgrade_package_name)

    def send_cm_package(self):
        """
        Send CM package to all nodes
        """
        self.logger.log("Ready to transform CM package to all nodes.")
        self.logger.debug("CM package send to: {0}".format(self.dest_package_path))

        self.ssh_tool.scpFiles(self.upgrade_context.upgrade_package, self.dest_package_path)
        self.logger.log("Send CM package to all nodes successfully.")

    def record_origin_cluster_state(self):
        """
        Reccord origin cluster state
        """
        self.logger.log("Start to record origin cluster state.")
        cmd = "source {0} ; cm_ctl query | grep cluster_state".format(EnvUtil.getMpprcFile())
        state_level_dict = {DefaultValue.CLUSTER_STATUS_UNAVAILABLE: 3,
                            DefaultValue.CLUSTER_STATUS_DEGRADED: 2,
                            DefaultValue.CLUSTER_STATUS_NORMAL: 1}
        start_time = time.time()
        end_time = start_time + 20
        while time.time() < end_time:
            status, output = subprocess.getstatusoutput(cmd)
            cluster_state = output.split(":")[-1].strip()
            self.logger.debug("Current cluster state: [{0}]".format(cluster_state))
            if status != 0 \
                    or cluster_state not in state_level_dict \
                    or cluster_state == DefaultValue.CLUSTER_STATUS_UNAVAILABLE:
                self.origin_cluster_state = DefaultValue.CLUSTER_STATUS_UNAVAILABLE
                break
            elif self.origin_cluster_state:
                if state_level_dict.get(cluster_state) != \
                        state_level_dict.get(self.origin_cluster_state):
                    self.origin_cluster_state = cluster_state
                else:
                    self.logger.debug("Get origin cluster stat finish. "
                                      "Origin state: [{0}]".format(self.origin_cluster_state))
                    break
            else:
                self.origin_cluster_state = cluster_state
                break
            time.sleep(2)
        self.logger.log("Cluster origin state is : [{0}]".format(self.origin_cluster_state))

    def prepare_upgrade_cm(self):
        """
        Backup CM on every node
        """
        self.logger.log("Start to prepare CM component files on all nodes.")
        cmd = "{0} -t {1} --upgrade-package {2} " \
              "--backup-version {3}".format(OMCommand.getLocalScript("Local_Upgrade_CM"),
                                            Const.ACTION_UPGRADE_PREPARE_UPGRADE_CM,
                                            self.dest_package_path,
                                            self.package_random_number)
        self.logger.debug("Command for prepare CM files : {0}.".format(cmd))
        self.ssh_tool.executeCommand(cmd)
        self.logger.log("Prepare upgrade CM component files successfully.")

    def upgrade_cm_component_binary_files(self):
        """
        Upgrade CM component
        """
        self.logger.log("Start to upgrade CM component on all nodes.")
        cmd = "{0} -t {1} --upgrade-package " \
              "{2}".format(OMCommand.getLocalScript("Local_Upgrade_CM"),
                           Const.ACTION_UPGRADE_CM_UPGRADE_BINARY,
                           self.dest_package_path)
        self.logger.debug("Command for upgrade CM files : {0}.".format(cmd))
        self.ssh_tool.executeCommand(cmd)
        self.logger.log("Upgrade CM component files successfully.")

    def post_upgrade_check(self):
        """
        Post upgrade check
        """
        self.logger.log("Finial check cluster:")
        cmd = "source {0} ; cm_ctl query | grep cluster_state".format(EnvUtil.getMpprcFile())
        start_time = time.time()
        end_time = start_time + 60
        normal_count = 0

        while (end_time - time.time()) > 0:
            status, output = subprocess.getstatusoutput(cmd)
            cluster_state = output.strip().split(":")[-1].strip()
            self.logger.debug("Get cluster state is [{0}]".format(cluster_state))
            if status == 0 and cluster_state in \
                [DefaultValue.CLUSTER_STATUS_NORMAL, DefaultValue.CLUSTER_STATUS_DEGRADED]:
                self.logger.log("Cluster state is : [{0}]".format(cluster_state))
                normal_count += 1
                if normal_count > 2:
                    self.logger.log("The cluster status check is available.")
                    return
            else:
                normal_count = 0
                self.logger.log("Cluster state check unavailable.")
            time.sleep(2)
        if self.origin_cluster_state == DefaultValue.CLUSTER_STATUS_UNAVAILABLE:
            self.logger.log("The cluster state allow Unavailable.")
        else:
            raise Exception("Post upgrade check cluster state is not available.")

    def do_rollback_cm(self):
        """
        Rollback CM component
        """
        self.logger.log("Start to rollback CM component files on all nodes.")
        backup_package_name = "{0}-{1}.tar.gz".format(Const.UPGRADE_BACKUP_TAR_NAME,
                                                      self.package_random_number)
        backup_pkg_path = os.path.join(EnvUtil.getEnv("PGHOST"), backup_package_name)
        cmd = "{0} -t {1} --upgrade-package " \
              "{2}".format(OMCommand.getLocalScript("Local_Upgrade_CM"),
                           Const.ACTION_UPGRADE_CM_ROLLBACK,
                           backup_pkg_path)
        self.logger.debug("Command for rollback CM files : {1}.".format(cmd))
        self.ssh_tool.executeCommand(cmd)
        cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (backup_pkg_path, backup_pkg_path)
        self.ssh_tool.executeCommand(cmd)
        self.logger.log("Rollback CM component files successfully.")

    def clear_tmp_files(self):
        """
        Clear upgrade temporary files
        """
        try:
            backup_dir = os.path.join(EnvUtil.getEnv("PGHOST"), Const.UPGRADE_BACKUP_DIR)
            decompress_dir = os.path.join(EnvUtil.getEnv("PGHOST"),
                                          Const.UPGRADE_CM_DECOMPRESS_DIR)
            cmd = g_file.SHELL_CMD_DICT["deleteDir"] % (backup_dir, backup_dir)
            cmd += " && {0}".format(g_file.SHELL_CMD_DICT["deleteDir"] % (decompress_dir, 
                                                                          decompress_dir))
            self.ssh_tool.executeCommand(cmd)
            self.logger.debug("Clean temporary directory successfully.")
            cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (self.dest_package_path,
                                                         self.dest_package_path)
            self.ssh_tool.executeCommand(cmd)
        except Exception as exp:
            self.logger.warn("Clean temporary upgrade directory failed."
                             "Output: {0}".format(str(exp)))
        self.logger.debug("Clean temporary upgrade directory finish.")

    def run(self):
        """
        Start upgrade CM component main method
        """
        self.logger.log("Start to perform the upgrade of CM component in cluster.")
        self.check_upgrade_cm_parameter()
        self.init_global()
        self.send_cm_package()
        self.record_origin_cluster_state()
        self.prepare_upgrade_cm()
        try:
            self.upgrade_cm_component_binary_files()
            self.post_upgrade_check()
        except Exception as exp:
            self.logger.log("Exception: {0}".format(str(exp)))
            self.logger.log("Start to rollback CM component.")
            self.do_rollback_cm()
            self.clear_tmp_files()
            sys.exit(1)
        self.clear_tmp_files()
        self.logger.log("Upgrade CM component successfully.")

