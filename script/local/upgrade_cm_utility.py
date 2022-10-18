#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import subprocess
import sys
import os
import pwd
import getopt
import time
import shutil

sys.path.append(sys.path[0] + "/../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ParameterParsecheck import Parameter

import impl.upgrade.UpgradeConst as Const

from domain_utils.cluster_file.cluster_dir import ClusterDir

from base_utils.os.file_util import FileUtil
from base_utils.os.compress_util import CompressUtil
from base_utils.os.net_util import NetUtil
from base_utils.os.env_util import EnvUtil


class ParseCommandLine(object):
    """
    ParseCommandLine
    """
    def usage(self):
        """
    Usage:
      python3 upgrade_cm_utility.py -t action [--upgrade-package]
    Common options:
      -t                                the type of action

      --upgrade-package                 upgrade CM component package path
      --help                            show this help, then exit
        """
        print(self.usage.__doc__)

    def parse_command_line(self):
        """
        function: Check parameter from command line
        input: NA
        output: NA
        """
        try:
            opts, args = getopt.getopt(sys.argv[1:], "t:", ["help", "upgrade-package=",
                                                            "backup-version="])
        except Exception as e:
            self.usage()
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50012"] % str(e))
        p_dict = dict()
        if len(args) > 0:
            GaussLog.exitWithError(
                ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

        for (key, value) in opts:
            if key == "--help":
                self.usage()
                sys.exit(0)
            elif key == "-t":
                p_dict["upgrade_action"] = value
            elif key == "--upgrade-package":
                p_dict["upgrade_package"] = value
            elif key == "--backup-version":
                p_dict["backup-version"] = value
            else:
                GaussLog.exitWithError(
                    ErrorCode.GAUSS_500["GAUSS_50000"] % key)
            Parameter.checkParaVaild(key, value)
        return p_dict


class UpgradeCmUtility(object):
    """
    Upgrade CM component with Binary list
    """
    def __init__(self, param_dict):
        self.upgrade_package = param_dict.get("upgrade_package")
        self.upgrade_action = param_dict.get("upgrade_action")
        self.backup_cm_files = list()
        self.upgrade_list_file = ""
        self.back_dir = ""
        self.logger = None
        self.cluster_info = None

    def check_param(self):
        """
        Check parameter value
        """
        action_list = [Const.ACTION_UPGRADE_PREPARE_UPGRADE_CM,
                       Const.ACTION_UPGRADE_CM_UPGRADE_BINARY,
                       Const.ACTION_UPGRADE_CM_ROLLBACK]
        if self.upgrade_action not in action_list:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50003"] % ("t", action_list))

        if self.upgrade_package and not os.path.isfile(self.upgrade_package):
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50022"] % ("--upgrade-package",
                                                                         "a file"))

        if self.upgrade_action == Const.ACTION_UPGRADE_PREPARE_UPGRADE_CM and \
                self.upgrade_package is None:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % "--upgrade-package")

    def init_global(self):
        """
        Initialize global value
        """
        user = pwd.getpwuid(os.getuid()).pw_name
        log_file = os.path.join(ClusterDir.getLogDirFromEnv(user),
                                "om", "gs_local_upgrade_cm_utility.log")
        tmp_dir = EnvUtil.getEnv("PGHOST")
        self.cluster_info = dbClusterInfo()
        self.cluster_info.initFromStaticConfig(user)
        self.logger = GaussLog(log_file, self.__class__.__name__)
        self.back_dir = os.path.join(tmp_dir, Const.UPGRADE_CM_DECOMPRESS_DIR)
        decompress_dir = os.path.join(self.back_dir, Const.UPGRADE_CM_DECOMPRESS_DIR)
        self.upgrade_list_file = os.path.join(decompress_dir, "upgrade_binary_list")

    def replace_files(self, src_dir, src_file_list, dest_dir):
        """
        Replace files to dest directory
        """
        cp_cmd = "cd {0} && /usr/bin/cp -rf {1} {2}".format(src_dir,
                                                            " ".join(src_file_list),
                                                            dest_dir)
        self.logger.debug("Replace files command is: {0}".format(cp_cmd))
        status, _ = subprocess.getstatusoutput(cp_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50214"] % src_file_list)

    def compress_tar_package(self, ready_backup_dir, backup_pkg_path):
        """
        Compress tar package
        """
        if os.path.isfile(backup_pkg_path):
            os.remove(backup_pkg_path)
        compress_cmd = "cd {1} && tar -czf {0} ./*".format(backup_pkg_path, ready_backup_dir)
        status, output = subprocess.getstatusoutput(compress_cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50231"] % backup_pkg_path +
                            " Error:\n%s" % output + "\nThe cmd is %s" % compress_cmd)

        self.logger.debug("Compress package [{0}] success.".format(backup_pkg_path))

    def restart_process(self, patten_key, time_out):
        """
        Restart process on local node
        """
        self.logger.log("Restart {0}.".format(patten_key))
        cmd = "(ps ux | grep '%s' | grep -v grep | " \
              "awk '{print $2}' | xargs -r kill -9)" % (patten_key)
        subprocess.getstatusoutput(cmd)
        cluster_manual_start = os.path.realpath(os.path.join(self.cluster_info.appPath,
                                                             "bin",
                                                             "cluster_manual_start"))
        if os.path.isfile(cluster_manual_start) and \
                (patten_key.endswith("cm_agent") or patten_key.endswith("cm_server")):
            self.logger.log("Current node has been stopped. "
                            "File [{0}] exist, so don't check [{1}] "
                            "process.".format(cluster_manual_start, patten_key))
            return
        start_time = time.time()
        end_time = start_time + time_out
        # grep -v 'source' | grep -v '&' Filter out scheduled task commands to prevent misjudgment
        cmd = "ps ux | grep '%s' | grep -v grep | grep -v 'source' | grep -v '&'" % patten_key
        while (end_time - time.time()) > 0:
            status, output = subprocess.getstatusoutput(cmd)
            if status == 0:
                self.logger.debug("Restart {0} success. OUTPUT: "
                                  "{1}".format(patten_key, output))
                break
            time.sleep(2)
        else:
            self.logger.error("Restart {0} failed. OUTPUT: {1}".format(patten_key, output))
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)

        get_start_time_cmd = "ps -eo pid,etimes,cmd | grep '%s' | " \
                             "grep -v grep | awk '{print $2}'" % patten_key
        status, output = subprocess.getstatusoutput(get_start_time_cmd)
        self.logger.debug("Get process start time : {0}".format(output))
        if status != 0:
            self.logger.error(ErrorCode.GAUSS_514["GAUSS_51400"] % get_start_time_cmd)
            sys.exit(-1)
        if output.strip().isdigit() and int(output.strip()) < 5:
            self.logger.log("Restart time of process [{0}] is: "
                            "[{1}].".format(patten_key, output.strip()))
        else:
            self.logger.error("Get start time of process {0} failed. "
                              "OUTPUT: {1}".format(patten_key, output))
            sys.exit(-1)

    def restart_cm_process(self):
        """
        Restart om_monitor cm_agent cm_server 
        """
        self.restart_process(os.path.join(self.cluster_info.appPath, "bin", "om_monitor"), 120)
        self.restart_process(os.path.join(self.cluster_info.appPath, "bin", "cm_agent"), 20)
        self.restart_process(os.path.join(self.cluster_info.appPath, "bin", "cm_server"), 20)

    def prepare(self):
        """
        Prepare step
        """
        self.check_param()
        self.init_global()

    def do_operation(self):
        """
        Operation step
        """
        pass

    def finish(self):
        """
        Finish step
        """
        pass

    def run(self):
        """
        Run operation
        """
        self.prepare()
        self.do_operation()
        self.finish()


class UpgradeCmPrepareUtility(UpgradeCmUtility):
    """
    Prepare upgrade CM component
    """
    def __init__(self, param_dict):
        super(UpgradeCmPrepareUtility, self).__init__(param_dict)
        self.backup_version = param_dict.get("backup-version")

    def clean_package_directory_with_upgrade_list(self, package_directory):
        """
        Generate
        """
        upgrade_file_list = FileUtil.readFile(self.upgrade_list_file)
        upgrade_file_list = [i.rstrip("\n") for i in upgrade_file_list]
        self.logger.debug("upgrade_list_file content:")
        for i in upgrade_file_list:
            self.logger.debug(i)
        if not upgrade_file_list:
            self.logger.debug("Upgrade binary list is empty.")
            self.clean_package_directory_so_file(package_directory)
            return

        split_point = os.path.basename(package_directory) + "/"
        for (dir_path, _, file_list) in os.walk(package_directory):
            relative_path_list = [os.path.join(dir_path.split(split_point)[-1], j)
                                  for j in file_list
                                  if os.path.join(dir_path.split(split_point)[-1], j)
                                  not in upgrade_file_list]
            for relative_path in relative_path_list:
                r_file = os.path.join(package_directory, relative_path)
                os.remove(r_file)
                if not os.listdir(os.path.dirname(r_file)):
                    self.logger.debug("Clean empty directory : "
                                      "[{0}]".format(os.path.dirname(r_file)))
                    os.removedirs(os.path.dirname(r_file))
                self.logger.debug("Remove file [{0}] from package directory.".format(r_file))
        self.logger.debug("Clean all files not in upgrade_list_file success.")

    def clean_package_directory_so_file(self, package_directory):
        """
        Generate package with default
        """
        so_list = ["libdcc.so", "libgstor.so"]
        lib_path = os.path.join(package_directory, "lib")
        if not os.path.isdir(lib_path):
            self.logger.debug("There not exist 'lib' directory in "
                              "[{0}].".format(package_directory))
            return
        remove_file_list = [os.path.join(lib_path, i) for i in os.listdir(lib_path)
                            if i not in so_list]
        for j in remove_file_list:
            os.remove(j)
            if not os.listdir(os.path.dirname(j)):
                self.logger.debug("Clean so directory: [{0}]".format(os.path.dirname(j)))
                os.removedirs(os.path.dirname(j))
        self.logger.debug("[{0}] lib directory list: {1}".format(package_directory,
                                                                 os.listdir(lib_path)))
        self.logger.debug("Clean so file success.")

    def check_package_file(self, decompress_dir):
        """
        Check CM package file
        """
        self.logger.log("Start to check files of CM package.")
        upgrade_list_file = os.path.join(decompress_dir, Const.UPGRADE_BINARY_LIST_FILE_NAME)
        if os.path.isfile(upgrade_list_file):
            self.logger.debug("Exist upgrade_list_file.")
            file_list = FileUtil.readFile(self.upgrade_list_file)
            check_file_list = [os.path.join(decompress_dir, i.rstrip("\n")) for i in file_list
                               if i.rstrip("\n")]
        else:
            self.logger.debug("Not exist upgrade_list_file.")
            check_file_list = [os.path.join(decompress_dir, "lib", i) for i 
                               in ["libdcc.so", "libgstor.so"]]
        self.logger.debug("Check CM package all file list: {0}".format(check_file_list))
        file_not_exist_list = [os.path.join(decompress_dir, i) for i in check_file_list 
                               if i and not os.path.exists(os.path.join(decompress_dir, i))]
        if file_not_exist_list:
            self.logger.error("The CM package file is incorrect.")
            self.logger.error("The following file does not exist: {0}".format(file_not_exist_list))
            sys.exist(-1)
        self.logger.log("Upgrade CM package is correct.")

    def generate_new_upgrade_package(self, decompress_dir):
        """
        Because upgrade cm package may exists upgrade_binary_list file.
        If exist: Perform the upgrade according to the file content.
        This method regenerates the compressed package
        based on the upgrade_binary_list file content.
        """
        self.logger.log("Start to regenerate upgrade package.")
        if os.path.isfile(self.upgrade_list_file):
            self.logger.debug("Start to regenerate upgrade package with upgrade_list_file.")
            self.clean_package_directory_with_upgrade_list(decompress_dir)
        else:
            self.logger.debug("Regenerate upgrade package with default.")
            self.clean_package_directory_so_file(decompress_dir)
        if not os.listdir(decompress_dir):
            self.logger.error(ErrorCode.GAUSS_502["GAUSS_50203"] % decompress_dir)
            sys.exit(-1)
        self.compress_tar_package(decompress_dir, self.upgrade_package)
        self.logger.log("Generate new upgrade package success.")

    def do_compare_backup(self, src_path):
        """
        Compare and backup CM files without upgrade config file
        """
        ready_backup_dir = os.path.join(self.back_dir, Const.UPGRADE_TMP_BACKUP_DIR)
        suffix_path = src_path.split(Const.UPGRADE_CM_DECOMPRESS_DIR + "/")[-1]
        app_path = os.path.join(self.cluster_info.appPath, suffix_path)
        backup_path = os.path.join(ready_backup_dir, suffix_path)

        if os.path.isfile(src_path):
            if not os.path.isfile(app_path):
                return
            if not os.path.isdir(os.path.dirname(backup_path)):
                FileUtil.createDirectory(os.path.dirname(backup_path))
            FileUtil.cpFile(app_path, backup_path)
            self.backup_cm_files.append(app_path)
        elif os.path.isdir(src_path):
            files_list = [os.path.join(src_path, file_name) for file_name
                          in os.listdir(src_path)]
            for i in files_list:
                self.do_compare_backup(i)
        else:
            self.logger.warn("Backup file [{0}] type error.".format(src_path))

    def backup_conf_file(self):
        """
        Backup cm_agent.conf cm_server.conf
        """
        local_node = [node for node in self.cluster_info.dbNodes
                      if node.name == NetUtil.GetHostIpOrName()][0]
        if local_node.cmservers:
            server_conf = os.path.join(local_node.cmservers[0].datadir, "cm_server.conf")
            shutil.copyfile(server_conf, os.path.join(self.back_dir, "cm_server.conf"))
            self.logger.debug("Backup cm_server.conf success.")

        cm_agent_conf = os.path.join(local_node.cmagents[0].datadir, "cm_agent.conf")
        shutil.copyfile(cm_agent_conf, os.path.join(self.back_dir, "cm_agent.conf"))
        self.logger.debug("Backup cm_agent.conf success.")

    def do_operation(self):
        """
        Decompress upgrade package and regenerate upgrade package
        """
        self.logger.log("Prepare upgrade CM component.")
        self.logger.log("Start decompress CM package.")

        backup_package_name = "{0}-{1}.tar.gz".format(Const.UPGRADE_BACKUP_TAR_NAME,
                                                      self.backup_version)
        backup_pkg_path = os.path.join(EnvUtil.getEnv("PGHOST"), backup_package_name)
        decompress_dir = os.path.join(self.back_dir, Const.UPGRADE_CM_DECOMPRESS_DIR)

        FileUtil.createDirectory(decompress_dir)
        CompressUtil.decompressFiles(self.upgrade_package, decompress_dir)
        self.logger.log("Decompress CM package success.")
        self.check_package_file(decompress_dir)

        self.generate_new_upgrade_package(decompress_dir)

        ready_backup_dir = os.path.join(self.back_dir, Const.UPGRADE_TMP_BACKUP_DIR)
        FileUtil.createDirectory(ready_backup_dir)
        self.logger.log("Backup origin cluster CM files with package compare.")
        self.do_compare_backup(decompress_dir)
        if not os.listdir(ready_backup_dir):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "backup CM component files.")
        self.logger.log("Prepare CM files success.")

        # compress backup packge
        self.compress_tar_package(ready_backup_dir, backup_pkg_path)
        self.logger.debug("Prepare CM component files list: {0}".format(self.backup_cm_files))

        self.backup_conf_file()
        self.logger.log("Compress backup package [{0}] finish.".format(backup_pkg_path))
        self.logger.log("Prepare upgrade CM success.")


class UpgradeCmUpgradeUtility(UpgradeCmUtility):
    """
    Upgrade CM component
    """
    def __init__(self, param_dict):
        super(UpgradeCmUpgradeUtility, self).__init__(param_dict)

    def copy_file_with_upgrade_list(self, file_list, src_path, dest_dir,
                                    split_flag = Const.UPGRADE_CM_DECOMPRESS_DIR + "/"):
        """
        Copy file with file list
        """
        if os.path.isfile(src_path):
            if os.path.basename(src_path) in file_list:
                self.logger.debug("Copy file [{0}].".format(src_path))
                suffix_path = src_path.split(split_flag)[-1]
                with_gauss_home_dir = os.path.dirname(os.path.join(dest_dir, suffix_path))
                if not os.path.isdir(with_gauss_home_dir):
                    FileUtil.createDirectory(with_gauss_home_dir,
                                             True,
                                             DefaultValue.KEY_DIRECTORY_MODE)

                self.replace_files(os.path.dirname(src_path),
                                   [os.path.basename(src_path)],
                                   with_gauss_home_dir)
            else:
                self.logger.debug("No need copy file: [{0}]".format(src_path))
        elif os.path.isdir(src_path):
            for i in os.listdir(src_path):
                src_sub_path = os.path.join(src_path, i)
                if os.path.isdir(src_sub_path):
                    self.copy_file_with_upgrade_list(file_list, src_sub_path, dest_dir)
        else:
            self.logger.warn(ErrorCode.GAUSS_502["GAUSS_50211"] + src_path)

    def get_para_dict(self, conf_file):
        """
        Get param dict
        """
        with open(conf_file, "r") as fd:
            file_content = fd.read()
        param_info_list = file_content.split("\n")
        result_dict = {para_line.split("=")[0].strip(): para_line.split("=")[1].strip()
                       for para_line in param_info_list
                       if para_line and not para_line.startswith("#") and
                       len(para_line.split("=")) > 1}
        self.logger.debug("Get para_dict from [{0}] :".format(conf_file))
        for i in result_dict:
            self.logger.debug("[{0}] : {1}".format(i, result_dict.get(i)))
        return result_dict

    def add_new_para(self, conf_file, para_dict):
        """
        Add new parameter
        """
        src_para_dict = self.get_para_dict(conf_file)
        update_key = [i for i in para_dict.keys() if i not in src_para_dict.keys()]
        cmd = ""
        if update_key:
            for key in update_key:
                update_str = "{0} = {1}".format(key, para_dict.get(key))
                if cmd:
                    cmd += " && echo '{0}' >> {1}".format(update_str, conf_file)
                else:
                    cmd = "echo '{0}' >> {1}".format(update_str, conf_file)
            self.logger.debug("Add new parameter to config file cmd: {0}".format(cmd))
            status, _ = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
        else:
            self.logger.debug("No exist new parameter in "
                              "[{0}].".format(os.path.basename(conf_file)))

    def update_para(self, conf_file, para_dict):
        """
        Update parameter
        """
        self.logger.debug("Start update parameter.")
        src_para_dict = self.get_para_dict(conf_file)
        src_key_list = src_para_dict.keys()
        update_key = [i for i in para_dict.keys() 
                      if i in src_key_list and para_dict.get(i) != src_para_dict.get(i)]
        sed_cmd = ""
        if update_key:
            for key in update_key:
                if not sed_cmd:
                    sed_cmd = 'sed -i "/{0} = */c\{0} = {1}" ' \
                              '{2}'.format(key, para_dict.get(key), conf_file)
                else:
                    sed_cmd += ' && sed -i "/{0} = */c\{0} = {1}" ' \
                               '{2}'.format(key, para_dict.get(key), conf_file)
            self.logger.debug("Update conf file cmd: {0}".format(sed_cmd))
            status, _ = subprocess.getstatusoutput(sed_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % sed_cmd)
            self.logger.debug("Update conf file success.")
        else:
            self.logger.debug("There is not exist difference parameter in "
                              "[{0}].".format(os.path.basename(conf_file)))

    def upgrade_conf(self, conf_file, para_dict):
        """
        Upgrade conf file
        """
        self.add_new_para(conf_file, para_dict)
        self.update_para(conf_file, para_dict)

    def upgrade_conf_file(self):
        """
        Upgrade conf file
        """
        local_node = [node for node in self.cluster_info.dbNodes
                      if node.name == NetUtil.GetHostIpOrName()][0]
        agent_inst_dir = local_node.cmagents[0].datadir

        # replace cm_agent.conf file
        src_dir = os.path.join(self.cluster_info.appPath, "share", "config")
        agent_conf_file = os.path.join(agent_inst_dir, "cm_agent.conf")
        self.replace_files(src_dir, ["cm_agent.conf.sample"], agent_conf_file)
        # config new cm_agent.conf
        backup_agent_para_dict = self.get_para_dict(os.path.join(self.back_dir,
                                                                 "cm_agent.conf"))
        self.upgrade_conf(os.path.join(agent_inst_dir, "cm_agent.conf"),
                          backup_agent_para_dict)

        if not local_node.cmservers:
            self.logger.debug("Local node not exist cm_server instance.")
            return
        server_inst_dir = local_node.cmservers[0].datadir
        # replace cm_server.conf file
        server_conf_file = os.path.join(server_inst_dir, "cm_server.conf")
        self.replace_files(src_dir, ["cm_server.conf.sample"], server_conf_file)
        # config new cm_server.conf
        backup_server_para_dict = self.get_para_dict(os.path.join(self.back_dir,
                                                                  "cm_server.conf"))
        self.upgrade_conf(os.path.join(server_inst_dir, "cm_server.conf"),
                          backup_server_para_dict)

    def do_operation(self):
        """
        Upgrade CM component binary files.
        """
        self.logger.log("Upgrade CM component binary files.")
        CompressUtil.decompressFiles(self.upgrade_package, self.cluster_info.appPath)
        # config new conf file
        self.upgrade_conf_file()
        self.logger.log("Upgrade CM component binary files success.")

        self.restart_cm_process()
        self.logger.log("CM component switch process success.")


class UpgradeCmRollbackUtility(UpgradeCmUtility):
    """
    UpgradeCmRollbackUtility
    """
    def __init__(self, param_dict):
        super(UpgradeCmRollbackUtility, self).__init__(param_dict)

    def clear_difference_files(self, check_dir):
        """
        Get difference files
        """
        backup_pkg_dir = os.path.join(self.back_dir, Const.UPGRADE_TMP_BACKUP_DIR)
        for i in os.listdir(check_dir):
            upgrade_path = os.path.join(check_dir, i)
            suffix_path = upgrade_path.split(Const.UPGRADE_TMP_BACKUP_DIR + "/")[-1]
            backup_path = os.path.join(backup_pkg_dir, suffix_path)
            gauss_home_path = os.path.join(self.cluster_info.appPath, suffix_path)

            if os.path.isfile(upgrade_path):
                if os.path.isfile(gauss_home_path) and not os.path.isfile(backup_path):
                    self.logger.debug("Need to clean file: {0}".format(gauss_home_path))
                    os.remove(gauss_home_path)
                    if not os.listdir(os.path.dirname(gauss_home_path)):
                        os.removedirs(os.path.dirname(gauss_home_path))
            elif os.path.isdir(upgrade_path):
                self.clear_difference_files(upgrade_path)
            else:
                self.logger.error(ErrorCode.GAUSS_502["GAUSS_50221"])
                sys.exit(-1)

    def rollback_conf_file(self):
        """
        Rollback conf file
        """
        self.logger.log("Start rollback conf file.")

        local_node = [node for node in self.cluster_info.dbNodes
                      if node.name == NetUtil.GetHostIpOrName()][0]
        if local_node.cmservers:
            server_conf = os.path.join(local_node.cmservers[0].datadir, "cm_server.conf")
            shutil.copyfile(os.path.join(self.back_dir, "cm_server.conf"), server_conf)
            self.logger.debug("Rollback cm_server.conf success.")

        cm_agent_conf = os.path.join(local_node.cmagents[0].datadir, "cm_agent.conf")
        shutil.copyfile(os.path.join(self.back_dir, "cm_agent.conf", cm_agent_conf))
        self.logger.debug("Rollback cm_agent.conf success.")

    def rollback_cm_files(self):
        """
        Rollback CM files
        """
        # Decompress backup tar package
        CompressUtil.decompressFiles(self.upgrade_package, self.cluster_info.appPath)
        self.logger.debug("Rollback backup CM files success.")

        # Clearing difference files
        upgrade_files_dir = os.path.join(self.back_dir, Const.UPGRADE_CM_DECOMPRESS_DIR)
        self.clear_difference_files(upgrade_files_dir)
        self.logger.debug("Clear difference CM files success.")
        self.rollback_conf_file()

    def do_operation(self):
        """
        Rollback CM component
        """
        self.logger.log("Start rollback CM component binary files.")
        self.rollback_cm_files()

        self.restart_cm_process()
        self.logger.log("Rollback CM component binary files successfully.")


if __name__ == '__main__':
    command_line = ParseCommandLine()
    parameeter_dict = command_line.parse_command_line()
    do_operate_dict = {Const.ACTION_UPGRADE_PREPARE_UPGRADE_CM: UpgradeCmPrepareUtility,
                       Const.ACTION_UPGRADE_CM_UPGRADE_BINARY: UpgradeCmUpgradeUtility,
                       Const.ACTION_UPGRADE_CM_ROLLBACK: UpgradeCmRollbackUtility}
    upgrade_operation = do_operate_dict.get(parameeter_dict.get("upgrade_action"))(parameeter_dict)
    upgrade_operation.run()

