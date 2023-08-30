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
#############################################################################
try:
    import sys
    import os
    import subprocess
    import time
    import datetime
    import pwd
    from datetime import datetime, timedelta

    sys.path.append(sys.path[0] + "/../../../../")
    from gspylib.common.ErrorCode import ErrorCode
    from gspylib.common.Common import DefaultValue, ClusterCommand
    from gspylib.common.DbClusterStatus import DbClusterStatus
    from gspylib.os.gsfile import g_file
    from gspylib.component.CM.CM import CM, CmResAttr, CmResCtrlCmd, DssInstAttr
    from gspylib.component.CM.CM import VipInstAttr, VipAddInst, VipDelInst
    from gspylib.component.CM.CM import VipCmResCtrlCmd, VipResAttr
    from gspylib.common.DbClusterInfo import dbClusterInfo
    from base_utils.os.crontab_util import CrontabUtil
    from base_utils.os.env_util import EnvUtil
    from base_utils.os.grep_util import GrepUtil
    from base_utils.os.cmd_util import CmdUtil
    from base_utils.os.file_util import FileUtil
    from base_utils.common.fast_popen import FastPopen
    from domain_utils.cluster_file.cluster_dir import ClusterDir
    from domain_utils.cluster_file.cluster_log import ClusterLog
    from gspylib.component.DSS.dss_comp import DssInst, UdevContext
    from gspylib.component.DSS.dss_checker import DssConfig

except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class CM_OLAP(CM):
    '''
    The class is used to define cluster manager component for olap database.
    '''
    # Don't need DEFAULT_TIMEOUT = 300, user cm_ctl default timeout
    DEFAULT_TIMEOUT = 0
    # Don't need DEFAULT_RESTART_NODEGROUP_TIMEOUT = 1800, user cm_ctl default timeout
    DEFAULT_RESTART_NODEGROUP_TIMEOUT = 0
    # The number of CM cert file
    CM_CERT_FILES_NUM = 8
    # Retry generate CM cert count
    RETRY_COUNT = 3

    def __init__(self):
        '''
        Constructor
        '''
        super(CM_OLAP, self).__init__()
        self.cluster_info = None

    def init_globals(self):
        user = pwd.getpwuid(os.getuid()).pw_name
        self.cluster_info = dbClusterInfo()
        if os.path.isfile(
                self.cluster_info.get_staic_conf_path(user, ignore_err=True)):
            self.cluster_info.initFromStaticConfig(user)


    def init_cm_server(self):
        """
        Init cm server
        """
        user = pwd.getpwuid(os.getuid()).pw_name
        server_simple_conf_file = os.path.realpath(os.path.join(self.binPath, "..",
                                                                "share/config",
                                                                "cm_server.conf.sample"))
        server_dest_conf_file = os.path.realpath(os.path.join(self.instInfo.datadir,
                                                              "cm_server.conf"))
        cmd = "if [ ! -d %s ] ; then mkdir -p %s ; chmod 700 %s ; " \
              "chown %s:%s %s; fi ; cp %s %s " % (self.instInfo.datadir,
                                                  self.instInfo.datadir,
                                                  self.instInfo.datadir,
                                                  user, user,
                                                  self.instInfo.datadir,
                                                  server_simple_conf_file,
                                                  server_dest_conf_file)
        self.logger.debug("Command for copy CM server cnf file command is: %s" % cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51615"] +
                            " Command:%s. Error:\n%s" % (cmd, output))
        log_path = EnvUtil.getEnvironmentParameterValue("GAUSSLOG", user)
        server_para_dict = {"log_dir": os.path.realpath(os.path.join(log_path,
                                                                     "cm", "cm_server"))}
        if self.dss_mode:
            cm_vote_disk = DssConfig.get_value_b64_handler('voting_disk_path',
                                                           self.dss_config,
                                                           action='decode')
            cm_share_disk = DssConfig.get_value_b64_handler('share_disk_path',
                                                            self.dss_config,
                                                            action='decode')
            server_para_dict.update({
                'share_disk_path': cm_share_disk,
                'voting_disk_path': cm_vote_disk,
                'dn_arbitrate_mode': 'share_disk',
                'ddb_type': '2'
            })
        self.setGucConfig(server_para_dict)
        self.logger.debug("Initializing cm_server instance successfully.")

    def init_cm_agent(self):
        """
        Init cm agent
        """
        user = pwd.getpwuid(os.getuid()).pw_name
        agent_simple_conf_file = os.path.realpath(os.path.join(self.binPath, "..",
                                                               "share/config",
                                                               "cm_agent.conf.sample"))
        agent_dest_conf_file = os.path.realpath(os.path.join(self.instInfo.datadir,
                                                             "cm_agent.conf"))
        cmd = "if [ ! -d %s ] ; then mkdir -p %s ; chmod 700 %s ; " \
              "chown %s:%s %s; fi ; cp %s %s " % (self.instInfo.datadir,
                                                  self.instInfo.datadir,
                                                  self.instInfo.datadir,
                                                  user, user,
                                                  self.instInfo.datadir,
                                                  agent_simple_conf_file,
                                                  agent_dest_conf_file)
        self.logger.debug("Command for copy CM agent config file: %s" % cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51615"] +
                            " Command:%s. Error:\n%s" % (cmd, output))
        log_path = EnvUtil.getEnvironmentParameterValue("GAUSSLOG", user)
        agent_para_dict = {"unix_socket_directory": os.path.dirname(self.binPath),
                           "log_dir": os.path.realpath(os.path.join(log_path, "cm", "cm_agent"))}
        if self.dss_mode:
            cm_vote_disk = DssConfig.get_value_b64_handler('voting_disk_path',
                                                           self.dss_config,
                                                           action='decode')
            agent_para_dict.update({
                'voting_disk_path': cm_vote_disk
                })

        self.setGucConfig(agent_para_dict)
        self.logger.debug("Initializing cm_agent instance successfully.")

    def initInstance(self):
        """
        function : install a single cm component
        input  : NA
        output : NA
        """
        if not self.instInfo.datadir:
            raise Exception("Data directory of instance is invalid.")

        if self.instInfo.datadir == "/cm_agent" and not os.path.exists(self.instInfo.datadir):
            self.logger.debug("No cm configuration, no need to init CM.")
            return

        if not os.path.exists(self.instInfo.datadir):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % ("cm data directory [%s]" %
                                                                  self.instInfo.datadir))

        if self.instInfo.instanceRole == DefaultValue.INSTANCE_ROLE_CMSERVER:
            self.init_cm_server()
        elif self.instInfo.instanceRole == DefaultValue.INSTANCE_ROLE_CMAGENT:
            if self.dss_mode:
                self.init_globals()
                self.init_cm_res_json()
            self.init_cm_agent()

    def uninstall(self):
        """
        function: uninstall the cm component
        input : NA
        output: NA
        """
        data_dir = self.instInfo.datadir
        dcf_data_dir = os.path.realpath(os.path.join(os.path.dirname(self.instInfo.datadir),
                                                     "dcf_data"))
        gstor_dir = os.path.realpath(os.path.join(os.path.dirname(self.instInfo.datadir),
                                                  "gstor"))
        if os.path.exists(data_dir) and DefaultValue.non_root_owner(data_dir):
            FileUtil.removeDirectory(data_dir)
        if os.path.exists(dcf_data_dir) and DefaultValue.non_root_owner(dcf_data_dir):
            FileUtil.removeDirectory(dcf_data_dir)
        if os.path.exists(gstor_dir) and DefaultValue.non_root_owner(gstor_dir):
            FileUtil.removeDirectory(gstor_dir)

    def _out_dot_and_wait_normal(self, node_id, cluster_normal_status,
                                 start_type, time_set):
        """
        Wait cluster to normal
        """
        end_time, timeout = time_set
        dot_count = 0
        start_status = 0
        start_result = ""
        # 1 -> failed
        # 0 -> success
        is_success = False
        # Wait for the cluster to start completely
        while True:
            # A point is output every 5 seconds
            time.sleep(5)
            sys.stdout.write(".")
            dot_count += 1
            # A line break is output per minute
            if dot_count >= 12:
                dot_count = 0
                sys.stdout.write("\n")

            start_status = 0
            start_result = ""
            # The cluster status is checked every 5 seconds
            (start_status, start_result) = self.doCheckStaus(node_id, cluster_normal_status)
            if start_status == 0:
                # Output successful start information
                if dot_count != 0:
                    sys.stdout.write("\n")
                self.logger.log("Successfully started %s." % start_type)
                is_success = True
                break
            # The output prompts when the timeout does not start successfully
            if end_time is not None and datetime.now() >= end_time:
                if dot_count != 0:
                    sys.stdout.write("\n")
                self.logger.log("Failed to start %s " % start_type + " in (%s)s." % timeout)
                self.logger.log("It will continue to start in the background.")
                self.logger.log("If you want to see the cluster status, "
                                "please try command gs_om -t status.")
                self.logger.log("If you want to stop the cluster, "
                                "please try command gs_om -t stop.")
                break
        self.logger.log("=" * 70)
        self.logger.log(start_result)
        return is_success

    def _cluster_switchover(self, is_success, para_set):
        """
        Cluster switchover
        """
        is_switch_over, is_single, user, timeout = para_set
        if is_switch_over:
            self.logger.debug("Ready to switchover cluster.")
        if is_success and is_switch_over and not is_single:
            # Perform the switch reset operation
            cmd = CM_OLAP.get_reset_switchover_cmd(user, timeout)
            self.logger.debug("Swithover command: {0}".format(cmd))
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.log(
                    "Failed to reset switchover the cluster. "
                    "Command: \"%s\".\nOutput: \"%s\"." % (cmd, output))


    @staticmethod
    def get_start_cmd(nodeId=0, timeout=DEFAULT_TIMEOUT, datadir="", azName=""):
        """
        function : Start all cluster or a node
        input : String, int, String, String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "source %s ; cm_ctl start" % user_profile
        # check node id
        if nodeId > 0:
            cmd += " -n %d" % nodeId
        # check data directory
        if datadir != "":
            cmd += " -D %s" % datadir
        # check timeout
        if timeout > 0:
            cmd += " -t %d" % timeout
        # azName
        if azName != "":
            cmd += " -z%s" % azName

        return cmd

    def startCluster(self, user, nodeId=0, timeout=DEFAULT_TIMEOUT,
                     isSwitchOver=True, isSingle=False,
                     cluster_normal_status=None, isSinglePrimaryMultiStandbyCluster=False,
                     azName="", datadir="", retry_times=3):
        """
        function:Start cluster or node
        input:String,int,int
        output:NA
        """
        start_type = "cluster"
        if nodeId > 0:
            start_type = "node"
        if datadir != "":
            start_type = "instance"
        if azName != "":
            start_type = azName
        # The output starts the screen-printing information of the group
        self.logger.log("Starting %s." % start_type)
        self.logger.log("======================================================================")
        # Call cm_ctl to start the
        cmd = CM_OLAP.get_start_cmd(nodeId, timeout=timeout, datadir=datadir, azName=azName)
        result_set = subprocess.getstatusoutput(cmd)
        # The output prompts when the failure to start
        if result_set[0] != 0:
            self.logger.error(ErrorCode.GAUSS_516["GAUSS_51607"] % start_type +
                              " Error: \n%s" % result_set[1])
            self.logger.log("The cluster may continue to start in the background.")
            self.logger.log("If you want to see the cluster status, "
                            "please try command gs_om -t status.")
            self.logger.log("If you want to stop the cluster, please try command gs_om -t stop.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % start_type +
                            " Error: \n%s" % result_set[1])

        if isSingle:
            self.logger.log("Successfully started cluster. "
                            "Waiting for cluster status to become Normal.")
            self.logger.log("=" * 70)
        elif isSinglePrimaryMultiStandbyCluster:
            if azName:
                self.logger.log("Successfully started %s." % start_type)
                self.logger.log("=" * 70)
                self.logger.log("End start %s." % start_type)
                return True
            else:
                self.logger.log("Successfully started single primary multi standby. "
                                "Wait for standby instance.")
                self.logger.log("=" * 70)
        # Output the startup instance success information
        elif nodeId == 0:
            self.logger.log("Successfully started primary instance. Wait for standby instance.")
            self.logger.log("=" * 70)
        else:
            self.logger.log("Successfully started %s." % start_type)
            self.logger.log("=" * 70)
            self.logger.log("End start %s." % start_type)
            return True

        is_success = self._out_dot_and_wait_normal(nodeId,
                                                   cluster_normal_status,
                                                   start_type,
                                                   (datetime.now() + timedelta(seconds=timeout),
                                                    timeout))
        self._cluster_switchover(is_success, (isSwitchOver, isSingle, user, timeout))

        return is_success

    def stop_cluster(self, stop_args_set):
        """
        Stop cluster
        """
        node_id, stop_mode, timeout, data_dir, az_name = stop_args_set
        stop_type = "cluster"
        # Specifies the stop node
        # Gets the specified node id
        if node_id > 0:
            stop_type = "node"
        if data_dir != "":
            stop_type = "instance"
        if az_name != "":
            stop_type = az_name
        # Perform a stop operation
        self.logger.log("Stopping %s." % stop_type)
        self.logger.log("=========================================")
        timeout = timeout if timeout != 0 else CM_OLAP.DEFAULT_TIMEOUT
        cmd = ClusterCommand.getStopCmd(node_id, stop_mode, timeout=0,
                                        datadir=data_dir, azName=az_name)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 and stop_type == "cluster":
            self.logger.log("Failed to stop %s." % stop_type +
                            " Try to stop it forcibly." + " Error:\n%s" % output)
            cmd = ClusterCommand.getStopCmd(node_id, "i", timeout, data_dir, az_name)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.debug(output)
                self.logger.log("Failed to stop %s forcibly." % stop_type)
            else:
                self.logger.log("Successfully stopped %s forcibly." % stop_type)
        elif status != 0:
            self.logger.log(output)
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51610"] % stop_type)
        else:
            self.logger.log("Successfully stopped %s." % stop_type)

        self.logger.log("=========================================")
        self.logger.log("End stop %s." % stop_type)

    def queryClusterStatus(self, outFile="", isFormat=False):
        """
        function: query cluster status
        input : int,string,boolean
        output: cluster status
        """

        if isFormat:
            cmd = self.getQueryStatusCmd(0, outFile, True, True)
        else:
            # query and save status into a file
            status_file = \
                "%s/gauss_check_status_%d.dat" % (EnvUtil.getTmpDirFromEnv(), os.getpid())
            FileUtil.cleanTmpFile(status_file)
            cmd = self.getQueryStatusCmd(0, status_file)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 and not isFormat:
            with open(status_file, 'r') as fp:
                output = fp.read()
            FileUtil.cleanTmpFile(status_file)
            if output.find("cm_ctl: can't connect to cm_server.") >= 0:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51640"])
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] % "cluster" +
                            " Error: \n%s" % output)
        if isFormat:
            return output
        # check cluster status
        cluster_status = DbClusterStatus()
        cluster_status.initFromFile(status_file)
        FileUtil.cleanTmpFile(status_file)
        return cluster_status

    def switchOver(self, user, nodeId, datadir):
        """
        function: Switch instances on a node to standby
        input : string, int, string
        output: NA
        """
        cmd = self._get_switch_over_cmd(user, nodeId, datadir)
        self.logger.debug("Switch over command: %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53007"] % "instances" +
                            " Error: \n%s" % output)

    def _kill_om_monitor(self):
        """
        Kill om_monitor process
        """
        # etcd log directory is not created, kill om_monitor.
        kill_cmd = DefaultValue.killInstProcessCmd("om_monitor", False)
        status, _ = CmdUtil.retryGetstatusoutput(kill_cmd)
        if status == 0:
            self.logger.debug("Kill om_monitor force: %s" % kill_cmd)

    def setMonitor(self, user):
        """"
        function: Set om monitor cron
        input : NA
        output: NA
        """
        self.logger.log("Set CRON.")
        app_path = ClusterDir.getInstallDir(user)
        log_path = ClusterLog.getOMLogPath(DefaultValue.OM_MONITOR_DIR_FILE,
                                             user,
                                             app_path)
        mpprc_file = EnvUtil.getEnv(DefaultValue.MPPRC_FILE_ENV)

        cron_file = "%s/gauss_cron_%d" % (EnvUtil.getTmpDirFromEnv(), os.getpid())
        # get all content by crontab command
        (status, output) = CrontabUtil.getAllCrontab()
        if status == 0:
            # overwrit cronFile, make it empty.
            FileUtil.createFile(cron_file, True, DefaultValue.KEY_FILE_MODE)
            content_cron_file = [output]
            if output != "":
                FileUtil.writeFile(cron_file, content_cron_file)
                FileUtil.deleteLine(cron_file, "\\/bin\\/om_monitor")
        elif status not in [256, 1]:  # status==256 means this user has no cron
            raise Exception(ErrorCode.GAUSS_508["GAUSS_50803"] + " Error: \n%s" % output)

        if mpprc_file != "" and mpprc_file is not None:
            cron_content = "*/1 * * * * source /etc/profile;(if [ -f ~/.profile ];" \
                           "then source ~/.profile;fi);source ~/.bashrc;source %s;" \
                           "nohup %s/bin/om_monitor -L %s >>/dev/null 2>&1 &" % (mpprc_file,
                                                                                 app_path,
                                                                                 log_path)
            content_cron_file = [cron_content]
        else:
            cron_content = "*/1 * * * * source /etc/profile;(if [ -f ~/.profile ];" \
                           "then source ~/.profile;fi);source ~/.bashrc;" \
                           "nohup %s/bin/om_monitor -L %s >>/dev/null 2>&1 &" % (app_path,
                                                                                 log_path)
            content_cron_file = [cron_content]

        # Set cron for clear corefiles
        gp_home = EnvUtil.getEnvironmentParameterValue("GPHOME", "")
        default_xml = "%s/cluster_default_agent.xml" % gp_home
        if os.path.exists(default_xml):
            corefile = dbClusterInfo.readClustercorePath(default_xml)
            if not os.path.exists(corefile):
                cron_content_coreclear = "* */1 * * * diskUse=$(df %s -h | grep -v 'Use' | " \
                                         "awk '{print $5}');" \
                                         "fileNum=$(expr $(ls %s | wc -l) - 5);" % (corefile,
                                                                                    corefile)
                cron_content_coreclear += "(if [ ${diskUse%%%%%%} -gt %s -a $fileNum -gt 5 ];" \
                                          "then ls -tr | head -$fileNum | " \
                                          "xargs -i -n$fileNum rm -rf {};fi) >>/dev/null " \
                                          "2>&1 &" % DefaultValue.CORE_PATH_DISK_THRESHOLD
                content_cron_file.append(cron_content_coreclear)
        FileUtil.writeFile(cron_file, content_cron_file)
        CrontabUtil.execCrontab(cron_file)
        FileUtil.removeFile(cron_file)

        self._kill_om_monitor()

        if mpprc_file != "" and mpprc_file is not None:
            cmd = "source /etc/profile;(if [ -f ~/.profile ];then source ~/.profile;fi);" \
                  "source ~/.bashrc;source %s; nohup %s/bin/om_monitor -L %s " \
                  ">>/dev/null 2>&1 &" % (mpprc_file, app_path, log_path)
        else:
            cmd = "source /etc/profile;(if [ -f ~/.profile ];then source ~/.profile;fi);" \
                  "source ~/.bashrc; nohup %s/bin/om_monitor -L %s >>" \
                  "/dev/null 2>&1 &" % (app_path, log_path)
        self.logger.debug("Command for start om_monitor: %s" % cmd)
        status = os.system(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "om_monitor")

    def setGucConfig(self, para_dict, setMode='set'):
        """
        function: set cm guc config file (cm_server.conf/cm_agent.conf)
        input : NA
        output: NA
        """
        user_profile = EnvUtil.getMpprcFile()
        EnvUtil.source(user_profile)
        self.logger.debug("setMode is {0}".format(setMode))
        if self.instInfo.instanceRole == DefaultValue.INSTANCE_ROLE_CMSERVER:
            config_file = os.path.join(self.instInfo.datadir, "cm_server.conf")
        else:
            config_file = os.path.join(self.instInfo.datadir, "cm_agent.conf")

        for key in para_dict.keys():
            value = para_dict[key].replace("/", "{0}/".format("\\")).replace("'", "\\'")
            cmd = "sed -i 's/\\t/    /g' %s && \
                   if [ 0 -eq `grep '%s' %s | grep -v '^[ ]*#' | wc -l` ]; \
                   then \
                       echo \"%s = %s\" >> %s; \
                   else \
                     if [ 0 -ne `grep '%s' %s | grep '#' | wc -l` ]; then \
                       sed -i \"s/^[ \\t]*%s.*=.*\\([ ]*#.*\\)/%s = %s \\1/g\" %s; \
                     else \
                       sed -i \"s/^[ \\t]*%s.*=.*\\([ ]*\\)/%s = %s \\1/g\" %s; \
                         fi \
                   fi" % \
                  (config_file,
                   key, config_file,
                   key, para_dict[key], config_file,
                   key, config_file,
                   key, key, value, config_file,
                   key, key, value, config_file)
            self.logger.debug("Command for setting cm parameter: %s" % cmd)
            (status, output) = CmdUtil.retryGetstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] % "GUC" +
                                " Error: \n%s" % str(output))

    def getGucConfig(self, paraList):
        """
        function: get cm guc parameter value from file (cm_server.conf/cm_agent.conf)
        input : NA
        output: NA
        """
        if self.instInfo.instanceRole == DefaultValue.INSTANCE_ROLE_CMSERVER:
            gucFile = "%s/cm_server.conf" % self.instInfo.datadir
        else:
            gucFile = "%s/cm_agent.conf" % self.instInfo.datadir
        paraDict = {}
        for paraName in paraList:
            (_, output) = GrepUtil.getGrepValue("-E", "^[ \\t]*%s ", gucFile)
            output_list = output.strip().split("\n")
            for line in output_list:
                if line.find("=") < 0:
                    continue
                value_line = line.split("=")[1]
                para_value = value_line.split("#")[0].strip()
                paraDict[paraName] = para_value
        return paraDict

    def get_cm_dict(self, user, item_type=None, alarm_component=None, guc_xml=(False, "")):
        """
        function: Get cms or cma configuration
        input : NA
        output: NA
        """
        if self.instInfo.instanceRole == DefaultValue.INSTANCE_ROLE_CMSERVER:
            instance_role = "cm_server"
            instance_simple = "cms"
        else:
            instance_role = "cm_agent"
            instance_simple = "cma"
        tmp_dict = dict()

        tmp_dict["log_dir"] = os.path.join(ClusterDir.getUserLogDirWithUser(user),
                                           "cm", instance_role)
        if guc_xml[0]:
            self.logger.log("start to get %s param from guc xml: %s" % (instance_role,
                                                                        guc_xml[-1]))
            tmp_guc_path = EnvUtil.getTmpDirFromEnv(user)
            tmp_guc_file = os.path.realpath(os.path.join(tmp_guc_path, "tmp_guc"))
            if os.path.isfile(tmp_guc_file):
                self.logger.debug("Check if dict is not null.")
                dynamic_dict = DefaultValue.dynamicGuc(user, self.logger, instance_simple,
                                                       tmp_guc_file, guc_xml)
                if dynamic_dict:
                    tmp_dict.update(dynamic_dict)
        if item_type == "ConfigInstance":
            tmp_dict["alarm_component"] = "%s" % alarm_component

            if instance_role == "cm_agent":
                tmp_dict["unix_socket_directory"] = "'%s'" % EnvUtil.getTmpDirFromEnv()
        return tmp_dict

    def configInstance(self, user, configItemType=None, alarm_component=None, cmsConfig=None,
                       guc_xml=(False, "")):
        """
        function: Get CMAgent configuration
        input : user, configItemType, alarm_component
        output: NA
        """
        tmp_dict = self.get_cm_dict(user, configItemType, alarm_component, guc_xml)
        tmp_dict.update(cmsConfig)
        self.setGucConfig(tmp_dict)

    def doCheckStaus(self, nodeId, cluster_normal_status=None, expected_redistributing=""):
        """
        function: Check cluster status
        input : user, nodeId, cluster_normal_status, expected_redistributing
        output: status, output
        """
        status_file = \
            "%s/gauss_check_status_%d.dat" % (EnvUtil.getTmpDirFromEnv(), os.getpid())
        FileUtil.cleanTmpFile(status_file)
        cmd = self.getQueryStatusCmd(0, status_file, showDetail=True, isFormat=False)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            FileUtil.cleanTmpFile(status_file)
            return (status, output)

        cluster_status = DbClusterStatus()
        cluster_status.initFromFile(status_file)
        FileUtil.cleanTmpFile(status_file)

        status = 0
        output = ""
        status_rep = None
        if nodeId > 0:
            nodeStatus = cluster_status.getDbNodeStatusById(nodeId)
            if nodeStatus is None:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51619"] % nodeId)

            status = 0 if nodeStatus.isNodeHealthy() else 1
            status_rep = nodeStatus.getNodeStatusReport()
        else:
            status = 0 if cluster_status.isAllHealthy(cluster_normal_status) \
                          and (cluster_status.redistributing == expected_redistributing
                               or expected_redistributing == "") else 1
            status_rep = cluster_status.getClusterStatusReport()
            self.logger.debug("status_result is : {0}".format(status_rep))
            output += "cluster_state      : %s\n" % cluster_status.clusterStatus
            output += "redistributing     : %s\n" % cluster_status.redistributing
            output += "node_count         : %d\n" % status_rep.nodeCount

        output += "Datanode State\n"
        output += "    primary           : %d\n" % status_rep.dnPrimary
        output += "    standby           : %d\n" % status_rep.dnStandby
        output += "    secondary         : %d\n" % status_rep.dnDummy
        output += "    cascade_standby   : %d\n" % status_rep.dn_cascade_standby
        output += "    building          : %d\n" % status_rep.dnBuild
        output += "    abnormal          : %d\n" % status_rep.dnAbnormal
        output += "    down              : %d\n" % status_rep.dnDown

        return (status, output)


    @staticmethod
    def _get_switch_over_cmd(user, nodeId, datadir):
        """
        function : Get the command of switching over standby instance
        input : String,int,String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "source %s ; cm_ctl switchover -n %d -D %s" % (user_profile, nodeId, datadir)
        # build shell command
        if user and os.getuid() == 0:
            cmd = "su - %s -c 'source %s;%s'" % (user, user_profile, cmd)

        return cmd


    @staticmethod
    def get_reset_switchover_cmd(user, timeout):
        """
        function : Reset Switch over
        input : String,String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "source %s ; cm_ctl switchover -a" % user_profile
        if timeout > 0:
            cmd += (" -t %d" % timeout)
        # build shell command
        if user and os.getuid() == 0:
            cmd = "su - %s -c 'source %s;%s'" % (user, user_profile, cmd)

        return cmd

    @staticmethod
    def getQueryStatusCmd(nodeId=0, outFile="", showDetail=True, isFormat=True):
        """
        function : Get the command of querying status of cluster or node
        input : String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "source %s ; cm_ctl query" % user_profile
        # check node id
        if nodeId > 0:
            cmd += " -n %d" % nodeId
        # check -v
        if showDetail:
            cmd += " -v"
            # status format
        if isFormat:
            cmd += " -C -i -d"
        # check out put file
        if outFile != "":
            cmd += " > %s" % outFile

        return cmd

    def killProcess(self):
        """
        function : kill cm server instance process
        input : NA
        output : NA
        """
        cmd = DefaultValue.killInstProcessCmd("cm_server", False)
        self.logger.debug("Kill cm_server cmd is: {0}".format(cmd))
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51606"] %
                            "cm_server" + " Error: \n%s" % str(output))
        self.logger.debug("Kill cm_server process successfully.")


    @staticmethod
    def encryptor(secret, path, logger):
        """
        encrypt secret
        """
        gauss_home = DefaultValue.getPathFileOfENV("GAUSSHOME")
        gp_home = DefaultValue.getPathFileOfENV("GPHOME")
        expect_sh = os.path.realpath(os.path.join(gp_home, "script", "local", "expect.sh"))
        cm_ctl = os.path.join(gauss_home, "bin/cm_ctl")
        cmd1 = "%s encrypt -M server -D %s" % (cm_ctl, path)
        cmd2 = "%s encrypt -M client -D %s" % (cm_ctl, path)
        if not gauss_home:
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "CM_HOME")

        for cmd in [cmd1, cmd2]:
            expect_key_word = "please enter the password*"
            expect_cmd = 'echo "{0}" | sh {1} "{2}" "{3}"'.format(secret,
                                                                  expect_sh,
                                                                  expect_key_word,
                                                                  cmd)
            logger.debug("Enryptor execute command: {0}".format(cmd))

            proc = FastPopen(expect_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = proc.communicate(expect_cmd)
            if proc.returncode != 0:
                raise Exception("Generate key file with cm_ctl failed. {0}".format(stdout))
            logger.debug("Generate key file successfully.")

    def _retry_generate_ca(self, target_dir, retry_count):
        """
        Retry perform generate CA files.
        """
        from gspylib.common.encrypted_openssl import EncryptedOpenssl
        current_retry_count = 0
        while current_retry_count < retry_count:
            current_retry_count += 1
            self.logger.debug("Retry [{0}] time to "
                              "generate CA for CM component.".format(current_retry_count))
            try:
                openssl = EncryptedOpenssl(target_dir, self.logger, pw_len=12)
                openssl.set_encryptor(CM_OLAP.encryptor)
                openssl.generate()
                self.logger.debug("Generate CA files successfully.")
                return openssl
            except Exception as exp:
                self.logger.debug("Retry [{0}] time failed. "
                                  "Error info : {1}".format(current_retry_count, str(exp)))
                continue
        self.logger.debug("Retry generate CA for CM component failed.")

    def create_cm_ca(self, ssh_tool, ca_org='cm'):
        """
        Create CA file for CM/dss component
        """
        self.logger.log("Create CA files for {} beginning.".format(ca_org))
        current_user = pwd.getpwuid(os.getuid()).pw_name
        gp_home = EnvUtil.getEnvironmentParameterValue("GPHOME", current_user)
        create_ca_script = os.path.realpath(os.path.join(gp_home, "script", "gspylib",
                                                         "common", "encrypted_openssl.py"))
        expect_sh = os.path.realpath(os.path.join(gp_home, "script", "local", "expect.sh"))
        target_dir = os.path.realpath(os.path.join(self.binPath, "..", "share", "sslcert", ca_org))

        if os.path.isfile(create_ca_script) and os.path.isfile(expect_sh):
            create_cmd = g_file.SHELL_CMD_DICT["createDir"] % (target_dir,
                                                               target_dir,
                                                               DefaultValue.KEY_DIRECTORY_MODE)
            status, _ = subprocess.getstatusoutput(create_cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_535["GAUSS_53507"] % create_cmd)
            openssl = None
            while True:
                FileUtil.cleanDirectoryContent(target_dir)
                openssl = self._retry_generate_ca(target_dir, CM_OLAP.RETRY_COUNT)
                # number of assurance certificate files.
                if openssl and len(os.listdir(target_dir)) > CM_OLAP.CM_CERT_FILES_NUM:
                    break
            if (ssh_tool):
                openssl.distribute_cert(ssh_tool)
            self.logger.log("Create CA files on directory [{0}]. "
                            "file list: {1}".format(target_dir, os.listdir(target_dir)))
        else:
            self.logger.log("There is not exists [%s]." % create_ca_script)

    def get_init_cm_cmd(self):
        user = pwd.getpwuid(os.getuid()).pw_name
        gauss_home = EnvUtil.getEnvironmentParameterValue('GAUSSHOME', user)
        dss_home = EnvUtil.getEnvironmentParameterValue('DSS_HOME', user)
        # not use realpath
        dms_contrl = os.path.join(gauss_home, 'bin/dms_contrl.sh')
        dss_contrl = os.path.join(gauss_home, 'bin/dss_contrl.sh')

        cmd = [
            str(CmResCtrlCmd(name='dms_res', attr=CmResAttr(dms_contrl))),
            str(
                CmResCtrlCmd(name='dss',
                             attr=CmResAttr(dss_contrl, res_type='APP')))
        ]

        for db_inst in self.cluster_info.dbNodes:
            cmd.append(
                str(
                    CmResCtrlCmd(action='edit',
                                 name='dss',
                                 attr=DssInstAttr(
                                     node_id=db_inst.id,
                                     dss_id=DssInst.get_current_dss_id(
                                         dss_home, db_inst,
                                         DssConfig.get_value_b64_handler(
                                             'dss_nodes_list',
                                             self.dss_config,
                                             action='decode')),
                                     dss_home="{};{}".format(
                                         dss_home,
                                         db_inst.datanodes[0].datadir)))))
        return "source {}; {}".format(EnvUtil.getMpprcFile(), ' ;'.join(cmd))

    def init_cm_res_json(self, rm_cm_json=True):
        cm_resource = os.path.realpath(
            os.path.join(self.instInfo.datadir, 'cm_resource.json'))
        if rm_cm_json and os.path.isfile(cm_resource):
            os.remove(cm_resource)
        cmd = self.get_init_cm_cmd()
        sts, out = subprocess.getstatusoutput(cmd)
        if sts != 0:
            raise Exception(
                'Failed to initialize the CM resource file. Error: {}'.format(
                    str(out)))

    def get_add_cm_res_cmd(self, cm_res_info):
        """
        Get add CM resource information cmd for VIP
        """
        cmd_list = []
        for res_name, _list in cm_res_info.items():
            check_res = "cm_ctl res --list --res_name=\"%s\"" % res_name
            stat, out= subprocess.getstatusoutput(check_res)
            if stat != 0 or not out:
                cmd_list.append(str(VipCmResCtrlCmd("add_res", res_name,
                                    attr=VipResAttr(_list[0][0]))))
            for _tup in _list:
                check_inst = "cm_ctl res --list --res_name=\"%s\" --list_inst" \
                             " | grep \"%s\"" % (res_name, _tup[1])
                stat, out= subprocess.getstatusoutput(check_inst)
                if stat != 0 or not out:
                    cmd_list.append(str(VipCmResCtrlCmd("add_inst", res_name,
                                        inst=VipAddInst(_tup[2], _tup[3]),
                                        attr=VipInstAttr(_tup[1]))))
        cmd = "source %s; %s" % (EnvUtil.getMpprcFile(), ' ;'.join(cmd_list))
        self.logger.log("Add cm resource information cmd: \n%s" % cmd)
        return cmd

    def _get_cm_res_info(self, base_ip):
        """
        Get the CM resource info for reducing
        """
        # Get resource name
        cmd = "cm_ctl res --list | grep \"VIP\" | awk -F \"|\" '{print $1}'" \
                  " | xargs -i cm_ctl res --list --res_name={} --list_inst" \
                  " | grep \"base_ip=%s\" | awk -F \"|\" '{print $1}'" % base_ip
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0:
            raise Exception("Failed to get res name. Cmd: \n%s" % cmd)
        if not out:
            return "", -1, -1
        res_name = out.strip()

        # Get intance ID
        cmd = "cm_ctl res --list --res_name=\"%s\" --list_inst | grep " \
                  "\"base_ip=%s\" | awk -F \"|\" '{print $4}'" % (res_name, base_ip)
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0 or not out:
            raise Exception("Failed to get the intance ID. Cmd: \n%s" % cmd)
        inst_id = int(out.strip())

        # Get the number of instances contained in a resource
        cmd = "cm_ctl res --list --res_name=\"%s\" --list_inst" \
                  " | grep \"VIP\" | wc -l" % res_name
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0 or not out:
            raise Exception("Failed to get the number of instances. Cmd: %s" % cmd)
        inst_num = int(out.strip())

        self.logger.log("CM resource info: res_name=%s,inst_id=%d,inst_num=%d   q" \
                        "" % (res_name, inst_id, inst_num))
        return res_name, inst_id, inst_num

    def get_reduce_cm_res_cmd(self, base_ips):
        """
        Get reduce cm resource information cmd for VIP
        """
        cmd_list = []
        for base_ip in base_ips:
            res_name, inst_id, inst_num = self._get_cm_res_info(base_ip)
            if not res_name:
                self.logger.log("The base IP is not found: %s" % base_ip)
                continue
            if  inst_num > 1:
                cmd_list.append(str(VipCmResCtrlCmd("del_inst", res_name,
                                    inst=VipDelInst(inst_id))))
            else:
                cmd_list.append(str(VipCmResCtrlCmd("del_res", res_name)))
        cmd = "source %s; %s" % (EnvUtil.getMpprcFile(), ' ;'.join(cmd_list))
        self.logger.log("Reduce cm resource information cmd: \n%s" % cmd)
        return cmd

    def config_cm_res_json(self, base_ips, cm_res_info):
        """
        Config cm resource file for vip
        """
        if not base_ips and not cm_res_info:
            raise Exception("The parameters cannot be empty at the same time")

        cmd = self.get_reduce_cm_res_cmd(base_ips)
        stat, out = subprocess.getstatusoutput(cmd)
        if stat != 0:
            raise Exception("Failed to reduce the CM resource for VIP." \
                            " Cmd: \n%s, Error: \n%s" % (cmd, str(out)))

        cmd = self.get_add_cm_res_cmd(cm_res_info)
        stat, out = subprocess.getstatusoutput(cmd)
        if stat != 0:
            raise Exception("Failed to add the CM resource for VIP." \
                            " Cmd: \n%s, Error: \n%s" % (cmd, str(out)))

        cmd = "cm_ctl res --check"
        stat, out = subprocess.getstatusoutput(cmd)
        if stat != 0:
            raise Exception("Failed to config the CM resource file for VIP." \
                            " Cmd: \n%s, Error: \n%s" % (cmd, str(out)))
