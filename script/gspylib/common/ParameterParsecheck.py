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
# Description  : ParameterParsecheck.py is a utility to get Parameter
# information and check it.
#############################################################################
import os
import getopt
import sys

sys.path.append(sys.path[0] + "/../../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.common.GaussLog import GaussLog
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo

PARAMETER_VALUEDICT = {}
ParameterDict = {}
Itemstr = []
skipItems = []
user_passwd = []
EnvParams = []
DbInitParam = []
DataGucParam = []
cm_server_guc_param = []
NODE_NAME = []

# Add parameter: the logic cluster name
PARA_CHECK_LIST = ["-t", "-h", "-m", "--mode", "-S"
                   "-i", "-j", "-U", "-u", "-G", "-g", "--alarm-type",
                   "-n", "-g",
                   "-N", "--time-out", "--alarm-component",
                   "--parallel-jobs", '--redis-mode', "--ring-num",
                   "--virtual-ip",
                   "--nodeName", "--name", "--failure-limit", "--skip-items",
                   "script_type=", "oldcluster_num=", "guc_string=", "setType="]
PATH_CHEKC_LIST = ["-M", "-o", "-f", "-X", "-P", "-s", "-R", "-Q",
                   "--position", "-B",
                   "--backupdir", "--sep-env-file", "-l", "--logpath",
                   "--backup-dir",
                   "--priority-tables", "--exclude-tables", "upgrade_bak_path=",
                   "old_cluster_app_path=", "new_cluster_app_path="]
VALUE_CHECK_LIST = ["|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{",
                    "}", "(", ")",
                    "[", "]", "~", "*", "?", "!", "\n"]

# append ':' after short options if it required parameter
# append '=' after long options if it required parameter
# no child branch
gs_preinstall = ["-?", "--help", "-V", "--version", "-U:", "-G:", "-L",
                 "--skip-os-set", "-X:", "--alarm-type=", "--alarm-server-addr=",
                 "--env-var=", "--sep-env-file=", "--skip-hostname-set", "--skip-cgroup-set",
                 "-l:", "--non-interactive", "--delete-root-trust", "--unused-third-party",
                 "--enable-perf-config", "--one-stop-install"]
gs_install = ["-?", "--help", "-V", "--version", "-X:", "-l:",
              "--gsinit-parameter=", "--dn-guc=", "--cms-guc=",
              "--time-out=", "--dorado-cluster-mode=", "--alarm-component=",
              "--enable-perf-config"]
gs_uninstall = ["-?", "--help", "-V", "--version", "-l:", "-L",
                "--delete-data", "--clear-disk"]
gs_postuninstall = ["-?", "--help", "-V", "--version", "--delete-user",
                    "--delete-group", "--clean-gphome",
                    "-U:", "-X:", "-l:", "-L"]
gs_check = ["-?", "--help", "-V", "--version", "-e:", "-i:",
            "-U:", "-o:", "-l:", "-L", "--hosts=",
            "--format=", "--cid=", "--disk-threshold=",
            "--time-out=", "--routing=", "--skip-items=",
            "--ShrinkNodes=", "--nodegroup-name=",
            "--skip-root-items", "--set", "--non-print"]
gs_sshexkey = ["-?", "--help", "-V", "--version",
               "-f:", "--skip-hostname-set", "-l:", "-h:", "-W:", "--no-deduplicate"]
gs_backup = ["-?", "--help", "-V", "--version", "--backup-dir=",
             "--parameter", "--force",
             "--binary", "--all", "-l:", "-h:", "-t:", "-X:"]
gs_collector = ["-?", "--help", "-V", "--version", "--begin-time=",
                "--end-time=",
                "--keyword=", "--speed-limit=", "-h:", "-f:", "-o:",
                "-l:", "-C:", "--timeout="]
gs_checkperf = ["-?", "--help", "-V", "--version", "--detail", "-o:",
                "-i:", "-l:", "-U:"]
gs_ssh = ["-?", "--help", "-V", "--version", "-c:"]
gs_checkos = ["-?", "--help", "-V", "--version", "-h:", "-f:", "-o:",
              "-i:", "--detail",
              "-l:", "-X:", "--skip-item-num="]
gs_checkse = ["-?", "--help", "-V", "--version", "-h:", "-f:", "-o:",
              "-i:", "--detail", "--database=",
              "-l:", "-X:"]
gs_expansion = ["-?", "--help", "-V", "--version", "-U:", "-G:", "-L", 
            "-X:", "-h:", "--sep-env-file=", "--time-out="]
gs_dropnode = ["-?", "--help", "-V", "--version", "-U:", "-G:",
            "-h:", "--sep-env-file="]

# gs_om child branch
gs_om_start = ["-t:", "-?", "--help", "-V", "--version", "-h:", "-I:",
               "--time-out=", "--az=", "-l:", "--nodeId=", "-D:",
               "--security-mode=", "--cluster-number=", "--component="]
gs_om_stop = ["-t:", "-?", "--help", "-V", "--version", "-h:", "-I:", "-m:",
              "--az=", "-l:", "--mode=", "--nodeId=", "--time-out=", "-D:",
              "--component="]
gs_om_restart = ["-t:", "-?", "--help", "-V", "--version", "-h:", "-I:",
               "--time-out=", "--az=", "-l:", "--nodeId=", "-D:",
               "--security-mode=", "--mode=", "-m:", "--component="]
gs_om_view = ["-t:", "-?", "--help", "-V", "--version", "-o:", "-l:", "--dynamic"]
gs_om_query = ["-t:", "-?", "--help", "-V", "--version", "-o:", "-l:", "--time-out="]
gs_om_status = ["-t:", "-?", "--help", "-V", "--version", "-h:", "-o:",
                "--detail", "--all", "-l:", "--az=", "--time-out="]
gs_om_generateconf = ["-t:", "-?", "--help", "-V", "--version", "-X:",
                      "--distribute", "-l:", "--old-values=", "--new-values="]
gs_om_cert = ["-t:", "-?", "--help", "-V", "--version", "-L", "-l:",
              "--cert-file=", "--rollback"]
gs_om_kerberos = ["-t:", "-?", "--help", "-V", "--version", "-m:", "-U:",
                  "-X:", "-l:", "--krb-server", "--krb-client"]
gs_om_refreshconf = ["-t:", "-?", "--help", "-V", "--version", "-l:"]
gs_om_killmonitor = ["-t:", "-?", "--help", "-V", "--version", "-l:"]
gs_om_generate_xml = ["-t:", "-?", "--help", "-V", "--version", "-l:", "--add-hostname=", "--add-hostip="]
gs_om_query_upgrade_records = ["-t:", "-?", "--help", "-V", "--version"]
# gs_upgradectl child branch
# AP and TP are same
gs_upgradectl_chose_strategy = ["-t:", "-?", "--help", "-V", "--version",
                                "-l:"]
# auto-upgrade parameter lists
gs_upgradectl_auto_upgrade = ["-t:", "-?", "--help", "-V", "--version", "-l:",
                              "-X:", "--grey", "-h:", "--continue", "--inplace-upgrade", "--bypass-stale-check"]
# auto-rollback parameter lists
gs_upgradectl_auto_rollback = ["-t:", "-?", "--help", "-V", "--version",
                               "-l:", "-X:", "--force"]
# show-step parameter lists
gs_upgradectl_show_upgrade_step = ["-S:", "-?", "--help", "-V", "--version", "-l:"]

# commit-upgrade parameter lists
gs_upgradectl_commit = ["-t:", "-?", "--help", "-V", "--version", "-l:", "-X:"]

# upgrade cm component
gs_upgradectl_upgrade_cm = ["-t:", "-?", "--help", "-V", "--version", "-l", "--upgrade-package="]

ParameterDict = {"preinstall": gs_preinstall,
                 "install": gs_install,
                 "uninstall": gs_uninstall,
                 "checkos": gs_checkos,
                 "checkse": gs_checkse,
                 "checkperf": gs_checkperf,
                 "check": gs_check,
                 "auto_upgrade": gs_upgradectl_auto_upgrade,
                 "chose_strategy": gs_upgradectl_chose_strategy,
                 "commit_upgrade": gs_upgradectl_commit,
                 "show-step": gs_upgradectl_show_upgrade_step,
                 "upgrade-cm": gs_upgradectl_upgrade_cm,
                 "auto_rollback": gs_upgradectl_auto_rollback,
                 "start": gs_om_start,
                 "stop": gs_om_stop,
                 "restart": gs_om_restart,
                 "status": gs_om_status,
                 "generateconf": gs_om_generateconf,
                 "cert": gs_om_cert,
                 "kerberos": gs_om_kerberos,
                 "sshexkey": gs_sshexkey,
                 "backup": gs_backup,
                 "collector": gs_collector,
                 "ssh": gs_ssh,
                 "postuninstall": gs_postuninstall,
                 "view": gs_om_view,
                 "query": gs_om_query,
                 "refreshconf": gs_om_refreshconf,
                 "expansion": gs_expansion,
                 "dropnode": gs_dropnode,
                 "killmonitor": gs_om_killmonitor,
                 "generate_xml": gs_om_generate_xml,
                 "query_upgrade_records": gs_om_query_upgrade_records
                 }

# List of scripts with the -t parameter
special_list = ["gs_om", "backup", "upgradectl"]

# The -t parameter list
action_om = ["start", "stop", "status", "restart", "generateconf", "kerberos",
             "cert", "view", "query", "refreshconf", "killmonitor", "generate_xml", "query_upgrade_records"]
action_upgradectl = ["chose-strategy", "auto-upgrade", "auto-rollback",
                     "commit-upgrade", "upgrade-cm", "show-step"]


class Parameter():
    '''
    get Parameter information and check it. 
    '''

    def __init__(self):
        '''
        '''
        self.action = ""
        self.mode = ""
        self.helpflag = False
        self.versionflag = False

    def ParseParameterValue(self, module):
        """
        function: parse the parameter value
        input : parameter_list
        output: options
        """
        # get the parameter list
        (shortParameter, longParameter) = self.getParseParameter(module)

        try:
            paraList = sys.argv[1:]
            for paraInfo in paraList:
                if (paraInfo.startswith('--')):
                    isFlag = False
                    for longPara in longParameter:
                        if (paraInfo[2:].startswith(longPara.strip("="))):
                            isFlag = True
                    if (not isFlag):
                        GaussLog.exitWithError(
                            ErrorCode.GAUSS_500["GAUSS_50000"] % paraInfo)
            # check delete parameter -h and -f, if specified lcname,
            # not required -h or -f.
            for check_i in sys.argv[1:]:
                if "--name" in check_i:
                    break
            (opts, args) = getopt.getopt(sys.argv[1:], shortParameter,
                                         longParameter)
        except Exception as e:
            s1 = str(e).split(" ")
            option = s1[1]
            if ("requires argument" in str(e)):
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % \
                                       option[1:] + " Error:\n%s" % str(e))
            elif ("not recognized" in str(e)):
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                       % option)
            elif ("not a unique prefix" in str(e)):
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50006"]
                                       % option)
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                       % str(e))

        if (len(args) > 0):
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                                   % str(args[0]))

        return opts

    def moveCrypto(self, module):
        """
        function: Parse the parameter
        input : parameter_list
        output: PARAMETER_VALUEDICT
        """
        if (module in ("preinstall", "sshexkey", "expansion")):
            DefaultValue.doConfigForParamiko()

    def printVersionInfo(self):
        """
        """
        if (self.versionflag):
            print("%s %s" % (sys.argv[0].split("/")[-1],
                             VersionInfo.COMMON_VERSION))
            sys.exit(0)

    def ParameterCommandLine(self, module):
        """
        function: Parse the parameter
        input : parameter_list
        output: PARAMETER_VALUEDICT
        """
        # copy crypto
        self.moveCrypto(module)

        # Determines whether help and version information is output
        self.helpflag, self.versionflag = self.getHelpAndVersionStatus()
        if (self.helpflag):
            PARAMETER_VALUEDICT['helpFlag'] = self.helpflag
            return PARAMETER_VALUEDICT

        # print version information
        self.printVersionInfo()

        # Special handling of the -t parameter
        self.getActionParameterValue(module)

        # get the parameter list
        opts = self.ParseParameterValue(module)

        parameterNeedValue = {"-t": "action",
                              "-S": "action",
                              "-c": "cmd",
                              "-m": "Mode",
                              "--mode": "Mode",
                              # hotpatch name
                              "-n": "patch_name",
                              "-d": "destPath",
                              "-s": "sourcePath",
                              "-j": "jobs",
                              "-U": "user",
                              "-G": "group",
                              "-I": "instance_name",
                              "-e": "scenes",
                              "-C": "configFile",
                              "--format": "format",
                              "--cid": "cid",
                              "--routing": "routing",
                              "--ShrinkNodes": "shrinkNodes",
                              "--az": "az_name",
                              "--root-passwd": "rootPasswd",
                              "--alarm-type": "warningType",
                              "--alarm-server-addr": "warningserverip",
                              "--time-out": "time_out", "": "",
                              "--dorado-cluster-mode" :"dorado-cluster-mode",
                              "--alarm-component": "alarm_component",
                              "--SSD-fault-time": "SSDFaultTime",
                              "--begin-time": "begintime",
                              "--end-time": "endtime",
                              "--keyword": "keyword",
                              "--redis-mode": "redismode",
                              "--failure-limit": "failure_limit",
                              "--virtual-ip": "virtual-ip",
                              "--master": "master",
                              "--standby": "standby",
                              "--disk-threshold": "disk-threshold",
                              "--target": "target",
                              "--name": "name",
                              "-N": "DSN",
                              "--type": "type",
                              "--remote-host": "remote_host",
                              "--remote-env-file": "remote_mpprcfile",
                              "--dilatation-mode": "dilatation_mode",
                              "--nodegroup-name": "nodegroup_name",
                              "--speed-limit": "speedLimit",
                              "--timeout": "timeout",
                              # add "resourcectl" for resource control
                              # in data redistribution
                              "--resource-level": "resource_level",
                              "-p": "port",
                              "--dn-port": "dn-port",
                              "--dn-ip": "dn-ip",
                              "--database": "database",
                              "--interval": "interval",
                              "--threshold": "threshold",
                              "--check-count": "check_count",
                              "--wait-count": "wait_count",
                              "--option": "option",
                              "--dbname": "dbname",
                              "--dbuser": "dbuser",
                              "--nodeId": "nodeId",
                              "--add-hostname": "add_hostname",
                              "--add-hostip": "add_hostip",
                              "--security-mode": "security_mode",
                              "--cluster-number": "cluster_number",
                              "--skip-item-num": "skip_item_num",
                              "--component": "component"
                              }
        parameterNeedValue_keys = parameterNeedValue.keys()

        parameterIsBool = {"-L": "localMode",
                           "--set": "set",
                           "--one-stop-install": "one_stop_install",
                           "--skip-root-items": "skipRootItems",
                           "--non-interactive": "preMode",
                           "--skip-os-set": "skipOSSet",
                           "--skip-hostname-set": "skipHostnameSet",
                           "--skip-cgroup-set": "skip_cgroup_set",
                           "--reset": "reset",
                           "--parameter": "isParameter",
                           "--binary": "isBinary",
                           "--delete-data": "cleanInstance",
                           "--clear-disk": "clearDisk",
                           "--delete-user": "delete-user",
                           "--delete-group": "delete-group",
                           "--dws-mode": "dws-mode",
                           "--dss_mode": "dss_mode",
                           "--detail": "show_detail",
                           "--detail-all": "show_detail_all",
                           "--rollback": "rollback",
                           "--vacuum-full": "enable_vacuum",
                           "--fast-redis": "enable_fast",
                           "--distribute": "distribute",
                           "--build-redistb": "buildTable",
                           "--key-files": "key-files",
                           "--all": "all",
                           "--upgrade": "upgrade",
                           "--lcname-only": "lcname-only",
                           "--high-perform": "high-perform",
                           "--elastic-group": "elastic-group",
                           "--addto-elastic-group": "isAddElasticGroup",
                           "--express": "express",
                           "--checkdisk": "checkdisk",
                           "--inplace": "inplace",
                           "--continue": "continue",
                           "--force": "force",
                           "--grey": "grey",
                           "--agent-mode": "agentMode",
                           "--krb-server": "krb-server",
                           "--krb-client": "krb-client",
                           "--non-print": "nonPrinting",
                           "--dynamic": "dynamic",
                           "--delete-root-trust": "root_delete_flag",
                           "--unused-third-party": "unused_third_party",
                           "--enable-perf-config": "enable_perf_config",
                           "--inplace-upgrade": "inplace_upgrade",
                           "--bypass-stale-check": "bypass_stale_check"
                           }
        parameterIsBool_keys = parameterIsBool.keys()

        # Parameter assignment and return
        for (key, value) in opts:
            if (key in parameterNeedValue_keys):
                PARAMETER_VALUEDICT[parameterNeedValue[key]] = value
            elif (key in parameterIsBool_keys):
                PARAMETER_VALUEDICT[parameterIsBool[key]] = True
            elif (key == "-h"):
                # Only obtain the last value of hostname
                del NODE_NAME[:]
                for node in value.strip().split(","):
                    if (node is not None and node != "" and (
                            node not in NODE_NAME)):
                        NODE_NAME.append(node.strip())
            elif (key == "-W" or key == "--password"):
                user_passwd.append(value)
            elif (key == "-D"):
                PARAMETER_VALUEDICT['dataDir'] = os.path.normpath(value)
            elif (key == "-M"):
                PARAMETER_VALUEDICT['cgroupMountDir'] = \
                    os.path.realpath(value.strip())
            elif (key == "-o"):
                PARAMETER_VALUEDICT['outFile'] = os.path.realpath(value)
                if (module not in ["collector", "check"]):
                    self.createOutputDir(os.path.realpath(value))
            elif (key == "-i"):
                for item in value.strip().split(","):
                    if item is not None and item != "" \
                            and (item not in Itemstr):
                        Itemstr.append(item)
            elif (key == "--skip-items"):
                for item in value.strip().split(","):
                    if (item is not None and item != "" and (
                            item not in skipItems)):
                        skipItems.append(item)
            elif self.action != "license" and (
                    key == "-f" or key == "--hosts"):
                hostFile = self.checkPath(key, value)
                PARAMETER_VALUEDICT['hostfile'] = os.path.realpath(hostFile)
            elif (key == "-X"):
                if (module != "uninstall"):
                    xmlFile = self.checkPath(key, value)
                    PARAMETER_VALUEDICT['confFile'] = os.path.realpath(xmlFile)
                else:
                    xmlFile = str(value)
                    PARAMETER_VALUEDICT['confFile'] = os.path.realpath(xmlFile)
            elif (key == "--env-var"):
                EnvParams.append(value)
            elif (key == "--sep-env-file"):
                PARAMETER_VALUEDICT['mpprcFile'] = os.path.realpath(value)
            elif (key == "--gsinit-parameter"):
                DbInitParam.append(value)
            elif (key == "--dn-guc"):
                DataGucParam.append(value)
            elif key == "--cms-guc":
                cm_server_guc_param.append(value)
            elif (key == "-l"):
                PARAMETER_VALUEDICT['logFile'] = os.path.realpath(value)
            elif (key == "--backup-dir"):
                PARAMETER_VALUEDICT['backupDir'] = \
                    os.path.realpath(value.strip())
            elif (key == "--all"):
                PARAMETER_VALUEDICT['isParameter'] = True
                PARAMETER_VALUEDICT['isBinary'] = True
            elif (key == "--parallel-jobs"):
                paralleljobs = self.checkParamternum(key, value)
                PARAMETER_VALUEDICT['paralleljobs'] = paralleljobs
            elif (key == "-g"):
                nodesNum = self.checkParamternum(key, value)
                PARAMETER_VALUEDICT['nodesNum'] = nodesNum
            elif (key == "--ring-num"):
                ringNumbers = self.checkParamternum(key, value)
                PARAMETER_VALUEDICT['ringNumbers'] = ringNumbers
            elif (key == "--cert-file"):
                PARAMETER_VALUEDICT['cert-file'] = \
                    os.path.realpath(value.strip())
            elif (key == "--priority-tables"):
                PARAMETER_VALUEDICT['priority-tables'] = \
                    os.path.realpath(value.strip())
            elif key == "--role":
                PARAMETER_VALUEDICT['role'] = value.strip()
            elif (key == "--exclude-tables"):
                PARAMETER_VALUEDICT['exclude-tables'] = \
                    os.path.realpath(value.strip())
            elif key == "--old-values":
                PARAMETER_VALUEDICT['old_values'] = value.strip().split(",")
            elif key == "--new-values":
                PARAMETER_VALUEDICT['new_values'] = value.strip().split(",")
            elif key == "--upgrade-package":
                PARAMETER_VALUEDICT["upgrade-package"] = value.strip()
            elif key == "--dorado-cluster-mode":
                PARAMETER_VALUEDICT["dorado-cluster-mode"] = value.strip()

            # Only check / symbol for gs_lcct.
            if key in ("--name", "--nodegroup-name"):
                self.checkLcGroupName(key, value)
            Parameter.checkParaVaild(key, value)

        parameterIsList = {"passwords": user_passwd,
                           "envparams": EnvParams,
                           "dbInitParams": DbInitParam,
                           "dataGucParams": DataGucParam,
                           "cmServerGucParams": cm_server_guc_param,
                           "itemstr": Itemstr,
                           "skipItems": skipItems,
                           "nodename": NODE_NAME
                           }
        parameterlenkeys = parameterIsList.keys()
        for key in parameterlenkeys:
            if (len(parameterIsList[key]) > 0):
                PARAMETER_VALUEDICT[key] = parameterIsList[key]
        return PARAMETER_VALUEDICT

    @staticmethod
    def checkParaVaild(para, value):
        """
        function: check para vaild
        input : NA
        output: NA
        """
        for role in VALUE_CHECK_LIST:
            if PARA_CHECK_LIST.__contains__(para):
                if value.find(role) >= 0:
                    GaussLog.exitWithError(ErrorCode.GAUSS_500[
                                               "GAUSS_50011"] % \
                                           (para,
                                            value) + " Invaild value: %s." %
                                           role)
            if PATH_CHEKC_LIST.__contains__(para):
                if os.path.realpath(value).find(role) >= 0:
                    GaussLog.exitWithError(ErrorCode.GAUSS_500[
                                               "GAUSS_50011"] % \
                                           (para, value) +
                                           " Invaild value: %s." % role)

    @staticmethod
    def check_parse(key, value):
        """
                function: check para supplements
                input : NA
                output: NA
                """
        if value is None:
            return
        for i in VALUE_CHECK_LIST:
            if value.find(i) >= 0:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50011"] % \
                                       (key, value) + " Invaild value: %s." % key)

    def checkLcGroupName(self, lcPara, lcGroupName):
        """
        function: Check if the virtual cluster name is legal.
        input : lcGroupName
        output: NA
        """
        import re
        PATTERN = "^[a-zA-Z0-9_]{1,63}$"
        pattern = re.compile(PATTERN)
        result = pattern.match(lcGroupName)
        if (result is None):
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % lcPara[1:]
                            + " The name of the logical cluster does not "
                              "exceed 63 characters and can only contain "
                              "letters, numbers, and underscores.")
        if (lcGroupName in ["group_version1", "group_version2",
                            "group_version3",
                            "elastic_group"]):
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % lcPara[1:]
                            + " The name of the logical cluster cannot be "
                              "'group_version1' or 'group_version2' or "
                              "'group_version3' or 'elastic_group'.")

    def getHelpAndVersionStatus(self):
        """
        function: get help and version information status
        input : NA
        output: helpflag, versionflag
        """
        helpflag = False
        versionflag = False
        for parameter in sys.argv[1:]:
            if (parameter == "-?" or parameter == "--help"):
                helpflag = True
            if (parameter == "-V" or parameter == "--version"):
                versionflag = True
        return helpflag, versionflag

    def getActionParameterValue(self, module):
        """
        function: get the action value
        input : parameter_list
        output: NA
        """
        actions = []
        if module in special_list:
            if sys.argv[1:] == []:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50014"]
                                       % module)
            if sys.argv[1:][-1] == "-t":
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % \
                                       "t" + " option -t requires argument.")

            for n, value in enumerate(sys.argv[1:]):
                if sys.argv[1:][n - 1] in ["-t", "-S"]:
                    actions.append(value)
                    if len(actions) != 1:
                        GaussLog.exitWithError(
                            ErrorCode.GAUSS_500["GAUSS_50006"] % actions[0])
                    self.action = value

            if self.action == "":
                if module == "gs_om":
                    GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                           % 't' + ".")
                else:
                    GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"]
                                           % "t' or '-S" + ".")

            if ((module == "gsom" and not self.action in action_om)
                    or (module == "upgradectl"
                        and not self.action in action_upgradectl)):
                if (self.action == "-S"):
                    GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                           % "S")
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "-t' or 'S")

    def createOutputDir(self, path):
        """
        function: create output directory
        input : path
        output: NA
        """
        try:
            DefaultValue.checkOutputFile(path)
        except Exception as e:
            GaussLog.exitWithError(str(e))
        dirName = os.path.dirname(os.path.realpath(path))
        if (not os.path.isdir(dirName)):
            try:
                os.makedirs(dirName, DefaultValue.DIRECTORY_PERMISSION)
            except Exception as e:
                GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50206"] % \
                                       ("outputfile[%s]" % path)
                                       + "Error:\n%s" % str(e))

    def checkParamternum(self, key, value):
        """
        function: Check some number parameters
        input : key, value
        output: numvalue
        """
        try:
            numvalue = int(value)
            if (numvalue <= 0):
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % \
                                       key[1:]
                                       + " Parameter '%s' must be greater"
                                         " than or equal to 1." % key)
        except Exception as e:
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50003"] % \
                                   (key[1:], "integer")
                                   + " Error:\n%s" % str(e))

        return numvalue

    def checkPath(self, key, value):
        """
        function: Check some path parameters
        input : key, value
        output: path
        """
        # Check that the path parameter is a file
        try:
            if (not value):
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % key[1:] +
                                       "Error:\noption %s requires argument"
                                       % key)
            path = str(value)
            FileUtil.check_file_permission(path, True)
            return path
        except Exception as e:
            GaussLog.exitWithError(str(e))

    def getParseParameter(self, module):
        """
        function: get parse parameters
        input : parameter_list
        output: shortPara,longPara
        """

        shortPara = ""
        longPara = []
        var = "--"

        ParameterList = ""
        if (module == "upgradectl"):
            if (self.action == "chose-strategy"):
                ParameterList = ParameterDict.get("chose_strategy")
            elif (self.action == "auto-rollback"):
                ParameterList = ParameterDict.get("auto_rollback")
            elif (self.action == "auto-upgrade"):
                ParameterList = ParameterDict.get("auto_upgrade")
            elif (self.action == "commit-upgrade"):
                ParameterList = ParameterDict.get("commit_upgrade")
            elif self.action == "upgrade-cm":
                ParameterList = ParameterDict.get("upgrade-cm")
            elif (self.action == "show-step"):
                ParameterList = ParameterDict.get("show-step")
            elif (self.action == "query_upgrade_records"):
                ParameterList = ParameterDict.get("query_upgrade_records")
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "t")

        elif (module == "gs_om"):
            if (self.action in action_om):
                ParameterList = ParameterDict.get(self.action)
            else:
                GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"]
                                       % "t")
        else:
            ParameterList = ParameterDict.get(module)

        for para in ParameterList:
            if var in para:
                varlong = para.strip("--")
                longPara.append(varlong)
            else:
                varshort = para.strip("-")
                shortPara += varshort

        return shortPara, longPara
