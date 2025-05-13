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
# Description  : params_handler.py is a utility for parsing and verifying streaming
# disaster recovery params.
#############################################################################

import os
import sys
import json
import optparse
import getpass

from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ErrorCode import ErrorCode
from base_utils.security.security_checker import SecurityChecker, ValidationError
from base_utils.os.env_util import EnvUtil
from base_utils.os.user_util import UserUtil
from domain_utils.cluster_file.version_info import VersionInfo


def check_streaming_start_mode(mode):
    """
    Check start mode
    """
    if mode not in ["primary", "disaster_standby"]:
        raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50011"] % ('-m', mode))


def check_xml_file(file):
    """
    Check xml file param
    """
    if not file:
        raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50001'] % 'X')
    SecurityChecker.check_is_string('xml file path', file)
    if not os.path.isfile(file):
        raise ValidationError(ErrorCode.GAUSS_502["GAUSS_50201"] % file)


def check_hadr_user(value):
    """
    Check disaster user
    """
    description = "disaster username"
    SecurityChecker.check_db_user(description, value)


def check_hadr_pwd(value):
    """
    Check disaster user password
    """
    description = "disaster user password"
    # check_db_password will be used in cloud scene
    SecurityChecker.check_db_user(description, value)


def check_wait_timeout(value):
    """
    Check wait timeout
    """
    description = "wait timeout"
    SecurityChecker.check_is_digit(description, value)


def check_local_cluster_conf(value):
    """
    Check local cluster conf
    """
    SecurityChecker.check_is_dict("localClusterConf", value)
    port = value.get('port')
    SecurityChecker.check_port_valid('port of localClusterConf', port)
    shards = value.get('shards')
    SecurityChecker.check_is_list('shards of localClusterConf', shards)
    for shard in shards:
        for node in shard:
            ip = node.get('ip')
            data_ip = node.get('dataIp')
            SecurityChecker.check_ip_valid('ip of localClusterConf', ip)
            SecurityChecker.check_ip_valid('dataIp of localClusterConf', data_ip)


def check_remote_cluster_conf(value):
    """
    Check local cluster conf
    """
    SecurityChecker.check_is_dict("remoteClusterConf", value)
    port = value.get('port')
    SecurityChecker.check_port_valid('port of remoteClusterConf', port)
    shards = value.get('shards')
    SecurityChecker.check_is_list('shards of remoteClusterConf', shards)
    for shard in shards:
        for node in shard:
            ip = node.get('ip')
            data_ip = node.get('dataIp')
            SecurityChecker.check_ip_valid('ip of remoteClusterConf', ip)
            SecurityChecker.check_ip_valid('dataIp of remoteClusterConf', data_ip)


STREAMING_PARAMS_FOR_MODULE = {
    "start": {
        "mode": check_streaming_start_mode,
        "xml_path": check_xml_file,
        "hadrUserName": check_hadr_user,
        "hadrUserPassword": check_hadr_pwd,
        "waitingTimeout": check_wait_timeout,
        "localClusterConf": check_local_cluster_conf,
        "remoteClusterConf": check_remote_cluster_conf
    },
    "stop": {
        "xml_path": check_xml_file,
        "waitingTimeout": check_wait_timeout,
        "localClusterConf": check_local_cluster_conf,
        "remoteClusterConf": check_remote_cluster_conf
    },
    "switchover": {
        "mode": check_streaming_start_mode,
        "waitingTimeout": check_wait_timeout
    },
    "failover": {
        "waitingTimeout": check_wait_timeout,
    },
    "query": {}
}

HELP_MSG = """
gs_sdr is a utility for streaming disaster recovery fully options.

Usage:
  gs_sdr -? | --help
  gs_sdr -V | --version
  gs_sdr -t start -m [primary|disaster_standby] -X XMLFILE [-U DR_USERNAME] [-W DR_PASSWORD] [--json JSONFILE] [--time-out=SECS] [-l LOGFILE] 
  gs_sdr -t stop -X XMLFILE|--json JSONFILE [-l LOGFILE] 
  gs_sdr -t switchover -m [primary|disaster_standby] [--time-out=SECS] [-l LOGFILE]
  gs_sdr -t failover [-l LOGFILE]
  gs_sdr -t query [-l LOGFILE]
General options:
  -?, --help                     Show help information for this utility,
                                 and exit the command line mode.
  -V, --version                  Show version information.
  -t                             Task name, it could be:
                                 "start", "stop", "switchover", "failover", "query".
  -m                             Option mode, it could be:
                                 "primary", "disaster_standby".
  -U                             Disaster recovery user name.
  -W                             Disaster recovery user password.
  -X                             Path of the XML configuration file.
  -l                             Path of log file.
  -f                             Force remove the last time start process file.         
  --json                         Path of params file for streaming options.
  --time-out=SECS                Maximum waiting time when Main standby connect to the primary dn,
                                    default value is 1200s.
"""


class ParamsHandler(object):
    """
    Parse and check params.
    """
    def __init__(self, logger, trace_id):
        self.params = None
        self.logger = logger
        self.trace_id = trace_id

    @staticmethod
    def option_parser():
        """
        parsing parameters
        :return: param obj
        """
        parser = optparse.OptionParser(conflict_handler='resolve')
        parser.disable_interspersed_args()
        parser.epilog = "Example: gs_sdr -t " \
                        "start -m primary -X clusterConfig.xml " \
                        "--time-out=1200."
        parser.add_option('-V', "--version", dest='version_info', action='store_true',
                          help='-V|--version show version info.')
        parser.add_option('-?', "--help", dest='help_info', action='store_true',
                          help='-?|--help show help message and exit.')
        parser.add_option('-t', dest='task', type='string',
                          help='Task name. It could be "start", "stop", '
                               '"switchover", "failover", "query"')
        parser.add_option('-m', dest='mode', type='string',
                          help='Cluster run mode. It could be ["primary", "disaster_standby"].')
        parser.add_option('-U', dest='hadrusername', type='string',
                          help='hadr user name.')
        parser.add_option('-W', dest='hadruserpasswd', type='string',
                          help='hadr user password.')
        parser.add_option('-X', dest='xml_path', type='string',
                          help='Cluster config xml path.')
        parser.add_option('--json', dest='json_path', type='string',
                          help='Config json file of streaming options')
        parser.add_option('--time-out=', dest='timeout', default="1200", type='string',
                          help='time out.')
        parser.add_option("-l", dest='logFile', type='string',
                          help='Path of log file.')
        parser.add_option("-f", dest='force', action='store_true',
                          help='-f|Force remove the last time start process file.')
        return parser

    def __print_usage(self):
        """
        Print help message
        """
        if self.params.help_info:
            print(HELP_MSG)
            sys.exit(0)

    def __print_version_info(self):
        """
        Print version info
        """
        if self.params.version_info:
            print("%s %s" % (sys.argv[0].split("/")[-1],
                             VersionInfo.COMMON_VERSION))
            sys.exit(0)

    def __cluster_conf_parser(self, file_path):
        """
        Parse params in json file
        """
        if self.params.json_path:
            if not os.path.isfile(file_path):
                raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50010']
                                      % '--json' + " Json file is not exist.")
            with open(file_path, 'r') as read_fp:
                param_dict = json.load(read_fp)
            for key, value in param_dict.items():
                if key not in StreamingConstants.STREAMING_JSON_PARAMS[self.params.task]:
                    continue
                setattr(self.params, key, value)
            return
        cluster_info = dbClusterInfo()
        if not self.params.xml_path or not os.path.isfile(self.params.xml_path):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50010']
                                  % '-X' + " XML file and json file are all not exist.")
        cluster_info.initFromXml(self.params.xml_path)
        remote_cluster_conf = dict()
        remote_cluster_conf.setdefault("port", cluster_info.remote_dn_base_port)
        remote_cluster_conf.setdefault("shards", cluster_info.remote_stream_ip_map)
        setattr(self.params, "remoteClusterConf", remote_cluster_conf)
        self.logger.debug("Remote stream cluster conf: %s." % str(remote_cluster_conf))

        local_cluster_conf = dict()
        local_cluster_conf.setdefault("port", cluster_info.local_dn_base_port)
        local_cluster_conf.setdefault("shards", cluster_info.local_stream_ip_map)
        setattr(self.params, "localClusterConf", local_cluster_conf)
        self.logger.debug("Local stream cluster conf: %s." % str(local_cluster_conf))
        if not remote_cluster_conf["shards"] or len(remote_cluster_conf["shards"])\
                != len(local_cluster_conf["shards"]):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50026'] % "streaming DR")

    def __init_default_params(self):
        """
        Init params if need default value
        """
        if not self.params.timeout.isdigit():
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50004"] % "--time-out")
        self.params.waitingTimeout = int(self.params.timeout)

    def __force_remove_step_file(self):
        """
        Remove the last process file
        """
        if not self.params.force:
            return
        self.logger.debug("remove the last process file on all connected nodes.")
        user = UserUtil.getUserInfo().get("name")
        pg_host = EnvUtil.getEnvironmentParameterValue("PGHOST", user)
        streaming_file_dir = os.path.join(pg_host, StreamingConstants.STREAMING_FILES_DIR)
        self.__do_remove_step_file(streaming_file_dir)
        self.logger.debug("Successfully remove the last process file on all connected nodes.")

    def __do_remove_step_file(self, streaming_file_dir):
        """
        remove step file
        """
        if not os.path.isdir(streaming_file_dir):
            self.logger.debug(f"Invalid directory: {streaming_file_dir}")
            return
        
        task_file_map = {
            StreamingConstants.ACTION_START: ("start_primary", "start_standby")
        }

        file_keys = task_file_map.get(self.params.task)
        if not file_keys:
            self.logger.logExit(f"Unknown task: {self.params.task}")
            return
        
        for key in file_keys:
            file_path = os.path.realpath(os.path.join(streaming_file_dir, StreamingConstants.STREAMING_STEP_FILES.get(key)))
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    self.logger.debug(f"Removed file: {file_path}")
            except Exception as e:
                self.logger.logExit(f"Failed to remove file {file_path}: {str(e)}")

    def __parse_args(self):
        """
        Parse arguments
        """
        parser = ParamsHandler.option_parser()
        self.params, _ = parser.parse_args()
        self.__print_usage()
        self.__print_version_info()
        self.__force_remove_step_file()
        if not hasattr(self.params, 'task') or not self.params.task:
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + ".")
        if self.params.task not in StreamingConstants.STREAMING_JSON_PARAMS.keys():
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50004"] % 't')
        # parse arguments in json/xml file
        if StreamingConstants.STREAMING_JSON_PARAMS[self.params.task]:
            self.__cluster_conf_parser(self.params.json_path)

    def __reload_hadr_user_info(self):
        """
        Input hadr user info
        """
        if self.params.task not in ["start"]:
            return
        if self.params.hadrusername and self.params.hadruserpasswd:
            self.params.hadrUserName = self.params.hadrusername
            self.params.hadrUserPassword = self.params.hadruserpasswd
            del self.params.hadruserpasswd
            return
        user_name = ""
        if not self.params.hadrusername:
            user_name = input("Please enter disaster user name:")
        self.params.hadrUserName = user_name if user_name else self.params.hadrusername
        if self.params.hadruserpasswd:
            self.params.hadrUserPassword = self.params.hadruserpasswd
            del self.params.hadruserpasswd
            return
        for i in range(3):
            user_passwd = getpass.getpass("Please enter password for [%s]:" %
                                          self.params.hadrUserName)
            user_passwd_check = getpass.getpass("Please repeat enter for password for [%s]:"
                                                % self.params.hadrUserName)
            if user_passwd == user_passwd_check:
                break
            if i == 2:
                self.logger.logExit("The two passwords entered for too many "
                                    "times are inconsistent. Authentication failed.")
            self.logger.error(
                ErrorCode.GAUSS_503["GAUSS_50306"] % user_name
                + "The two passwords are different, please enter password again.")
        self.params.hadrUserPassword = user_passwd
        del user_passwd
        del user_passwd_check
        self.logger.debug("The hadr user information is successfully loaded.")

    def get_valid_params(self):
        """
        Check params
        """
        try:
            self.__parse_args()
            self.logger.log(StreamingConstants.LOG_REMARK)
            self.logger.log('Streaming disaster recovery ' + self.params.task + ' ' + self.trace_id)
            self.logger.log(StreamingConstants.LOG_REMARK)
            self.__init_default_params()
            self.__reload_hadr_user_info()
            for param_name, validate in STREAMING_PARAMS_FOR_MODULE[self.params.task].items():
                check_value = getattr(self.params, param_name)
                if self.params.task == "stop" or self.params.task == "start":
                    if param_name == "xml_path" and not check_value:
                        check_value = getattr(self.params, 'json_path')
                validate(check_value)
        except ValidationError as error:
            self.logger.logExit(str(error))
        return self.params
