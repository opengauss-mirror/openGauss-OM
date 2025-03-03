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
# Description  : params_handler.py is a utility for parsing and verifying dorado
# disaster recovery params.
#############################################################################

import os
import sys
import pwd
import json
import optparse
import getpass
from impl.streaming_disaster_recovery.streaming_base import StreamingConstants
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.env_util import EnvUtil
from base_utils.security.security_checker import SecurityChecker, ValidationError
from domain_utils.cluster_file.version_info import VersionInfo


def check_ddr_start_mode(mode):
    """
    Check start mode
    """
    if mode not in ["primary", "disaster_standby"]:
        raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50011"] % ('-m', mode))

def check_ddr_start_disaster_type(disaster_type):
    """
    Check start para: disaster_type
    """
    if disaster_type not in ["dorado", "stream"]:
        raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50011"] % ('--disaster_type', disaster_type))

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

def check_dorado_config(value):
    """
    Check dorado config
    """
    description = "dorado config"
    SecurityChecker.check_is_string(description, value)


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
    Check remote cluster conf
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


DORADO_PARAMS_FOR_MODULE = {
    "start": {
        "mode": check_ddr_start_mode,
        "disaster_type": check_ddr_start_disaster_type,
        "xml_path": check_xml_file,
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
        "mode": check_ddr_start_mode,
        "waitingTimeout": check_wait_timeout
    },
    "failover": {
        "waitingTimeout": check_wait_timeout,
    },
    "query": {}
}

HELP_MSG = """
gs_ddr is a utility for dorado disaster recovery fully options.

Usage:
  gs_ddr -? | --help
  gs_ddr -V | --version
  gs_ddr -t start -m [primary|disaster_standby] --disaster_type [dorado|stream] -X XMLFILE [--time-out=SECS] [-l LOGFILE] 
  gs_ddr -t stop -X XMLFILE|--json JSONFILE [-l LOGFILE] 
  gs_ddr -t switchover -m [primary|disaster_standby] [-r | --restart] [--time-out=SECS] [-l LOGFILE]
  gs_ddr -t failover [-r | --restart] [-l LOGFILE]
  gs_ddr -t query [-l LOGFILE]
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
  -r, --restart                  Restart the cluster when do "switchover" or "failover" 
  --time-out=SECS                Maximum waiting time when Main standby connect to the primary dn,
                                    default value is 1200s.
  --disaster_type                Set the type of dual-cluster, It could be:
                                 "dorado", "stream", the default value is "dorado".
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
        parser.epilog = "Example: gs_ddr -t " \
                        "start -m primary -X clusterConfig.xml " \
                        "--time-out=1200."
        parser.add_option('-V', "--version", dest='version_info', action='store_true',
                          help='-V|--version show version info.')
        parser.add_option('-?', "--help", dest='help_info', action='store_true',
                          help='-?|--help show help message and exist.')
        parser.add_option('-t', dest='task', type='string',
                          help='Task name. It could be "start", "stop", '
                               '"switchover", "failover", "query"')
        parser.add_option('-m', dest='mode', type='string',
                          help='Cluster run mode. It could be ["primary", "disaster_standby"].')
        parser.add_option('-X', dest='xml_path', type='string',
                          help='Cluster config xml path.')
        parser.add_option('--json', dest='json_path', type='string',
                          help='Config json file of dorado options')
        parser.add_option('--time-out=', dest='timeout', default="1200", type='string',
                          help='time out.')
        parser.add_option("-l", dest='logFile', type='string',
                          help='Path of log file.')
        parser.add_option('-r', "--restart", dest='restart', action='store_true',
                          help='restart cluster when do gs_ddr switchover or failover.')
        parser.add_option('--stage=', dest='stage', default=None, type='string',
                          help='[Internal Usage] Stage when do gs_ddr. It could be 1 or 2')
        parser.add_option('--disaster_type', dest='disaster_type', default="dorado", type='string',
                          help='Disaster dual-cluster type: It could be "dorado", "stream"')
        parser.add_option('-f', dest='force', action='store_true',
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

    def __force_remove_start_file(self):
        """
        Remove the last start process file
        """
        user = pwd.getpwuid(os.getuid()).pw_name
        dorado_file_dir = EnvUtil.getEnvironmentParameterValue("PGHOST", user)
        if self.params.force:
            self.logger.debug("Remove ddr start process file for start.")
            process_file_primary = os.path.realpath(os.path.join(dorado_file_dir, "ddr_cabin/.ddr_start_primary.step"))
            process_file_standby = os.path.realpath(os.path.join(dorado_file_dir, "ddr_cabin/.ddr_start_standby.step"))
            if os.path.exists(process_file_primary):
                os.remove(process_file_primary)
            if os.path.exists(process_file_standby):
                os.remove(process_file_standby)
            self.logger.debug("Successfully remove start process file on all connected nodes.")

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
        self.logger.debug("Remote cluster conf: %s." % str(remote_cluster_conf))

        local_cluster_conf = dict()
        local_cluster_conf.setdefault("port", cluster_info.local_dn_base_port)
        local_cluster_conf.setdefault("shards", cluster_info.local_stream_ip_map)
        setattr(self.params, "localClusterConf", local_cluster_conf)
        self.logger.debug("Local cluster conf: %s." % str(local_cluster_conf))
        if not remote_cluster_conf.get("shards") or len(remote_cluster_conf.get("shards", [])) != \
            len(local_cluster_conf.get("shards", [])):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50026'] % "dorado DR")

    def __init_default_params(self):
        """
        Init params if need default value
        """
        if not self.params.timeout.isdigit() or int(self.params.timeout) == 0:
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50004"] % "--time-out")
        self.params.waitingTimeout = int(self.params.timeout)

        if not self.params.restart:
            self.params.restart = False

    def __parse_args(self):
        """
        Parse arguments
        """
        parser = ParamsHandler.option_parser()
        self.params, _ = parser.parse_args()
        self.__print_usage()
        self.__print_version_info()
        if self.params.force:
            self.__force_remove_start_file()
        if not hasattr(self.params, 'task') or not self.params.task:
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + ".")
        if self.params.task not in StreamingConstants.STREAMING_JSON_PARAMS.keys():
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50004"] % 't')
        # parse arguments in json/xml file
        if StreamingConstants.STREAMING_JSON_PARAMS[self.params.task]:
            self.__cluster_conf_parser(self.params.json_path)

    def get_valid_params(self):
        """
        Check params
        """
        try:
            self.__parse_args()
            self.logger.log(StreamingConstants.LOG_REMARK)
            self.logger.log('Dorado disaster recovery ' + self.params.task + ' ' + self.trace_id)
            self.logger.log(StreamingConstants.LOG_REMARK)
            self.__init_default_params()
            for param_name, validate in DORADO_PARAMS_FOR_MODULE[self.params.task].items():
                check_value = getattr(self.params, param_name)
                if self.params.task == "stop" or self.params.task == "start":
                    if param_name == "xml_path" and not check_value:
                        check_value = getattr(self.params, 'json_path')
                validate(check_value)
        except ValidationError as error:
            self.logger.logExit(str(error))
        return self.params

