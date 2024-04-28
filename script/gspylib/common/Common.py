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
# Description  : Common is a utility with a lot of common functions
#############################################################################
import ctypes
import sys
import subprocess
import os
import platform
import socket
import types
import re
import time
import multiprocessing
import _thread as thread
import pwd
import json
import base64
import secrets
import string
import stat
import csv
import copy
from subprocess import PIPE
from subprocess import Popen
from base_utils.os.password_util import PasswordUtil

# The installation starts, but the package is not decompressed completely.
# The lib64/libz.so.1 file is incomplete, and the hashlib depends on the
# libz.so.1 file.

num = 0
while num < 10:
    try:
        import hashlib

        break
    except ImportError:
        num += 1
        time.sleep(1)

import shutil
from ctypes import *
from datetime import datetime

localDirPath = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, localDirPath + "/../../../lib")
try:
    import psutil
except ImportError as e:
    # mv psutil mode .so file by python version
    pythonVer = str(sys.version_info[0]) + '.' + str(sys.version_info[1])
    psutilLinux = os.path.join(localDirPath,
                               "./../../../lib/psutil/_psutil_linux.so")
    psutilPosix = os.path.join(localDirPath,
                               "./../../../lib/psutil/_psutil_posix.so")
    psutilLinuxBak = "%s_%s" % (psutilLinux, pythonVer)
    psutilPosixBak = "%s_%s" % (psutilPosix, pythonVer)

    glo_cmd = "rm -rf '%s' && cp -r '%s' '%s' " % (psutilLinux,
                                                   psutilLinuxBak,
                                                   psutilLinux)
    glo_cmd += " && rm -rf '%s' && cp -r '%s' '%s' " % (psutilPosix,
                                                        psutilPosixBak,
                                                        psutilPosix)
    psutilFlag = True
    for psutilnum in range(3):
        (status_mvPsutil, output_mvPsutil) = subprocess.getstatusoutput(
            glo_cmd)
        if (status_mvPsutil != 0):
            psutilFlag = False
            time.sleep(1)
        else:
            psutilFlag = True
            break
    if (not psutilFlag):
        print("Failed to execute cmd: %s. Error:\n%s" % (glo_cmd,
                                                         output_mvPsutil))
        sys.exit(1)
    # del error import and reload psutil
    del sys.modules['psutil._common']
    del sys.modules['psutil._psposix']
    import psutil

sys.path.append(localDirPath + "/../../")
from gspylib.common.ErrorCode import ErrorCode
from os_platform.UserPlatform import g_Platform
from gspylib.os.gsfile import g_file
from os_platform.gsservice import g_service
from gspylib.threads.parallelTool import parallelTool
from base_utils.executor.cmd_executor import CmdExecutor
from base_utils.executor.local_remote_cmd import LocalRemoteCmd
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.security.random_value import RandomValue
from base_utils.os.process_util import ProcessUtil
from domain_utils.sql_handler.sql_executor import SqlExecutor
from domain_utils.sql_handler.sql_file import SqlFile
from base_utils.os.net_util import NetUtil
from base_utils.common.constantsbase import ConstantsBase
from base_utils.security.sensitive_mask import SensitiveMask
from os_platform.linux_distro import LinuxDistro
from base_diff.sql_commands import SqlCommands
from gspylib.common.DbClusterInfo import dbClusterInfo
from base_utils.common.fast_popen import FastPopen
from gspylib.common.Constants import Constants
from domain_utils.cluster_file.profile_file import ProfileFile
from domain_utils.domain_common.cluster_constants import ClusterConstants
from gspylib.common.aes_cbc_util import AesCbcUtil

noPassIPs = []
g_lock = thread.allocate_lock()

# uwal num
BASE_ID_GTM = 1001
BASE_ID_DATANODE = 6001

SYSTEM_SSH_ENV = "export LD_LIBRARY_PATH=/usr/lib64"

def check_content_key(content, key):
    if not (type(content) == bytes):
        raise Exception(ErrorCode.GAUSS_530["GAUSS_53025"])
    elif not (type(key) in (bytes, str)):
        raise Exception(ErrorCode.GAUSS_530["GAUSS_53026"])

    iv_len = 16
    if not (len(content) >= (iv_len + 16)):
        raise Exception(ErrorCode.GAUSS_530["GAUSS_53027"])


class DefaultValue():
    """
    Default value of some variables
    """

    def __init__(self):
        pass

    TASK_QUERY_STATUS = "status"
    TASK_START = "startup"
    TASK_STOP = "shutdown"
    ###########################
    # DWS path info
    ###########################
    DWS_IMAGE_PATH = "/opt/dws/image"
    DWS_PACKAGE_PATH = "/opt/dws/package"
    DWS_APP_PAHT = "/opt/dws/app"


    ###########################
    # init action timeout value
    ###########################
    # start timeout value
    TIMEOUT_CLUSTER_START = 300
    # stop timeout value
    TIMEOUT_CLUSTER_STOP = 300

    ##
    TIMEOUT_PSSH_COMMON = 80
    ###########################
    ###########################
    # preinstall timeoutvalue
    TIMEOUT_PSSH_PREINSTALL = 1800
    # install timeout value
    TIMEOUT_PSSH_INSTALL = 1800
    # uninstall timeout value
    TIMEOUT_PSSH_UNINSTALL = 43200
    # postpreinstall timeout value
    TIMEOUT_PSSH_POSTPREINSTALL = 1800
    # binary-upgrade and rollback timeout value
    TIMEOUT_PSSH_BINARY_UPGRADE = 14400
    # check timeout value
    TIMEOUT_PSSH_CHECK = 1800
    # backup timeout value
    TIMEOUT_PSSH_BACKUP = 1800
    # collector timeout value
    TIMEOUT_PSSH_COLLECTOR = 1800

    # exponsion switchover timeout value
    TIMEOUT_EXPANSION_SWITCH = 30

    ###########################
    # init authority parameter
    ###########################
    # directory mode
    DIRECTORY_MODE = 750
    # directory permission
    DIRECTORY_PERMISSION = 0o750
    # file node
    FILE_MODE = 640
    FILE_MODE_PERMISSION = 0o640
    KEY_FILE_MODE = 600
    BIN_FILE_MODE = 700
    KEY_FILE_MODE_IN_OS = 0o600
    MIN_FILE_MODE = 400
    SPE_FILE_MODE = 500
    KEY_DIRECTORY_MODE = 700
    MAX_DIRECTORY_MODE = 755
    SQL_FILE_MODE = 644
    # the host file permission. Do not changed it.
    HOSTS_FILE = 644
    KEY_HOSTS_FILE = 0o644

    # The available size of install app directory
    APP_DISK_SIZE = 100
    # in grey upgrade, need to install new bin instead of replacing
    # old bin in inplace upgrade
    # so need 10G to guarantee enough space
    GREY_DISK_SIZE = 10
    # The remaining space of device
    INSTANCE_DISK_SIZE = 200
    DSS_DISK_MODE = 660

    ###########################
    # upgrade parameter
    ###########################
    GREY_UPGRADE_STEP_UPGRADE_PROCESS = 3

    CAP_WIO = "CAP_SYS_RAWIO"

    # env parameter
    MPPRC_FILE_ENV = "MPPDB_ENV_SEPARATE_PATH"
    SUCCESS = "Success"
    FAILURE = "Failure"
    # tablespace version directory name
    # it is from gaussdb kernel code
    TABLESPACE_VERSION_DIRECTORY = "PG_9.2_201611171"
    # default database name
    DEFAULT_DB_NAME = "postgres"
    # database size file
    DB_SIZE_FILE = "total_database_size"
    # om_monitor log directory
    OM_MONITOR_DIR_FILE = "../cm/om_monitor"
    # action flag file name
    ACTION_FLAG_FILE = ".action_flag_file"
    # action log file name
    EXPANSION_LOG_FILE = "gs_expansion.log"
    DROPNODE_LOG_FILE = "gs_dropnode.log"
    # dump file for cn instance
    SCHEMA_COORDINATOR = "schema_coordinator.sql"
    # dump file for job data
    COORDINATOR_JOB_DATA = "schema_coordinator_job_data.sql"
    # dump file for statistics data
    COORDINATOR_STAT_DATA = "schema_coordinator_statistics_data.sql"
    # dump global info file for DB instance
    SCHEMA_DATANODE = "schema_datanode.sql"
    # record default group table info
    DUMP_TABLES_DATANODE = "dump_tables_datanode.dat"
    # dump default group table info file for DB instance
    DUMP_Output_DATANODE = "dump_output_datanode.sql"
    # default alarm tools
    ALARM_COMPONENT_PATH = "/opt/huawei/snas/bin/snas_cm_cmd"
    # root scripts path
    ROOT_SCRIPTS_PATH = "/root/gauss_om"

    # package bak file name list
    PACKAGE_BACK_LIST = ["Gauss200-OLAP-Package-bak.tar.gz",
                         "Gauss200-Package-bak.tar.gz",
                         "GaussDB-Kernel-Package-bak.tar.gz"]
    # network scripts file for RHEL
    REDHAT_NETWORK_PATH = "/etc/sysconfig/network-scripts"
    # cert files list,the order of these files SHOULD NOT be modified
    CERT_FILES_LIST = ["cacert.pem",
                       "server.crt",
                       "server.key",
                       "server.key.cipher",
                       "server.key.rand",
                       "sslcrl-file.crl"]
    SSL_CRL_FILE = CERT_FILES_LIST[5]
    CLIENT_CERT_LIST = ["client.crt",
                        "client.key",
                        "client.key.cipher",
                        "client.key.rand"]
    GDS_CERT_LIST = ["cacert.pem",
                     "server.crt",
                     "server.key",
                     "server.key.cipher",
                     "server.key.rand",
                     "client.crt",
                     "client.key",
                     "client.key.cipher",
                     "client.key.rand"]
    GRPC_CERT_LIST = ["clientnew.crt",
                      "clientnew.key",
                      "cacertnew.pem",
                      "servernew.crt",
                      "servernew.key",
                      "openssl.cnf",
                      "client.key.cipher",
                      "client.key.rand",
                      "server.key.cipher",
                      "server.key.rand"]
    SERVER_CERT_LIST = ["client.crt",
                        "client.key",
                        "cacert.pem",
                        "server.crt",
                        "server.key",
                        "openssl.cnf",
                        "client.key.cipher",
                        "client.key.rand",
                        "server.key.cipher",
                        "server.key.rand",
                        "client.key.pk8"]
    BIN_CERT_LIST = ["server.key.cipher",
                     "server.key.rand"]
    CERT_BACKUP_FILE = "gsql_cert_backup.tar.gz"
    PATH_CHECK_LIST = ["|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"",
                       "{", "}", "(", ")", "[", "]", "~", "*", "?", " ", "!",
                       "\n"]
    PASSWORD_CHECK_LIST = [";", "'", "$"]
    # The xml file path is needed by kerberos in FI_librA
    # FI_KRB_XML is used in mppdb
    FI_KRB_XML = "auth_config/mppdb-site.xml"
    # FI_ELK_KRB_XML is used in elk
    FI_ELK_KRB_XML = "auth_config/elk-krb-site.xml"
    FI_KRB_CONF = "krb5.conf"
    # cluster status
    CLUSTER_STATUS_NORMAL = "Normal"
    CLUSTER_STATUS_DEGRADED = "Degraded"
    CLUSTER_STATUS_UNAVAILABLE = "Unavailable"
    ###########################
    # instance role
    ###########################
    # init value
    INSTANCE_ROLE_UNDEFINED = -1
    # cm_server
    INSTANCE_ROLE_CMSERVER = 0
    # gtm
    INSTANCE_ROLE_GTM = 1
    # etcd
    INSTANCE_ROLE_ETCD = 2
    # cn
    INSTANCE_ROLE_COODINATOR = 3
    # dn
    INSTANCE_ROLE_DATANODE = 4
    # cm_agent
    INSTANCE_ROLE_CMAGENT = 5

    ###########################
    # instance type. only for CN/DN
    ###########################
    # master
    MASTER_INSTANCE = 0
    # standby
    STANDBY_INSTANCE = 1
    # dummy standby
    DUMMY_STANDBY_INSTANCE = 2
    # cascade standby
    CASCADE_STANDBY = 3

    ###########################
    # parallel number
    ###########################
    DEFAULT_PARALLEL_NUM = 12

    # SQL_EXEC_COMMAND
    SQL_EXEC_COMMAND_WITHOUT_HOST_WITHOUT_USER = "%s -p %s -d %s "

    # cluster type
    CLUSTER_TYPE_SINGLE = "single"
    CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY = "single-primary-multi-standby"
    CLUSTER_TYPE_SINGLE_INST = "single-inst"

    # ssh option
    SSH_OPTION = " -o BatchMode=yes -o TCPKeepAlive=yes -o " \
                 "ServerAliveInterval=30 -o ServerAliveCountMax=10 -o " \
                 "ConnectTimeout=30 -o ConnectionAttempts=10 "
    # base64 option
    BASE_ENCODE = "encode"
    BASE_DECODE = "decode"

    # Default name of the byte stream file which contain the disabled features.
    DEFAULT_DISABLED_FEATURE_FILE_NAME = "gaussdb.version"
    # Default license control file name.
    DEFAULT_LICENSE_FILE_NAME = "gaussdb.license"

    COLLECT_CONF_JSON_KEY_LIST = [
        "Content",
        "TypeName",
        "Interval",
        "Count"
    ]
    COLLECT_CONF_CONTENT_MAP = {
        # System check config
        # cat /proc/cpuinfo;
        "HardWareInfo": "cpuInfo,memInfo,disk",
        # cat /proc/meminfo df -h
        # top; ps ux; iostat
        "RunTimeInfo": "ps,ioStat,netFlow,spaceUsage",
        # -xm 2 3; netstat; free -m du -sh
        # Log & Conf_Gstack check config
        "Coordinator": "CN",
        "DataNode": "DN",
        "Gtm": "GTM",
        # Log check config
        "ClusterManager": "cm,om,bin",
        # Core Dump check
        "gaussdb": "gaussdb",
        "gs_gtm": "gs_gtm",
        "gs_rewind": "gs_rewind",
        "cm_server": "cm_server",
        "cm_agent": "cm_agent",
        "gs_ctl": "gs_ctl",
        "gaussdb_stack": "gaussdb_stack",
        "gs_gtm_stack": "gs_gtm_stack",
        "gs_rewind_stack": "gs_rewind_stack",
        "cm_server_stack": "cm_server_stack",
        "cm_agent_stack": "cm_agent_stack",
        "gs_ctl_stack": "gs_ctl_stack",
        "AioWorker": "AioWorker",
        "AlarmChecker": "AlarmChecker",
        "Archiver": "Archiver",
        "Auditor": "Auditor",
        "AutoVacLauncher": "AutoVacLauncher",
        "AutoVacWorker": "AutoVacWorker",
        "AuxMain": "AuxMain",
        "BackendMode": "BackendMode",
        "BgWriter": "BgWriter",
        "BootStrap": "BootStrap",
        "Catchup": "Catchup",
        "CBMWriter": "CBMWriter",
        "Checkpointer": "Checkpointer",
        "CommAuxStream": "CommAuxStream",
        "CommPoolCleaner": "CommPoolCleaner",
        "CommRcvStream": "CommRcvStream",
        "CommRcvWorker": "CommRcvWorker",
        "CommSendStream": "CommSendStream",
        "CpMonitor": "CpMonitor",
        "DataRcvWriter": "DataRcvWriter",
        "DataReceiver": "DataReceiver",
        "DataSender": "DataSender",
        "ExtremeRTO": "ExtremeRTO",
        "FencedUDFMaster": "FencedUDFMaster",
        "GaussMaster": "GaussMaster",
        "Heartbeater": "Heartbeater",
        "JobExecutor": "JobExecutor",
        "LWLockMonitor": "LWLockMonitor",
        "PageWriter": "PageWriter",
        "ParallelRecov": "ParallelRecov",
        "PercentileJob": "PercentileJob",
        "Reaper": "Reaper",
        "RemoteSrv": "RemoteSrv",
        "StartupProcess": "StartupProcess",
        "StatCollector": "StatCollector",
        "Stream": "Stream",
        "SysLogger": "SysLogger",
        "ThdPoolListener": "ThdPoolListener",
        "TwoPhaseCleaner": "TwoPhaseCleaner",
        "WalRcvWriter": "WalRcvWriter",
        "WalReceiver": "WalReceiver",
        "WalSender": "WalSender",
        "WalWriter": "WalWriter",
        "WDRSnapshot": "WDRSnapshot",
        "WlmArbiter": "WlmArbiter",
        "WlmCollector": "WlmCollector",
        "WlmMonitor": "WlmMonitor"
    }

    COLLECT_CONF_MAP = {
        "System": "HardWareInfo,RunTimeInfo",
        "Database": "*",
        "Log": "Coordinator,DataNode,Gtm,ClusterManager,FFDC,AWRReport",
        "XLog": "Coordinator,DataNode",
        "Config": "Coordinator,DataNode,Gtm",
        "Gstack": "Coordinator,DataNode,Gtm",
        "CoreDump": "gaussdb,gs_gtm,gs_rewind,cm_server,cm_agent,gs_ctl,"
                    "gaussdb_stack,gs_gtm_stack,gs_rewind_stack,"
                    "cm_server_stack,cm_agent_stack,cm_server_stack,"
                    "gs_ctl_stack,AioWorker,AlarmChecker,Archiver,Auditor,"
                    "AutoVacLauncher,AutoVacWorker,AuxMain,BackendMode,"
                    "BgWriter,BootStrap,Catchup,CBMWriter,Checkpointer,"
                    "CommAuxStream,CommPoolCleaner,CommRcvStream,CommRcvWorker,"
                    "CommSendStream,CpMonitor,DataRcvWriter,DataReceiver,"
                    "DataSender,ExtremeRTO,FencedUDFMaster,GaussMaster,"
                    "Heartbeater,JobExecutor,JobScheduler,LWLockMonitor,"
                    "PageWriter,ParallelRecov,PercentileJob,Reaper,RemoteSrv,"
                    "StartupProcess,StatCollector,Stream,SysLogger,"
                    "ThdPoolListener,TwoPhaseCleaner,WalRcvWriter,WalReceiver,"
                    "WalSender,WalWriter,WDRSnapshot,WlmArbiter,WlmCollector,"
                    "WlmMonitor",
        "Trace": "Dump",
        "Plan": "*"
    }

    DATABASE_CHECK_WHITE_LIST = ["dbe_perf", "pg_catalog"]
    # Default retry times of SQL query attempts after successful
    # operation "gs_ctl start".
    DEFAULT_RETRY_TIMES_GS_CTL = 20
    CORE_PATH_DISK_THRESHOLD = 50

    # Cert type
    GRPC_CA = "grpc"
    SERVER_CA = "server"
    # rsa file name
    SSH_PRIVATE_KEY = os.path.expanduser("~/.ssh/id_om")
    SSH_PUBLIC_KEY = os.path.expanduser("~/.ssh/id_om.pub")
    SSH_AUTHORIZED_KEYS = os.path.expanduser("~/.ssh/authorized_keys")
    SSH_KNOWN_HOSTS = os.path.expanduser("~/.ssh/known_hosts")

    @staticmethod
    def encodeParaline(cmd, keyword):
        """
        """
        if (keyword == "encode"):
            cmd = base64.b64encode(cmd.encode()).decode()
            return cmd
        if (keyword == "decode"):
            cmd = base64.b64decode(cmd.encode()).decode()
            return cmd

    @staticmethod
    def CheckNetWorkBonding(serviceIP, isCheckOS=True):
        """
        function : Check NetWork ConfFile
        input  : String, bool
        output : List
        """
        networkCardNum = NetUtil.getNICNum(serviceIP)
        NetWorkConfFile = DefaultValue.getNetWorkConfFile(networkCardNum)
        bondingConfFile = "/proc/net/bonding/%s" % networkCardNum
        networkCardNumList = []
        networkCardNumList.append(networkCardNum)
        if os.path.exists(NetWorkConfFile):
            cmd = "grep -i 'BONDING_OPTS\|BONDING_MODULE_OPTS' %s" % \
                  NetWorkConfFile
            (status, output) = subprocess.getstatusoutput(cmd)
            if ((status == 0) and (output.strip() != "")):
                if ((output.find("mode") > 0) and os.path.exists(
                        bondingConfFile)):
                    networkCardNumList = networkCardNumList + \
                                         NetUtil.checkBondMode(
                                             bondingConfFile, isCheckOS)
                else:
                    raise Exception(ErrorCode.GAUSS_506["GAUSS_50611"] +
                                    " Command:%s. Error:\n%s" % (cmd, output))
            elif isCheckOS:
                print("BondMode Null")
        else:
            (flag, netcardList) = NetUtil.getNetWorkBondFlag(
                networkCardNum)
            if flag:
                if os.path.exists(bondingConfFile):
                    networkCardNumList = networkCardNumList + \
                                         NetUtil.checkBondMode(
                                             bondingConfFile, isCheckOS)
                else:
                    sys.exit(ErrorCode.GAUSS_506["GAUSS_50611"] +
                             "Without NetWorkConfFile mode.")
            else:
                print("BondMode Null")
        if (len(networkCardNumList) != 1):
            del networkCardNumList[0]
        return networkCardNumList

    @staticmethod
    def checkNetWorkMTU(nodeIp, isCheckOS=True):
        """
        function: gs_check check NetWork card MTU parameters
        input: string, string
        output: int
        """
        try:
            networkCardNum = DefaultValue.CheckNetWorkBonding(nodeIp,
                                                              isCheckOS)
            mtuValue = psutil.net_if_stats()[networkCardNum[0]].mtu
            if (not mtuValue):
                return "        Abnormal reason: Failed to obtain " \
                       "network card MTU value."
            return mtuValue
        except Exception as e:
            return "        Abnormal reason: Failed to obtain the " \
                   "networkCard parameter [MTU]. Error: \n        %s" % str(e)

    @staticmethod
    def getNetWorkConfFile(networkCardNum):
        """
        function : Get NetWork ConfFile
        input  : int
        output : String
        """
        SuSENetWorkConfPath = "/etc/sysconfig/network"
        RedHatNetWorkConfPath = "/etc/sysconfig/network-scripts"
        UbuntuNetWorkConfPath = "/etc/network"
        NetWorkConfFile = ""
        distname, version, idnum = LinuxDistro.linux_distribution()
        distname = distname.lower()
        if (distname in ("redhat", "centos", "euleros", "openeuler", "fusionos")):
            NetWorkConfFile = "%s/ifcfg-%s" % (RedHatNetWorkConfPath,
                                               networkCardNum)
        else:
            NetWorkConfFile = "%s/ifcfg-%s" % (SuSENetWorkConfPath,
                                               networkCardNum)

        if (not os.path.exists(NetWorkConfFile)):
            if (distname in (
                    "redhat", "centos", "euleros", "openeuler", "fusionos")):
                cmd = "find %s -iname 'ifcfg-*-%s' -print" % (
                    RedHatNetWorkConfPath, networkCardNum)
            elif (distname == "debian" and version == "buster/sid"):
                cmd = "find %s -iname 'ifcfg-*-%s' -print" % (
                    UbuntuNetWorkConfPath, networkCardNum)
            else:
                cmd = "find %s -iname 'ifcfg-*-%s' -print" % (
                    SuSENetWorkConfPath, networkCardNum)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0 and DefaultValue.checkDockerEnv()):
                return output.strip()
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
            if (len(output.split('\n')) != 1):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                NetWorkConfFile)

            NetWorkConfFile = output.strip()

        return NetWorkConfFile


    @staticmethod
    def get_remote_ips(host, mpp_file):
        """
        Get ips from remote host
        """
        cmd = "source %s && pssh -s -t 30 -H %s \"hostname -I\"" % (mpp_file, host)
        status, output = subprocess.getstatusoutput(cmd)
        if status == 0 and output != "":
            ips = output.strip().split()
            return ips
        else:
            raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                            % "check remote ips for node:%s, Error:%s." % (host, output))

    @staticmethod
    def obtain_file_content(dest_file, deduplicate=True, is_list=True):
        """
        function:obtains the content of each line in the file.
        input: file dir
        :return: file context lines list
        """
        result = [] if is_list else None
        if not os.path.isfile(dest_file):
            return result
        with open(dest_file, "r") as fp_read:
            if is_list:
                for line in fp_read:
                    result.append(line.strip('\n'))
            else:
                result = fp_read.read().strip()
        if deduplicate and is_list:
            result = list(set(result))
        return result

    @staticmethod
    def get_all_dn_num_for_dr(file_path, dn_inst, cluster_info, logger):
        """get_all_dn_num_for_dr_cluster"""
        # DN inst supports a maximum of replicaNum=8 in postgresql.conf.
        default_num = 8
        content = DefaultValue.obtain_file_content(file_path, is_list=False)
        if content:
            default_num = 0
            shards = json.loads(content)['remoteClusterConf']["shards"]
            logger.debug("Stream cluster json shards:%s" % shards)
            if cluster_info.isSingleInstCluster():
                for shard in shards:
                    default_num += len(shard)
            else:
                default_num += len(shards[0])
            peer_insts = cluster_info.getPeerInstance(dn_inst)
            default_num += len(peer_insts)
        logger.debug("Get config replconninfo dn num:%s" % default_num)
        return default_num

    @staticmethod
    def getIpByHostName():
        '''
        function: get local host ip by the hostname
        input : NA
        output: hostIp
        '''
        # get hostname
        hostname = socket.gethostname()

        # get local host in /etc/hosts
        cmd = "grep -E \"^[1-9 \\t].*%s[ \\t]*#Gauss.* IP Hosts Mapping$\" " \
              "/etc/hosts | grep -E \" %s \"" % (hostname, hostname)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status == 0 and output != ""):
            hostIp = output.strip().split(' ')[0].strip()
            return hostIp

        # get local host by os function
        hostIp = socket.gethostbyname(hostname)

        # due to two loopback address in ubuntu, 127.0.1.1 are choosed by hostname.
        # there is need to choose 127.0.0.1
        version = LinuxDistro.linux_distribution()[1].split('/')[0]
        if version == "buster" and hostIp == "127.0.1.1":
            hostIp = "127.0.0.1"
        return hostIp

    @staticmethod
    def GetPythonUCS():
        """
        function: get python3 unicode value. Using it to chose which
                  Crypto we need.
                  1114111 is Crypto_UCS4
                  65535 is Crypto_UCS2
                  the value 0 is only grammar support.
        input: NA
        output: NA
        """
        if sys.maxunicode == 1114111:
            return 4
        elif sys.maxunicode == 65535:
            return 2
        else:
            return 0

    @staticmethod
    def getUserId(user):
        """
        function : get user id
        input : user
        output : user id
        """
        try:
            pwd.getpwnam(user).pw_uid
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"] % user +
                            "Detail msg: %s" % str(e))


    @staticmethod
    def doConfigForParamiko():
        """
        function: Config depend file for pramiko 2.4.2. wen only support 2.7.x
        input : NA
        output: NA
        """
        localDir = os.path.dirname(os.path.realpath(__file__))
        sys.path.insert(0, os.path.join(localDir, "./../../lib"))

    @staticmethod
    def getTmpDir(user, xml_path):
        """
        function : Get the temporary directory for user
        input : NA
        output : String 
        """
        return ClusterConfigFile.readClusterTmpMppdbPath(user, xml_path)

    @staticmethod
    def getTmpDirAppendMppdb(user):
        """
        function : Get the user's temporary directory 
        input : String
        output : String
        """
        # get the user's temporary directory 
        tmpDir = EnvUtil.getTmpDirFromEnv(user)
        # if the env paramter not exist, return ""
        if (tmpDir == ""):
            return tmpDir
        # modify tmp dir
        forbidenTmpDir = "/tmp/%s" % user
        if (tmpDir == forbidenTmpDir):
            tmpDir = os.path.join(EnvUtil.getEnv("GPHOME"),
                                  "%s_mppdb" % user)
        return tmpDir

    @staticmethod
    def checkPasswdForceChange(checkUser):
        """
        function: Check if user password is forced to change at next login.
        input : user name
        output: NA
        """
        distname, version, _ = LinuxDistro.linux_distribution()
        if (distname.lower() in ("suse", "redhat", "centos", "euleros",
                                 "openeuler", "fusionos")):
            cmd = g_file.SHELL_CMD_DICT["checkPassword"] % (checkUser,
                                                            "'^Last.*Change'")
        else:
            return
        (timestatus, output) = subprocess.getstatusoutput(cmd)
        if (timestatus != 0):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error:\n%s" % output)
        if (output == ""):
            return
        result = output.split(":")[1].strip()
        # If passwd is forced to change. Throw error code.
        if (distname.lower() == "suse"):
            if (version == '11'):
                if ("password is forced to change at next login" in result):
                    raise Exception(ErrorCode.GAUSS_503["GAUSS_50307"])
            elif (version == '12'):
                if ("password must be changed" in result):
                    raise Exception(ErrorCode.GAUSS_503["GAUSS_50307"])
        if (distname.lower() in ("redhat", "centos", "euleros",
                                 "openeuler", "fusionos")):
            if ("password must be changed" in result):
                raise Exception(ErrorCode.GAUSS_503["GAUSS_50307"])


    @staticmethod
    def getUserHome(user=""):
        """
        function :Get the user Home
        input : String
        output : String
        """
        cmd = "su - %s -c \"echo ~\" 2>/dev/null" % user
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or output.strip() == "":
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error:\n%s" % output)
        return output.strip()


    @staticmethod
    def getOSInitFile():
        """
        function : Get the OS initialization file
        input : NA
        output : String
        """
        distname, version, _ = LinuxDistro.linux_distribution()
        systemDir = "/usr/lib/systemd/system/"
        systemFile = "/usr/lib/systemd/system/gs-OS-set.service"
        # OS init file 
        #     now we only support SuSE, RHEL/CentOS and Ubuntu
        initFileSuse = "/etc/init.d/boot.local"
        initFileRedhat = "/etc/rc.d/rc.local"
        initFileUbuntu = "/lib/systemd/system/rc.local.service"
        # system init file
        initSystemFile = "/usr/local/gauss/script/gauss-OS-set.sh"
        initSystemPath = "/usr/local/gauss/script"
        dirName = os.path.dirname(os.path.realpath(__file__))

        # Get the startup file of suse or redhat os
        if (os.path.isdir(systemDir)):
            # Judge if cgroup para 'Delegate=yes' is written in systemFile
            cgroup_gate = False
            cgroup_gate_para = "Delegate=yes"
            if os.path.exists(systemFile):
                with open(systemFile, 'r') as fp:
                    retValue = fp.readlines()
                for line in retValue:
                    if line.strip() == cgroup_gate_para:
                        cgroup_gate = True
                        break

            if (not os.path.exists(systemFile) or not cgroup_gate):
                srcFile = "%s/../etc/conf/gs-OS-set.service" % dirName
                FileUtil.cpFile(srcFile, systemFile)
                FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, systemFile)
                # only support RHEL/Centos/Euler
                if (distname != "SuSE"):
                    # enable gs-OS-set.service
                    (status, output) = g_service.manageOSService("gs-OS-set",
                                                                 "enable")
                    if (status != 0):
                        raise Exception(ErrorCode.GAUSS_508["GAUSS_50802"] %
                                        "enable gs-OS-set" + " Error: \n%s" %
                                        output)

            if (not os.path.exists(initSystemPath)):
                FileUtil.createDirectory(initSystemPath)
            if (not os.path.exists(initSystemFile)):
                FileUtil.createFile(initSystemFile, False)
                FileUtil.writeFile(initSystemFile, ["#!/bin/bash"], "w")
            FileUtil.changeMode(DefaultValue.KEY_DIRECTORY_MODE, initSystemFile)
            return initSystemFile
        if (distname == "SuSE" and os.path.isfile(initFileSuse)):
            initFile = initFileSuse
        elif (distname in ("redhat", "centos", "euleros", "openEuler", "FusionOS") and
              os.path.isfile(initFileRedhat)):
            initFile = initFileRedhat
        elif (distname == "debian" and version == "buster/sid" and
              os.path.isfile(initFileUbuntu)):
            initFile = initFileUbuntu
        else:
            initFile = ""

        return initFile

    @staticmethod
    def checkInList(listsrc, listdest):
        """
        function: check the listsrc element is not in listdest
        input: listsrc, listdest
        output: True or False
        """
        if (listsrc == [] or listdest == []):
            return False

        for key in listsrc:
            if (key in listdest):
                return True
        return False

    @staticmethod
    def checkSSDInstalled():
        """
        function: check SSD 
        input: NA
        output: True/False
        """
        cmd = "hio_info"
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            return False
        return True

    @staticmethod
    def Deduplication(listname):
        """
        function: Deduplication the list
        input : NA
        output: NA
        """
        listname.sort()
        for i in range(len(listname) - 2, -1, -1):
            if listname.count(listname[i]) > 1:
                del listname[i]
        return listname

    @staticmethod
    def checkPathVaild(envValue):
        """
        function: check path vaild
        input : envValue
        output: NA
        """
        if (envValue.strip() == ""):
            return
        for rac in DefaultValue.PATH_CHECK_LIST:
            flag = envValue.find(rac)
            if flag >= 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % envValue +
                                " There are illegal characters in the path.")

    @staticmethod
    def getPathFileOfENV(envName):
        """
        function : Get the env.
        input : envName
        output
        """
        value = EnvUtil.getEnv(envName)
        if (value and not g_file.checkClusterPath(value)):
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51805"] % envName +
                            "It may have been modified after the cluster "
                            "installation is complete.")
        return value

    @staticmethod
    def obtainInstStr(objectList):
        """
        function : Obtain the message from the objectList
        input : List
        output : String
        """
        info = ""
        if (isinstance(objectList, types.ListType)):
            for obj in objectList:
                info += "%s\n" % str(obj)
        return info

    @staticmethod
    def findUnsupportedParameters(parameterList):
        """
        function : find unsupported configuration parameters,
        just ignore other invalid parameters.
                   if don't find any unsupported configuration
                   parameter, return [].
        input : List
        output : []
        """
        # init unsupported args list
        unsupportedArgs = ["support_extended_features"]
        inputedUnsupportedParameters = []
        for param in parameterList:
            # split it by '='
            keyValue = param.split("=")
            if (len(keyValue) != 2):
                continue
            if (keyValue[0].strip() in unsupportedArgs):
                inputedUnsupportedParameters.append(param)

        return inputedUnsupportedParameters

    @staticmethod
    def checkOsVersion():
        """
        function : Check os version
        input : NA
        output : boolean
        """
        # now we support this platform:
        #     RHEL/CentOS     "6.4", "6.5", "6.6", "6.7", "6.8", "6.9",
        #     "7.0", "7.1", "7.2", "7.3", "7.4", "7.5"64bit
        #     SuSE11  sp1/2/3/4 64bit
        #     EulerOS '2.0'64bit
        #     SuSE12  sp0/1/2/3 64bit
        try:
            g_Platform.getCurrentPlatForm()
            return True
        except Exception as e:
            return False

    @staticmethod
    def distributeRackFile(sshTool, hostList):
        """
        function: Distributing the rack Information File
        input : NA
        output: NA
        """
        rack_conf_file = os.path.realpath(os.path.join(
            EnvUtil.getEnv("GPHOME"),
            "script/gspylib/etc/conf/rack_info.conf"))
        rack_info_temp = os.path.realpath(os.path.join(
            EnvUtil.getEnv("GPHOME"),
            "script/gspylib/etc/conf/rack_temp.conf"))
        if os.path.isfile(rack_info_temp):
            shutil.move(rack_info_temp, rack_conf_file)
        if os.path.isfile(rack_conf_file):
            sshTool.scpFiles(rack_conf_file, rack_conf_file, hostList)

    @staticmethod
    def cleanUserEnvVariable(userProfile, cleanGAUSS_WARNING_TYPE=False,
                             cleanGS_CLUSTER_NAME=True):
        """
        function : Clean the user environment variable
        input : String,boolean 
        output : NA
        """
        try:
            # check use profile
            if os.path.isfile(userProfile):
                # clean version
                FileUtil.deleteLine(userProfile, "^\\s*export\\"
                                               "s*GAUSS_VERSION=.*$")
                # clean lib
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*LD_LIBRARY_PATH=\\"
                                  "$GAUSSHOME\\/lib:\\$LD_LIBRARY_PATH$")
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*LD_LIBRARY_PATH=\\"
                                  "$GAUSSHOME\\/lib\\/libsimsearch:\\"
                                  "$LD_LIBRARY_PATH$")
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*LD_LIBRARY_PATH=\\$GPHOME\\"
                                  "/script\\/gspylib\\/clib:\\"
                                  "$LD_LIBRARY_PATH$")
                # clean bin
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*PATH=\\$GAUSSHOME\\"
                                  "/bin:\\$PATH$")
                # clean GAUSSHOME
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*GAUSSHOME=.*$")
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*PGHOST=.*$")
                # clean GAUSSLOG
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*GAUSSLOG=.*$")
                # clean S3_ACCESS_KEY_ID
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*S3_ACCESS_KEY_ID=.*$")
                # clean S3_SECRET_ACCESS_KEY
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*S3_SECRET_ACCESS_KEY=.*$")
                # clean S3_CLIENT_CRT_FILE
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*S3_CLIENT_CRT_FILE=.*$")
                # clean ETCD_UNSUPPORTED_ARCH
                FileUtil.deleteLine(userProfile,
                                  "^\\s*export\\s*ETCD_UNSUPPORTED_ARCH=.*$")

                if (cleanGAUSS_WARNING_TYPE):
                    # clean extension connector environment variable
                    # because only deleting env_ec in postinstall, put it with
                    # GAUSS_WARNING_TYPE
                    FileUtil.deleteLine(userProfile, "^if \[ -f .*\/env_ec")
                    # clean GAUSS_WARNING_TYPE
                    FileUtil.deleteLine(userProfile, "^\\s*export\\"
                                                   "s*GAUSS_WARNING_TYPE=.*$")

                if (cleanGS_CLUSTER_NAME):
                    # clean GS_CLUSTER_NAME
                    FileUtil.deleteLine(userProfile, "^\\s*export\\"
                                                   "s*GS_CLUSTER_NAME=.*$")

                # clean AGENTPATH
                FileUtil.deleteLine(userProfile, "^\\s*export\\s*AGENTPATH=.*$")
                # clean AGENTLOGPATH
                FileUtil.deleteLine(userProfile, "^\\s*export\\s*AGENTLOGPATH="
                                               ".*$")
                # clean umask
                FileUtil.deleteLine(userProfile, "^\\s*umask\\s*.*$")

        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def setComponentEnvVariable(userProfile, envList):
        """
        funciton: Set component environment variable
        input: userProfile- env file, envList - environment variable list
        output: NA
        """
        try:
            FileUtil.createFileInSafeMode(userProfile)
            with open(userProfile, "a") as fp:
                for inst_env in envList:
                    fp.write(inst_env)
                    fp.write(os.linesep)
                fp.flush()
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] %
                            userProfile + " Error: \n%s" % str(e))

    @staticmethod
    def setUserEnvVariable(userProfile, installPath, tmpPath, logPath,
                           agentPath, agentLogPath):
        """
        function : Set the user environment variable
        input : String,String,String,String,String,String
        output : NA
        """
        envList = ["export GAUSSHOME=%s" % installPath, \
                   "export PATH=$GAUSSHOME/bin:$PATH", \
                   "export LD_LIBRARY_PATH=$GAUSSHOME/lib:$LD_LIBRARY_PATH", \
                   "export S3_CLIENT_CRT_FILE=$GAUSSHOME/lib/client.crt", \
                   "export GAUSS_VERSION=%s" %
                   VersionInfo.getPackageVersion(), \
                   "export PGHOST=%s" % tmpPath, \
                   "export GAUSSLOG=%s" % logPath,
                   "umask 077"]
        if agentPath != '':
            envList.append("export AGENTPATH=%s" % agentPath)
        if agentLogPath != '':
            envList.append("export AGENTLOGPATH=%s" % agentLogPath)
        DefaultValue.setComponentEnvVariable(userProfile, envList)


    @staticmethod
    def createCADir(sshTool, caDir, hostList):
        """
        function : create the dir of ca file
        input : config file path and ca dir path
        output : NA
        """
        opensslFile = os.path.join(caDir, "openssl.cnf")
        tmpFile = os.path.join(os.path.realpath(
            os.path.join(caDir, "..")), "openssl.cnf")
        if (not os.path.isfile(opensslFile)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % opensslFile)

        # not rename file, just move it out and clean the dir, then move back
        cmd = g_file.SHELL_CMD_DICT["renameFile"] % (opensslFile,
                                                     opensslFile,
                                                     tmpFile)
        cmd += " && " + g_file.SHELL_CMD_DICT["cleanDir"] % (caDir,
                                                             caDir,
                                                             caDir)
        cmd += " && " + g_file.SHELL_CMD_DICT["renameFile"] % (tmpFile,
                                                               tmpFile,
                                                               opensslFile)
        sshTool.executeCommand(cmd,
                               DefaultValue.SUCCESS, hostList)
        # create ./demoCA/newcerts ./demoCA/private
        newcertsPath = os.path.join(caDir, "demoCA/newcerts")
        FileUtil.createDirectory(newcertsPath)
        privatePath = os.path.join(caDir, "demoCA/private")
        FileUtil.createDirectory(privatePath)
        # touch files: ./demoCA/serial ./demoCA/index.txt
        serFile = os.path.join(caDir, "demoCA/serial")
        FileUtil.createFile(serFile, mode=DefaultValue.KEY_FILE_MODE)
        FileUtil.writeFile(serFile, ["01"])
        indexFile = os.path.join(caDir, "demoCA/index.txt")
        FileUtil.createFile(indexFile, mode=DefaultValue.KEY_FILE_MODE)

    @staticmethod
    def createServerCA(caType, caDir, logger):
        """
        function : create ca file
        input : ca file type and ca dir path
        output : NA
        """
        if (caType == DefaultValue.SERVER_CA):
            logger.log("The sslcert will be generated in %s" % caDir)
            randpass = RandomValue.getRandStr()
            confFile = caDir + "/openssl.cnf"
            if not os.path.isfile(confFile):
                raise Exception(ErrorCode.GAUSS_502
                                ["GAUSS_50201"] % confFile)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256  -passout stdin -out " % \
                   (randpass)
            cmd += "demoCA/private/cakey.pem 2048"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % output)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf -new " % (randpass)
            cmd += "-key demoCA/private/cakey.pem -passin stdin " \
                   "-out "
            cmd += "demoCA/careq.pem -subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=root'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            FileUtil.replaceFileLineContent("CA:FALSE",
                                          "CA:TRUE",
                                          confFile)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf " % (randpass)
            cmd += "-batch -passin stdin -out demoCA/cacert.pem " \
                   "-keyfile "
            cmd += "demoCA/private/cakey.pem "
            cmd += "-selfsign -infiles demoCA/careq.pem "
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256 -passout stdin -out " \
                   "server.key 2048" % (randpass)
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf -new " % (randpass)
            cmd += "-key server.key -passin stdin -out server.req " \
                   "-subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=server'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            FileUtil.replaceFileLineContent("CA:TRUE",
                                          "CA:FALSE",
                                          confFile)
            indexAttrFile = caDir + "/demoCA/index.txt.attr"
            if os.path.isfile(indexAttrFile):
                FileUtil.replaceFileLineContent("unique_subject = yes",
                                              "unique_subject = no",
                                              indexAttrFile)
            else:
                raise Exception(ErrorCode.GAUSS_502
                                ["GAUSS_50201"] % indexAttrFile)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf -batch -in " % (randpass)
            cmd += "server.req -passin stdin -out server.crt " \
                   "-days 3650 -md sha256 -subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=server'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && gs_guc encrypt -M server -K '%s' -D ./ " % randpass
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            # client key
            randpassClient = RandomValue.getRandStr()
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256  -passout stdin -out " \
                   "client.key 2048" % (randpassClient)
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf " % (randpassClient)
            cmd += "-new -key client.key -passin stdin " \
                   "-out client.req -subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=client'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf " % (randpass)
            cmd += "-batch -in client.req  -passin stdin -out "
            cmd += "client.crt -days 3650 -md sha256"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && gs_guc encrypt -M client -K '%s' -D ./ " % randpassClient
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl pkcs8 -topk8 -outform DER" % randpassClient
            cmd += " -passin stdin  "
            cmd += " -in client.key -out client.key.pk8 -nocrypt"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            del randpass, randpassClient


    @staticmethod
    def changeOpenSslConf(confFile, hostList):
        """
        function : change the openssl.cnf file
        input : confFile, hostList
        output : NA
        """
        # Clean the old content.
        lineList = FileUtil.readFile(confFile)
        for i in range(len(lineList)):
            if ("[" in lineList[i] and
                    "alt_names" in lineList[i] and
                    "]" in lineList[i]):
                row = i + 1
                FileUtil.deleteLineByRowNum(confFile, row)
            if ("DNS." in lineList[i] and "=" in lineList[i]):
                FileUtil.deleteLineByRowNum(confFile, row)
        # Add new one.
        dnsList = []
        dnsList.append("\n")
        dnsList.append("[ alt_names ]")
        dnsList.append("DNS.1 = localhost")
        cont = 2
        for host in hostList:
            dns = "DNS." + str(cont) + " = " + host
            dnsList.append(dns)
            cont = cont + 1
        FileUtil.writeFile(confFile, dnsList)

    @staticmethod
    def is_create_grpc(logger, gauss_home_path):
        """
        function : Check whether the grpc.conf file exists.
        input : logger object, gauss_home_path
        output : True or False
        """
        logger.debug("Start check grpc.conf file.")
        conf_file = os.path.realpath(os.path.join(gauss_home_path,
                                                  "share",
                                                  "sslcert",
                                                  "grpc",
                                                  "openssl.cnf"))

        if os.path.isfile(conf_file):
            logger.debug("Exist openssl.cnf file [%s]." % conf_file)
            return True
        else:
            logger.debug("Does not exist openssl.cnf file [%s]." % conf_file)
            return False

    @staticmethod
    def createCA(caType, caDir):
        """
        function : create ca file
        input : ca file type and ca dir path
        output : NA
        """
        if caType == DefaultValue.GRPC_CA:
            randpass = RandomValue.getRandStr()
            confFile = caDir + "/openssl.cnf"
            if (os.path.isfile(confFile)):
                FileUtil.replaceFileLineContent("cakey.pem",
                                              "cakeynew.pem",
                                              confFile)
                FileUtil.replaceFileLineContent("careq.pem",
                                              "careqnew.pem",
                                              confFile)
                FileUtil.replaceFileLineContent("cacert.pem",
                                              "cacertnew.pem",
                                              confFile)
                FileUtil.replaceFileLineContent("server.key",
                                              "servernew.key",
                                              confFile)
                FileUtil.replaceFileLineContent("server.req",
                                              "servernew.req",
                                              confFile)
                FileUtil.replaceFileLineContent("server.crt",
                                              "servernew.crt",
                                              confFile)
                FileUtil.replaceFileLineContent("client.key",
                                              "clientnew.key",
                                              confFile)
                FileUtil.replaceFileLineContent("client.req",
                                              "clientnew.req",
                                              confFile)
                FileUtil.replaceFileLineContent("client.crt",
                                              "clientnew.crt",
                                              confFile)
            else:
                raise Exception(ErrorCode.GAUSS_502
                                ["GAUSS_50201"] % confFile)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256  -passout stdin -out " % \
                   (randpass)
            cmd += "demoCA/private/cakeynew.pem 2048"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf -new " % (randpass)
            cmd += "-key demoCA/private/cakeynew.pem -passin stdin " \
                   "-out "
            cmd += "demoCA/careqnew.pem -subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=root'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf -days 7300 " % (randpass)
            cmd += "-batch -passin stdin -out demoCA/cacertnew.pem " \
                   "-md sha512 -keyfile "
            cmd += "demoCA/private/cakeynew.pem "
            cmd += "-selfsign -infiles demoCA/careqnew.pem "
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256 -passout stdin -out " \
                   "servernew.key 2048" % (randpass)
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf -new " % (randpass)
            cmd += "-key servernew.key  -passin stdin -out servernew.req " \
                   "-subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=root'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            indexAttrFile = caDir + "/demoCA/index.txt.attr"
            if (os.path.isfile(indexAttrFile)):
                FileUtil.replaceFileLineContent("unique_subject = yes",
                                              "unique_subject = no",
                                              indexAttrFile)
            else:
                raise Exception(ErrorCode.GAUSS_502
                                ["GAUSS_50201"] % indexAttrFile)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf -batch -in " % (randpass)
            cmd += "servernew.req -passin stdin -out servernew.crt " \
                   "-days 7300 -md sha512"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl genrsa -aes256  -passout stdin -out " \
                   "clientnew.key 2048" % (randpass)
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl req -config openssl.cnf " % (randpass)
            cmd += "-new -key clientnew.key -passin stdin " \
                   "-out clientnew.req -subj "
            cmd += "'/C=CN/ST=Beijing/L=Beijing/"
            cmd += "O=huawei/OU=gauss/CN=root'"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && echo '%s' | openssl ca -config openssl.cnf " % (randpass)
            cmd += "-batch -in clientnew.req  -passin stdin -out "
            cmd += "clientnew.crt -days 7300 -md sha512"
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && gs_guc encrypt -M server -K '%s' -D ./ " % randpass
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % output)
            cmd = CmdUtil.getCdCmd(caDir)
            cmd += " && gs_guc encrypt -M client -K '%s' -D ./ " % randpass
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514
                                ["GAUSS_51402"] + "Error:\n%s" % SensitiveMask.mask_pwd(output))
            del randpass

    @staticmethod
    def cleanServerCaDir(caDir):
        """
        function : clean the dir of ca file and change mode of ca files
        input : ca dir path
        output : NA
        """
        certFile = caDir + "/demoCA/cacert.pem"
        if os.path.exists(certFile):
            FileUtil.moveFile(certFile, caDir)
        clientReq = caDir + "/server.req"
        FileUtil.removeFile(clientReq)
        clientReq = caDir + "/client.req"
        FileUtil.removeFile(clientReq)
        demoCA = caDir + "/demoCA"
        FileUtil.removeDirectory(demoCA)
        allCerts = caDir + "/*"
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, allCerts)

    @staticmethod
    def cleanCaDir(caDir):
        """
        function : clean the dir of ca file and change mode of ca files
        input : ca dir path
        output : NA
        """
        certFile = caDir + "/demoCA/cacertnew.pem"
        if os.path.exists(certFile):
            FileUtil.moveFile(certFile, caDir)
        clientReq = caDir + "/clientnew.req"
        FileUtil.removeFile(clientReq)
        clientReq = caDir + "/servernew.req"
        FileUtil.removeFile(clientReq)
        demoCA = caDir + "/demoCA"
        FileUtil.removeDirectory(demoCA)
        allCerts = caDir + "/*"
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, allCerts)

    @staticmethod
    def obtainSSDDevice():
        """
        function : Obtain the SSD device
        input : NA
        output : []
        """
        devList = []
        cmd = "ls -ll /dev/hio? | awk '{print $10}'"
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status == 0 and output.find("No such file or directory") < 0):
            devList = output.split("\n")
        else:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53005"] +
                            " Command:%s. Error:\n%s" % (cmd, output))
        return devList

    @staticmethod
    def checkOutputFile(outputFile):
        """
        function : check the output file
        input : String
        output : NA
        """
        if (os.path.isdir(outputFile)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % "output file")
        # get parent directory of output file
        parent_dir = os.path.dirname(outputFile)
        if (os.path.isfile(parent_dir)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50211"] %
                            "base directory of output file")

    @staticmethod
    def KillAllProcess(userName, procName):
        """
        function : Kill all processes by userName and procName.
        input : userName, procName
        output : boolean
        """
        return ProcessUtil.killallProcess(userName, procName, "9")

    @staticmethod
    def sendNetworkCmd(ip):
        """
        function : Send the network command of ping. 
        input : String
        output : NA
        """
        cmd = "%s |%s ttl |%s -l" % (CmdUtil.getPingCmd(ip, "5", "1"),
                                     CmdUtil.getGrepCmd(),
                                     CmdUtil.getWcCmd())
        (status, output) = subprocess.getstatusoutput(cmd)
        if (str(output) == '0' or status != 0):
            g_lock.acquire()
            noPassIPs.append(ip)
            g_lock.release()

    @staticmethod
    def fast_ping(node_ip):
        """
        ping node with short timeout
        """
        cmd = "ping %s -c 1 -w 4" % node_ip
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
        proc.communicate()
        status = proc.returncode
        result = (node_ip, True) if status == 0 else (node_ip, False)
        return result

    @staticmethod
    def fast_ping_on_node(on_node, from_ip, to_ip, logger):
        """
        Ping on remote node with -I
        """
        cmd = "ping %s -c 1 -w 4" % on_node
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE,
                         preexec_fn=os.setsid, close_fds=True)
        proc.communicate()
        status = proc.returncode
        if status != 0:
            logger.debug("Node:%s ping failed, can not execute remote check." % on_node)
            return on_node, False
        if on_node == NetUtil.GetHostIpOrName():
            cmd_remote = "ping %s -I %s -c 1 -w 4" % (to_ip, from_ip)
        else:
            cmd_remote = "source %s && pssh -s -H %s 'ping %s -I %s -c 1 -w 4'" \
                         % (EnvUtil.getMpprcFile(), on_node, to_ip, from_ip)
        proc = FastPopen(cmd_remote, stdout=PIPE, stderr=PIPE,
                         preexec_fn=os.setsid, close_fds=True)
        proc.communicate()
        status = proc.returncode
        result = (to_ip, True) if status == 0 else (to_ip, False)
        logger.debug("Remote ping result on node:%s, from ip:%s, to ip:%s, result:%s."
                     % (on_node, from_ip, to_ip, result))
        return result

    @staticmethod
    def checkIsPing(ips):
        """
        function : Check the connection status of network.
        input : []
        output : []
        """
        global noPassIPs
        noPassIPs = []
        parallelTool.parallelExecute(DefaultValue.sendNetworkCmd,
                                               ips)
        return noPassIPs

    @staticmethod
    def killInstProcessCmd(instName, isRemote=False, signal=9,
                           isExactMatch=True, instType="",
                           procAbsPath="", instDir=""):
        """
        instName: process name
        isRemote: do it under remote machine. default is false
        signal  : kill signle. default is 9 
        isExactMatch: the match rule. default is exact match
        instType: instance type. default is "", now only support for get
        coordinator instance
        procAbsPath: process abs path. default is ""
        instDir: instance data directory. default is ""
        """
        pstree = "python3 %s -sc" % os.path.realpath(os.path.dirname(
            os.path.realpath(__file__)) + "/../../py_pstree.py")
        # only cm_server need kill all child process, when do kill -9
        if instName == "cm_server" and signal == 9:
            if isRemote:
                cmd = "pidList=\`ps ux | grep '\<cm_server\>' | grep -v " \
                      "'grep' " \
                      "| awk '{print \$2}' | xargs \`; for pid in \$pidList;" \
                      " do %s \$pid | xargs -r -n 100 kill -9; echo " \
                      "'SUCCESS'; " \
                      "done" % pstree
                # only try to kill -9 process of cmserver
                cmd += "; ps ux | grep '\<cm_server\>' | grep -v grep | awk " \
                       "'{print \$2}' | xargs -r kill -9; echo 'SUCCESS'"
            else:
                cmd = "pidList=`ps ux | grep '\<cm_server\>' | grep -v " \
                      "'grep' |" \
                      " awk '{print $2}' | xargs `; for pid in $pidList; " \
                      "do %s $pid | xargs -r -n 100 kill -9; echo 'SUCCESS';" \
                      " done" % pstree
                cmd += "; ps ux | grep '\<cm_server\>' | grep -v grep | " \
                       "awk '{print $2}' | xargs -r kill -9; echo 'SUCCESS'"
            return cmd

        if "" != instType and "" != procAbsPath and "" != instDir:
            if isRemote:
                cmd = "ps ux | grep '\<%s\>' | grep '%s' | grep '%s' | " \
                      "grep -v grep | awk '{print \$2}' | xargs -r kill -%d " \
                      "" % \
                      (instType, procAbsPath, instDir, signal)
            else:
                cmd = "ps ux | grep '\<%s\>' | grep '%s' | grep '%s' | " \
                      "grep -v grep | awk '{print $2}' | xargs -r kill -%d " \
                      % \
                      (instType, procAbsPath, instDir, signal)
        else:
            if (isExactMatch):
                if (isRemote):
                    cmd = "ps ux | grep '\<%s\>' | grep -v grep | awk " \
                          "'{print \$2}' | xargs -r kill -%d " % (instName,
                                                                  signal)
                else:
                    cmd = "ps ux | grep '\<%s\>' | grep -v grep | awk " \
                          "'{print $2}' | xargs -r kill -%d " % (instName,
                                                                 signal)
            else:
                if (isRemote):
                    cmd = "ps ux | grep '%s' | grep -v grep | awk " \
                          "'{print \$2}' | xargs -r kill -%d " % (instName,
                                                                  signal)
                else:
                    cmd = "ps ux | grep '%s' | grep -v grep | " \
                          "awk '{print $2}' | xargs -r kill -%d " % (instName,
                                                                     signal)
        return cmd

    @staticmethod
    def retry_gs_guc(cmd):
        """
        function : Retry 3 times when HINT error
        input : cmd
        output : NA
        """
        retryTimes = 0
        while True:
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status == 0):
                break
            if (retryTimes > 1):
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50008"] +
                                " Command:%s. Error:\n%s" % (cmd, output))
            retryTimes = retryTimes + 1
            time.sleep(3)


    @staticmethod
    def distributeXmlConfFile(g_sshTool, confFile, hostname=None,
                              mpprcFile="", localMode=False):
        '''
        function: distribute the confFile to remote nodes
        input: g_sshTool, hostname, confFile, mpprcFile
        output:NA
        '''
        if hostname is None:
            hostname = []
        try:
            # distribute xml file
            # check and create xml file path
            xmlDir = os.path.dirname(confFile)
            xmlDir = os.path.normpath(xmlDir)
            LocalRemoteCmd.checkRemoteDir(g_sshTool, xmlDir, hostname, mpprcFile,
                                        localMode)
            local_node = NetUtil.GetHostIpOrName()
            # Skip local file overwriting
            if not hostname:
                hostname = g_sshTool.hostNames[:]
            if local_node in hostname:
                hostname.remove(local_node)
            if (not localMode):
                # Send xml file to every host
                g_sshTool.scpFiles(confFile, xmlDir, hostname, mpprcFile)
            # change owner and mode of xml file
            cmd = CmdUtil.getChmodCmd(str(DefaultValue.FILE_MODE), confFile)
            CmdExecutor.execCommandWithMode(cmd,
                                            g_sshTool,
                                            localMode,
                                            mpprcFile,
                                            hostname)
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def getSecurityMode():
        """
        function:to set security mode,if security_mode is not in config
                 file,return off.
        input:String
        output:String
        """
        securityModeValue = "off"
        try:
            cmd = "ps -ux | grep \"\\-\\-securitymode\" | grep -v \"grep\""
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0 and output != "":
                raise Exception(
                    (ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                     + "Error: \n %s" % output))
            if output != "":
                securityModeValue = "on"
            return securityModeValue
        except Exception as ex:
            raise Exception(str(ex))

    @staticmethod
    def checkTransactionReadonly(user, DbclusterInfo, normalCNList=None):
        """
        function : check the CN's parameter default_transaction_read_only is on
                   if eques on, return 1 and error info
        input : user, DbclusterInfo, normalCNList
        output : 0/1
        """
        cnList = []
        if normalCNList is None:
            normalCNList = []
        localhost = NetUtil.GetHostIpOrName()
        sql = "show default_transaction_read_only;"
        try:
            if (len(normalCNList)):
                cnList = normalCNList
            else:
                # Find CN instance in cluster
                for dbNode in DbclusterInfo.dbNodes:
                    if (len(dbNode.coordinators) != 0):
                        cnList.append(dbNode.coordinators[0])

            security_mode_value = DefaultValue.getSecurityMode()
            # Execute sql on every CN instance
            if (security_mode_value == "on"):
                for cooInst in cnList:
                    if (localhost == cooInst.hostname):
                        (status, result, error_output) = \
                            SqlExecutor.excuteSqlOnLocalhost(cooInst.port,
                                                                sql)
                        if (status != 2):
                            return 1, "[%s]: Error: %s result: %s status: " \
                                      "%s" % \
                                   (cooInst.hostname, error_output,
                                    result, status)
                        if (result[0][0].strip().lower() == "on"):
                            return 1, "The database is in read only mode."
                    else:
                        currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                        pid = os.getpid()
                        outputfile = "metadata_%s_%s_%s.json" % (
                            cooInst.hostname, pid, currentTime)
                        tmpDir = EnvUtil.getTmpDirFromEnv()
                        filepath = os.path.join(tmpDir, outputfile)
                        ClusterCommand.executeSQLOnRemoteHost(cooInst.hostname,
                                                              cooInst.port,
                                                              sql,
                                                              filepath)
                        (status, result, error_output) = \
                            SqlExecutor.getSQLResult(cooInst.hostname,
                                                        outputfile)
                        if (status != 2):
                            return 1, "[%s]: Error: %s result: %s status: " \
                                      "%s" % \
                                   (cooInst.hostname, error_output, result,
                                    status)
                        if (result[0][0].strip().lower() == "on"):
                            return 1, "The database is in read only mode."
            else:
                for cooInst in cnList:
                    (status, output) = ClusterCommand.remoteSQLCommand(
                        sql, user, cooInst.hostname, cooInst.port)
                    resList = output.split('\n')
                    if (status != 0 or len(resList) < 1):
                        return 1, "[%s]: %s" % (cooInst.hostname, output)
                    if (resList[0].strip() == "on"):
                        return 1, "The database is in read only mode."
            return 0, "success"
        except Exception as e:
            return 1, str(e)

    @staticmethod
    def getCpuSet():
        """
        function: get cpu set of current board
                  cat /proc/cpuinfo |grep processor
        input: NA
        output: cpuSet
        """
        # do this function to get the parallel number
        cpuSet = multiprocessing.cpu_count()
        if (cpuSet > 1):
            return cpuSet
        else:
            return DefaultValue.DEFAULT_PARALLEL_NUM

    @staticmethod
    def checkSHA256(binFile, sha256File):
        """
        """
        if binFile == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % "bin file")
        if sha256File == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                            % "verification file")

        sha256Obj = hashlib.sha256()
        if not sha256Obj:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50238"] %
                            binFile + "can not get verification Obj.")
        with open(binFile, "rb") as filebin:
            while True:
                strRead = filebin.read(8096)
                if not strRead:
                    break
                sha256Obj.update(strRead)
        strSHA256 = sha256Obj.hexdigest()
        with open(sha256File, "r") as fileSHA256:
            strRead = fileSHA256.readline()
            oldSHA256 = strRead.strip()
            if strSHA256 != oldSHA256:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50238"] % binFile)

    @staticmethod
    def checkDirSize(path, needSize, g_logger):
        """
        function: Check the size of directory
        input : path,needSize
        output: NA
        """
        # The file system of directory
        diskSizeInfo = {}
        dfCmd = "%s | head -2 |tail -1 | %s -F\" \" '{print $1}'" % \
                (CmdUtil.getDiskFreeCmd(path), CmdUtil.getAwkCmd())
        (status, output) = subprocess.getstatusoutput(dfCmd)
        if (status != 0):
            g_logger.logExit(ErrorCode.GAUSS_502["GAUSS_50219"] %
                             "the system file directory" +
                             " Command:%s. Error:\n%s" % (dfCmd, output))

        fileSysName = str(output)
        diskSize = diskSizeInfo.get(fileSysName)
        if (diskSize is None):
            vfs = os.statvfs(path)
            diskSize = vfs.f_bavail * vfs.f_bsize // (1024 * 1024)
            diskSizeInfo[fileSysName] = diskSize

        # 200M for a instance needSize is 200M
        if (diskSize < needSize):
            g_logger.logExit(ErrorCode.GAUSS_504["GAUSS_50400"] % (fileSysName,
                                                                   needSize))

        diskSizeInfo[fileSysName] -= needSize
        return diskSizeInfo

    @staticmethod
    def getPrimaryDnNum(dbClusterInfoGucDnPr):
        """
        """
        dataCount = 0
        dbNodeList = dbClusterInfoGucDnPr.dbNodes
        for dbNode in dbNodeList:
            dataCount = dataCount + dbNode.dataNum
        return dataCount

    @staticmethod
    def getPhysicMemo(PhsshTool, instaLocalMode):
        """
        """
        if instaLocalMode:
            cmd = g_file.SHELL_CMD_DICT["physicMemory"]
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "Error:\n%s" % str(output))
            else:
                memTotalList = output.split("\n")
                for content in memTotalList:
                    if ("MemTotal" in content):
                        memoList = content.split(":")
                        memo = memoList[1]
                        memo = memo.replace("kB", "")
                        memo = memo.replace("\n", "")
                        memo = memo.strip()
                        memo = int(memo) / 1024 / 1024
            return memo
        physicMemo = []
        cmd = g_file.SHELL_CMD_DICT["physicMemory"]
        (status, output) = PhsshTool.getSshStatusOutput(cmd)
        for ret in status.values():
            if (ret != DefaultValue.SUCCESS):
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                "Error:\n%s" % str(output))
        memTotalList = output.split("\n")
        for content in memTotalList:
            if ("MemTotal" in content):
                memoList = content.split(":")
                memo = memoList[1]
                memo = memo.replace("kB", "")
                memo = memo.strip()
                memo = int(memo) / 1024 / 1024
                physicMemo.append(memo)
        minPhysicMemo = min(physicMemo)
        return minPhysicMemo

    @staticmethod
    def getDataNodeNum(dbClusterInfoGucDn):
        """
        """
        dataNodeNum = []
        dbNodeList = dbClusterInfoGucDn.dbNodes
        for dbNode in dbNodeList:
            dataNodeNum.append(dbNode.dataNum)
        maxDataNodeNum = max(dataNodeNum)
        return maxDataNodeNum

    @staticmethod
    def dynamicGuc(instanceType, tmpGucFile, gucXml=False):
        """
        function: set hba config
        input : NA
        output: NA
        """
        try:
            instance = instanceType
            gucList = FileUtil.readFile(tmpGucFile)
            gucStr = gucList[0].replace("\n", "")
            dynamicParaList = gucStr.split(",")
            for guc in dynamicParaList:
                if (guc == ""):
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50203"] %
                                    gucStr)

            # getting the path of guc_list.conf.
            dirName = os.path.dirname(os.path.realpath(__file__))
            if gucXml:
                gucFile = os.path.join(dirName,
                                       "./../etc/conf/guc_cloud_list.xml")
            else:
                gucFile = os.path.join(dirName, "./../etc/conf/guc_list.xml")
            gucFile = os.path.normpath(gucFile)

            # reading xml.
            gucDict = {}
            rootNode = ClusterConfigFile.initParserXMLFile(gucFile)
            instanceEle = rootNode.find(instance)
            instanceList = instanceEle.findall("PARAM")
            for gucElement in instanceList:
                DefaultValue.checkGuc(gucElement.attrib['VALUE'])
                gucDict[gucElement.attrib['KEY']] = gucElement.attrib['VALUE']
            gucParaDict = DefaultValue.initGuc(gucDict,
                                               dynamicParaList, gucXml)

            return gucParaDict
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def checkGuc(gucValue):
        """
        function: check path vaild
        input : envValue
        output: NA
        """
        gucCheckList = ["|", ";", "&", "$", "<", ">", "`", "{", "}", "[", "]",
                        "~", "?", " ", "!"]
        if (gucValue.strip() == ""):
            return
        for rac in gucCheckList:
            flag = gucValue.find(rac)
            if gucValue.strip() == "%x %a %m %u %d %h %p %S" and rac == " ":
                continue
            if flag >= 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % gucValue +
                                " There are illegal characters %s "
                                "in the content." % rac)

    @staticmethod
    def initGuc(gucDict, dynamicParaList, gucXml=False):
        """
        """
        for guc in gucDict:
            if (guc == "comm_max_datanode" and not gucXml):
                if (int(dynamicParaList[0]) < 256):
                    gucDict[guc] = 256
                elif (int(dynamicParaList[0]) < 512):
                    gucDict[guc] = 512
                elif (int(dynamicParaList[0]) < 1024):
                    gucDict[guc] = 1024
                elif (int(dynamicParaList[0]) < 2048):
                    gucDict[guc] = 2048
                else:
                    gucDict[guc] = 4096
                continue
            elif (guc == "max_process_memory"):
                if (gucDict[guc] == "80GB"):
                    continue
                if (int(dynamicParaList[0]) < 256):
                    ratioNum = 1
                elif (int(dynamicParaList[0]) < 512):
                    ratioNum = 2
                else:
                    ratioNum = 3
                gucDict[guc] = gucDict[guc].replace(
                    "PHYSIC_MEMORY", dynamicParaList[1])
                gucDict[guc] = gucDict[guc].replace(
                    "MAX_MASTER_DATANUM_IN_ONENODE", dynamicParaList[2])
                gucDict[guc] = gucDict[guc].replace("N", str(ratioNum))
                try:
                    gucDict[guc] = eval(gucDict[guc])
                except Exception as e:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                                    "calculate: %s" % gucDict[guc])
                gucDict[guc] = int(gucDict[guc])
                if (gucDict[guc] >= 2 and gucDict[guc] <= 2047):
                    gucDict[guc] = str(gucDict[guc]) + "GB"
                elif (gucDict[guc] < 2):
                    gucDict[guc] = "2GB"
                else:
                    gucDict[guc] = "2047GB"
                continue
            elif guc == "shared_buffers":
                if (int(dynamicParaList[0]) < 256):
                    ratioNum = 1
                elif (int(dynamicParaList[0]) < 512):
                    ratioNum = 2
                else:
                    ratioNum = 3
                gucDict[guc] = gucDict[guc].replace(
                    "PHYSIC_MEMORY", dynamicParaList[1])
                gucDict[guc] = gucDict[guc].replace(
                    "MAX_MASTER_DATANUM_IN_ONENODE", dynamicParaList[2])
                gucDict[guc] = gucDict[guc].replace("N", str(ratioNum))
                try:
                    gucDict[guc] = eval(gucDict[guc])
                except Exception as e:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                                    "calculate: %s" % gucDict[guc])
                gucDict[guc] = int(gucDict[guc] * 1024)
                if gucDict[guc] >= 1024:
                    gucDict[guc] = "1GB"
                else:
                    gucDict[guc] = str(gucDict[guc]) + "MB"
        return gucDict

    @staticmethod
    def getPrivateGucParamList():
        """
        function : Get the private guc parameter list.
        input : NA
        output
        """
        # only used by dummy standby instance
        #     max_connections value is 100
        #     memorypool_enable value is false
        #     shared_buffers value is 32MB
        #     bulk_write_ring_size value is 32MB
        #     max_prepared_transactions value is 10
        #     cstore_buffers value is 16MB
        #     autovacuum_max_workers value is 0
        #     max_pool_size value is 50
        #     wal_buffers value is -1

        # add the parameter content to the dictionary list
        priavetGucParamDict = {}
        priavetGucParamDict["max_connections"] = "100"
        priavetGucParamDict["memorypool_enable"] = "false"
        priavetGucParamDict["shared_buffers"] = "32MB"
        priavetGucParamDict["bulk_write_ring_size"] = "32MB"
        priavetGucParamDict["max_prepared_transactions"] = "10"
        priavetGucParamDict["cstore_buffers"] = "16MB"
        priavetGucParamDict["autovacuum_max_workers"] = "0"
        priavetGucParamDict["wal_buffers"] = "-1"
        priavetGucParamDict["max_locks_per_transaction"] = "64"
        priavetGucParamDict["sysadmin_reserved_connections"] = "3"
        priavetGucParamDict["max_wal_senders"] = "4"
        return priavetGucParamDict

    @staticmethod
    def checkKerberos(mpprcFile):
        """
        function : check kerberos authentication
        input : mpprcfile absolute path
        output : True/False
        """
        krb5Conf = os.path.join(os.path.dirname(mpprcFile),
                                DefaultValue.FI_KRB_CONF)
        tablespace = EnvUtil.getEnv("ELK_SYSTEM_TABLESPACE")
        if (tablespace is not None and tablespace != ""):
            xmlfile = os.path.join(os.path.dirname(mpprcFile),
                                   DefaultValue.FI_ELK_KRB_XML)
        else:
            xmlfile = os.path.join(os.path.dirname(mpprcFile),
                                   DefaultValue.FI_KRB_XML)
        if (os.path.exists(xmlfile) and os.path.exists(krb5Conf) and
                EnvUtil.getEnv("PGKRBSRVNAME")):
            return True
        return False

    @staticmethod
    def setActionFlagFile(module="", mode=True):
        """
        function: Set action flag file
        input : module
        output: NAself
        """
        if os.getuid() == 0:
            return
        # Get the temporary directory from PGHOST
        tmpDir = EnvUtil.getTmpDirFromEnv()
        if not tmpDir:
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "PGHOST")
        # check if tmp dir exists
        if not os.path.exists(tmpDir):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            tmpDir + " Please check it.")
        if not os.access(tmpDir, os.R_OK | os.W_OK | os.X_OK):
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50103"] % tmpDir)
        actionFlagFile = os.path.join(tmpDir,
                                      DefaultValue.ACTION_FLAG_FILE + "_%s"
                                      % os.getpid())
        if mode:
            FileUtil.createFileInSafeMode(actionFlagFile)
            with open(actionFlagFile, "w") as fp:
                fp.write(module)
                fp.flush()
            os.chmod(actionFlagFile, ConstantsBase.KEY_FILE_PERMISSION)
        else:
            if os.path.exists(actionFlagFile):
                os.remove(actionFlagFile)

    @staticmethod
    def isUnderUpgrade(user):
        tempPath = EnvUtil.getTmpDirFromEnv(user)
        bakPath = os.path.join(tempPath, "binary_upgrade")
        if os.path.isdir(bakPath):
            if os.listdir(bakPath):
                return True
        return False

    @staticmethod
    def enableWhiteList(sshTool, mpprcFile, nodeNames, logger):
        """
        function: write environment value WHITELIST_ENV for agent mode
        input : sshTool, mpprcFile, nodeNames, logger
        output: NA
        """
        env_dist = os.environ
        if "HOST_IP" in env_dist.keys():
            cmd = "sed -i '/WHITELIST_ENV=/d' %s ; " \
                  "echo 'export WHITELIST_ENV=1' >> %s" % (mpprcFile,
                                                           mpprcFile)
            sshTool.executeCommand(cmd,
                                   DefaultValue.SUCCESS, nodeNames)
            logger.debug("Successfully write $WHITELIST_ENV in %s" % mpprcFile)

    @staticmethod
    def checkDockerEnv():
        cmd = "egrep  '^1:.+(docker|lxc|kubepods)' /proc/1/cgroup"
        (status, output) = subprocess.getstatusoutput(cmd)
        if output:
            return True
        else:
            return False

    @staticmethod
    def getSpecificNode(userProfile, flagStr, logger=None, with_cm=False):
        """
        :param flagStr: Primary/Standby/Cascade
        :return: correspond nodes
        """
        try:
            count = 0
            while count < 30:
                cmd = "source {0} && gs_om -t query".format(
                    userProfile)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status == 0 and not with_cm:
                    break

                if status == 0 and with_cm:
                    if ("cluster_state   : Normal" in output or "cluster_state   : Degraded" in output):
                        break
                    if count == 2:
                        start_cmd = "source {0} && gs_om -t start --time-out 30".format(userProfile)
                        _, output = subprocess.getstatusoutput(start_cmd)
                        if logger:
                            logger.debug("Start cluster for get current primary datanode, "
                                        "the result is : \n{0}".format(output))
                time.sleep(10)
                count += 1
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                "Command:%s. Error:\n%s" % (cmd, output))
            targetString = output.split("Datanode")[1]
            dnPrimary = [x for x in re.split(r"[|\n]", targetString)
                         if flagStr in x or "Main" in x]
            primaryList = []
            for dn in dnPrimary:
                primaryList.append(list(filter(None, dn.split(" ")))[1])
            return primaryList, output
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def getPrimaryNode(userProfile, logger=None, with_cm=False):
        """
        :param
        :return: PrimaryNode
        """
        return DefaultValue.getSpecificNode(userProfile, "Primary", logger, with_cm)

    @staticmethod
    def getStandbyNode(userProfile, logger=None):
        """
        :param
        :return: StandbyNode
        """
        return DefaultValue.getSpecificNode(userProfile, "Standby", logger)


    @staticmethod
    def non_root_owner(filepath):
        """
        :param filepath:
        :return:
        """
        if not os.path.exists(filepath):
            return False
        if os.stat(filepath).st_uid != 0:
            return True
        return False

    @staticmethod
    def check_cm_package(cluster_info, package_path, logger):
        """
        Check CM package
        """
        if cluster_info.cmscount == 0:
            logger.debug("No CM instance in configure file.")
            return True

        logger.debug("There include cm instance on local node.")
        if not os.path.isfile(package_path):
            logger.debug("CM is config in configure file, but not exist cm package.")
            return False
        logger.debug("CM is config in configure file and cm package exist.")
        return True


    @staticmethod
    def get_cm_server_num_from_static(cluster_info):
        """
        Get cm_server num from static config file
        """
        cm_server_num = 0
        for db_node in cluster_info.dbNodes:
            cm_server_num += len(db_node.cmservers)
        return cm_server_num


    @staticmethod
    def get_secret(length=32):
        """
        function : random secret
        input : int
        output : string
        """
        secret_types = string.ascii_letters + string.digits + string.punctuation
        exception_str = "`;$'\"{}[\\"
        while True:
            secret_word = ''.join(secrets.choice(secret_types) for _ in range(length))
            check_flag = False
            for i in exception_str:
                if i in secret_word:
                    check_flag = True
                    break
            if check_flag:
                continue
            if (any(c.islower() for c in secret_word)
                    and any(c.isupper() for c in secret_word)
                    and any(c in string.punctuation for c in secret_word)
                    and sum(c.isdigit() for c in secret_word) >= 4):
                break
        return secret_word

    @staticmethod
    def check_add_cm(old_cluster_config_file, new_cluster_config_file, logger):
        """
        Check need install CM instance
        """
        old_cluster_info = dbClusterInfo()
        new_cluster_info = dbClusterInfo()
        user = pwd.getpwuid(os.getuid()).pw_name
        old_cluster_info.initFromStaticConfig(user, old_cluster_config_file)
        new_cluster_info.initFromStaticConfig(user, new_cluster_config_file)

        if DefaultValue.get_cm_server_num_from_static(new_cluster_info) > 0 and \
                DefaultValue.get_cm_server_num_from_static(old_cluster_info) == 0:
            logger.debug("Need to install CM instance to node.")
            return True
        logger.debug("No need to install CM instance to node.")
        return False

    @staticmethod
    def try_fast_popen(cmd, retry_time=3, sleep_time=1, check_output=False):
        """
        function : retry getStatusoutput
        @param cmd: command  going to be execute
        @param retry_time: default retry 3 times after execution failure
        @param sleep_time: default sleep 1 second then start retry
        """
        retry_time += 1
        for i in range(retry_time):
            proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                time.sleep(sleep_time)
            elif check_output:
                if str(stdout+stderr).strip():
                    break
                else:
                    time.sleep(sleep_time)
            else:
                break
        return proc.returncode, stdout, stderr

    @staticmethod
    def get_ssh_protect_path():
        """
        get the temp path
        :return: string
        """
        ssh_protect_path = os.path.expanduser(Constants.SSH_PROTECT_PATH)
        if not os.path.exists(ssh_protect_path):
            FileUtil.createDirectory(ssh_protect_path,
                                   mode=DefaultValue.KEY_DIRECTORY_MODE)
        if os.path.isdir(ssh_protect_path):
            dir_permission = oct(os.stat(ssh_protect_path).st_mode)[-3:]
            if dir_permission != str(DefaultValue.KEY_DIRECTORY_MODE):
                os.chmod(ssh_protect_path, stat.S_IRWXU)
        else:
            msg = "Failed to create the directory because the file"
            msg = "%s %s with the same name exists." % (
                msg, ssh_protect_path)
            raise Exception(msg)
        return ssh_protect_path

    @staticmethod
    def get_dn_info(cluster_info):
        """
        Get primary dn info
        """
        instances = []
        dn_instances = [dn_inst for db_node in cluster_info.dbNodes
                        for dn_inst in db_node.datanodes if int(dn_inst.mirrorId) == 1]
        for dn_inst in dn_instances:
            dn_info = {}
            dn_info["id"] = dn_inst.instanceId
            dn_info["data_dir"] = dn_inst.datadir
            dn_info["host_name"] = dn_inst.hostname
            instances.append(dn_info)
        return instances

    @staticmethod
    def get_local_ips():
        """
        get local node all ips
        :return:
        """
        # eg "ip_mappings: [('lo', '127.0.0.1'), ('eth1', '10.10.10.10')]"
        ip_mappings = NetUtil.getIpAddressAndNICList()
        local_ips = []
        for ip_info in ip_mappings:
            local_ips.append(ip_info[1])
        return local_ips

    @staticmethod
    def get_pid(desc):
        """
        function : get the ID of the process
                   that contains the specified content
        input : string
        output : list
        """
        pids = []
        cmd = "ps ux | grep '%s' | grep -v grep" % desc
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()
        if stderr:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Error: %s." % str(stderr))
        for pid_line in stdout.split(os.linesep):
            if len(pid_line.strip().split()) > 2:
                pid = pid_line.strip().split()[1]
                if pid.isdigit():
                    pids.append(str(pid))
        return pids

    @staticmethod
    def clear_ssh_id_rsa(mpprcfile, logger=""):
        """
        :param mpprcfile:
        :param logger:
        :return:
        """
        clear_cmd = "source %s;%s;/usr/bin/ssh-add -D" % (mpprcfile, SYSTEM_SSH_ENV)
        status, output = subprocess.getstatusoutput(clear_cmd)
        if status != 0:
            if logger:
                logger.error("Failed to clear id_rsa in ssh-agent,Errors:%s" % output)
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "clear ssh agent"
                + " Error:\n%s" % (output))
        if logger:
            logger.debug("Successfully to clear id_rsa in ssh-agent")

    @staticmethod
    def add_ssh_id_rsa(secret_word, mpprcfile, shell_file, logger=""):
        """
        :param secret_word:
        :param mpprcfile:
        :param logger:
        :return:
        """
        DefaultValue.clear_ssh_id_rsa(mpprcfile, logger)
        id_rsa_path = DefaultValue.SSH_PRIVATE_KEY
        cmd = "source %s;%s;echo \"%s\" | /bin/sh %s %s" %(
            mpprcfile, SYSTEM_SSH_ENV, str(secret_word), shell_file, id_rsa_path)
        if logger:
            logger.debug("ssh-add cmd:%s" %cmd)
        (status, stdout, stderr) = DefaultValue.try_fast_popen(cmd)
        output = stdout + stderr
        if logger:
            logger.debug("add ssh id_rsa status:%s" %status)
            logger.debug("add ssh id_rsa output:%s" %output)
        if status != 0:
            raise Exception("Failed to ssh-add perform.Error: %s" % output)
        if logger:
            logger.debug("Successfully to add id_rsa in ssh-agent")


    @staticmethod
    def register_ssh_agent(mpprcfile, logger=""):
        """
        function : register ssh agent
        input : NA
        output : NA
        """
        if logger:
            logger.debug("Start to register ssh agent.")
        agent_path = os.path.join("~/gaussdb_tmp/", "gauss_socket_tmp")
        agent_path = os.path.expanduser(agent_path)
        cmd = "ssh-agent -a %s" % (agent_path)
        cmd_ssh_add = "source %s;%s;ssh-agent -a %s" % (mpprcfile, SYSTEM_SSH_ENV, agent_path)
        list_pid = DefaultValue.get_pid(cmd)
        if not list_pid:
            if os.path.exists(agent_path):
                os.remove(agent_path)
        status, output = subprocess.getstatusoutput(cmd_ssh_add)
        if status != 0 and "Address already in use" not in output:
            if logger:
                logger.error("cms is: %s;Errors:%s" % (cmd_ssh_add, output))
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "register ssh agent"
                + "cmd is:%s;Error:\n%s" % (cmd_ssh_add, output))
        bashrc_file = os.path.join(pwd.getpwuid(os.getuid()).pw_dir,
                                   ".bashrc")
        ProfileFile.updateUserEnvVariable(bashrc_file, "SSH_AUTH_SOCK", agent_path)
        if logger:
            logger.debug("Update environment value SSH_AUTH_SOCK successfully.")
        update_pid_env_flag = False
        list_pid = DefaultValue.get_pid(cmd)
        if not list_pid:
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "register ssh agent"
                + " Error:\nCan't find the process of ssh agent")
        for pid in list_pid:
            if str(pid):
                ProfileFile.updateUserEnvVariable(bashrc_file, "SSH_AGENT_PID",
                                                   str(pid))
                if logger:
                    logger.debug("Update environment value SSH_AGENT_PID successfully.")
                update_pid_env_flag = True
                break
        if not update_pid_env_flag:
            raise Exception(
                ErrorCode.GAUSS_518["GAUSS_51804"] % "SSH_AGENT_PID")
        DefaultValue.check_use_ssh_agent(cmd, bashrc_file, logger)
        if logger:
            logger.debug("ssh-add perform successfully.")

    @staticmethod
    def check_use_ssh_agent(cmd, mpprcfile, logger="", retry_imes=6):
        """
        function:check whether the ssh-agent process is available
        :param cmd:
        :param logger:
        :param retryTimes:
        :return:
        """
        RETRY_TIMES = 0
        while True:
            check_cmd = "source %s;%s;ssh-add -D" % (mpprcfile, SYSTEM_SSH_ENV)
            proc = FastPopen(check_cmd, stdout=PIPE, stderr=PIPE,
                             preexec_fn=os.setsid, close_fds=True)
            stdout, stderr = proc.communicate()
            output = stdout + stderr
            status = proc.returncode
            if status == 0:
                if logger:
                    logger.debug("The ssh-agent process is available")
                break
            if logger:
                logger.debug("ssh-add -D status:%s" %status)
                logger.debug("ssh-add -D output:%s" %output)
            if RETRY_TIMES >= retry_imes:
                if logger:
                    logger.error("Failed to check whether  thessh-agent "
                                 "process is available")
                raise Exception((ErrorCode.GAUSS_535["GAUSS_53507"] % check_cmd)
                                + "Errors:%s" %output)
            DefaultValue.eval_ssh_agent(cmd, mpprcfile, logger)
            time.sleep(2)
            RETRY_TIMES += 1

    @staticmethod
    def eval_ssh_agent(cmd, mpprcfile, logger):
        """
        eval ssh-agent process and ensure that there is only one ssh-agent
        working process
        :param list_pid:
        :return:
        """
        err_msg = ErrorCode.GAUSS_511["GAUSS_51108"]
        try:
            ssh_agent = "ssh-agent"
            list_agent_pid = DefaultValue.get_pid("ssh-agent")
            list_pid = DefaultValue.get_pid(cmd)
            if list_pid and list_agent_pid and len(list_agent_pid) > 1:
                kill_cmd = "ps ux|grep '%s'|grep -v '%s'|grep -v grep |" \
                           " awk '{print $2}'| xargs kill -9" % (ssh_agent, cmd)
                status, output = subprocess.getstatusoutput(kill_cmd)
                if status != 0:
                    if logger:
                        logger.error(
                            (ErrorCode.GAUSS_535["GAUSS_53507"] % kill_cmd)
                            + "Errors:%s" % output)
                    raise Exception(
                        (ErrorCode.GAUSS_535["GAUSS_53507"] % kill_cmd)
                        + "Errors:%s" % output)
            eval_ssh_agent = "source %s;eval `ssh-agent -s`" % mpprcfile
            (status, stdout, stderr) = DefaultValue.try_fast_popen(eval_ssh_agent)
            output = stdout + stderr
            if logger:
                logger.debug("eval_ssh_agent status:%s" % status)
                logger.debug("eval_ssh_agent output:%s" % output)
            if status != 0:
                raise Exception(
                    (ErrorCode.GAUSS_535["GAUSS_53507"] % eval_ssh_agent)
                    + "Errors:%s" % output)
            if logger:
                logger.debug("Successfully to eval ssh agent")
        except Exception as e:
            raise Exception("%s %s" % (err_msg, str(e)))

    @staticmethod
    def register_remote_ssh_agent(session, remote_ip, logger=""):
        """
        function : register ssh agent
        input : NA
        output : NA
        """
        if logger:
            logger.debug("Start to register ssh agent on [%s] node." % remote_ip)
        agent_path = os.path.join("~/gaussdb_tmp/", "gauss_socket_tmp")
        agent_path = os.path.expanduser(agent_path)
        kill_ssh_agent_cmd = "ps ux|grep 'ssh-agent'|grep -v grep |" \
                             " awk '{print $2}'| xargs kill -9"
        DefaultValue.kill_remote_process(session, kill_ssh_agent_cmd, logger)
        DefaultValue.add_remote_ssh_agent(session, agent_path, logger)
        if logger:
            logger.debug("ssh-add perform successfully on [%s] node ." % remote_ip)

    @staticmethod
    def add_remot_ssh_id_rsa(session, secret_word, mpprcfile, shell_file, logger=""):
        """
        :param session:
        :param secret_word:
        :param mpprcfile:
        :param shell_file:
        :param logger:
        :return:
        """
        clear_cmd = "%s;/usr/bin/ssh-add -D" % SYSTEM_SSH_ENV
        (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, clear_cmd)
        if env_msg and "All identities removed" not in env_msg:
            if logger:
                logger.error(
                    "Failed to clear id_rsa in ssh-agent,Errors:%s" % env_msg)
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "clear ssh agent"
                + " Error:\n%s" % (env_msg))
        if logger:
            logger.debug("Successfully to clear id_rsa in ssh-agent")

        id_rsa_path = DefaultValue.SSH_PRIVATE_KEY
        cmd = "source %s;echo \"%s\" | /bin/sh %s %s" % (
            mpprcfile, str(secret_word), shell_file, id_rsa_path)
        if logger:
            logger.debug("ssh-add cmd:%s" % cmd)
        (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, cmd)
        if env_msg:
            logger.debug("add ssh id_rsa output:%s" % env_msg)
            raise Exception("Failed to ssh-add perform.Error: %s" % env_msg)
        if logger:
            logger.debug("add ssh id_rsa output:%s" % channel_read)
            logger.debug("Successfully to add id_rsa in ssh-agent")

    @staticmethod
    def kill_remote_process(session, kill_cmd, logger=""):
        """
        :param ssh_agent:
        :return:
        """
        (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, kill_cmd)
        if logger:
            logger.debug("cmd is %s; result is:%s;error is:%s."
                         % (kill_cmd, channel_read, env_msg))

    @staticmethod
    def add_remote_ssh_agent(session, agent_path, logger=""):
        """
        :param session:
        :param agent_path:
        :param logger:
        :return:
        """
        delete_cmd = "rm -rf %s" % agent_path
        DefaultValue.ssh_exec_cmd(session, delete_cmd)
        cmd = "ssh-agent -a %s" % agent_path
        cmd_ssh_add = "source %s;%s;ssh-agent -a %s" % (ClusterConstants.ETC_PROFILE, SYSTEM_SSH_ENV, agent_path)
        (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, cmd_ssh_add)
        if env_msg and "Address already in use" not in env_msg:
            if logger:
                logger.error("cms is: %s;Errors:%s" % (cmd_ssh_add, env_msg))
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "register remote ssh agent"
                + "cmd is:%s;Error:\n%s" % (cmd_ssh_add, env_msg))
        bashrc_file = os.path.join(pwd.getpwuid(os.getuid()).pw_dir,
                                   ".bashrc")
        DefaultValue.update_user_env_variable_cmd(
            session, bashrc_file, "SSH_AUTH_SOCK", agent_path, logger)
        if logger:
            logger.debug("Update environment value SSH_AUTH_SOCK successfully.")

        list_pid = DefaultValue.get_remote_pid(session, cmd, logger)
        if not list_pid:
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "register ssh agent"
                + " Error:\nCan't find the process of ssh agent")
        update_pid_env_flag = False
        for pid in list_pid:
            if str(pid):
                DefaultValue.update_user_env_variable_cmd(
                    session, bashrc_file, "SSH_AGENT_PID", str(pid), logger)
                if logger:
                    logger.debug("Update environment value SSH_AGENT_PID successfully.")
                update_pid_env_flag = True
                break
        if not update_pid_env_flag:
            raise Exception(
                ErrorCode.GAUSS_518["GAUSS_51804"] % "SSH_AGENT_PID")
        DefaultValue.eval_remote_ssh_agent(session, cmd, bashrc_file, logger)


    @staticmethod
    def update_user_env_variable_cmd(session, userProfile, variable, value, logger=""):
        """
        function : Update the user environment variable
        input : String,String,String
        output : NA
        :param session:
        :param userProfile:
        :param variable:
        :param value:
        :param logger:
        :return:
        """
        try:
            # delete old env information
            delete_content = "^\\s*export\\s*%s=.*$" % variable
            delete_line_cmd = "sed -i '/%s/d' %s" % (delete_content, userProfile)
            # write the new env information into userProfile
            write_content = 'export %s=%s' % (variable, value)
            write_line_cmd = "sed -i '$a%s' %s" % (write_content, userProfile)
            update_cmd = "%s && %s" % (delete_line_cmd, write_line_cmd)
            (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, update_cmd)
            if env_msg:
                if logger:
                    logger.error(
                        "cms is: %s;Errors:%s" % (update_cmd, env_msg))
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51632"] % "update env file;"
                    + "cmd is:%s;Error:\n%s." % (update_cmd, env_msg))

        except Exception as e:
            raise Exception(str(e))


    @staticmethod
    def get_remote_pid(session, process, logger=""):
        """
        function : get the ID of the process
                that contains the specified content
        input : string
        output : list
        """
        pids = []
        cmd = "ps ux | grep '%s' | grep -v grep" % process
        (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, cmd)
        if env_msg:
            if logger:
                logger.error("cms is: %s;Errors:%s" % (cmd, env_msg))
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            "Error: %s." % str(env_msg))
        for pid_line in channel_read.split(os.linesep):
            if len(pid_line.strip().split()) > 2:
                pid = pid_line.strip().split()[1]
                if pid.isdigit():
                    pids.append(str(pid))
        return pids

    @staticmethod
    def eval_remote_ssh_agent(session, cmd, mpprcfile, logger):
        """
        eval remote ssh-agent process and ensure that there is only one ssh-agent
        working process
        :param list_pid:
        :return:
        """
        err_msg = ErrorCode.GAUSS_511["GAUSS_51108"]
        try:
            ssh_agent = "ssh-agent"
            list_agent_pid = DefaultValue.get_pid("ssh-agent")
            list_pid = DefaultValue.get_remote_pid(session, cmd, logger)
            if list_pid and list_agent_pid and len(list_agent_pid) > 1:
                kill_cmd = "ps ux|grep '%s'|grep -v '%s'|grep -v grep |" \
                           " awk '{print $2}'| xargs kill -9" % (ssh_agent, cmd)
                DefaultValue.kill_remote_process(session, kill_cmd, logger)
            eval_ssh_agent = "source %s;eval `ssh-agent -s`" % mpprcfile
            (env_msg, channel_read) = DefaultValue.ssh_exec_cmd(session, eval_ssh_agent)
            if env_msg:
                raise Exception(
                    (ErrorCode.GAUSS_535["GAUSS_53507"] % eval_ssh_agent)
                    + "Errors:%s" % env_msg)
            if logger:
                logger.debug("eval_ssh_agent output:%s" % channel_read)
            if logger:
                logger.debug("Successfully to eval ssh agent")
        except Exception as e:
            raise Exception("%s %s" % (err_msg, str(e)))

    @staticmethod
    def ssh_exec_cmd(session, cmd):
        '''
        ssh remote node and execute cmd
        :param session:
        :param cmd:
        :return:
        '''
        # make sure no echo
        ssh_channel = session.open_session()
        ssh_channel.exec_command(cmd)
        env_msg = ssh_channel.recv_stderr(9999).decode().strip()
        channel_read = ssh_channel.recv(9999).decode().strip()
        return env_msg, channel_read

    @staticmethod
    def remove_metadata_and_dynamic_config_file(user, ssh_tool, logger):
        """
        Remove CM metadata directory and dynamic_config file,
        because of CM need flush dcc value.
        """
        logger.debug("Start remove CM metadata directory and dynamic_config_file.")
        # This cluster info is new cluster info.
        cluster_info = dbClusterInfo()
        cluster_info.initFromStaticConfig(user)
        cluster_dynamic_config = os.path.realpath(os.path.join(cluster_info.appPath,
                                                               "bin", "cluster_dynamic_config"))
        for node in cluster_info.dbNodes:
            cm_meta_data = \
                os.path.realpath(os.path.join(os.path.dirname(node.cmagents[0].datadir),
                                              "dcf_data", "metadata"))
            rm_meta_data_cmd = g_file.SHELL_CMD_DICT["deleteDir"] % (cm_meta_data, cm_meta_data)
            rm_dynamic_cmd = g_file.SHELL_CMD_DICT["deleteFile"] % (cluster_dynamic_config,
                                                                    cluster_dynamic_config)
            perform_cmd = "{0} && {1}".format(rm_dynamic_cmd, rm_meta_data_cmd)
            CmdExecutor.execCommandWithMode(perform_cmd, ssh_tool, host_list=[node.name])
            logger.debug("Remove dynamic_config_file and CM metadata directory "
                         "on node [{0}] successfully.".format(node.name))
        logger.log("Remove dynamic_config_file and CM metadata directory on all nodes.")

    @staticmethod
    def distribute_file_to_node(params):
        """
        Distribute file to dest node with path
        """
        dest_ip, from_path, to_path, timeout = params
        pscp_cmd = "source %s ; pscp -t %s -H %s %s %s" % (
            EnvUtil.getMpprcFile(), timeout, dest_ip, from_path, to_path)
        status, output = CmdUtil.getstatusoutput_by_fast_popen(pscp_cmd)
        return status, output, dest_ip

    @staticmethod
    def check_is_cm_cluster(logger):
        """
        Check cm_ctl is exist.
        """
        cmd = "source %s; cm_ctl view | grep cmDataPath" % EnvUtil.getMpprcFile()
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            logger.debug("Check cm_ctl is failed msg: %s." % output)
            return False
        logger.debug("Successfully check cm_ctl is available.")
        return True

    @staticmethod
    def is_disaster_cluster(clusterinfo):
        """
        function: determine cluster status normal or disaster
        input: NA
        output: NA
        """
        cmd = "source %s; cm_ctl view | grep cmDataPath | awk -F [:] '{print $2}' | head -n 1" % \
              EnvUtil.getMpprcFile()
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise Exception(ErrorCode.GAUSS_514['GAUSS_51400'] % cmd + "Error:\n%s" % stderr)
        cm_agent_conf_file = stdout.strip() + "/cm_agent/cm_agent.conf"
        if not os.path.isfile(cm_agent_conf_file):
            host_list = clusterinfo.getClusterNodeNames()
            cm_agent_conf_temp_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "cm_agent_tmp.conf")
            for host_ip in host_list:
                get_file_cmd = g_file.SHELL_CMD_DICT["scpFileFromRemote"] % \
                  (host_ip, NetUtil.GetHostIpOrName(), cm_agent_conf_file, cm_agent_conf_temp_file)
                proc = FastPopen(get_file_cmd, stdout=PIPE, stderr=PIPE)
                stdout, stderr = proc.communicate()
                if not os.path.isfile(cm_agent_conf_temp_file):
                    continue
                else:
                    break
            if os.path.isfile(cm_agent_conf_temp_file):
                with open(cm_agent_conf_temp_file, "r") as cma_conf_file:
                    content = cma_conf_file.read()
                    ret = re.findall(r'agent_backup_open *= *1|agent_backup_open *= *2', content)
                    g_file.removeFile(cm_agent_conf_temp_file)
                    if ret:
                        return True
                    else:
                        return False
            else:
                raise Exception(ErrorCode.GAUSS_502['GAUSS_50201'] % cm_agent_conf_file)
        with open(cm_agent_conf_file, "r") as cma_conf_file:
            content = cma_conf_file.read()
            ret = re.findall(r'agent_backup_open *= *1|agent_backup_open *= *2', content)
        if ret:
            return True
        else:
            return False

    @staticmethod
    def cm_exist_and_is_disaster_cluster(clusterinfo, logger):
        """
        check current cluster cm exist and is disaster cluster.
        """
        cm_exist = DefaultValue.check_is_cm_cluster(logger)
        if not cm_exist:
            return False
        is_disaster = DefaultValue.is_disaster_cluster(clusterinfo)
        if not is_disaster:
            return False
        return True

    @staticmethod
    def write_content_on_file(dest_file, content, authority=None):
        """
        Write content on file
        """
        authority = authority if authority else DefaultValue.KEY_FILE_MODE_IN_OS
        with os.fdopen(os.open(dest_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                               authority), "w") as fp_write:
            fp_write.write(str(content))

    @staticmethod
    def get_data_ip_info(instance, logger):
        """
        Obtain data ip from file or cluster instance.
        """
        cluster_conf_record = os.path.join(EnvUtil.getEnv("PGHOST"),
                                           "streaming_cabin/cluster_conf_record")
        if not os.path.isfile(cluster_conf_record):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % cluster_conf_record)
        with open(cluster_conf_record, 'r') as read_fp:
            conf_dict = json.load(read_fp)
        if not conf_dict or len(conf_dict) != 2:
            logger.debug("Failed obtain data ip list.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "check data ip file")
        inst_data_ip = ""
        local_shards_list = conf_dict["localClusterConf"]["shards"]
        for shard_list in local_shards_list:
            for shard in shard_list:
                if shard["ip"] not in instance.listenIps:
                    continue
                inst_data_ip = shard["dataIp"]
        logger.debug("File record:%s, \nGot data ip:%s for instanceId:%s." %
                     (conf_dict, inst_data_ip, instance.instanceId))
        if not inst_data_ip:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain local data ip")
        return inst_data_ip

    @staticmethod
    def obtain_hadr_user_encrypt_str(cluster_info, db_user, logger, mode, ignore_res=False):
        """
        Obtain hadr user encrypted string
        """
        sql = "select value from gs_global_config where name='hadr_user_info';"
        instances = []
        for node in cluster_info.dbNodes:
            if cluster_info.isSingleInstCluster():
                for inst in node.datanodes:
                    instances.append(inst)
        for inst in instances:
            logger.debug("Obtain hadr user info string on node:%s with port:%s."
                         % (inst.hostname, inst.port))
            status, output = ClusterCommand.remoteSQLCommand(sql, db_user, inst.hostname,
                                                             inst.port, maintenance_mode=mode)
            if status == 0 and output:
                logger.debug("Successfully obtain hadr user info string.")
                return output
        if ignore_res:
            return
        logger.debug("Failed obtain hadr user info string.")
        raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "obtain hadr user info")

    @staticmethod
    def getstatusoutput_hide_pass(joint_cmd):
        """
        Hide password of process
        """
        proc = Popen(["sh", "-"], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate(joint_cmd)
        text = stderr or stdout
        sts = proc.returncode
        if sts is None:
            sts = 0
        if text and text[-1:] == '\n':
            text = text[:-1]
        return sts, text

    @staticmethod
    def decrypt_hadr_user_info(params):
        """
        Decrypt hadr user info
        """
        if len(params) != 6:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50000"] % "decrypt hadr user info")
        rand_pwd, hadr_str, cluster_info, db_user, logger, mode = params
        sql = "select pg_catalog.gs_decrypt_aes128('%s', '%s');" % (hadr_str, rand_pwd)
        instances = []
        for node in cluster_info.dbNodes:
            if cluster_info.isSingleInstCluster():
                for inst in node.datanodes:
                    instances.append(inst)
            else:
                for inst in node.coordinators:
                    instances.append(inst)
        for inst in instances:
            logger.debug("Decrypt hadr user info on node:%s with port:%s."
                         % (inst.hostname, inst.port))
            status, output = ClusterCommand.remoteSQLCommand(sql, db_user, inst.hostname,
                                                             inst.port, maintenance_mode=mode)
            if status == 0 and output and "|" in output and len(output.split("|")) == 2:
                logger.debug("Successfully decrypt hadr user info string.")
                hadr_user, hadr_pwd = output.strip().split("|")[0], output.strip().split("|")[1]
                return hadr_user, hadr_pwd
        logger.debug("Failed decrypt hadr user info string.")
        raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] % "decrypt hadr user info")

    @staticmethod
    def decrypt_hadr_rand_pwd(logger):
        """
        Decrypt hadr rand pwd
        """
        db_user = pwd.getpwuid(os.getuid()).pw_name
        gauss_home = ClusterDir.getInstallDir(db_user)
        bin_path = os.path.join(os.path.realpath(gauss_home), "bin")
        if not bin_path:
            logger.debug("Failed obtain bin path.")
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "bin path")
        cipher_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "binary_upgrade/hadr.key.cipher")
        rand_file = os.path.join(EnvUtil.getTmpDirFromEnv(), "binary_upgrade/hadr.key.rand")
        if os.path.isfile(cipher_file) and os.path.isfile(rand_file):
            bin_path = os.path.join(EnvUtil.getTmpDirFromEnv(), "binary_upgrade")
        rand_pwd = AesCbcUtil.aes_cbc_decrypt_with_path(bin_path, bin_path, key_name="hadr")
        if rand_pwd:
            logger.debug("Successfully decrypt rand pwd.")
            return rand_pwd

    @staticmethod
    def get_proc_title(pwd_para_name):
        """
        Obtain the process name after sensitive information is hidden.
        """
        cmd = "cat /proc/%s/cmdline" % os.getpid()
        status, output = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0 or not output:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % "proc title" + " Cmd is:%s." % cmd)
        title_str_list = []
        for title_str in output.split("\0"):
            if "=" in title_str:
                title_str_list.extend(title_str.split("="))
            else:
                title_str_list.extend(title_str.split(" "))
        if pwd_para_name in title_str_list:
            w_index = title_str_list.index(pwd_para_name)
            title_str_list[w_index], title_str_list[w_index + 1] = "", ""
        title_name = " ".join(title_str_list).strip()
        return title_name

    @staticmethod
    def set_proc_title(name):
        """
        set proc title to new name
        """
        new_name = name.encode('ascii', 'replace')
        try:
            libc = ctypes.CDLL('libc.so.6')
            proc_name = ctypes.c_char_p.in_dll(libc, '__progname_full')
            with open('/proc/self/cmdline') as fp:
                old_progname_len = len(fp.readline())
            if old_progname_len > len(new_name):
                # padding blank chars
                new_name += b' ' * (old_progname_len - len(new_name))
                # Environment variables are already copied to Python app zone.
                # We can get environment variables by `os.environ` module,
                # so we can ignore the destroying from the following action.
                libc.strcpy(proc_name, ctypes.c_char_p(new_name))
                buff = ctypes.create_string_buffer(len(new_name) + 1)
                buff.value = new_name
                libc.prctl(15, ctypes.byref(buff), 0, 0, 0)
        except Exception as err_msg:
            raise Exception(ErrorCode.GAUSS_505["GAUSS_50503"] + str(err_msg))

    @staticmethod
    def check_is_streaming_dr_cluster():
        """check_is_steaming_cluster_cluster"""
        stream_file = os.path.realpath(os.path.join(EnvUtil.getEnv("PGHOST"), "streaming_cabin"))
        if os.path.exists(stream_file):
            sys.exit(ErrorCode.GAUSS_512["GAUSS_51244"] % "current operate on dr cluster")

    @staticmethod
    def get_primary_dn_instance_id(inst_status="Primary", ignore=False):
        """
        function: get Primary/Standby dn instance id for centralized/distribute cluster
        :param: inst_status Primary/Standby
        return; instance id
        """
        cmd = r"source %s; cm_ctl query -v | grep -E 'instance_state\ *:\ %s' " \
              r"-B 4 | grep -E 'type\ *:\ Datanode' -B 5 | grep instance_id | awk " \
              r"'{print $NF}'" % (EnvUtil.getMpprcFile(), inst_status)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0 or not output:
            if ignore is True:
                return []
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            cmd + " Error: \n%s" % output)
        return output.strip().split('\n')

    @staticmethod
    def isgreyUpgradeNodeSpecify(user, step=-1, nodes=None, logger=None):
        """
        step = -1 means we just check if step in all the specified nodes is the
        same otherwise, we check if all the specified nodes is the given step
        """
        try:
            if nodes:
                logger.debug(
                    "check if the nodes %s step is %s " % (nodes, step))
            else:
                logger.debug(
                    "check if all the nodes step is %s" % step)
                # This cluster info is new cluster info.
                clusterNodes = []
                cluster_info = dbClusterInfo()
                cluster_info.initFromStaticConfig(user)
                for dbNode in cluster_info.dbNodes:
                    clusterNodes.append(dbNode.name)
                nodes = copy.deepcopy(clusterNodes)
            
            logger.debug(
                "IsgreyUpgradeNodeSpecify: all the nodes is %s" % nodes)
            
            # upgrade backup path
            tmpDir = EnvUtil.getTmpDirFromEnv(user)
            if tmpDir == "":
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$PGHOST")
            upgradeBackupPath = "%s/%s" % (tmpDir, "binary_upgrade")
            stepFile = os.path.join(upgradeBackupPath, "upgrade_step.csv")
            if not os.path.isfile(stepFile):
                logger.debug(
                    "No step file, which means not in upgrade occasion or "
                    "node %s step is same" % nodes)
                return True

            with open(stepFile, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row['node_host'] in nodes:
                        if step == -1:
                            step = int(row['step'])
                        else:
                            if step <= int(row['step']):
                                continue
                            else:
                                logger.debug("The nodes %s step is not all %s"
                                % (nodes, step))
                                return False
                logger.debug("The nodes %s step is all %s" %  (nodes, step))
            return True
        except Exception as e:
            # failed to read the upgrade_step.csv in isgreyUpgradeNodeSpecify
            logger.logExit(str(e))

class ClusterCommand():
    '''
    Common for cluster command
    '''

    def __init__(self):
        pass

    # gs_sshexkey execution takes total steps
    TOTAL_STEPS_SSHEXKEY = 11
    # gs_preinstall -L execution takes total steps
    TOTAL_STEPS_PREINSTALL_L = 14
    # gs_preinstall execution takes total steps
    TOTAL_STEPS_PREINSTALL = 17
    # gs_install execution takes total steps
    TOTAL_STEPS_INSTALL = 7
    # gs_om -t managecn -m add execution takes total steps
    TOTAL_STEPS_OM_ADD = 20
    # gs_om -t managecn -m delete execution takes total steps
    TOTAL_STEPS_OM_DELETE = 16
    # gs_om -t changeip execution takes total steps
    TOTAL_STEPS_OM_CHANGEIP = 11
    # gs_expand -t dilatation execution takes total steps
    TOTAL_STEPS_EXPAND_DILA = 17
    # gs_expand -t redistribute execution takes total steps
    TOTAL_STEPS_EXPAND_REDIS = 6
    # gs_shrink -t entry1_percontraction execution takes total steps
    TOTAL_STEPS_SHRINK_FIRST = 9
    # gs_shrink -t entry2_redistributre execution takes total steps
    TOTAL_STEPS_SHRINK_SECOND = 8
    # gs_shrink -t entry3_postcontraction execution takes total steps
    TOTAL_STEPS_SHRINK_THIRD = 7
    # gs_replace -t warm-standby execution takes total steps
    TOTAL_STEPS_REPLACE_WARM_STANDBY = 11
    # gs_replace -t warm-standby rollback replace execution takes total steps
    TOTAL_STEPS_REPLACE_WARM_STANDBY_REPLACE = 9
    # gs_replace -t warm-standby rollback install execution takes total steps
    TOTAL_STEPS_REPLACE_WARM_STANDBY_INSTALL = 7
    # gs_replace -t warm-standby rollback config execution takes total steps
    TOTAL_STEPS_REPLACE_WARM_STANDBY_CONFIG = 6
    # gs_replace -t install execution takes total steps
    TOTAL_STEPS_REPLACE_INSTALL = 6
    # gs_replace -t config execution takes total steps
    TOTAL_STEPS_REPLACE_CONFIG = 6
    # gs_replace -t start execution takes total steps
    TOTAL_STEPS_REPLACE_START = 3
    # gs_uninstall execution takes total steps
    TOTAL_STEPS_UNINSTALL = 8
    # gs_upgradectl -t auto-upgrade execution takes total steps
    TOTAL_STEPS_GREY_UPGRADECTL = 12
    # gs_upgradectl -t auto-upgrade --inplace execution takes total steps
    TOTAL_STEPS_INPLACE_UPGRADECTL = 15
    # gs_postuninstall execution takes total steps
    TOTAL_STEPS_POSTUNINSTALL = 3
    # warm-standby rollback to flag of begin warm standby
    WARM_STEP_INIT = "Begin warm standby"
    # warm-standby rollback to flag of replace IP finished
    WARM_STEP_REPLACEIPS = "Replace IP finished"
    # warm-standby rollback to flag of install warm standby nodes finished
    WARM_STEP_INSTALL = "Install warm standby nodes finished"
    # warm-standby rollback to flag of configure warm standby nodes finished
    WARM_STEP_CONFIG = "Configure warm standby nodes finished"
    # rollback to flag of start cluster
    INSTALL_STEP_CONFIG = "Config cluster"
    # rollback to flag of start cluster
    INSTALL_STEP_START = "Start cluster"

    @staticmethod
    def getStartCmd(nodeId=0, timeout=DefaultValue.TIMEOUT_CLUSTER_START, datadir="", azName = ""):
        """
        function : Start all cluster or a node
        input : String,int,String,String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "%s %s ; cm_ctl start" % (CmdUtil.SOURCE_CMD, user_profile)
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

    @staticmethod
    def getStopCmd(nodeId=0, stopMode="", timeout=0, datadir="", azName = ""):
        """
        function : Stop all cluster or a node
        iinput : String,int,String,String
        output : String
        """
        userProfile = EnvUtil.getMpprcFile()
        cmd = "%s %s ; cm_ctl stop" % (CmdUtil.SOURCE_CMD, userProfile)
        # check node id
        if nodeId > 0:
            cmd += " -n %d" % nodeId
        # check data directory
        if datadir != "":
            cmd += " -D %s" % datadir
        # check stop mode
        if stopMode != "":
            cmd += " -m %s" % stopMode
        # check timeout
        if timeout > 0:
            cmd += " -t %d" % timeout
        # azName
        if azName != "":
            cmd += " -z%s" % azName

        return cmd


    @staticmethod
    def getQueryStatusCmdForDisplay(nodeId=0, outFile="",
                                    clusterType="",
                                    showDetail=True,
                                    showAll=True):
        """
        function : Get the command of querying status of cluster or node
        input : String
        output : String
        """
        user_profile = EnvUtil.getMpprcFile()
        cmd = "%s %s ; cm_ctl query" % (CmdUtil.SOURCE_CMD, user_profile)
        # check node id
        if nodeId > 0:
            cmd += " -v -n %d" % nodeId
        # check -v
        if showDetail:
            if (clusterType ==
                    DefaultValue.CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY):
                cmd += " -v -C -i -d -z ALL"
            else:
                cmd += " -v -C -i -d"
        else:
            if showAll:
                cmd += " -v"

        # check out put file
        if outFile != "":
            cmd += " > %s" % outFile
        return cmd

    @staticmethod
    def getQueryStatusCmd(hostName="", outFile="", showAll=True):
        """
        function : Get the command of querying status of cluster or node
        input : String
        output : String
        """
        userProfile = EnvUtil.getMpprcFile()
        cmd = "%s %s ; gs_om -t status" % (CmdUtil.SOURCE_CMD,
                                           userProfile)
        # check node id
        if (hostName != ""):
            cmd += " -h %s" % hostName
        else:
            if (showAll):
                cmd += " --all"
        # check out put file
        if (outFile != ""):
            cmd += " > %s" % outFile

        return cmd


    @staticmethod
    def execSQLCommand(sql, user, host, port, database="postgres",
                       option="", IsInplaceUpgrade=False):
        """
        function : Execute sql command
        input : String,String,String,int
        output : String
        """
        database = database.replace('$', '\$')
        currentTime = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S%f")
        pid = os.getpid()
        # init SQL query file
        sqlFile = os.path.join(
            EnvUtil.getTmpDirFromEnv(user),
            "gaussdb_query.sql_%s_%s_%s" % (str(port), str(currentTime),
                                            str(pid)))
        # init SQL result file
        queryResultFile = os.path.join(
            EnvUtil.getTmpDirFromEnv(user),
            "gaussdb_result.sql_%s_%s_%s" % (str(port), str(currentTime),
                                             str(pid)))
        if os.path.exists(sqlFile) or os.path.exists(queryResultFile):
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
        # create an empty sql query file
        try:
            FileUtil.createFile(sqlFile, True, DefaultValue.KEY_FILE_MODE)
        except Exception as e:
            if os.path.exists(sqlFile):
                os.remove(sqlFile)
            return 1, str(e)

        # witer the SQL command into sql query file
        try:
            FileUtil.createFileInSafeMode(sqlFile)
            with open(sqlFile, 'w') as fp:
                fp.writelines(sql)
        except Exception as e:
            LocalRemoteCmd.cleanFile(sqlFile)
            return 1, str(e)
        try:
            # init hostPara
            userProfile = EnvUtil.getMpprcFile()
            hostPara = ("-h %s" % host) if host != "" else ""
            # build shell command
            # if the user is root, switch the user to execute
            if (IsInplaceUpgrade):
                gsqlCmd = SqlCommands.getSQLCommandForInplaceUpgradeBackup(
                    port, database)
            else:
                gsqlCmd = SqlCommands.getSQLCommand(
                    port, database)
            executeCmd = "%s %s -f '%s' --output '%s' -t -A -X %s" % (
                gsqlCmd, hostPara, sqlFile, queryResultFile, option)
            cmd = CmdUtil.getExecuteCmdWithUserProfile(user, userProfile,
                                                          executeCmd, False)
            (status, output) = subprocess.getstatusoutput(cmd)
            if SqlFile.findErrorInSqlFile(sqlFile, output):
                status = 1
            if (status != 0):
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
                return (status, output)
            # read the content of query result file.
        except Exception as e:
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
            raise Exception(str(e))
        try:
            with open(queryResultFile, 'r') as fp:
                rowList = fp.readlines()
        except Exception as e:
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
            return 1, str(e)

        # remove local sqlFile
        LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))

        return (0, "".join(rowList)[:-1])


    @staticmethod
    def remoteSQLCommand(sql, user, host, port, ignoreError=True,
                         database="postgres", useTid=False,
                         IsInplaceUpgrade=False, maintenance_mode=False,
                         user_name="", user_pwd=""):
        """
        function : Execute sql command on remote host
        input : String,String,String,int
        output : String,String
        """
        database = database.replace('$', '\$')
        currentTime = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S%f")
        pid = os.getpid()
        # clean old sql file
        # init SQL query file
        sqlFile = os.path.join(EnvUtil.getTmpDirFromEnv(user),
                               "gaussdb_remote_query.sql_%s_%s_%s" % (
                                   str(port),
                                   str(currentTime),
                                   str(pid)))
        # init SQL result file
        queryResultFile = os.path.join(EnvUtil.getTmpDirFromEnv(user),
                                       "gaussdb_remote_result.sql_%s_%s_%s" % (
                                           str(port),
                                           str(currentTime),
                                           str(pid)))
        RE_TIMES = 3
        if useTid:
            threadPid = CDLL('libc.so.6').syscall(186)
            sqlFile = sqlFile + str(threadPid)
            queryResultFile = queryResultFile + str(threadPid)
        if (os.path.exists(sqlFile) or os.path.exists(queryResultFile)):
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
        # create new sql file
        if (os.getuid() == 0):
            cmd = "su - %s -c 'touch %s && chmod %s %s'" % (
                user, sqlFile, DefaultValue.KEY_FILE_MODE, sqlFile)
        else:
            cmd = "touch %s && chmod %s %s" % (sqlFile,
                                               DefaultValue.KEY_FILE_MODE,
                                               sqlFile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            output = "%s\n%s" % (cmd, output)
            if (os.path.exists(sqlFile) or os.path.exists(queryResultFile)):
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
            return (status, output)
        # witer the SQL command into sql query file
        try:
            FileUtil.createFileInSafeMode(sqlFile)
            with open(sqlFile, 'w') as fp:
                fp.writelines(sql)
        except Exception as e:
            LocalRemoteCmd.cleanFile(sqlFile)
            return (1, str(e))
        # send new sql file to remote node if needed
        localHost = NetUtil.GetHostIpOrName()
        if str(localHost) != str(host):
            cmd = LocalRemoteCmd.getRemoteCopyCmd(sqlFile, sqlFile, host)
            if os.getuid() == 0 and user != "":
                cmd = "su - %s \"%s\"" % (user, cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
                output = "%s\n%s" % (cmd, output)
                return (status, output)
        # execute sql file
        mpprcFile = EnvUtil.getMpprcFile()
        if IsInplaceUpgrade:
            gsql_cmd = SqlCommands.getSQLCommandForInplaceUpgradeBackup(
                port, database)
        else:
            gsql_cmd = SqlCommands.getSQLCommand(port, database, user_name=user_name,
                                                 user_pwd=user_pwd)
        if maintenance_mode:
            gsql_cmd += " -m "
        if str(localHost) != str(host):
            sshCmd = CmdUtil.getSshCmd(host)
            if os.getuid() == 0 and user != "":
                cmd = " %s 'su - %s -c \"" % (sshCmd, user)
                if mpprcFile != "" and mpprcFile is not None:
                    cmd += "source %s;" % mpprcFile
                cmd += "%s -f %s --output %s -t -A -X \"'" % (gsql_cmd,
                                                              sqlFile,
                                                              queryResultFile)
                if ignoreError:
                    cmd += " 2>/dev/null"
            else:
                cmd = ""
                if mpprcFile != "" and mpprcFile is not None:
                    cmd += "source %s;" % mpprcFile
                cmd += "%s -f %s --output %s -t -A -X " % (gsql_cmd,
                                                            sqlFile,
                                                            queryResultFile)
                if user_pwd:
                    cmd = "echo \"%s\" | %s" % (cmd, sshCmd)
                else:
                    cmd = "%s '%s'" % (sshCmd, cmd)
                if ignoreError:
                    cmd += " 2>/dev/null"
            for i in range(RE_TIMES):
                proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE,
                                 preexec_fn=os.setsid, close_fds=True)
                stdout, stderr = proc.communicate()
                output1 = stdout + stderr
                status1 = proc.returncode
                if SqlFile.findErrorInSqlFile(sqlFile, output1):
                    if SqlFile.findTupleErrorInSqlFile(output1):
                        time.sleep(1)  # find tuple error --> retry
                    else:  # find error not tuple error
                        status1 = 1
                        break
                else:  # not find error
                    break
            # if failed to execute gsql, then clean the sql query file on
            # current node and other node
            if (status1 != 0):
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile),
                                       host)
                return (status1, output1)
        else:
            if (os.getuid() == 0 and user != ""):
                cmd = "su - %s -c \"" % user
                if (mpprcFile != "" and mpprcFile is not None):
                    cmd += "source %s;" % mpprcFile
                cmd += "%s -f %s --output %s -t -A -X \"" % (gsql_cmd,
                                                             sqlFile,
                                                             queryResultFile)
                if (ignoreError):
                    cmd += " 2>/dev/null"
            else:
                cmd = ""
                if (mpprcFile != "" and mpprcFile is not None):
                    cmd += "source %s;" % mpprcFile
                cmd += "%s -f %s --output %s -t -A -X " % (gsql_cmd,
                                                           sqlFile,
                                                           queryResultFile)
                if (ignoreError):
                    cmd += " 2>/dev/null"
            for i in range(RE_TIMES):
                proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE,
                                 preexec_fn=os.setsid, close_fds=True)
                stdout, stderr = proc.communicate()
                output1 = stdout + stderr
                status1 = proc.returncode
                if SqlFile.findErrorInSqlFile(sqlFile, output1):
                    if SqlFile.findTupleErrorInSqlFile(output1):
                        time.sleep(1)  # find tuple error --> retry
                    else:  # find error not tuple error
                        status1 = 1
                        break
                else:  # not find error
                    break
            # if failed to execute gsql, then clean the sql query file
            # on current node and other node
            if (status1 != 0):
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
                return (status1, output1)
        if (str(localHost) != str(host)):
            remoteCmd = LocalRemoteCmd.getRemoteCopyCmd(
                queryResultFile,
                EnvUtil.getTmpDirFromEnv(user) + "/", str(localHost))
            cmd = "%s \"%s\"" % (sshCmd, remoteCmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                output = "%s\n%s" % (cmd, output)
                LocalRemoteCmd.cleanFile(sqlFile)
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile),
                                       host)
                return (status, output)
        # read the content of query result file.
        try:
            with open(queryResultFile, 'r') as fp:
                rowList = fp.readlines()
        except Exception as e:
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
            if (str(localHost) != str(host)):
                LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile),
                                       host)
            return (1, str(e))
        # remove local sqlFile
        LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile))
        # remove remote sqlFile
        if (str(localHost) != str(host)):
            LocalRemoteCmd.cleanFile("%s,%s" % (queryResultFile, sqlFile), host)
        return (0, "".join(rowList)[:-1])

    @staticmethod
    def countTotalSteps(script, act="", model=""):
        """
        function: get script takes steps in total
        input:
            script: command name
            act: the type of command
            model: mode setting
        """
        try:
            totalSteps = 0
            if (script == "gs_preinstall"):
                if model:
                    totalSteps = ClusterCommand.TOTAL_STEPS_PREINSTALL_L
                else:
                    totalSteps = ClusterCommand.TOTAL_STEPS_PREINSTALL
            elif (script == "gs_install"):
                if (model == ClusterCommand.INSTALL_STEP_CONFIG):
                    totalSteps = ClusterCommand.TOTAL_STEPS_INSTALL - 1
                elif (model == ClusterCommand.INSTALL_STEP_START):
                    totalSteps = ClusterCommand.TOTAL_STEPS_INSTALL - 2
                else:
                    totalSteps = ClusterCommand.TOTAL_STEPS_INSTALL
            elif (script == "gs_om"):
                if (act == "managecn"):
                    if (model == "add"):
                        totalSteps = ClusterCommand.TOTAL_STEPS_OM_ADD
                    if (model == "delete"):
                        totalSteps = ClusterCommand.TOTAL_STEPS_OM_DELETE
                if (act == "changeip"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_OM_CHANGEIP
            elif (script == "gs_expand"):
                if (act == "dilatation"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_EXPAND_DILA
                if (act == "redistribute"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_EXPAND_REDIS
            elif (script == "gs_shrink"):
                if (act == "entry1"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_SHRINK_FIRST
                if (act == "entry2"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_SHRINK_SECOND
                if (act == "entry3"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_SHRINK_THIRD
            elif (script == "gs_sshexkey"):
                if model:
                    totalSteps = ClusterCommand.TOTAL_STEPS_SSHEXKEY - 2
                else:
                    totalSteps = ClusterCommand.TOTAL_STEPS_SSHEXKEY
            elif (script == "gs_replace"):
                if (act == "warm-standby"):
                    if (model == ClusterCommand.WARM_STEP_INIT):
                        totalSteps = ClusterCommand. \
                            TOTAL_STEPS_REPLACE_WARM_STANDBY
                    if (model == ClusterCommand.WARM_STEP_REPLACEIPS):
                        totalSteps = ClusterCommand. \
                            TOTAL_STEPS_REPLACE_WARM_STANDBY_REPLACE
                    if (model == ClusterCommand.WARM_STEP_INSTALL):
                        totalSteps = ClusterCommand. \
                            TOTAL_STEPS_REPLACE_WARM_STANDBY_INSTALL
                    if (model == ClusterCommand.WARM_STEP_CONFIG):
                        totalSteps = ClusterCommand. \
                            TOTAL_STEPS_REPLACE_WARM_STANDBY_CONFIG
                if (act == "install"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_REPLACE_INSTALL
                if (act == "config"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_REPLACE_CONFIG
                if (act == "start"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_REPLACE_START
            elif (script == "gs_upgradectl"):
                if (act == "small-binary-upgrade" or act ==
                        "large-binary-upgrade"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_GREY_UPGRADECTL
                if (act == "inplace-binary-upgrade"):
                    totalSteps = ClusterCommand.TOTAL_STEPS_INPLACE_UPGRADECTL
            elif (script == "gs_uninstall"):
                totalSteps = ClusterCommand.TOTAL_STEPS_UNINSTALL
            elif (script == "gs_postuninstall"):
                totalSteps = ClusterCommand.TOTAL_STEPS_POSTUNINSTALL
            return totalSteps
        except Exception as e:
            raise Exception(str(e))


    @staticmethod
    def aes_cbc_encrypt_with_multi(passwd, dest_path, logger):

        # # check if the password contains illegal characters
        PasswordUtil.checkPasswordVaild(passwd)
        # encrypt tool path
        encrypt_path = os.path.realpath("%s/../clib" % os.path.dirname(os.path.realpath(__file__)))
        # encrypt ca path
        encrypt_ca_path = dest_path
        cmd = "export LD_LIBRARY_PATH={encrypt_path}"
        cmd += " && if [ -e {encrypt_ca_path} ];then rm -rf {encrypt_ca_path}/;fi"
        cmd += " && mkdir -p {encrypt_ca_path}/cipher && mkdir -p {encrypt_ca_path}/rand"
        cmd += " && cd {encrypt_path}"
        cmd += " && ./encrypt {passwd} {encrypt_ca_path}/cipher {encrypt_ca_path}/rand"
        cmd = cmd.format(encrypt_path=encrypt_path, passwd=passwd, encrypt_ca_path=encrypt_ca_path)
        status, output = CmdUtil.getstatusoutput_by_fast_popen(cmd)
        if status != 0 and "encrypt success" not in output:
            raise Exception(ErrorCode.GAUSS_511["GAUSS_51103"] % "encrypt ..."
                            + "Error is:%s" % SensitiveMask.mask_pwd(output))
        logger.log("Generate cluster user password files successfully.\n")

    @staticmethod
    def executeSQLOnRemoteHost(hostName, port, sql, outputfile,
                               snapid="defaultNone", database="postgres"):
        """
        function: execute SQL on remote host
        input :hostName, port, sql, outputfile, database
        output: NA
        """
        from gspylib.threads.SshTool import SshTool
        from gspylib.common.OMCommand import OMCommand
        hosts = []
        hosts.append(hostName)
        gs_sshTool = SshTool(hosts)
        currentTime = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S%f")
        pid = os.getpid()
        sqlfile = "%s_%s_%s.sql" % (hostName, pid, currentTime)
        tmpDir = EnvUtil.getTmpDirFromEnv() + "/"
        sqlfilepath = os.path.join(tmpDir, sqlfile)
        FileUtil.createFileInSafeMode(sqlfilepath)
        try:
            with open(sqlfilepath, "w") as fp:
                fp.write(sql)
                fp.flush()

            LocalRemoteCmd.scpFile(hostName, sqlfilepath, tmpDir)
            cmd = "%s  -p %s -S %s -f %s -s %s -d %s" % (
                OMCommand.getLocalScript("Local_Execute_Sql"), port,
                sqlfilepath, outputfile, snapid, database)
            gs_sshTool.executeCommand(cmd)
            cmd = "%s %s" % (CmdUtil.getRemoveCmd("directory"), sqlfilepath)
            (status, output) = subprocess.getstatusoutput(cmd)
        except Exception as e:
            cmd = "%s %s" % (CmdUtil.getRemoveCmd("directory"), sqlfilepath)
            (status, output) = subprocess.getstatusoutput(cmd)
            raise Exception(str(e))

    @staticmethod
    def get_pass_phrase():
        """
        :return:
        """
        encrypt_dir = DefaultValue.get_ssh_protect_path()
        if os.path.isdir(encrypt_dir):
            output = AesCbcUtil.aes_cbc_decrypt_with_multi(*AesCbcUtil.format_path(encrypt_dir))
            if len(str(output).strip().split()) < 1:
                raise Exception(
                    "Decrypt key failed from protect ssh directory.")
            data = str(output).strip().split()[-1]
            return data
        else:
            raise Exception("Get passphrase failed.")


class ClusterInstanceConfig():
    """
    Set Instance Config
    """

    def __init__(self):
        pass

    @staticmethod
    def setConfigItem(typename, datadir, configFile, parmeterDict):
        """
        function: Modify a parameter
        input : typename, datadir, configFile, parmeterDict
        output: NA
        """
        # check mpprc file path
        mpprcFile = EnvUtil.getMpprcFile()

        # comment out any existing entries for this setting
        if (typename == DefaultValue.INSTANCE_ROLE_CMSERVER or typename ==
                DefaultValue.INSTANCE_ROLE_CMAGENT):
            # gs_guc only support for DB instance
            # if the type is cm_server or cm_agent, we will use sed to
            # instead of it
            for entry in parmeterDict.items():
                key = entry[0]
                value = entry[1]
                # delete the old parameter information
                cmd = "sed -i 's/^.*\(%s.*=.*\)/#\\1/g' %s" % (key, configFile)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50008"] +
                                    " Command:%s. Error:\n%s" % (cmd, output))

                # append new config to file
                cmd = 'echo "      " >> %s' % (configFile)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                    " Error: \n%s" % output)

                cmd = 'echo "%s = %s" >> %s' % (key, value, configFile)
                (status, output) = subprocess.getstatusoutput(cmd)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                    " Error: \n%s" % output)
        else:
            # build GUC parameter string
            gucstr = ""
            for entry in parmeterDict.items():
                gucstr += " -c \"%s=%s\"" % (entry[0], entry[1])
            # check the GUC parameter string
            if (gucstr == ""):
                return
            cmd = "source %s; gs_guc set -D %s %s" % \
                  (mpprcFile, datadir, gucstr)
            DefaultValue.retry_gs_guc(cmd)

    @staticmethod
    def setReplConninfo(dbInst, peerInsts, clusterInfo):
        """
        function: Modify replconninfo for datanode
        input : dbInst
        output: NA
        """
        masterInst = None
        standbyInst = None
        dummyStandbyInst = None
        nodename = ""
        # init masterInst, standbyInst and dummyStandbyInst
        for pi in iter(peerInsts):
            if (pi.instanceType == DefaultValue.MASTER_INSTANCE):
                masterInst = pi
            elif (pi.instanceType == DefaultValue.STANDBY_INSTANCE):
                standbyInst = pi
            elif (pi.instanceType ==
                  DefaultValue.DUMMY_STANDBY_INSTANCE):
                dummyStandbyInst = pi

        if (dbInst.instanceType == DefaultValue.MASTER_INSTANCE):
            masterInst = dbInst
            nodename = "dn_%d_%d" % (masterInst.instanceId,
                                     standbyInst.instanceId)
        elif (dbInst.instanceType == DefaultValue.STANDBY_INSTANCE):
            standbyInst = dbInst
            nodename = "dn_%d_%d" % (masterInst.instanceId,
                                     standbyInst.instanceId)
        elif (dbInst.instanceType == DefaultValue.DUMMY_STANDBY_INSTANCE):
            dummyStandbyInst = dbInst
            nodename = "dn_%d_%d" % (masterInst.instanceId,
                                     dummyStandbyInst.instanceId)
        if (len(masterInst.haIps) == 0 or len(standbyInst.haIps) == 0):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51621"] +
                            " Data directory: %s." % dbInst.datadir)
        if (dummyStandbyInst is not None and len(dummyStandbyInst.haIps) == 0):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51621"] +
                            " Data directory: %s." % dbInst.datadir)

        connInfo1 = ""
        connInfo2 = ""
        channelCount = len(masterInst.haIps)
        # get master instance number
        masterDbNode = clusterInfo.getDbNodeByName(masterInst.hostname)
        if masterDbNode is None:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                            ("database node configuration on host [%s]"
                             % masterInst.hostname))
        masterDataNum = masterDbNode.getDnNum(masterInst.instanceType)
        # get standby instance number
        standbyDbNode = clusterInfo.getDbNodeByName(standbyInst.hostname)
        if standbyDbNode is None:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                            ("database node configuration on host [%s]"
                             % standbyInst.hostname))
        standbyDataNum = standbyDbNode.getDnNum(standbyInst.instanceType)
        # get dummy instance number
        if dummyStandbyInst is not None:
            dummyDbNode = clusterInfo.getDbNodeByName(
                dummyStandbyInst.hostname)
            if dummyDbNode is None:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                                ("database node configuration on host [%s]"
                                 % dummyStandbyInst.hostname))
            dummyDataNum = dummyDbNode.getDnNum(dummyStandbyInst.instanceType)
        for i in range(channelCount):
            if (dbInst.instanceType == DefaultValue.MASTER_INSTANCE):
                if (i > 0):
                    connInfo1 += ","
                connInfo1 += "localhost=%s localport=%d localservice=%s " \
                             "remotehost=%s remoteport=%d remoteservice=%s" % \
                             (dbInst.haIps[i], dbInst.haPort,
                              (dbInst.port + masterDataNum * 4),
                              standbyInst.haIps[i],
                              standbyInst.haPort, (standbyInst.port +
                                                   standbyDataNum * 4))
                if dummyStandbyInst is not None:
                    if (i > 0):
                        connInfo2 += ","
                    connInfo2 += "localhost=%s localport=%d localservice=%s " \
                                 "remotehost=%s remoteport=%d " \
                                 "remoteservice=%s" % \
                                 (dbInst.haIps[i], dbInst.haPort,
                                  (dbInst.port + masterDataNum * 4),
                                  dummyStandbyInst.haIps[i],
                                  dummyStandbyInst.haPort,
                                  (dummyStandbyInst.port + dummyDataNum * 4))
            elif dbInst.instanceType == DefaultValue.STANDBY_INSTANCE:
                if i > 0:
                    connInfo1 += ","
                connInfo1 += "localhost=%s localport=%d " \
                             "localservice=%s remotehost=%s remoteport=%d " \
                             "remoteservice=%s" % \
                             (dbInst.haIps[i], dbInst.haPort,
                              (dbInst.port + standbyDataNum * 4),
                              masterInst.haIps[i], masterInst.haPort,
                              (masterInst.port + masterDataNum * 4))
                if (dummyStandbyInst is not None):
                    if i > 0:
                        connInfo2 += ","
                    connInfo2 += "localhost=%s localport=%d localservice=%s " \
                                 "remotehost=%s remoteport=%d " \
                                 "remoteservice=%s" % \
                                 (dbInst.haIps[i], dbInst.haPort,
                                  (dbInst.port + standbyDataNum * 4),
                                  dummyStandbyInst.haIps[i],
                                  dummyStandbyInst.haPort,
                                  (dummyStandbyInst.port + dummyDataNum * 4))
            elif (dbInst.instanceType == DefaultValue.DUMMY_STANDBY_INSTANCE):
                if i > 0:
                    connInfo1 += ","
                connInfo1 += "localhost=%s localport=%d localservice=%s " \
                             "remotehost=%s remoteport=%d remoteservice=%s" % \
                             (dbInst.haIps[i], dbInst.haPort,
                              (dbInst.port + dummyDataNum * 4),
                              masterInst.haIps[i],
                              masterInst.haPort,
                              (masterInst.port + masterDataNum * 4))
                if i > 0:
                    connInfo2 += ","
                connInfo2 += "localhost=%s localport=%d " \
                             "localservice=%s remotehost=%s remoteport=%d " \
                             "remoteservice=%s" % \
                             (dbInst.haIps[i], dbInst.haPort,
                              (dbInst.port + dummyDataNum * 4),
                              standbyInst.haIps[i], standbyInst.haPort,
                              (standbyInst.port + standbyDataNum * 4))

        return connInfo1, connInfo2, dummyStandbyInst, nodename

    @staticmethod
    def getInstanceInfoForSinglePrimaryMultiStandbyCluster(dbInst, peerInsts):
        """
        function: get the instance name, master instance and standby
                  instance list
        input : dbInst
        output: NA
        """
        masterInst = None
        standbyInstIdLst = []
        instancename = ""
        # init masterInst, standbyInst
        for pi in iter(peerInsts):
            if pi.instanceType == DefaultValue.MASTER_INSTANCE:
                masterInst = pi
            elif pi.instanceType == DefaultValue.STANDBY_INSTANCE or \
                    pi.instanceType == DefaultValue.CASCADE_STANDBY:
                standbyInstIdLst.append(pi.instanceId)

        if dbInst.instanceType == DefaultValue.MASTER_INSTANCE:
            masterInst = dbInst
            instancename = "dn_%d" % masterInst.instanceId
            standbyInstIdLst.sort()
            for si in iter(standbyInstIdLst):
                instancename += "_%d" % si
        elif dbInst.instanceType == DefaultValue.STANDBY_INSTANCE or \
              dbInst.instanceType == DefaultValue.CASCADE_STANDBY:
            instancename = "dn_%d" % masterInst.instanceId
            standbyInstIdLst.append(dbInst.instanceId)
            standbyInstIdLst.sort()
            for si in iter(standbyInstIdLst):
                instancename += "_%d" % si
        return (instancename, masterInst, standbyInstIdLst)

    @staticmethod
    def setReplConninfoForSinglePrimaryMultiStandbyCluster(dbInst,
                                                           peerInsts,
                                                           clusterInfo):
        """
        function: Modify replconninfo for datanode
        input : dbInst
        output: NA
        """
        masterInst = None
        standbyInstIdLst = []
        nodename = ""
        connInfo1 = []
        (nodename, masterInst, standbyInstIdLst) = ClusterInstanceConfig. \
            getInstanceInfoForSinglePrimaryMultiStandbyCluster(dbInst,
                                                               peerInsts)
        if len(masterInst.haIps) == 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51621"] +
                            " Data directory: %s." % dbInst.datadir)
        if len(standbyInstIdLst) == 0:
            return connInfo1, nodename

        dbNode = clusterInfo.getDbNodeByName(dbInst.hostname)
        if dbNode is None:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                            ("database node configuration on host [%s]"
                             % dbInst.hostname))

        channelCount = len(masterInst.haIps)
        if dbInst.instanceType == DefaultValue.MASTER_INSTANCE:
            for pj in iter(peerInsts):
                peerDbNode = clusterInfo.getDbNodeByName(pj.hostname)
                if peerDbNode is None:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                                    ("database node configuration on host [%s]"
                                     % pj.hostname))
                chanalInfo = ""
                for i in range(channelCount):
                    if i > 0:
                        chanalInfo += ","
                    chanalInfo += "localhost=%s localport=%d " \
                                  "localheartbeatport=%d localservice=%s " \
                                  "remotehost=%s remoteport=%d " \
                                  "remoteheartbeatport=%d remoteservice=%s" % \
                                  (dbInst.haIps[i], dbInst.haPort,
                                   dbInst.port + 5,
                                   (dbInst.port + 4), pj.haIps[i],
                                   pj.haPort, pj.port + 5,
                                   pj.port + 4)
                    if pj.instanceType == DefaultValue.CASCADE_STANDBY:
                        chanalInfo += " iscascade=true"

                connInfo1.append(chanalInfo)
        else:
            for pj in iter(peerInsts):
                peerDbNode = clusterInfo.getDbNodeByName(pj.hostname)
                if peerDbNode is None:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                                    ("database node configuration on host [%s]"
                                     % pj.hostname))
                chanalInfo = ""
                for i in range(channelCount):
                    if i > 0:
                        chanalInfo += ","
                    chanalInfo += "localhost=%s localport=%d " \
                                  "localheartbeatport=%d localservice=%s " \
                                  "remotehost=%s remoteport=%d " \
                                  "remoteheartbeatport=%d remoteservice=%s" % \
                                  (dbInst.haIps[i], dbInst.haPort,
                                   dbInst.port + 5,
                                   (dbInst.port + 4), pj.haIps[i],
                                   pj.haPort, pj.port + 5,
                                   (pj.port + 4))
                    if pj.instanceType == DefaultValue.CASCADE_STANDBY:
                        chanalInfo += " iscascade=true"
                connInfo1.append(chanalInfo)

        return connInfo1, nodename

    @staticmethod
    def get_data_from_dcc(cluster_info, logger, user, paralist):
        """
        function: get value from dcc
        :param cluster_info: cluster info
        :param logger: logger obj
        :param user: cluster user
        :param paralist: paralist
        :return: key-value map dict
        """
        gausshome = ClusterDir.getInstallDir(user)
        cm_ctl = os.path.realpath(os.path.join(gausshome, "bin/cm_ctl"))
        if not os.path.isfile(cm_ctl):
            raise Exception(ErrorCode.GAUSS_502["GAUSS-50201"] % "file cm_ctl")
        cms_count = 0
        etcd_count = 0
        for dbnode in cluster_info.dbNodes:
            for _ in dbnode.cmservers:
                cms_count += 1
            for _ in dbnode.etcds:
                etcd_count += 1
        if cms_count == 0 or etcd_count > 1:
            raise Exception(ErrorCode.GAUSS_500["GAUSS-50011"] % paralist)
        para_value_map = {}
        for para_key in paralist:
            cmd = "source %s; %s ddb --get '%s'" % (EnvUtil.getMpprcFile(), cm_ctl, para_key)
            logger.debug("Get dcc value cmd:%s." % cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd, "Error:%s" % output)
            logger.debug("Get dcc value:%s." % output)
            res = output.strip("\n").split("\n")
            if len(res) != 2:
                raise Exception(ErrorCode.GAUSS_500["GAUSS-50019"] % res)
            if res[-1].find("Key not found") > -1:
                para_value_map[para_key] = ""
                continue
            para_value_map[para_key] = res[-1].split(":")[-1].strip()
        logger.debug("Get all values from dcc component res:%s." % para_value_map)
        return para_value_map

    @staticmethod
    def set_data_on_dcc(cluster_info, logger, user, paradict):
        """
        function: set data on dcc
        :param cluster_info: cluster info
        :param logger: logger obj
        :param user: cluster user
        :param paradict: paradict
        :return: NA
        """
        gausshome = ClusterDir.getInstallDir(user)
        cm_ctl = os.path.realpath(os.path.join(gausshome, "bin/cm_ctl"))
        if not os.path.isfile(cm_ctl):
            raise Exception(ErrorCode.GAUSS_502["GAUSS-50201"] % "file cm_ctl")
        cms_count = 0
        etcd_count = 0
        for dbnode in cluster_info.dbNodes:
            for _ in dbnode.cmservers:
                cms_count += 1
            for _ in dbnode.etcds:
                etcd_count += 1
        if cms_count == 0 or etcd_count > 1:
            raise Exception(ErrorCode.GAUSS_500["GAUSS-50011"] % paradict)
        for para_key in list(paradict.keys()):
            cmd = "source %s; %s ddb --put '%s' '%s'" % \
                  (EnvUtil.getMpprcFile(), cm_ctl, para_key, paradict[para_key])
            logger.debug("Set dcc value cmd:%s." % cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd, "Error:%s" % output)
            logger.debug("Set dcc data:%s." % output)
            res = output.strip("\n").split("\n")
            if len(res) != 2:
                raise Exception(ErrorCode.GAUSS_500["GAUSS-50019"] % res)
        logger.debug("Successfully set the dcc data information.")


class TempfileManagement():
    """
    create and remove temp file or directory
    """

    def __init__(self):
        """
        function: init function
        input: NA
        output: NA
        """
        pass

    @staticmethod
    def removeTempFile(filename, Fuzzy=False):
        """
        function: remove temp files in PGHOST
        input:
              fileName string  Specified file name or keywords
              Fuzzy    bool    Whether to remove files with the same prefix,
              default is False
        output: NA
        """

        if Fuzzy:
            keywords = filename + "*"
            FileUtil.removeFile(keywords, "shell")
        else:
            FileUtil.removeFile(filename)


class CmPackageException(BaseException):
    def __init__(self):
        BaseException.__init__(self)
        self.error_info = "Cm package exception. " \
                          "Please check the installation package " \
                          "or delete the CM configuration from the XML file."

    def __str__(self):
        return self.error_info
