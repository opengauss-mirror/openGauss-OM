#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
# Description : LocalCheckPreUpgrade.py is a utility to check OS info on local node.
#############################################################################

import os
import sys
import getopt
import subprocess
import time
import concurrent.futures

localDirPath = os.path.dirname(os.path.realpath(__file__))

sys.path.append(sys.path[0] + "/../")
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.GaussLog import GaussLog
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.net_util import NetUtil
from base_utils.os.cpu_util import CpuUtil
from base_utils.os.disk_util import DiskUtil
from base_utils.os.memory_util import MemoryUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.user_util import UserUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from domain_utils.cluster_file.version_info import VersionInfo

sys.path.insert(0, localDirPath + "/../../lib")
import psutil

ACTION_CHECK_ALL = "Check_All"
ACTION_CHECK_CPU = "Check_Cpu"
ACTION_CHECK_MEM = "Check_Mem"
ACTION_CHECK_DISK = "Check_Disk"
ACTION_CHECK_PROCESS = "Check_Process"
ACTION_CHECK_NETWORK = "Check_Network"
ACTION_CHECK_DATABASE = "Check_Database"
ACTION_CHECK_REPLAYGAY = "Check_Replaygay"

#############################################################################
# Global variables
#############################################################################
MASTER_INSTANCE = 0
STANDBY_INSTANCE = 1

g_logger = None
g_opts = None
g_clusterInfo = None
g_replication_stats = {}

CPU_ERROR_VALUE = 95
CPU_WARNING_VALUE = 85
MEM_ERROR_VALUE = 95
MEM_WARNING_VALUE = 85
TMP_DIR_ERROR_VALUE = 50
HOME_DIR_ERROR_VALUE = 50
GAUSSHOME_DIR_ERROR_VALUE = 1024
MAX_ACTIVE_CONNECTIONS = 20
LSN_ERROR_THRESHOLD = 5
POOL_SIZE = 2


###########################################################################
# system resource
###########################################################################
class CpuInfo:
    """
    Class: CpuInfo
    """

    def __init__(self):
        """
        function : Init class CpuInfo
        input  : NA
        output : NA
        """
        self.used = []
        self.errmsg = ""


class MemInfo:
    """
    Class: MemInfo
    """

    def __init__(self):
        """
        function : Init class MemInfo
        input  : NA
        output : NA
        """
        self.used = 0
        self.errmsg = ""


class DiskInfo:
    """
    Class: DiskInfo
    """

    def __init__(self):
        """
        function : Init class DiskInfo
        input  : NA
        output : NA
        """
        self.tmp_dir_avail = 0
        self.home_dir_avail = 0
        self.gauss_home_dir_avail = 0
        self.dss_log_value = 0
        self.dss_data_value = 0


class DssInfo:
    """
    Class: DssInfo
    """

    def __init__(self):
        """
        function : Init class DssInfo
        input  : NA
        output : NA
        """
        self.dss_log_value = 0
        self.dss_data_value = 0


class ProcessInfo:
    """
    Class: ProcessInfo
    """

    def __init__(self):
        """
        function : Init class ProcessInfo
        input  : NA
        output : NA
        """
        self.process = 0
        self.errmsg = ""


class NetworkInfo:
    """
    Class: NetworkInfo
    """

    def __init__(self):
        """
        function : Init class NetworkInfo
        input  : NA
        output : NA
        """
        self.status = ""
        self.output = ""


class MaxProcessMemoryInfo:
    """
    Class: MaxProcessMemoryInfo
    """

    def __init__(self):
        self.max_process = ""
        self.used_process = ""
        self.enable_memory_limit = ""


class ActiveConnectionInfo:
    """
    Class: ActiveConnection
    """

    def __init__(self):
        """
        function : Init class ActiveConnection
        input  : NA
        output : NA
        """
        self.active_connection = ""


class ReplyInfo:
    """
    Class: ReplyInfo
    """

    def __init__(self):
        """
        function : Init class ReplyInfo
        input  : NA
        output : NA
        """
        self.lsn_rate = ""
        self.diff_replay = ""
        self.replay_time = ""


#############################################################################
class CmdOptions:
    """
    Class: CmdOptions
    """

    def __init__(self):
        """
        function : Init class CmdOptions
        input  : NA
        output : NA
        """
        self.action = ""
        self.user = ""
        self.log_file = ""
        self.hostname = ""
        self.mppdbfile = ""
        self.is_dss = False
        self.lsn_speed = ""


#########################################################
# Init global log
#########################################################
def init_globals():
    """
    function : init Globals
    input  : NA
    output : NA
    """
    global g_logger
    global g_clusterInfo

    g_logger = GaussLog(g_opts.log_file, "LocalCheckPreUpgrade")
    g_clusterInfo = dbClusterInfo()
    g_clusterInfo.initFromStaticConfig(g_opts.user)


def usage():
    """
    Usage:
     python3 --help | -?
     python3 LocalCheckPreUpgrade -t action [-l logfile] [-U user] [-V]
    Common options:
     -t                                The type of action.
     -U                                The user name of the node.
     -s                                the path of MPPDB file
     -l --log-file=logfile             The path of log file.
        --lsn-speed=num                The speed of lsn.
     -? --help                         Show this help screen.
     -V --version

    """
    print(usage.__doc__)


def parse_command_line():
    """
    function : Parse command line and save to global variables
    input  : NA
    output : NA
    """
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "t:s:l:U:V?", ["help", "log-file=", "lsn-speed"]
        )
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(e))

    if len(args) > 0:
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"] % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    for key, value in opts:
        if key == "-?" or key == "--help":
            usage()
            sys.exit(0)
        elif key == "-V" or key == "--version":
            print("%s %s" % (sys.argv[0].split("/")[-1], VersionInfo.COMMON_VERSION))
            sys.exit(0)
        elif key == "-t":
            g_opts.action = value
        elif key == "-U":
            g_opts.user = value
        elif key == "-s":
            g_opts.mppdbfile = value
        elif key == "-l" or key == "--log-file":
            g_opts.log_file = os.path.realpath(value)
        elif key == "--lsn-speed":
            g_opts.lsn_speed = value
        Parameter.checkParaVaild(key, value)


def check_parameter():
    """
    function : check parameter
    input  : NA
    output : NA
    """
    if g_opts.action == "":
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % "t" + ".")
    if (
        g_opts.action != ACTION_CHECK_ALL
        and g_opts.action != ACTION_CHECK_CPU
        and g_opts.action != ACTION_CHECK_MEM
        and g_opts.action != ACTION_CHECK_DISK
        and g_opts.action != ACTION_CHECK_PROCESS
        and g_opts.action != ACTION_CHECK_NETWORK
        and g_opts.action != ACTION_CHECK_DATABASE
        and g_opts.action != ACTION_CHECK_REPLAYGAY
    ):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "t")

    if g_opts.log_file == "":
        dir_name = os.path.dirname(os.path.realpath(__file__))
        g_opts.log_file = os.path.join(dir_name, ClusterConstants.LOCAL_LOG_FILE)

    if g_opts.user == "":
        user_info = UserUtil.getUserInfo()
        g_opts.user = user_info["name"]

    if EnvUtil.getEnv("DSS_HOME"):
        g_opts.is_dss = True


def collect_cpu_info():
    """
    collect cpu info
    """
    cpu_info = CpuInfo()
    cpu_info.used = CpuUtil.get_cpu_uesd()
    cpu_info.used.sort()
    return cpu_info


def check_cpu_used():
    """
    check cpu used
    """
    data = collect_cpu_info()
    min_used = data.used[0]
    if min_used > CPU_ERROR_VALUE:
        g_logger.log(
            "Error, CPU usage is at %s%%, which is greater than the threshold of %s%%!"
            % (min_used, CPU_ERROR_VALUE)
        )
    elif min_used > CPU_WARNING_VALUE:
        g_logger.log(
            "Warning, CPU usage is at %s%% which greater than the threshold of %s%%!"
            % (min_used, CPU_WARNING_VALUE)
        )
    else:
        g_logger.log("Normal, CPU usage is at %s%%" % min_used)


def collect_mem_info():
    """
    collect mem info
    """
    mem_info = MemInfo()
    mem_info.used = MemoryUtil.getMemUsage()
    return mem_info


def check_mem_used():
    data = collect_mem_info()
    if data.used > MEM_ERROR_VALUE:
        g_logger.log(
            "Error, Memory usage is at %s%% which is greater than the threshold of %s%%!"
            % (data.used, MEM_ERROR_VALUE)
        )
    elif data.used > MEM_WARNING_VALUE:
        g_logger.log(
            "Warning, Memory usage is at %s%% which is greater than the threshold of %s%%!"
            % (data.used, MEM_WARNING_VALUE)
        )
    else:
        g_logger.log("Normal, Memory usage is at %s%%" % data.used)


def query_dss_info():
    """
    query dss info
    """
    if not g_opts.is_dss:
        return False
    # check dss info
    data = DssInfo()
    cmd = "dsscmd lsvg -m G"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        g_logger.debug("Exec %s failed! Output: %s" % (cmd, output))
        return False, output
    for line in output.splitlines():
        if line.startswith("data"):
            data.dss_data_value = line.split()[5]
        elif line.startswith("log"):
            data.dss_log_value = line.split()[5]
    return True, data


def collect_disk_info():
    """
    collect disk info
    """
    data = DiskInfo()
    tmp_path = "/tmp"
    home_path = "/home"
    gauss_home = EnvUtil.getEnv("GAUSSHOME")
    dirs_list = [tmp_path, home_path, gauss_home]
    for path in dirs_list:
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % path)

    # The unit of disk size is mb
    data.tmp_dir_avail = DiskUtil.getMountPathAvailSize(tmp_path)
    data.home_dir_avail = DiskUtil.getMountPathAvailSize(home_path)
    data.gauss_home_dir_avail = DiskUtil.getMountPathAvailSize(gauss_home)
    return data


def get_dss_log_or_data_threshold():
    """
    get dss log or data threshold
    """
    cmd = "cm_ctl list --param --server |grep datastorage_threshold_value_check"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception("Exec %s failed! Output: %s" % (cmd, output))
    dss_threshold = output.splitlines()[0].split("=")[1].strip()
    return dss_threshold


def check_disk_used():
    data = collect_disk_info()
    success_msgs_str = "All disk space is enough."
    error_msgs = []

    if data.tmp_dir_avail < TMP_DIR_ERROR_VALUE:
        error_msgs.append(
            "The /tmp dir available space is not enough, the disk space size is %s less than 50m."
            % data.tmp_dir_avail
        )

    if data.home_dir_avail < HOME_DIR_ERROR_VALUE:
        error_msgs.append(
            "The /home dir available space is not enough, the disk space size is %s less than 50m."
            % data.home_dir_avail
        )

    gauss_home = EnvUtil.getEnv("GAUSSHOME")
    if data.gauss_home_dir_avail < GAUSSHOME_DIR_ERROR_VALUE:
        error_msgs.append(
            "The %s dir available space is not enough, the disk space size is %s less than 1GB."
            % (gauss_home, data.gauss_home_dir_avail)
        )

    # check dss
    if not g_opts.is_dss:
        if error_msgs:
            g_logger.log("Error, " + "\n".join(error_msgs))
        else:
            g_logger.log("Normal, %s" % success_msgs_str)
        return

    status, data = query_dss_info()
    if not status:
        error_msgs.append("Query dss info failed, output is %s." % data)
        g_logger.log("Error, " + "\n".join(error_msgs))
        return

    dss_threshold = get_dss_log_or_data_threshold()
    if float(data.dss_data_value) > float(dss_threshold):
        error_msgs.append(
            f"Dss data dir available space is not enough, the disk utilization rate is {data.dss_data_value}."
        )

    if float(data.dss_log_value) > float(dss_threshold):
        error_msgs.append(
            f"Dss log dir available space is not enough, the disk utilization rate is {data.dss_log_value}."
        )

    if error_msgs:
        g_logger.log("Error, " + "\n".join(error_msgs))
    else:
        g_logger.log("Normal, %s" % success_msgs_str)


def check_process(timeout=None):
    """
    function: check process
    input : NA
    output: NA
    """
    if not timeout:
        timeout = 10
    try:
        cmd = "source %s; timeout %ss bash -c 'gs_om -t status'" % (
            EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH"),
            timeout,
        )
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or "Normal" not in output:
            g_logger.log("Error, process is not normal")
        else:
            g_logger.log("Normal, process is normal")
    except Exception as e:
        g_logger.log("Error, check process failed! Output: %s" % output)


def query_replication_stats(port):
    """
    function: query replication stats for a node
    input : node - database node to query
    output: NA
    """
    sql = "select receiver_replay_location from pg_stat_replication;"
    return gsql_execute(sql, port)


def get_primary_hostname():
    """
    function: get primary node
    input : NA
    output: NA
    """
    for db_node in g_clusterInfo.dbNodes:
        for dn_inst in db_node.datanodes:
            if dn_inst.instanceType == 0:
                return dn_inst.hostname
    return None


def is_primary_node():
    local_node = NetUtil.GetHostIpOrName()
    primary_home = get_primary_hostname()
    if local_node != primary_home or g_opts.is_dss:
        return False
    return True


def get_node_port():
    try:
        local_node = NetUtil.GetHostIpOrName()
        node = g_clusterInfo.getDbNodeByName(local_node)
        port = node.datanodes[0].port
        return port
    except Exception as e:
        g_logger.logExit("Error querying node port: %s" % str(e))


def lsn_to_int(lsn: str) -> int:
    """
    Convert an LSN (Log Sequence Number) string to a 64-bit integer.

    Args:
        lsn: LSN string in the format 'XXXX/YYYYYYYY' (e.g., '16/3002D50')

    Returns:
        Integer representation of the LSN.

    Raises:
        ValueError: If the LSN format is invalid.
    """
    try:
        # Split the LSN string into two parts (e.g., '16/3002D50' -> ['16', '3002D50'])
        part1, part2 = lsn.strip().split("/")
        # Convert hexadecimal parts to a 64-bit integer
        # High 32 bits: first part, low 32 bits: second part
        return (int(part1, 16) << 32) + int(part2, 16)
    except ValueError:
        raise ValueError(f"Invalid LSN format: {lsn}")


def lsn_diff_python(lsn1: str, lsn2: str) -> int:
    """
    Calculate the difference between two LSNs in bytes (pure Python implementation).

    Args:
        lsn1: First LSN string.
        lsn2: Second LSN string.

    Returns:
        Difference in bytes (lsn2 - lsn1).
        Positive if lsn2 is ahead of lsn1, negative otherwise.
    """
    return lsn_to_int(lsn2) - lsn_to_int(lsn1)


def parse_replication_stats(
    first_stat_replication_str, second_stat_replication_str, time_diff
):
    """
    Parse replication stats and calculate the minimum LSN rate.
    Returns: (success, lsn_rate_min, errmsg)
    """
    first_stat_replication = first_stat_replication_str.strip().split("\n")
    second_stat_replication = second_stat_replication_str.strip().split("\n")
    lsn_rate_list = []
    for first, second in zip(first_stat_replication, second_stat_replication):
        lsn_value = lsn_diff_python(first, second)
        if lsn_value == 0:
            g_logger.debug("lsn_rate_min: %s" % lsn_value)
            return True, 0, ""
        lsn_rate = lsn_value / time_diff
        lsn_rate_list.append(lsn_rate)

    if not lsn_rate_list:
        errmsg = "No valid LSN rate calculated."
        g_logger.debug(errmsg)
        return False, None, errmsg

    lsn_rate_list.sort()
    return True, lsn_rate_list[0], ""


def get_lsn_rate_min():
    """
    get lsn rate min
    """
    if not is_primary_node() or g_opts.is_dss:
        return True, 0, ""
    port = get_node_port()
    success, first_stat_replication_str, errmsg = query_replication_stats(port)
    if not success:
        g_logger.debug("query_replication_stats failed: %s" % errmsg)
        return success, first_stat_replication_str, errmsg
    # set time diff is 10s
    time_diff = 10
    time.sleep(time_diff)
    success, second_stat_replication_str, errmsg = query_replication_stats(port)
    if not success:
        g_logger.debug("query_replication_stats failed: %s" % errmsg)
        return success, second_stat_replication_str, errmsg

    return parse_replication_stats(
        first_stat_replication_str, second_stat_replication_str, time_diff
    )


def check_network():
    """
    function: check network
    input : NA
    output: NA
    """
    data = collect_network()
    g_logger.log("%s, %s" % (data.status, data.output))


def collect_network():
    """
    collect network info
    """
    data = NetworkInfo()
    local_name = NetUtil.GetHostIpOrName()
    node_names = g_clusterInfo.getClusterNodeNames()
    node_names.remove(local_name)

    back_ips = []
    for node in g_clusterInfo.dbNodes:
        if node.name in node_names and node.backIps:
            back_ips.append(node.backIps[0])

    if not back_ips:
        data.status = "Normal"
        data.output = "successfully checked network"
        return data
    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(12, len(back_ips))
        ) as executor:
            ping_results = list(executor.map(ping_ip, back_ips))

        failed_ips = [res for res in ping_results if not res]
        if failed_ips:
            data.status = "Error"
            data.output = "failed checked network"
        else:
            data.status = "Normal"
            data.output = "successfully checked network"
    except Exception as e:
        data.status = "Error"
        data.output = str(e)
    return data


def ping_ip(ip, num=10):
    """
    function: ping ip
    input : NA
    output: NA
    """
    try:
        ping = CmdUtil.get_ping_tool()
        cmd = "%s -c %s %s -W 1" % (ping, num, ip)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            g_logger.debug("Failed to ping %s. %s" % (ip, output))
            return False
        return True
    except Exception as e:
        g_logger.debug("Error exec %s: %s" % (cmd, str(e)))
        return False


def gsql_execute(sql, port, timeout=None):
    """
    function: gsql execute
    input : NA
    output: NA
    """
    if not timeout:
        timeout = 3
    try:
        sql_escaped = sql.replace('"', '\\"')
        cmd = 'timeout %ss bash -c "gsql -m -d postgres -p %s -A -t -c \\"%s\\""' % (
            timeout,
            port,
            sql_escaped,
        )
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            errmsg = "Exec %s failed!, output is %s" % (cmd, output)
            g_logger.debug(errmsg)
            return False, None, errmsg
        return True, output.strip(), ""
    except Exception as e:
        errmsg = "Error exec %s: %s" % (cmd, str(e))
        g_logger.debug(errmsg)
        return False, None, errmsg


def query_active_connections(port):
    """
    function: query active connections
    input : NA
    output: NA
    """
    app_name_list = [
        "PercentileJob",
        "statement flush thread",
        "Asp",
        "CfsShrinker",
        "ApplyLauncher",
        "JobScheduler",
        "TxnSnapCapturer",
        "cm_agent",
    ]
    app_names_str = "', '".join(app_name_list)
    sql = f"select count(*) from pg_stat_activity where state != 'idle' and \
            application_name not in ('{app_names_str}');"
    return gsql_execute(sql, port)


def parse_max_process_memory_info(output):
    """
    prase max process memory info
    """
    lines = output.splitlines()
    for line in lines:
        if "max_process_memory" in line:
            max_process_memory = line.split("|")[1]
        if "process_used_memory" in line:
            process_used_memory = line.split("|")[1]
    return max_process_memory, process_used_memory


def query_max_process_memory(port):
    """
    query max process
    """
    sql_get = "select memorytype, memorymbytes from gs_total_memory_detail where memorytype in ('max_process_memory', 'process_used_memory');"
    return gsql_execute(sql_get, port)


def query_enable_memory_limit(port):
    """
    query enable memory limit
    """
    sql = "show enable_memory_limit;"
    return gsql_execute(sql, port)


def collect_max_process_info():
    """
    Collect max process memory info.
    Returns: (success, data, errmsg)
    """
    data = MaxProcessMemoryInfo()
    port = get_node_port()

    # Query enable_memory_limit
    success, output, errmsg = query_enable_memory_limit(port)
    if not success:
        return success, output, "".join(errmsg)

    enable_memory_limit = output.strip()
    data.enable_memory_limit = enable_memory_limit
    if enable_memory_limit == "off":
        return True, data, ""

    # Query max_process_memory and process_used_memory
    success, output, errmsg = query_max_process_memory(port)
    if not success:
        return False, output, "".join(errmsg)

    data.max_process, data.used_process = parse_max_process_memory_info(output)
    return True, data, ""


def get_replay_size(port):
    """
    get replay size
    """
    sql = "select client_addr, pg_xlog_location_diff(receiver_flush_location, receiver_replay_location) as replaygay from pg_stat_replication;"
    success, output, errmsg = gsql_execute(sql, port)
    if not success:
        return success, output, errmsg

    output_list = output.splitlines()
    diff_replay_list = []
    for line in output_list:
        diff_replay = line.split("|")[1]
        if diff_replay == "0":
            continue
        diff_replay_list.append(diff_replay)
    return success, diff_replay_list, ""


def collect_replay_info():
    """
    collect reply info
    """
    data = ReplyInfo()
    success, lsn_speed, errmsg = get_lsn_rate_min()
    if not success:
        return success, lsn_speed, errmsg

    port = get_node_port()
    success, diff_replay_list, errmsg = get_replay_size(port)
    if not success:
        return success, diff_replay_list, errmsg

    if not diff_replay_list or not lsn_speed:
        data.replay_time = "0"
        return success, data, ""

    for diff_replay in diff_replay_list:
        data.replay_time = int(diff_replay) / lsn_speed

    return success, data, ""


def set_track_activities():
    """
    function: set track_activities
    """
    cmd = "gs_guc reload -c 'track_activities = on'"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        errmsg = "Failed to set track_activities. Commands for setting: %s." % cmd
        g_logger.debug(errmsg)
        return False, None, errmsg
    return True, output.strip(), ""


def get_track_activities(port):
    """
    function: get track_activities
    """
    sql = "show track_activities;"
    return gsql_execute(sql, port)


def collect_active_connections():
    """
    Function: Check active connections
    Returns: (success, data, errmsg)
    """
    data = ActiveConnectionInfo()
    port = get_node_port()

    # 1. Check the status of track_activities
    success, output, errmsg = get_track_activities(port)
    if not success:
        return success, output, "".join(errmsg)
    if output.strip() == "on":
        # If already enabled, directly query active connections
        success, output, errmsg = query_active_connections(port)
        if not success:
            return success, output, "".join(errmsg)
        data.active_connection = output.strip()
        return success, data, "".join(errmsg)

    # 2. If not enabled, try to enable track_activities
    success, output, errmsg = set_track_activities()
    if not success:
        return success, output, "".join(errmsg)

    # 3. After enabling, query active connections again
    success, output, errmsg = query_active_connections(port)
    if not success:
        return success, output, "".join(errmsg)
    data.active_connection = output.strip()
    return success, data, "".join(errmsg)


def check_max_process_memory():
    success, data, errmsg = collect_max_process_info()
    if not success:
        g_logger.log("Error, %s" % errmsg)
        return

    if data.enable_memory_limit == "off":
        g_logger.log("Normal, enable_memory_limit is off")
    else:
        if int(data.max_process) * 0.9 < int(data.used_process):
            g_logger.log("Warning, max_process_memory is less than process_used_memory")
        else:
            g_logger.log(
                "Normal, max_process_memory is greater than process_used_memory"
            )


def check_active_connections():
    success, data, errmsg = collect_active_connections()
    if not success:
        g_logger.log("Error, %s" % errmsg)
        return

    if int(data.active_connection) > MAX_ACTIVE_CONNECTIONS:
        g_logger.log(
            "Error, The number of active connections is %s which exceeds the threshold of 20!"
            % data.active_connection
        )
    else:
        g_logger.log(
            "Normal, The number of active connections is %s" % data.active_connection
        )


def check_database():
    check_max_process_memory()
    check_active_connections()


def check_replaygay():
    """
    check replay time
    """
    if not is_primary_node() or g_opts.is_dss:
        g_logger.log("Normal, do not check replaygay.")
        return

    success, data, errmsg = collect_replay_info()
    if not success:
        g_logger.log("Error, %s" % errmsg)
        return

    if int(data.replay_time) > LSN_ERROR_THRESHOLD:
        g_logger.log(
            "Error, the replaygay time is %smin, which is greater than the threshold of 5min."
            % data.replay_time
        )
    else:
        g_logger.log("Normal, the replaygay time is %smin." % data.replay_time)


def run_task_with_log(task):
    try:
        task()
    except Exception as e:
        g_logger.log(f"Exception in {task.__name__}: {e}")


def check_all():
    """
    check all tasks
    """
    # all tasks
    task_list = [
        check_cpu_used,
        check_mem_used,
        check_disk_used,
        check_process,
        check_network,
        check_database,
        check_replaygay,
    ]

    with concurrent.futures.ProcessPoolExecutor(max_workers=POOL_SIZE) as executor:
        futures = [executor.submit(run_task_with_log, task) for task in task_list]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                g_logger.log(f"Exception in process: {exc}")


def do_local_check():
    """
    function: check OS item on local node
    input : NA
    output: NA
    """
    function_dict = {
        ACTION_CHECK_ALL: check_all,
        ACTION_CHECK_CPU: check_cpu_used,
        ACTION_CHECK_MEM: check_mem_used,
        ACTION_CHECK_DISK: check_disk_used,
        ACTION_CHECK_PROCESS: check_process,
        ACTION_CHECK_NETWORK: check_network,
        ACTION_CHECK_DATABASE: check_database,
        ACTION_CHECK_REPLAYGAY: check_replaygay,
    }

    if g_opts.action in function_dict.keys():
        function_dict[g_opts.action]()
    else:
        g_logger.logExit(
            ErrorCode.GAUSS_500["GAUSS_50004"] % "t" + " Value: %s." % g_opts.action
        )


if __name__ == "__main__":
    """
    main function
    """
    try:
        parse_command_line()
        check_parameter()
        init_globals()
    except Exception as e:
        GaussLog.exitWithError(str(e))

    try:
        do_local_check()
        g_logger.closeLog()
    except Exception as e:
        g_logger.logExit(str(e))

    sys.exit(0)
