#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
# Description : LocalCheckSE.py is a utility to check security configurations info on local node.
#############################################################################
import os
import sys
import getopt
import subprocess
import re

localDirPath = os.path.dirname(os.path.realpath(__file__))

sys.path.append(sys.path[0] + "/../")
from gspylib.common.ParameterParsecheck import Parameter
from gspylib.common.GaussLog import GaussLog
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from domain_utils.cluster_file.version_info import VersionInfo
from base_utils.os.net_util import NetUtil
from base_utils.os.cmd_util import CmdUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants
from datetime import datetime, timedelta

sys.path.insert(0, localDirPath + "/../../lib")
import pwd
import grp

ACTION_CHECK_Connection_configuration = "Check_Connection_configuration"
ACTION_CHECK_File_directory_security = "Check_File_directory_security"
ACTION_CHECK_Security_authentication_configuration = "Check_Security_authentication_configuration"
ACTION_CHECK_Account_password_management = "Check_Account_password_management"
ACTION_CHECK_Permission_management = "Check_Permission_management"
ACTION_CHECK_Database_auditing = "Check_Database_auditing"
ACTION_CHECK_Error_reporting_and_logging_configuration = "Check_Error_reporting_and_logging_configuration"
ACTION_CHECK_Backup_configuration = "Check_Backup_configuration"
ACTION_CHECK_Runtime_environment_configuration = "Check_Runtime_environment_configuration"
ACTION_CHECK_Other_configurations = "Check_Other_configurations"

ACTION_SET_Connection_configuration = "Set_Connection_configuration"
ACTION_SET_File_directory_security = "Set_File_directory_security"
ACTION_SET_Security_authentication_configuration = "Set_Security_authentication_configuration"
ACTION_SET_Account_password_management = "Set_Account_password_management"
ACTION_SET_Permission_management = "Set_Permission_management"
ACTION_SET_Database_auditing = "Set_Database_auditing"
ACTION_SET_Error_reporting_and_logging_configuration = "Set_Error_reporting_and_logging_configuration"
ACTION_SET_Backup_configuration = "Set_Backup_configuration"
ACTION_SET_Runtime_environment_configuration = "Set_Runtime_environment_configuration"
ACTION_SET_Other_configurations = "Set_Other_configurations"

#############################################################################
# Global variables
#############################################################################
netWorkLevel = 10000
expectMTUValue = 8192
expectRXValue = 4096
expectTXValue = 4096
MASTER_INSTANCE = 0
STANDBY_INSTANCE = 1

g_logger = None
g_opts = None
g_clusterInfo = None
netWorkBondInfo = None
g_readlist = None


#############################################################################
def getValueFromFile(key):
    """
    function : Get value from file
    input  : String
    output : String
    """
    file_path = os.path.join(os.environ['PGDATA'], 'postgresql.conf')
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith(key) or line.startswith('#' + key):
                return line.split('=')[1].split('#')[0].strip()
    return None


###########################################################################
# User Info:
###########################################################################
class UserInfo:
    """
    Class: userInfo
    """

    def __init__(self):
        """
        function : Init class userInfo
        input  : NA
        output : NA
        """
        self.username = None
        self.groupname = None


def getUserInfo():
    """
    function : Get user info
    input  : NA
    output : Instantion
    """
    data = UserInfo()
    user_id = os.getuid()

    user_info = pwd.getpwuid(user_id)
    data.username = user_info.pw_name
    group_info = grp.getgrgid(user_info.pw_gid)
    data.groupname = group_info.gr_name
    return data


#############################################################################
def extractRowsCount(s):
    """
    function : extract rows count
    input  : String
    output : String
    """
    import re
    match = re.search(r'\((\d+) row[s]*\)$', s)
    if match:
        return int(match.group(1))
    else:
        return None


def extract_values(s, value):
    """
    function : extract values
    input  : String, String
    output : String
    """
    row = int(value)
    lines = s.strip().splitlines()[-row - 1:-1]
    return lines


def extract_types(s):
    """
    function : extract types
    input  : String
    output : String
    """
    match = re.search(r'=\{(.*?)\}', s)
    if match:
        return match.group(1)
    else:
        return ""


#############################################################################
def getDatabaseInfo(data, sql_query):
    """
    function : Get database info
    input  : Instantion, String
    output : Instantion
    """
    port = int(getValueFromFile('port'))
    database = g_opts.database
    cmd = f"gsql -d {database} -p '{port}' -r -c \"{sql_query}\""
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception(ErrorCode.GAUSS_505["GAUSS_50504"] % (cmd, output))
    if "ERROR:" in output:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % output)
    value = extractRowsCount(output)
    if not value is None:
        data.output = value
        if data.output > 0:
            data.db.extend(extract_values(output, value))
        else:
            data.db.append("")
    return data


#############################################################################
# monitor IP
#############################################################################
class MonitorIP:
    """
    Class: monitorIP
    """

    def __init__(self):
        """
        function : Init class monitorIP
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectMonitorIP():
    """
    function : Collector monitorIP
    input  : NA
    output : Instantion
    """
    data = MonitorIP()
    data.db = []
    sql_query = """SELECT name,setting FROM pg_settings WHERE name = 'listen_addresses' AND (position('*' in setting) OR position('0.0.0.0' in setting) OR position('::' in setting));"""
    data = getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# ports for Services
#############################################################################
class PortsforServices:
    """
    Class: portsforServices
    """

    def __init__(self):
        """
        function : Init class portsforServices
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectPortsforServices():
    """
    function : Collector PortsforServices
    input  : NA
    output : Instantion
    """
    data = PortsforServices()
    value = getValueFromFile('port')
    data.output = int(value)
    return data


#############################################################################
# connection Configuration
#############################################################################
class ConnectionConfiguration:
    """
    Class: connectionConfiguration
    """

    def __init__(self):
        """
        function : Init class connectionConfiguration
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectConnectionConfiguration():
    """
    function : Collector ConnectionConfiguration
    input  : NA
    output : Instantion
    """
    data = ConnectionConfiguration()
    data.db = []
    sql_query = """show max_connections;"""
    getDatabaseInfo(data, sql_query)
    data.output = int(data.db[0])
    return data


#############################################################################
# DataBase Connection
#############################################################################
class DBConnection:
    """
    Class: DBConnection
    """

    def __init__(self):
        """
        function : Init class DBConnection
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectDBConnection():
    """
    function : Collector Database Configuration
    input  : NA
    output : Instantion
    """
    data = DBConnection()
    data.db = []
    sql_query = """SELECT datname FROM pg_database WHERE datistemplate = false AND (datconnlimit = -1 OR datconnlimit > 1024);"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Admin Connection
#############################################################################
class AdminConnection:
    """
    Class: AdminConnection
    """

    def __init__(self):
        """
        function : Init class AdminConnection
        input  : NA
        output : NA
        """
        self.output = None
        self.maxValue = None
        self.errormsg = None


def collectAdminConnection():
    """
    function : Collector AdminConnection
    input  : NA
    output : Instantion
    """
    data = AdminConnection()
    value = getValueFromFile('sysadmin_reserved_connections')
    maxValue = getValueFromFile('max_connections')
    data.output = int(value)
    data.maxValue = int(maxValue)
    return data


#############################################################################
# User Connection
#############################################################################
class UserConnection:
    """
    Class: UserConnection
    """

    def __init__(self):
        """
        function : Init class UserConnection
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectUserConnection():
    """
    function : Collector UserConnection
    input  : NA
    output : Instantion
    """
    data = UserConnection()
    data.db = []
    sql_query = """SELECT rolname, rolconnlimit FROM pg_roles WHERE rolname NOT LIKE 'gs_role%' AND rolconnlimit = -1;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# unix socket
#############################################################################
class Unixsocket:
    """
    Class: unixsocket
    """

    def __init__(self):
        """
        function : Init class unixsocket
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectUnixsocket():
    """
    function : Collector Unixsocket
    input  : NA
    output : Instantion
    """
    data = Unixsocket()
    value = getValueFromFile('unix_socket_permissions')
    data.output = value
    return data


#############################################################################
# md5 Host
#############################################################################
class Md5Host:
    """
    Class: md5Host
    """

    def __init__(self):
        """
        function : Init class md5Host
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMD5Host():
    """
    function : Collector md5Host
    input  : NA
    output : Instantion
    """
    data = Md5Host()
    pg_hba_path = os.path.join(os.getenv('PGDATA'), 'pg_hba.conf')
    cmd_list = [
        'grep',
        '-P',
        r'^[^#]*host(ssl|nossl)?\s+.+(?:MD5|md5)\s*$',
        pg_hba_path
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_list)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data


#############################################################################
# host no ssl
#############################################################################
class Hostnossl:
    """
    Class: hostnossl
    """

    def __init__(self):
        """
        function : Init class hostnossl
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectHostnossl():
    """
    Collect hostnossl configuration.

    input  : NA
    output : Instantion
    """
    data = Hostnossl()
    hba_file = os.path.join(os.getenv('PGDATA', ''), 'pg_hba.conf')
    cmd_list = [
        'grep',
        '-P',
        r'^[^#]*hostnossl',
        hba_file
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_list)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data


#############################################################################
# host Address no 0.0.0.0/0
#############################################################################
class HostAddressno0:
    """
    Class: hostAddressno0
    """

    def __init__(self):
        """
        function : Init class hostAddressno0
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectHostAddressno0():
    """
    function : Collector Hostnoall
    input  : NA
    output : Instantion
    """
    data = HostAddressno0()
    hba_path = os.path.join(os.getenv('PGDATA', ''), 'pg_hba.conf')
    cmd_list = ['grep', '0.0.0.0/0', hba_path]
    (output, error, status) = CmdUtil.execCmdList(cmd_list)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data


#############################################################################
# ssl Connection
#############################################################################
class SslConnection:
    """
    Class: sslConnection
    """

    def __init__(self):
        """
        function : Init class sslConnection
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectSSLConnection():
    """
    function : Collector SSLConnection
    input  : NA
    output : Instantion
    """
    data = SslConnection()
    value = getValueFromFile('ssl')
    data.output = value
    return data


#############################################################################
# I/O min Home
#############################################################################
class MinHome:
    """
    Class: minHome
    """

    def __init__(self):
        """
        function : Init class minHome
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinHome():
    """
    function : Collector minHome
    input  : NA
    output : Instantion
    """
    data = MinHome()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = f"find -L {os.getenv('GAUSSHOME')} -prune \( ! -user {GAUSSUSER} -o ! -group {GAUSSGROUP} -o -perm /g=rwx,o=rwx \)"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min Share
#############################################################################
class MinShare:
    """
    Class: minShare
    """

    def __init__(self):
        """
        function : Init class minShare
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinShare():
    """
    function : Collector MinShare
    input  : NA
    output : Instantion
    """
    data = MinShare()
    share_dir = os.path.join(os.getenv('GAUSSHOME', ''), 'share')
    cmd_list = [
        'find',
        share_dir,
        '-prune',
        '-perm', '/g=rwx,o=rwx'
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_list)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data


#############################################################################
# min Bin
#############################################################################
class MinBin:
    """
    Class: minBin
    """

    def __init__(self):
        """
        function : Init class minBin
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinBin():
    """
    function : Collector MinBin
    input  : NA
    output : Instantion
    """
    data = MinBin()
    bin_dir = os.path.join(os.getenv('GAUSSHOME', ''), 'bin')
    cmd_list = [
        'find',
        bin_dir,
        '-prune',
        '-perm', '/g=rwx,o=rwx'
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_list)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data

#############################################################################
# min Data
#############################################################################
class MinData:
    """
    Class: minData
    """

    def __init__(self):
        """
        function : Init class minData
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinData():
    """
    function : Collector MinData
    input  : NA
    output : Instantion
    """
    data = MinData()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = f"find {os.getenv('PGDATA')} -prune \( ! -user {GAUSSUSER} -o ! -group {GAUSSGROUP} -o -perm /g=rwx,o=rwx \)"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min Archive
#############################################################################
class MinArchive:
    """
    Class: minArchive
    """

    def __init__(self):
        """
        function : Init class minArchive
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinArchive():
    """
    function : Collector MinArchive
    input  : NA
    output : Instantion
    """
    data = MinArchive()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = f"find {os.getenv('GAUSSHOME')}/archive -prune \( ! -user {GAUSSUSER} -o ! -group {GAUSSGROUP} -o -perm /g=rwx,o=rwx \)"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min postgres configuration
#############################################################################
class MinPGConf:
    """
    Class: minPGConf
    """

    def __init__(self):
        """
        function : Init class minPGConf
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinPGConf():
    """
    function : Collector MinPGConf
    input  : NA
    output : Instantion
    """
    data = MinPGConf()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = f"find {os.getenv('PGDATA')}/postgresql.conf \( ! -user {GAUSSUSER} -o ! -group {GAUSSGROUP} -o -perm /u=x,g=rwx,o=rwx \)"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min pg_hba configuration
#############################################################################
class MinPGHbaConf:
    """
    Class: minPGHbaConf
    """

    def __init__(self):
        """
        function : Init class minPGHbaConf
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinPGHbaConf():
    """
    function : Collector MinPGHbaConf
    input  : NA
    output : Instantion
    """
    data = MinPGHbaConf()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = f"find {os.getenv('PGDATA')}/pg_hba.conf \( ! -user {GAUSSUSER} -o ! -group {GAUSSGROUP} -o -perm /u=x,g=rwx,o=rwx \)"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min pg log
#############################################################################
class MinPGLog:
    """
    Class: minPGLog
    """

    def __init__(self):
        """
        function : Init class minPGLog
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectMinPGLog():
    """
    function : Collector MinPGLog
    input  : NA
    output : Instantion
    """
    data = MinPGLog()
    user = getUserInfo()
    GAUSSUSER = user.username
    GAUSSGROUP = user.groupname
    cmd = "find ${GAUSSLOG} -prune \( ! -user %s -o ! -group %s -o -perm /g=rwx,o=rwx \)" % (GAUSSUSER, GAUSSGROUP)
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# min Client AuthTime
#############################################################################
class ClientAuthTime:
    """
    Class: ClientAuthTime
    """

    def __init__(self):
        """
        function : Init class ClientAuthTime
        input  : NA
        output : NA
        """
        self.output = None
        self.errormsg = None


def collectClientAuthTime():
    """
    function : Collector ClientAuthTime
    input  : NA
    output : Instantion
    """
    data = ClientAuthTime()
    data.db = []
    sql_query = """show authentication_timeout;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# min Auth Encription Count
#############################################################################
class AuthEncriptionCount:
    """
    Class: AuthEncriptionCount
    """

    def __init__(self):
        """
        function : Init class AuthEncriptionCount
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuthEncriptionCount():
    """
    function : Collector AuthEncriptionCount
    input  : NA
    output : Instantion
    """
    data = AuthEncriptionCount()
    data.db = []
    sql_query = """show auth_iteration_count;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# min Failed Login Count
#############################################################################
class FailedLoginCount:
    """
    Class: FailedLoginCount
    """

    def __init__(self):
        """
        function : Init class FailedLoginCount
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectFailedLoginCount():
    """
    function : Collector FailedLoginCount
    input  : NA
    output : Instantion
    """
    data = FailedLoginCount()
    data.db = []
    sql_query = """show failed_login_attempts;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Password Complexity Validation
#############################################################################
class PasswordComplexityValidation:
    """
    Class: PasswordComplexityValidation
    """

    def __init__(self):
        """
        function : Init class PasswordComplexityValidation
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPasswordComplexityValidation():
    """
    function : Collector PasswordComplexityValidation
    input  : NA
    output : Instantion
    """
    data = PasswordComplexityValidation()
    data.db = []
    sql_query = """show password_policy;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Password Encryption Type
#############################################################################
class PasswordEncryptionType:
    """
    Class: PasswordEncryptionType
    """

    def __init__(self):
        """
        function : Init class PasswordEncryptionType
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPasswordEncryptionType():
    """
    function : Collector PasswordEncryptionType
    input  : NA
    output : Instantion
    """
    data = PasswordEncryptionType()
    data.db = []
    sql_query = """show password_encryption_type;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Password Reuse Time
#############################################################################
class PasswordReuseTime:
    """
    Class: PasswordReuseTime
    """

    def __init__(self):
        """
        function : Init class PasswordReuseTime
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPasswordReuseTime():
    """
    function : Collector PasswordReuseTime
    input  : NA
    output : Instantion
    """
    data = PasswordReuseTime()
    data.db = []
    sql_query = """show password_reuse_time;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Password Lock Time
#############################################################################
class PasswordLockTime:
    """
    Class: PasswordLockTime
    """

    def __init__(self):
        """
        function : Init class PasswordLockTime
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPasswordLockTime():
    """
    function : Collector PasswordLockTime
    input  : NA
    output : Instantion
    """
    data = PasswordLockTime()
    data.db = []
    sql_query = """show password_lock_time;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Rol Password
#############################################################################
class RolPassword:
    """
    Class: RolPassword
    """

    def __init__(self):
        """
        function : Init class RolPassword
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectRolPassword():
    """
    function : Collector RolPassword
    input  : NA
    output : Instantion
    """
    data = RolPassword()
    data.db = []
    sql_query = """SELECT rolpassword FROM pg_authid WHERE rolsuper=true;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Rol valid
#############################################################################
class RolValid:
    """
    Class: RolValid
    """

    def __init__(self):
        """
        function : Init class RolValid
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectRolValid():
    """
    function : Collector RolValid
    input  : NA
    output : Instantion
    """
    data = RolValid()
    data.db = []
    sql_query = """SELECT rolname, rolvalidbegin, rolvaliduntil FROM pg_roles WHERE rolsuper=false AND rolname NOT LIKE 'gs_role%' AND (rolvalidbegin IS NULL OR rolvaliduntil IS NULL);"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Password Effect Time
#############################################################################
class PasswordEffectTime:
    """
    Class: PasswordEffectTime
    """

    def __init__(self):
        """
        function : Init class PasswordEffectTime
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPasswordEffectTime():
    """
    function : Collector PasswordEffectTime
    input  : NA
    output : Instantion
    """
    data = PasswordEffectTime()
    data.db = []
    sql_query = """show password_effect_time;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Public Rol PG Authid
#############################################################################
class PublicRolPGAuthid:
    """
    Class: PublicRolPGAuthid
    """

    def __init__(self):
        """
        function : Init class PublicRolPGAuthid
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPublicRolPGAuthid():
    """
    function : Collector PublicRolPGAuthid
    input  : NA
    output : Instantion
    """
    data = PublicRolPGAuthid()
    data.db = []
    sql_query = """SELECT relname,relacl FROM pg_class WHERE relname = 'pg_authid' AND CAST(relacl AS TEXT) LIKE '%,=%}';"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Public Rol Create Perm
#############################################################################
class PublicRolCreatePerm:
    """
    Class: PublicRolCreatePerm
    """

    def __init__(self):
        """
        function : Init class PublicRolCreatePerm
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPublicRolCreatePerm():
    """
    function : Collector PublicRolCreatePerm
    input  : NA
    output : Instantion
    """
    data = PublicRolCreatePerm()
    data.db = []
    sql_query = """SELECT CAST(has_schema_privilege('public','public','CREATE') AS TEXT);"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Public Rol All Perm
#############################################################################
class PublicRolAllPerm:
    """
    Class: PublicRolAllPerm
    """

    def __init__(self):
        """
        function : Init class PublicRolAllPerm
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectPublicRolAllPerm():
    """
    function : Collector PublicRolAllPerm
    input  : NA
    output : Instantion
    """
    data = []
    data_table = PublicRolAllPerm()
    data_table.db = []
    sql_query_table = """SELECT relname,relacl FROM pg_class WHERE (CAST(relacl AS TEXT) LIKE '%,=arwdDxt/%}' OR CAST(relacl AS TEXT) LIKE '{=arwdDxt/%}') AND (CAST(relacl AS TEXT) LIKE '%,=APmiv/%}' OR CAST(relacl AS TEXT) LIKE '{=APmiv/%}');"""
    getDatabaseInfo(data_table, sql_query_table)
    data.append(data_table)
    data_schema = PublicRolAllPerm()
    data_schema.db = []
    sql_query_schema = """SELECT nspname,nspacl FROM pg_namespace WHERE (CAST(nspacl AS TEXT) LIKE '%,=UC/%}' OR CAST(nspacl AS TEXT) LIKE '{=UC/%}') AND (CAST(nspacl AS TEXT) LIKE '%,=APm/%}' OR CAST(nspacl AS TEXT) LIKE '{=APm/%}');"""
    getDatabaseInfo(data_schema, sql_query_schema)
    data.append(data_schema)
    data_function = PublicRolAllPerm()
    data_function.db = []
    sql_query_function = """SELECT proname,proacl FROM pg_proc WHERE (CAST(proacl AS TEXT) LIKE '%,=X/%}' OR CAST(proacl AS TEXT) LIKE '{=X/%}') AND (CAST(proacl AS TEXT) LIKE '%,=APm/%}' OR CAST(proacl AS TEXT) LIKE '{=APm/%}');"""
    getDatabaseInfo(data_function, sql_query_function)
    data.append(data_function)
    return data


#############################################################################
# Admin Privileges
#############################################################################
class AdminPrivileges:
    """
    Class: AdminPrivileges
    """

    def __init__(self):
        """
        function : Init class AdminPrivileges
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAdminPrivileges():
    """
    function : Collector AdminPrivileges
    input  : NA
    output : Instantion
    """
    data = []
    data_createrole = AdminPrivileges()
    data_createrole.db = []
    sql_query_createrole = """SELECT rolname FROM pg_roles WHERE rolcreaterole = true AND rolsuper = false;"""
    getDatabaseInfo(data_createrole, sql_query_createrole)
    data.append(data_createrole)
    data_createdb = AdminPrivileges()
    data_createdb.db = []
    sql_query_createdb = """SELECT rolname FROM pg_roles WHERE rolcreatedb = true AND rolsuper = false;"""
    getDatabaseInfo(data_createdb, sql_query_createdb)
    data.append(data_createdb)
    data_auditadmin = AdminPrivileges()
    data_auditadmin.db = []
    sql_query_auditadmin = """SELECT rolname FROM pg_roles WHERE rolauditadmin = true AND rolsuper = false;"""
    getDatabaseInfo(data_auditadmin, sql_query_auditadmin)
    data.append(data_auditadmin)
    data_monitoradmin = AdminPrivileges()
    data_monitoradmin.db = []
    sql_query_monitoradmin = """SELECT rolname FROM pg_roles WHERE rolmonitoradmin = true AND rolsuper = false;"""
    getDatabaseInfo(data_monitoradmin, sql_query_monitoradmin)
    data.append(data_monitoradmin)
    data_peratoradmin = AdminPrivileges()
    data_peratoradmin.db = []
    sql_query_peratoradmin = """SELECT rolname FROM pg_roles WHERE roloperatoradmin = true AND rolsuper = false;"""
    getDatabaseInfo(data_peratoradmin, sql_query_peratoradmin)
    data.append(data_peratoradmin)
    data_policyadmin = AdminPrivileges()
    data_policyadmin.db = []
    sql_query_policyadmin = """SELECT rolname FROM pg_roles WHERE rolpolicyadmin = true AND rolsuper = false;"""
    getDatabaseInfo(data_policyadmin, sql_query_policyadmin)
    data.append(data_policyadmin)
    return data


#############################################################################
# Enable Separation Of Duty
#############################################################################
class EnableSeparationOfDuty:
    """
    Class: EnableSeparationOfDuty
    """

    def __init__(self):
        """
        function : Init class EnableSeparationOfDuty
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectEnableSeparationOfDuty():
    """
    function : Collector EnableSeparationOfDuty
    input  : NA
    output : Instantion
    """
    data = EnableSeparationOfDuty()
    data.db = []
    sql_query = """show enableSeparationOfDuty;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Enable Copy Server Files
#############################################################################
class EnableCopyServerFiles:
    """
    Class: EnableCopyServerFiles
    """

    def __init__(self):
        """
        function : Init class EnableCopyServerFiles
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectEnableCopyServerFiles():
    """
    function : Collector EnableCopyServerFiles
    input  : NA
    output : Instantion
    """
    data = EnableCopyServerFiles()
    data.db = []
    sql_query = """show enable_copy_server_files;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Enabled
#############################################################################
class AuditEnabled:
    """
    Class: AuditEnabled
    """

    def __init__(self):
        """
        function : Init class AuditEnabled
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditEnabled():
    """
    function : Collector AuditEnabled
    input  : NA
    output : Instantion
    """
    data = AuditEnabled()
    data.db = []
    sql_query = """show audit_enabled;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Login Logout
#############################################################################
class AuditLoginLogout:
    """
    Class: AuditLoginLogout
    """

    def __init__(self):
        """
        function : Init class AuditLoginLogout
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditLoginLogout():
    """
    function : Collector AuditLoginLogout
    input  : NA
    output : Instantion
    """
    data = AuditLoginLogout()
    data.db = []
    sql_query = """show audit_login_logout;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Database Process
#############################################################################
class AuditDatabaseProcess:
    """
    Class: AuditDatabaseProcess
    """

    def __init__(self):
        """
        function : Init class AuditDatabaseProcess
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditDatabaseProcess():
    """
    function : Collector AuditDatabaseProcess
    input  : NA
    output : Instantion
    """
    data = AuditDatabaseProcess()
    data.db = []
    sql_query = """show audit_database_process;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit User Locked
#############################################################################
class AuditUserLocked:
    """
    Class: AuditUserLocked
    """

    def __init__(self):
        """
        function : Init class AuditUserLocked
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditUserLocked():
    """
    function : Collector AuditUserLocked
    input  : NA
    output : Instantion
    """
    data = AuditUserLocked()
    data.db = []
    sql_query = """show audit_user_locked;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Grant Revoke
#############################################################################
class AuditGrantRevoke:
    """
    Class: AuditGrantRevoke
    """

    def __init__(self):
        """
        function : Init class AuditGrantRevoke
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditGrantRevoke():
    """
    function : Collector AuditGrantRevoke
    input  : NA
    output : Instantion
    """
    data = AuditGrantRevoke()
    data.db = []
    sql_query = """show audit_grant_revoke;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit System Object
#############################################################################
class AuditSystemObject:
    """
    Class: AuditSystemObject
    """

    def __init__(self):
        """
        function : Init class AuditSystemObject
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditSystemObject():
    """
    function : Collector AuditSystemObject
    input  : NA
    output : Instantion
    """
    data = AuditSystemObject()
    data.db = []
    sql_query = """show audit_system_object;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Dml State Select
#############################################################################
class AuditDmlStateSelect:
    """
    Class: AuditDmlStateSelect
    """

    def __init__(self):
        """
        function : Init class AuditDmlStateSelect
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditDmlStateSelect():
    """
    function : Collector AuditDmlStateSelect
    input  : NA
    output : Instantion
    """
    data = AuditDmlStateSelect()
    data.db = []
    sql_query = """show audit_dml_state_select;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Resource Policy
#############################################################################
class AuditResourcePolicy:
    """
    Class: AuditResourcePolicy
    """

    def __init__(self):
        """
        function : Init class AuditResourcePolicy
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditResourcePolicy():
    """
    function : Collector AuditResourcePolicy
    input  : NA
    output : Instantion
    """
    data = AuditResourcePolicy()
    data.db = []
    sql_query = """show audit_resource_policy;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Rotation Interval
#############################################################################
class AuditRotationInterval:
    """
    Class: AuditRotationInterval
    """

    def __init__(self):
        """
        function : Init class AuditRotationInterval
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditRotationInterval():
    """
    function : Collector AuditRotationInterval
    input  : NA
    output : Instantion
    """
    data = AuditRotationInterval()
    data.db = []
    sql_query = """show audit_rotation_interval;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Rotation Size
#############################################################################
class AuditRotationSize:
    """
    Class: AuditRotationSize
    """

    def __init__(self):
        """
        function : Init class AuditRotationSize
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditRotationSize():
    """
    function : Collector AuditRotationSize
    input  : NA
    output : Instantion
    """
    data = AuditRotationSize()
    data.db = []
    sql_query = """show audit_rotation_size;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit Space Limit
#############################################################################
class AuditSpaceLimit:
    """
    Class: AuditSpaceLimit
    """

    def __init__(self):
        """
        function : Init class AuditSpaceLimit
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditSpaceLimit():
    """
    function : Collector AuditSpaceLimit
    input  : NA
    output : Instantion
    """
    data = AuditSpaceLimit()
    data.db = []
    sql_query = """show audit_space_limit;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Audit File Remain Threshold
#############################################################################
class AuditFileRemainThreshold:
    """
    Class: AuditFileRemainThreshold
    """

    def __init__(self):
        """
        function : Init class AuditFileRemainThreshold
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAuditFileRemainThreshold():
    """
    function : Collector AuditFileRemainThreshold
    input  : NA
    output : Instantion
    """
    data = AuditFileRemainThreshold()
    data.db = []
    sql_query = """show audit_file_remain_threshold;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Logging Collector
#############################################################################
class LoggingCollector:
    """
    Class: LoggingCollector
    """

    def __init__(self):
        """
        function : Init class LoggingCollector
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLoggingCollector():
    """
    function : Collector LoggingCollector
    input  : NA
    output : Instantion
    """
    data = LoggingCollector()
    data.db = []
    sql_query = """show logging_collector;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Filename
#############################################################################
class LogFilename:
    """
    Class: LogFilename
    """

    def __init__(self):
        """
        function : Init class LogFilename
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogFilename():
    """
    function : Collector LogFilename
    input  : NA
    output : Instantion
    """
    data = LogFilename()
    data.db = []
    sql_query = """show log_filename;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Filename
#############################################################################
class LogFileMode:
    """
    Class: LogFileMode
    """

    def __init__(self):
        """
        function : Init class LogFileMode
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogFileMode():
    """
    function : Collector LogFileMode
    input  : NA
    output : Instantion
    """
    data = LogFileMode()
    data.db = []
    sql_query = """show log_file_mode;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Truncate On Rotation
#############################################################################
class LogTruncateOnRotation:
    """
    Class: LogTruncateOnRotation
    """

    def __init__(self):
        """
        function : Init class LogTruncateOnRotation
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogTruncateOnRotation():
    """
    function : Collector LogTruncateOnRotation
    input  : NA
    output : Instantion
    """
    data = LogTruncateOnRotation()
    data.db = []
    sql_query = """show log_truncate_on_rotation;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Rotation Age
#############################################################################
class LogRotationAge:
    """
    Class: LogRotationAge
    """

    def __init__(self):
        """
        function : Init class LogRotationAge
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogRotationAge():
    """
    function : Collector LogRotationAge
    input  : NA
    output : Instantion
    """
    data = LogRotationAge()
    data.db = []
    sql_query = """show log_rotation_age;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Rotation Size
#############################################################################
class LogRotationSize:
    """
    Class: LogRotationSize
    """

    def __init__(self):
        """
        function : Init class LogRotationSize
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogRotationSize():
    """
    function : Collector LogRotationSize
    input  : NA
    output : Instantion
    """
    data = LogRotationSize()
    data.db = []
    sql_query = """show log_rotation_size;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Client Min Messages
#############################################################################
class ClientMinMessages:
    """
    Class: ClientMinMessages
    """

    def __init__(self):
        """
        function : Init class ClientMinMessages
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectClientMinMessages():
    """
    function : Collector ClientMinMessages
    input  : NA
    output : Instantion
    """
    data = ClientMinMessages()
    data.db = []
    sql_query = """show client_min_messages;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Min Messages
#############################################################################
class LogMinMessages:
    """
    Class: LogMinMessages
    """

    def __init__(self):
        """
        function : Init class LogMinMessages
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogMinMessages():
    """
    function : Collector LogMinMessages
    input  : NA
    output : Instantion
    """
    data = LogMinMessages()
    data.db = []
    sql_query = """show log_min_messages;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Min ErrorStatement
#############################################################################
class LogMinErrorStatement:
    """
    Class: LogMinErrorStatement
    """

    def __init__(self):
        """
        function : Init class LogMinErrorStatement
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogMinErrorStatement():
    """
    function : Collector LogMinErrorStatement
    input  : NA
    output : Instantion
    """
    data = LogMinErrorStatement()
    data.db = []
    sql_query = """show log_min_error_statement;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Connections
#############################################################################
class LogConnections:
    """
    Class: LogConnections
    """

    def __init__(self):
        """
        function : Init class LogConnections
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogConnections():
    """
    function : Collector LogConnections
    input  : NA
    output : Instantion
    """
    data = LogConnections()
    data.db = []
    sql_query = """show log_connections;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Disconnections
#############################################################################
class LogDisconnections:
    """
    Class: LogDisconnections
    """

    def __init__(self):
        """
        function : Init class LogDisconnections
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogDisconnections():
    """
    function : Collector LogDisconnections
    input  : NA
    output : Instantion
    """
    data = LogDisconnections()
    data.db = []
    sql_query = """show log_disconnections;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Error Verbosity
#############################################################################
class LogErrorVerbosity:
    """
    Class: LogErrorVerbosity
    """

    def __init__(self):
        """
        function : Init class LogErrorVerbosity
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogErrorVerbosity():
    """
    function : Collector LogErrorVerbosity
    input  : NA
    output : Instantion
    """
    data = LogErrorVerbosity()
    data.db = []
    sql_query = """show log_error_verbosity;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Log Hostname
#############################################################################
class LogHostname:
    """
    Class: LogHostname
    """

    def __init__(self):
        """
        function : Init class LogHostname
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectLogHostname():
    """
    function : Collector LogHostname
    input  : NA
    output : Instantion
    """
    data = LogHostname()
    data.db = []
    sql_query = """show log_hostname;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Debug PrintParse
#############################################################################
class DebugPrintParse:
    """
    Class: DebugPrintParse
    """

    def __init__(self):
        """
        function : Init class DebugPrintParse
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectDebugPrintParse():
    """
    function : Collector DebugPrintParse
    input  : NA
    output : Instantion
    """
    data = DebugPrintParse()
    data.db = []
    sql_query = """show debug_print_parse;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Debug PrintPlan
#############################################################################
class DebugPrintPlan:
    """
    Class: DebugPrintPlan
    """

    def __init__(self):
        """
        function : Init class DebugPrintPlan
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectDebugPrintPlan():
    """
    function : Collector DebugPrintPlan
    input  : NA
    output : Instantion
    """
    data = DebugPrintPlan()
    data.db = []
    sql_query = """show debug_print_plan;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Debug Print Rewritten
#############################################################################
class DebugPrintRewritten:
    """
    Class: DebugPrintRewritten
    """

    def __init__(self):
        """
        function : Init class DebugPrintRewritten
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectDebugPrintRewritten():
    """
    function : Collector DebugPrintRewritten
    input  : NA
    output : Instantion
    """
    data = DebugPrintRewritten()
    data.db = []
    sql_query = """show debug_print_rewritten;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# WalLevel
#############################################################################
class WalLevel:
    """
    Class: WalLevel
    """

    def __init__(self):
        """
        function : Init class WalLevel
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectWalLevel():
    """
    function : Collector WalLevel
    input  : NA
    output : Instantion
    """
    data = WalLevel()
    data.db = []
    sql_query = """show wal_level;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# ArchiveMode
#############################################################################
class ArchiveMode:
    """
    Class: ArchiveMode
    """

    def __init__(self):
        """
        function : Init class ArchiveMode
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectArchiveMode():
    """
    function : Collector ArchiveMode
    input  : NA
    output : Instantion
    """
    data = ArchiveMode()
    data.db = []
    sql_query_wal = """show wal_level;"""
    getDatabaseInfo(data, sql_query_wal)
    sql_query_archive = """show archive_mode;"""
    getDatabaseInfo(data, sql_query_archive)
    return data


#############################################################################
# Umask
#############################################################################
class Umask:
    """
    Class: Umask
    """

    def __init__(self):
        """
        function : Init class Umask
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectUmask():
    """
    function : Collector Umask
    input  : NA
    output : Instantion
    """
    data = Umask()
    cmd = "umask"
    (output, error, status) = CmdUtil.execCmdList('umask', subprocess.PIPE, True)
    if status == 0:
        data.output = output
    else:
        data.errormsg = error
    return data


#############################################################################
# Hidepid
#############################################################################
class Hidepid:
    """
    Class: Hidepid
    """

    def __init__(self):
        """
        function : Init class Hidepid
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectHidepid():
    """
    function : Collector Hidepid
    input  : NA
    output : Instantion
    """
    data = Hidepid()
    cmd = 'mount | grep "proc on /proc" | grep hidepid'
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        data.output = result.stdout
    else:
        data.errormsg = result.stderr
    return data


#############################################################################
# Ntpd
#############################################################################
class Ntpd:
    """
    Class: Ntpd
    """

    def __init__(self):
        """
        function : Init class Ntpd
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectNtpd():
    """
    function : Collector Ntpd
    input  : NA
    output : Instantion
    """
    data = Ntpd()
    cmd = 'service ntpd status 2>&1 | grep Active'
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if not result.stdout:
        cmd = 'systemctl status ntpd.service'
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
    data.output = result.stdout
    return data


#############################################################################
# Backslash Quote
#############################################################################
class BackslashQuote:
    """
    Class: BackslashQuote
    """

    def __init__(self):
        """
        function : Init class BackslashQuote
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectBackslashQuote():
    """
    function : Collector BackslashQuote
    input  : NA
    output : Instantion
    """
    data = BackslashQuote()
    data.db = []
    sql_query = """show backslash_quote;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
# Allow System Table Mods
#############################################################################
class AllowSystemTableMods:
    """
    Class: AllowSystemTableMods
    """

    def __init__(self):
        """
        function : Init class AllowSystemTableMods
        input  : NA
        output : NA
        """
        self.output = None
        self.db = None
        self.errormsg = None


def collectAllowSystemTableMods():
    """
    function : Collector AllowSystemTableMods
    input  : NA
    output : Instantion
    """
    data = AllowSystemTableMods()
    data.db = []
    sql_query = """show allow_system_table_mods;"""
    getDatabaseInfo(data, sql_query)
    return data


#############################################################################
def checkConnection(isSetting=False):
    """
    function : Check Connection
    input  : Bool
    output : NA
    """
    checkMonitorIP(isSetting)
    checkPortsforServices()
    checkConnectionConfiguration(isSetting)
    checkDBConnection(isSetting)
    checkAdminConnection(isSetting)
    checkUserConnection(isSetting)
    checkUnixsocket(isSetting)
    checkMD5Host()
    checkHostnossl()
    checkHostAddressno0()
    checkSSLConnection(isSetting)


def checkMonitorIP(isSetting):
    """
    function : Check MonitorIP
    input  : NA
    output : NA
    """
    data = collectMonitorIP()
    if not (data.output == 0):
        if not isSetting:
            g_logger.log(
                "        Warning reason:Prohibit listening on all IP addresses on the host.Listening to all IP addresses will not achieve network isolation. By prohibiting listening to all IP addresses on the host, malicious connection requests from other networks can be blocked.You should set the parameter listen_addresses to \"localhost\" or the IP address of the network card that needs to receive business requests. Multiple addresses are separated by commas, and then restart the database.")
        else:
            setMonitorIP(data)

def checkPortsforServices():
    """
    function : Check collectPortsforServices
    input  : NA
    output : NA
    """
    data = collectPortsforServices()
    if data.output == 5432:
        g_logger.log("        Warning reason:Ensure external service ports use non-default port numbers.Using default port numbers makes it easy for malicious attackers to access and attack the system. It is necessary to configure the external service port number to a non-default port number.You can specify the port numbers for each instance either through the configuration file during database installation or in the configuration files located in the database data directory.")

def checkConnectionConfiguration(isSetting):
    """
    function : Check connection Configuration
    input  : Bool
    output : NA
    """
    expectedConnection = 5000
    data = collectConnectionConfiguration()
    if (data.output != expectedConnection):
        if not isSetting:
            g_logger.log("        Warning reason:Ensure correct configuration of maximum connection settings for the database instance.Setting parameters too high may cause the database to request more System V shared memory or semaphores, exceeding the values allowed by the operating system's default configuration. Users need to determine the size of parameter values based on business specifications or consult technical support.You can modify the value of the parameter max_connections and then restart the database.")
        else:
            admin_connections = collectAdminConnection()
            if admin_connections.output >= 5000:
                setAdminConnection(admin_connections)
            setConnectionConfiguration(data)

def checkDBConnection(isSetting):
    """
    function : Check DataBase connection
    input  : Bool
    output : NA
    """
    data = collectDBConnection()
    if (data.output > 0):
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure the maximum connection settings for the database are configured correctly.Setting the parameter datconnlimit too low will affect the maximum number of concurrent connections to the database. Setting it too high or without any limit may lead to exceeding the system's load capacity due to the number of sessions, thereby impacting the database's availability.")
        else:
            setDBConnection(data)

def checkAdminConnection(isSetting):
    """
    function : Check Admin connection
    input  : Bool
    output : NA
    """
    data = collectAdminConnection()
    if not ((data.output < data.maxValue) and (data.output >= 3)):
        if not isSetting:
            g_logger.log("        Warning reason:Ensure the connection settings used by system administrators are configured correctly.The parameter sysadmin_reserved_connections represents the minimum number of connections reserved for the database system administrator. This ensures that there are dedicated connection channels for the system administrator, preventing connections from being occupied by regular users or malicious users, which could otherwise prevent the administrator from connecting. The value of this parameter must be less than the value of max_connections.")
        else:
            setAdminConnection(data)

def checkUserConnection(isSetting):
    """
    function : Check User connection
    input  : Bool
    output : NA
    """
    data = collectUserConnection()
    if not (data.output == 1):
        if not isSetting:
            g_logger.log("        Warning reason:Ensure the maximum connection settings for users are configured correctly.When the actual number of connections for the current user exceeds the user's maximum connection limit, no new connections can be established.Limiting the maximum number of connections for different users based on business requirements can prevent a single user from monopolizing all connections.")
        else:
            setUserConnection(data)

def checkUnixsocket(isSetting):
    """
    function : Check Unixsocket
    input  : Bool
    output : NA
    """
    data = collectUnixsocket()
    if not (data.output == '0700'):
        if not isSetting:
            g_logger.log("        Warning reason:Ensure correct access permissions are configured for UNIX domain sockets.The recommended configuration is 0700 (only the user currently connected to the database can access it, neither members of the same group nor others have permission), which meets the requirement for minimal file permissions. This prevents files from being accessed or altered by other users, thus safeguarding socket communication functionality.")
        else:
            setUnixsocket(data)

def checkMD5Host():
    """
    function : Check MD5Host
    input  : NA
    output : NA
    """
    data = collectMD5Host()
    if data.output:
        g_logger.log("        Warning reason:Ensure there are no 'host' entries using MD5 authentication.The MD5 authentication method poses security risks and may lead to password cracking. It is advisable to use a more secure authentication method such as SHA256 or certificate-based authentication.")

def checkHostnossl():
    """
    function : Check Hostnossl
    input  : NA
    output : NA
    """
    data = collectHostnossl()
    if data.output:
        g_logger.log("        Warning reason:Ensure there are no 'hostnossl' entries.The 'hostnossl' entry specifies connections that do not use SSL encryption, while the 'host' entry allows both SSL and non-SSL connections. The 'hostssl' entry is restricted to using only SSL connections. From a security standpoint, it is recommended to use SSL encryption for data transmission to prevent information leakage.")

def checkHostAddressno0():
    """
    function : Check HostAddressno0
    input  : NA
    output : NA
    """
    data = collectHostAddressno0()
    if data.output:
        g_logger.log(
            "        Warning reason:Ensure there are no 'host' entries specifying the source address as 0.0.0.0/0.Allowing any IP to connect to the database can lead to malicious users launching network attacks, compromising the database's security. It is recommended that the source addresses configured in the 'host' entry should only include the IPs that need to connect to the database.")

def checkSSLConnection(isSetting):
    """
    function : Check SSLConnection
    input  : NA
    output : NA
    """
    data = collectSSLConnection()
    if (data.output == 'off'):
        if not isSetting:
            g_logger.log("        Warning reason:Ensure SSL connections are enabled on the server side.Enabling this parameter also requires ensuring that the ssl_cert_file, ssl_key_file, and ssl_ca_file parameters are correctly configured, and that the SSL certificate permissions are set to 0600. Incorrect configurations may prevent the database from starting normally. Additionally, enabling SSL connections will have some impact on performance.")
        else:
            setSSLConnection(data)


#############################################################################
def setConnection(isSetting=True):
    """
    function : Set Connection
    input  : Boolean
    output : NA
    """
    checkMonitorIP(isSetting)
    checkConnectionConfiguration(isSetting)
    checkDBConnection(isSetting)
    checkAdminConnection(isSetting)
    checkUserConnection(isSetting)
    checkUnixsocket(isSetting)
    checkSSLConnection(isSetting)

def restartNode():
    """
    function : restart db node
    input  : NA
    output : NA
    """
    cmd_restart = [
            'gs_ctl', 'restart',
            '-D', os.getenv('PGDATA')
        ]
    CmdUtil.execCmdList(cmd_restart)

def setNodeParamter(config):
    """
    function : set db parameter
    input  : config
    output : output
    """
    pgdata = os.getenv('PGDATA')
    cmd_set = [
        'gs_guc', 'set',
        '-D', pgdata,
        '-c', config
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_set, subprocess.PIPE, True)
    return output

def reloadNodeParamter(config):
    """
    function : reload db parameter
    input  : config
    output : output
    """
    pgdata = os.getenv('PGDATA')
    cmd_reload = [
        'gs_guc', 'reload',
        '-D', pgdata,
        '-c', config
    ]
    (output, error, status) = CmdUtil.execCmdList(cmd_reload, subprocess.PIPE, True)
    return output


def setMonitorIP(data):
    """
    function : Set Monitor IP
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter("listen_addresses='localhost'")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Monitor IP")    
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setConnectionConfiguration(data):
    """
    function : Set Connection Configuration
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter('max_connections=5000')
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Connection Configuration.")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setDBConnection(data):
    """
    function : Set DataBase Connection
    input  : Instantion
    output : NA
    """
    result = collectDBConnection()
    result.db = []
    try:
        for item in data.db:
            sql_query = """UPDATE pg_database SET datconnlimit=1024 WHERE datname='%s';""" %(item.strip())
            getDatabaseInfo(result, sql_query)
    except Exception as e:
        data.errormsg = e.__str__()

def setAdminConnection(data):
    """
    function : Set Admin Connection
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter('sysadmin_reserved_connections=3')
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Admin Connection")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setUserConnection(data):
    """
    function : Set User Connection
    input  : Instantion
    output : NA
    """
    result = collectUserConnection()
    result.db = []
    try:
        for item in data.db:
            user_to_modify = item.split("|")[0].strip()
            if user_to_modify == getUserInfo().username:
                continue
            sql_query = """ALTER ROLE %s CONNECTION LIMIT 1024;""" % user_to_modify
            getDatabaseInfo(result, sql_query)
    except Exception as e:
        data.errormsg = e.__str__()

def setUnixsocket(data):
    """
    function : Set Unix socket
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter('unix_socket_permissions=0700')
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Unix socket")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setSSLConnection(data):
    """
    function : Set SSL Connection
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter('ssl=on')
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set SSL Connection")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkFileSecurity(isSetting=False):
    """
    function : Check File Security
    input  : Bool
    output : NA
    """
    checkMinHome(isSetting)
    checkMinShare(isSetting)
    checkMinBin(isSetting)
    checkMinData(isSetting)
    checkMinArchive(isSetting)
    checkMinPGConf(isSetting)
    checkMinPGHbaConf(isSetting)
    checkMinPGLog(isSetting)


def checkMinHome(isSetting):
    """
    function : Check MinData
    input  : Bool
    output : NA
    """
    data = collectMinHome()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for the database installation directory.To prevent files in the installation directory from being maliciously tampered with or destroyed, this directory should be protected and access should not be allowed for non-database installation users. Proper permission settings can ensure the security of the database system.")
        else:
            setMinHome(data)

def checkMinShare(isSetting):
    """
    function : Check MinShare
    input  : Bool
    output : NA
    """
    data = collectMinShare()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for shared directories.To prevent shared components from being maliciously tampered with or destroyed, this directory should be protected and access should not be allowed for non-database installation users.")
        else:
            setMinShare(data)

def checkMinBin(isSetting):
    """
    function : Check MinBin
    input  : Bool
    output : NA
    """
    data = collectMinBin()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for binary file directories.To prevent binary files from being maliciously tampered with or destroyed, thereby threatening the security of client information, this directory should be protected and access should not be allowed for non-database installation users.")
        else:
            setMinBin(data)

def checkMinData(isSetting):
    """
    function : Check MinData
    input  : Bool
    output : NA
    """
    data = collectMinData()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for data directories.The data directory contains user data files. To prevent these data files from being maliciously tampered with or destroyed, which could threaten the security of client data, this directory should be protected and access should not be allowed for non-database installation users.")
        else:
            setMinData(data)

def checkMinArchive(isSetting):
    """
    function : Check MinArchive
    input  : Bool
    output : NA
    """
    data = collectMinArchive()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for log archive directories.When the wal_level parameter is set to 'archive', the directory permissions should be configured to 0700 to ensure that only the database installation user has access.")
        else:
            setMinArchive(data)

def checkMinPGConf(isSetting):
    """
    function : Check MinPGConf
    input  : Bool
    output : NA
    """
    data = collectMinPGConf()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for the postgresql.conf file.The configuration file postgresql.conf contains the operational parameters for the database. To prevent malicious tampering with the configuration file, it should be protected and access should not be allowed for non-database installation users.")
        else:
            setMinPGConf(data)

def checkMinPGHbaConf(isSetting):
    """
    function : Check MinPGHbaConf
    input  : Bool
    output : NA
    """
    data = collectMinPGHbaConf()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for the pg_hba.conf file.The configuration file pg_hba.conf contains connection information for the database, such as client authentication methods. To prevent malicious tampering with the configuration file, it should be protected and access should only be allowed for the database installation user.")
        else:
            setMinPGHbaConf(data)

def checkMinPGLog(isSetting):
    """
    function : Check MinPGLog
    input  : Bool
    output : NA
    """
    data = collectMinPGLog()
    if data.output:
        if not isSetting:
            g_logger.log("        Warning reason:Ensure minimal permissions for the log directory.The database log directory contains many operational logs, and to prevent these log files from being maliciously tampered with or destroyed, thereby threatening the security of client data, this directory should be protected and access should not be allowed for non-database installation users.")
        else:
            setMinPGLog(data)


#############################################################################
def setFileSecurity(isSetting=True):
    """
    function : Set File Security
    input  : Bool
    output : NA
    """
    checkMinHome(isSetting)
    checkMinShare(isSetting)
    checkMinBin(isSetting)
    checkMinData(isSetting)
    checkMinArchive(isSetting)
    checkMinPGConf(isSetting)
    checkMinPGHbaConf(isSetting)
    checkMinPGLog(isSetting)


def setMinHome(data):
    """
    function : Set Min Home
    input  : Instantion
    output : NA
    """
    try:
        cmd_set = ['chmod', '0700', os.getenv('GAUSSHOME')]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Home")
        data.errormsg = e.__str__()

def setMinShare(data):
    """
    function : Set Min Share
    input  : Instantion
    output : NA
    """
    try:
        share_path = os.path.join(os.getenv('GAUSSHOME'), 'share')
        cmd_set = ['chmod', '0700', share_path]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Share")
        data.errormsg = e.__str__()

def setMinBin(data):
    """
    function : Set Min Bin
    input  : Instantion
    output : NA
    """
    try:
        bin_path = os.path.join(os.getenv('GAUSSHOME'), 'bin')
        cmd_set = ['chmod', '0700', bin_path]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Bin")
        data.errormsg = e.__str__()

def setMinData(data):
    """
    function : Set Min Data
    input  : Instantion
    output : NA
    """
    try:
        cmd_set = ['chmod', '0700', os.getenv('PGDATA')]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Data")
        data.errormsg = e.__str__()

def setMinArchive(data):
    """
    function : Set Min Archive
    input  : Instantion
    output : NA
    """
    try:
        archive_path = os.path.join(os.getenv('GAUSSHOME'), 'archive')
        cmd_set = ['chmod', '0700', archive_path]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Archive")
        data.errormsg = e.__str__()

def setMinPGConf(data):
    """
    function : Set Min PGConf
    input  : Instantion
    output : NA
    """
    try:
        pgconf_path = os.path.join(os.getenv('PGDATA'), 'postgresql.conf')
        cmd_set = ['chmod', '0600', pgconf_path]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Data")
        data.errormsg = e.__str__()

def setMinPGHbaConf(data):
    """
    function : Set Min PGHbaConf
    input  : Instantion
    output : NA
    """
    try:
        pghba_conf = os.path.join(os.getenv('PGDATA'), 'pg_hba.conf')
        cmd_set = ['chmod', '0600', pghba_conf]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Data")
        data.errormsg = e.__str__()

def setMinPGLog(data):
    """
    function : Set Min PGLog
    input  : Instantion
    output : NA
    """
    try:
        cmd_set = ['chmod', '0700', os.getenv('GAUSSLOG')]
        CmdUtil.execCmdList(cmd_set)
    except Exception as e:
        g_logger.log("Failed to set Min Data")
        data.errormsg = e.__str__()


#############################################################################
def checkSecurityAuthConf(isSetting=False):
    """
    function : Check Security Auth Conf
    input  : Bool
    output : NA
    """
    checkClientAuthTime(isSetting)
    checkAuthEncriptionCount(isSetting)
    checkFailedLoginCount(isSetting)


def checkClientAuthTime(isSetting):
    """
    function : Check ClientAuthTime
    input  : Bool
    output : NA
    """
    data = collectClientAuthTime()
    if not data.db[0].strip() == '1min':
        if not isSetting:
            g_logger.log("        Warning reason: Ensure correct client authentication timeout configuration.The default timeout is recommended to be set to 1 minute. If a client does not complete authentication with the server within the parameter-set time, the server automatically disconnects from the client. This prevents problematic clients from indefinitely occupying connection slots.Setting the parameter value too low may lead to authentication failures due to timeouts.")
        else:
            setClientAuthTime(data)

def checkAuthEncriptionCount(isSetting):
    """
    function : Check AuthEncriptionCount
    input  : Bool
    output : NA
    """
    data = collectAuthEncriptionCount()
    if int(data.db[0]) < 10000:
        if not isSetting:
            g_logger.log("        Warning reason: Ensure correct configuration of authentication encryption iteration counts.Setting the number of iterations too low will reduce the security of password storage, while setting it too high can degrade performance in scenarios involving password encryption, such as user creation and authentication. Please set the number of iterations reasonably according to actual hardware conditions, with a minimum of 10,000 iterations.")
        else:
            setAuthEncriptionCount(data)

def checkFailedLoginCount(isSetting):
    """
    function : Check FailedLoginCount
    input  : Bool
    output : NA
    """
    data = collectFailedLoginCount()
    if int(data.db[0]) == 0:
        if not isSetting:
            g_logger.log("        Warning reason: Ensure correct configuration of account login failure attempt counts.Configuring the number of failed login attempts through the parameter 'failed_login_attempts' can prevent passwords from being cracked by brute force.When the number of consecutive authentication failures exceeds this parameter value, the account will be automatically locked.")
        else:
            setFailedLoginCount(data)


#############################################################################
def setSecurityAuthenticationConfiguration(isSetting=True):
    """
    function : Set Security Authentication Configuration
    input  : Bool
    output : NA
    """
    checkClientAuthTime(isSetting)
    checkAuthEncriptionCount(isSetting)
    checkFailedLoginCount(isSetting)


def setClientAuthTime(data):
    """
    function : Set Client AuthTime
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("authentication_timeout=1min")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Client AuthTime")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuthEncriptionCount(data):
    """
    function : Set AuthEncription Count
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("auth_iteration_count=10000")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set AuthEncription Count")
    except Exception as e:
        data.errormsg = e.__str__()

def setFailedLoginCount(data):
    """
    function : Set FailedLogin Count
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("failed_login_attempts=10")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set FailedLogin Count")
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkAccountPasswordManagement(isSetting=False):
    """
    function : Check Account Password Management
    input  : Bool
    output : NA
    """
    checkPasswordComplexityValidation(isSetting)
    checkPasswordEncryptionType(isSetting)
    checkPasswordReuseTime(isSetting)
    checkPasswordLockTime(isSetting)
    checkRolPassword()
    checkRolValid(isSetting)
    checkPasswordEffectTime(isSetting)


def checkPasswordComplexityValidation(isSetting):
    """
    function : Check PasswordComplexityValidation
    input  : Bool
    output : NA
    """
    data = collectPasswordComplexityValidation()
    if not int(data.db[0]) == 1:
        if not isSetting:
            g_logger.log("        Warning reason: Ensure password complexity checking is enabled.Passwords with low complexity are easily guessed or cracked by brute force. For the sake of password security, please enable password complexity checks.")
        else:
            setPasswordComplexityValidation(data)

def checkPasswordEncryptionType(isSetting):
    """
    function : Check PasswordEncryptionType
    input  : Bool
    output : NA
    """
    data = collectPasswordEncryptionType()
    if int(data.db[0]) == 0 or int(data.db[0]) == 1:
        if not isSetting:
            g_logger.log("        Warning reason: Ensure password encryption method is configured correctly.The MD5 method has been proven to be insecure and should not be configured, it is retained only for compatibility with open-source third-party tools. It should be configured to use the SHA256 method (default configuration).")
        else:
            setPasswordEncryptionType(data)

def checkPasswordReuseTime(isSetting):
    """
    function : Check PasswordReuseTime
    input  : Bool
    output : NA
    """
    data = collectPasswordReuseTime()
    if int(data.db[0]) == 0:
        if not isSetting:
            g_logger.log("        Warning reason: Ensure correct configuration of password reuse days.Avoid users repeatedly using the same password, as it may lead to the password being cracked.")
        else:
            setPasswordReuseTime(data)

def checkPasswordLockTime(isSetting):
    """
    function : Check PasswordLockTime
    input  : Bool
    output : NA
    """
    data = collectPasswordLockTime()
    if data.db[0].strip() == "0":
        if not isSetting:
            g_logger.log("        Warning reason: Ensure correct configuration of account automatic unlock time.To prevent passwords from being attempted to be cracked by brute force, this parameter must be set to a non-zero value.")
        else:
            setPasswordLockTime(data)

def checkRolPassword():
    """
    function : Check RolPassword
    input  : NA
    output : NA
    """
    data = collectRolPassword()
    if not data.db[0].strip():
        g_logger.log("        Warning reason: Ensure initial user password change at first login.If the initial user password is empty and not promptly modified, it can easily lead to low-cost attack incidents and also raise external doubts, posing security risks.")

def checkRolValid(isSetting):
    """
    function : Check RolValid
    input  : Bool
    output : NA
    """
    data = collectRolValid()
    if data.db[0].strip():
        if not isSetting:
            g_logger.log("        Warning reason: Ensure configuration of user expiration periods.If this configuration is ignored, there may be a risk of inconsistent expiration times for login accounts across nodes. Therefore, it is recommended to reasonably configure the validity period of users or roles according to business needs, and timely clean up unused expired users or roles.")
        else:
            setRolValid(data)

def checkPasswordEffectTime(isSetting):
    """
    function : Check PasswordEffectTime
    input  : Bool
    output : NA
    """
    data = collectPasswordEffectTime()
    if data.db[0].strip() == "0":
        if not isSetting:
            g_logger.log("        Warning reason: Ensure configuration of password expiration periods.Once the password reaches its expiration reminder time, the system will prompt the user to change the password when logging into the database. It is recommended that users regularly update their passwords to enhance the security of password usage.")
        else:
            setPasswordEffectTime(data)


#############################################################################
def setAccountPasswordManagement(isSetting=True):
    """
    function : Set Account Password Management
    input  : Bool
    output : NA
    """
    checkPasswordComplexityValidation(isSetting)
    checkPasswordEncryptionType(isSetting)
    checkPasswordReuseTime(isSetting)
    checkPasswordLockTime(isSetting)
    checkRolValid(isSetting)
    checkPasswordEffectTime(isSetting)


def setPasswordComplexityValidation(data):
    """
    function : Set Password Complexity Validation
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("password_policy=1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Password Complexity Validation")
    except Exception as e:
        data.errormsg = e.__str__()

def setPasswordEncryptionType(data):
    """
    function : Set Password Encryption Type
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("password_encryption_type=2")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Password Encryption Type")
    except Exception as e:
        data.errormsg = e.__str__()

def setPasswordReuseTime(data):
    """
    function : Set Password ReuseTime
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("password_reuse_time=60")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Password Encryption Type")
    except Exception as e:
        data.errormsg = e.__str__()

def setPasswordLockTime(data):
    """
    function : Set Password Lock Time
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("password_lock_time=1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Password Lock Time")
    except Exception as e:
        data.errormsg = e.__str__()

def setRolValid(data):
    """
    function : Set Rol Valid
    input  : Instantion
    output : NA
    """
    result = collectRolValid()
    result.db = []
    try:
        now = datetime.now()
        one_year_later = now + timedelta(days=365)
        start_date_str = now.strftime('%Y-%m-%d')
        end_date_str = one_year_later.strftime('%Y-%m-%d')
        for item in data.db:
            sql_query = """ALTER ROLE %s VALID BEGIN '%s' VALID UNTIL '%s';""" %(item.split("|")[0].strip(), start_date_str, end_date_str)
            getDatabaseInfo(result, sql_query)
    except Exception as e:
        data.errormsg = e.__str__()

def setPasswordEffectTime(data):
    """
    function : Set Password Effect Time
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("password_effect_time=90")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Password Effect Time")
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkPermissionManagement(isSetting=False):
    """
    function : Check Permission Management
    input  : Bool
    output : NA
    """
    checkPublicRolPGAuthid(isSetting)
    checkPublicRolCreatePerm(isSetting)
    checkPublicRolAllPerm(isSetting)
    checkAdminPrivileges(isSetting)
    checkEnableSeparationOfDuty(isSetting)
    checkEnableCopyServerFiles(isSetting)


def checkPublicRolPGAuthid(isSetting):
    """
    function : Check PublicRolPGAuthid
    input  : Bool
    output : NA
    """
    data = collectPublicRolPGAuthid()
    if data.db[0].strip():
        if not isSetting:
            g_logger.log(
                "        Warning reason: Prohibit the PUBLIC role from having permissions on the pg_authid system table.Since all users inherit the permissions of the PUBLIC role, to prevent sensitive information from being leaked or altered, the PUBLIC role is not allowed to have any permissions on the pg_authid system table.")
        else:
            setPublicRolPGAuthid(data)

def checkPublicRolCreatePerm(isSetting):
    """
    function : Check PublicRolCreatePerm
    input  : Bool
    output : NA
    """
    data = collectPublicRolCreatePerm()
    if data.db[0].strip() != "false":
        if not isSetting:
            g_logger.log(
                "        Warning reason: Disallow the PUBLIC role from having CREATE permissions in the public schema.If the PUBLIC role has CREATE permissions in the public schema, any user can create tables or other database objects in the public schema, which may lead to security risks as other users can also view and modify these tables and database objects.")
        else:
            setPublicRolCreatePerm(data)

def checkPublicRolAllPerm(isSetting):
    """
    function : Check PublicRolAllPerm
    input  : Bool
    output : NA
    """
    data = collectPublicRolAllPerm()
    if data[0].db[0].strip() or data[1].db[0].strip() or data[2].db[0].strip():
        if not isSetting:
            g_logger.log("        Warning reason:Disallow granting all privileges on objects to the PUBLIC role.The PUBLIC role belongs to any user, and if all permissions of an object are granted to the PUBLIC role, then any user will inherit all permissions of this object, which violates the principle of least privilege. To ensure the security of database data, this role should have as few permissions as possible, and it is prohibited to grant all permissions of an object to the PUBLIC role.")
        else:
            setPublicRolAllPerm(data)

def checkAdminPrivileges(isSetting):
    """
    function : Check AdminPrivileges
    input  : Bool
    output : NA
    """
    data = collectAdminPrivileges()
    if data[0].db[0].strip() or data[1].db[0].strip() or data[2].db[0].strip() or data[3].db[0].strip() or data[4].db[
        0].strip() or data[5].db[0].strip():
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure revocation of unnecessary administrative privileges from regular users.As a regular user, they should not possess administrative permissions beyond their normal scope. To ensure that the permissions of regular users are minimized while meeting normal business needs, unnecessary administrative permissions for regular users should be revoked.")
        else:
            setAdminPrivileges(data)

def checkEnableSeparationOfDuty(isSetting):
    """
    function : Check EnableSeparationOfDuty
    input  : Bool
    output : NA
    """
    data = collectEnableSeparationOfDuty()
    if data.db[0].strip() == "off":
        if not isSetting:
            g_logger.log("        Warning reason:Ensure separation of powers configuration is enabled.If a three-tier separation of powers permission management model needs to be used, it should be specified during the database initialization phase, and it is not recommended to switch back and forth between permission management models. Specifically, if switching from a non-three-tier separation of powers to a three-tier separation of powers permission management model is required, it is necessary to re-evaluate whether the existing user permission sets are reasonable.")
        else:
            setEnableSeparationOfDuty(data)

def checkEnableCopyServerFiles(isSetting):
    """
    function : Check EnableCopyServerFiles
    input  : Bool
    output : NA
    """
    data = collectEnableCopyServerFiles()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure removal of server-side file COPY permissions from system administrators.After canceling the server-side file COPY permissions for system administrators, system administrators will no longer be able to perform server-side file COPY operations. This configuration does not affect initial users.")
        else:
            setEnableCopyServerFiles(data)


#############################################################################
def setPermissionManagement(isSetting=True):
    """
    function : Set Permission Management
    input  : Bool
    output : NA
    """
    checkPublicRolPGAuthid(isSetting)
    checkPublicRolCreatePerm(isSetting)
    checkPublicRolAllPerm(isSetting)
    checkAdminPrivileges(isSetting)
    checkEnableSeparationOfDuty(isSetting)
    checkEnableCopyServerFiles(isSetting)


def setPublicRolPGAuthid(data):
    """
    function : Set Public Rol PG Authid
    input  : Instantion
    output : NA
    """
    result = PublicRolPGAuthid()
    result.db = []
    try:
        sql_query = """REVOKE ALL ON pg_authid FROM PUBLIC;"""
        getDatabaseInfo(result, sql_query)
    except Exception as e:
        data.errormsg = e.__str__()

def setPublicRolCreatePerm(data):
    """
    function : Set Public Rol Create Perm
    input  : Instantion
    output : NA
    """
    result = PublicRolCreatePerm()
    result.db = []
    try:
        sql_query = """REVOKE CREATE ON SCHEMA public FROM PUBLIC;"""
        getDatabaseInfo(result, sql_query)
    except Exception as e:
        data.errormsg = e.__str__()

def setPublicRolAllPerm(data):
    """
    function : Set Public Rol Create Perm
    input  : Instantion
    output : NA
    """
    result = PublicRolAllPerm()
    result.db = []
    try:
        if data[0].db[0].strip():
            for item in data[0].db:
                sql_query = """REVOKE ALL ON %s FROM PUBLIC;""" % (item.split("|")[0].strip())
                getDatabaseInfo(result, sql_query)
        if data[1].db[0].strip():
            for item in data[1].db:
                sql_query = """REVOKE ALL ON SCHEMA %s FROM PUBLIC;""" % (item.split("|")[0].strip())
                getDatabaseInfo(result, sql_query)
        if data[2].db[0].strip():
            set_remove_all_function(data[2].db, result)
    except Exception as e:
        raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] % e.__str__())

def set_remove_all_function(data, result):
    """
    function : Set Remove All Function
    input  : Instantion, Instantion
    output : NA
    """
    for item in data:
        df = PublicRolAllPerm()
        df.db = []
        proname = item.split("|")[0].strip()
        sql_df = """SELECT proargtypes::regtype[] AS arg_types, proargnames AS arg_names FROM pg_proc WHERE proname = '%s';""" % proname
        getDatabaseInfo(df, sql_df)
        for line in df.db:
            arg_type = extract_types(line.split("|")[0].strip())
            sql_query = """REVOKE ALL ON FUNCTION %s(%s) FROM PUBLIC;""" % (proname, arg_type)
            getDatabaseInfo(result, sql_query)

def setAdminPrivileges(data):
    """
    function : Set Admin Privileges
    input  : Instantion
    output : NA
    """
    result = AdminPrivileges()
    result.db = []
    try:
        alter_role(data, result)
    except Exception as e:
        data = AdminPrivileges()
        data.errormsg = e.__str__()

def alter_role(data, result):
    """
    function : Alter role
    input  : Instantion, Instantion
    output : NA
    """
    role_actions = [
        ("NOCREATEROLE", 0),
        ("NOCREATEDB", 1),
        ("NOAUDITADMIN", 2),
        ("NOMONADMIN", 3),
        ("NOOPRADMIN", 4),
        ("NOPOLADMIN", 5)
    ]

    for action, index in role_actions:
        for item in data[index].db:
            role_name = item.split("|")[0].strip()
            if not role_name:
                continue
            sql_query = f"ALTER ROLE {role_name} {action};"
            getDatabaseInfo(result, sql_query)

def setEnableSeparationOfDuty(data):
    """
    function : Set Enable Separation Of Duty
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter("enableSeparationOfDuty = on")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Enable Separation Of Duty")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setEnableCopyServerFiles(data):
    """
    function : Set Enable Copy Server Files
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("enable_copy_server_files=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Enable Copy Server Files")
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkDatabaseAuditing(isSetting=False):
    """
    function : Check Database Auditing
    input  : Bool
    output : NA
    """
    checkAuditEnabled(isSetting)
    checkAuditLoginLogout(isSetting)
    checkAuditDatabaseProcess(isSetting)
    checkAuditUserLocked(isSetting)
    checkAuditGrantRevoke(isSetting)
    checkAuditSystemObject(isSetting)
    checkAuditDmlStateSelect(isSetting)
    checkAuditResourcePolicy(isSetting)
    checkAuditRotationInterval(isSetting)
    checkAuditRotationSize(isSetting)
    checkAuditSpaceLimit(isSetting)
    checkAuditFileRemainThreshold(isSetting)


def checkAuditEnabled(isSetting):
    """
    function : Check AuditEnabled
    input  : Bool
    output : NA
    """
    data = collectAuditEnabled()
    if data.db[0].strip() != "on":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure database auditing functionality is enabled.Audit logs are stored in binary form in the pg_audit directory. Enabling auditing will increase disk space usage and have a certain impact on performance.")
        else:
            setAuditEnabled(data)

def checkAuditLoginLogout(isSetting):
    """
    function : Check AuditLoginLogout
    input  : Bool
    output : NA
    """
    data = collectAuditLoginLogout()
    if data.db[0].strip() != "7":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure user login and logout auditing is enabled.Enabling this option allows for tracking which users have logged into the database and when they logged out; otherwise, it is not possible to audit user login and logout activities.")
        else:
            setAuditLoginLogout(data)

def checkAuditDatabaseProcess(isSetting):
    """
    function : Check AuditDatabaseProcess
    input  : Bool
    output : NA
    """
    data = collectAuditDatabaseProcess()
    if data.db[0].strip() != "1":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure database startup, shutdown, recovery, and switchover auditing is enabled.Enabling this option allows for tracing changes in the database's operational status.")
        else:
            setAuditDatabaseProcess(data)

def checkAuditUserLocked(isSetting):
    """
    function : Check AuditUserLocked
    input  : Bool
    output : NA
    """
    data = collectAuditUserLocked()
    if data.db[0].strip() != "1":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure user lock and unlock auditing is enabled.Enabling this option allows for recording audit logs of locking and unlocking operations on database users.")
        else:
            setAuditUserLocked(data)

def checkAuditGrantRevoke(isSetting):
    """
    function : Check AuditGrantRevoke
    input  : Bool
    output : NA
    """
    data = collectAuditGrantRevoke()
    if data.db[0].strip() != "1":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure permission grant and revoke auditing is enabled.Enabling this option allows for recording audit logs of operations that grant and revoke database user permissions.")
        else:
            setAuditGrantRevoke(data)

def checkAuditSystemObject(isSetting):
    """
    function : Check AuditSystemObject
    input  : Bool
    output : NA
    """
    data = collectAuditSystemObject()
    if int(data.db[0].strip()) < 67121159:
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure auditing of database object creation, deletion, and modification is enabled.The parameter 'audit_system_object' determines whether to record audit logs for CREATE, DROP, and ALTER operations on database objects.")
        else:
            setAuditSystemObject(data)

def checkAuditDmlStateSelect(isSetting):
    """
    function : Check AuditDmlStateSelect
    input  : Bool
    output : NA
    """
    data = collectAuditDmlStateSelect()
    if data.db[0].strip() != "1":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure auditing of database object querying is enabled.Enabling this option allows for tracing user queries on the database, but usually, database query operations are relatively frequent. Enabling this option will affect query performance and result in increased audit log records, occupying more disk space. Users can decide whether to enable it based on business needs.")
        else:
            setAuditDmlStateSelect(data)

def checkAuditResourcePolicy(isSetting):
    """
    function : Check AuditResourcePolicy
    input  : Bool
    output : NA
    """
    data = collectAuditResourcePolicy()
    if data.db[0].strip() != "on":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure audit priority strategy configuration is correct.The space policy can ensure the upper limit of audit log disk usage, but it does not guarantee the retention of historical audit logs; the time limit policy ensures the retention of audit logs for a specific period, which may result in increased log space usage.")
        else:
            setAuditResourcePolicy(data)

def checkAuditRotationInterval(isSetting):
    """
    function : Check AuditRotationInterval
    input  : Bool
    output : NA
    """
    data = collectAuditRotationInterval()
    if data.db[0].strip() != "1d":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum retention period for individual audit files.Setting the parameter value too low will result in frequent generation of audit log files.Setting it too high will lead to a single file recording too many logs and occupying a large amount of space, which is not conducive to the management of audit log files.Do not adjust this parameter at will, otherwise it may cause the 'audit_resource_policy' parameter to become ineffective.")
        else:
            setAuditRotationInterval(data)

def checkAuditRotationSize(isSetting):
    """
    function : Check AuditRotationSize
    input  : Bool
    output : NA
    """
    data = collectAuditRotationSize()
    if data.db[0].strip() != "10MB":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum size for individual audit log files.Setting the parameter value too low will result in frequent generation of audit log files. Setting it too high will lead to a single file recording too many logs and occupying a large amount of space, which is not conducive to the management of audit log files. Please do not adjust this parameter at will, as it may cause the 'audit_resource_policy' parameter to become ineffective.")
        else:
            setAuditRotationSize(data)

def checkAuditSpaceLimit(isSetting):
    """
    function : Check AuditSpaceLimit
    input  : Bool
    output : NA
    """
    data = collectAuditSpaceLimit()
    if data.db[0].strip() != "1GB":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum disk space usage for all audit log files.Setting the parameter value too high will increase disk space usage. Setting it too low will result in a shorter retention time for audit logs, which may lead to the loss of important log information.")
        else:
            setAuditSpaceLimit(data)

def checkAuditFileRemainThreshold(isSetting):
    """
    function : Check AuditFileRemainThreshold
    input  : Bool
    output : NA
    """
    data = collectAuditFileRemainThreshold()
    if data.db[0].strip() != "1048576":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum number of audit log files.Setting the parameter value too high will increase disk space usage. Setting it too low will result in a shorter recordable period for audit logs, which may lead to the loss of important log information. Arbitrarily adjusting this parameter may affect the effectiveness of the 'audit_resource_policy' parameter.")
        else:
            setAuditFileRemainThreshold(data)


#############################################################################
def setDatabaseAuditing(isSetting=True):
    """
    function : Set Database Auditing
    input  : Bool
    output : NA
    """
    checkAuditEnabled(isSetting)
    checkAuditLoginLogout(isSetting)
    checkAuditDatabaseProcess(isSetting)
    checkAuditUserLocked(isSetting)
    checkAuditGrantRevoke(isSetting)
    checkAuditSystemObject(isSetting)
    checkAuditDmlStateSelect(isSetting)
    checkAuditResourcePolicy(isSetting)
    checkAuditRotationInterval(isSetting)
    checkAuditRotationSize(isSetting)
    checkAuditSpaceLimit(isSetting)
    checkAuditFileRemainThreshold(isSetting)

def setAuditEnabled(data):
    """
    function : Set Audit Enabled
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_enabled = on")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Enabled")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditLoginLogout(data):
    """
    function : Set Audit Login Logout
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_login_logout = 7")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Login Logout")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditDatabaseProcess(data):
    """
    function : Set Audit Database Process
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_database_process = 1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Database Process")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditUserLocked(data):
    """
    function : Set Audit User Locked
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_user_locked = 1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit User Locked")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditGrantRevoke(data):
    """
    function : Set Audit Grant Revoke
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_grant_revoke = 1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Grant Revoke")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditSystemObject(data):
    """
    function : Set Audit System Object
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_system_object = 67121159")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit System Object")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditDmlStateSelect(data):
    """
    function : Set Audit Dml State Select
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_dml_state_select = 1")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Dml State Select")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditResourcePolicy(data):
    """
    function : Set Audit Resource Policy
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_resource_policy = on")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Resource Policy")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditRotationInterval(data):
    """
    function : Set Audit Rotation Interval
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_rotation_interval = 1440")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Resource Policy")
            g_logger.log("Failed to set Audit Rotation Interval")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditRotationSize(data):
    """
    function : Set Audit Rotation Size
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_rotation_size = 10MB")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Rotation Size")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditSpaceLimit(data):
    """
    function : Set Audit Space Limit
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_space_limit = 1GB")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit Space Limit")
    except Exception as e:
        data.errormsg = e.__str__()

def setAuditFileRemainThreshold(data):
    """
    function : Set Audit File Remain Threshold
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("audit_file_remain_threshold = 1048576")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Audit File Remain Threshold")
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkErrorReportingAndLoggingConfiguration(isSetting=False):
    """
    function : Check Error Reporting And Logging Configuration
    input  : Bool
    output : NA
    """
    checkLoggingCollector(isSetting)
    checkLogFilename(isSetting)
    checkLogFileMode(isSetting)
    checkLogTruncateOnRotation(isSetting)
    checkLogRotationAge(isSetting)
    checkLogRotationSize(isSetting)
    checkClientMinMessages(isSetting)
    checkLogMinMessages(isSetting)
    checkLogMinErrorStatement(isSetting)
    checkLogConnections(isSetting)
    checkLogDisconnections(isSetting)
    checkLogErrorVerbosity(isSetting)
    checkLogHostname(isSetting)
    checkDebugPrintParse(isSetting)
    checkDebugPrintPlan(isSetting)
    checkDebugPrintRewritten(isSetting)


def checkLoggingCollector(isSetting):
    """
    function : Check LoggingCollector
    input  : Bool
    output : NA
    """
    data = collectLoggingCollector()
    if data.db[0].strip() != "on":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure the log collector is enabled.When sending server logs to stderr, the 'logging_collector' parameter can be omitted, and the log messages will be sent to the space pointed to by the server's stderr. The disadvantage of this method is that it is difficult to roll back logs and is only suitable for smaller log volumes.")
        else:
            setLoggingCollector(data)

def checkLogFilename(isSetting):
    """
    function : Check LogFilename
    input  : Bool
    output : NA
    """
    data = collectLogFilename()
    if data.db[0].strip() != "postgresql-%Y-%m-%d_%H%M%S.log":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct log name configuration.It is recommended to use the % escape character to define log file names, so that they can automatically include date and time information, thereby facilitating effective management of log files.")
        else:
            setLogFilename(data)

def checkLogFileMode(isSetting):
    """
    function : Check LogFileMode
    input  : Bool
    output : NA
    """
    data = collectLogFileMode()
    if data.db[0].strip() != "0600":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct log file permissions configuration.Log files may contain user data, so access to log files must be restricted to prevent the disclosure or tampering of log information.")
        else:
            setLogFileMode(data)

def checkLogTruncateOnRotation(isSetting):
    """
    function : Check LogTruncateOnRotation
    input  : Bool
    output : NA
    """
    data = collectLogTruncateOnRotation()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Prohibit overwriting of identically named log files.When set to 'on', the database will write server log messages in an overwrite mode, which means that when the log file is rotated, new log messages will overwrite old ones. When set to 'off', new log messages will be appended to the existing log file with the same name without overwriting the old ones. To ensure longer retention of logs, it is necessary to set this parameter to 'off', prohibiting the overwriting of log files with the same name.")
        else:
            setLogTruncateOnRotation(data)

def checkLogRotationAge(isSetting):
    """
    function : Check LogRotationAge
    input  : Bool
    output : NA
    """
    data = collectLogRotationAge()
    if data.db[0].strip() != "1d":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum retention time for individual log files.When the log recording time exceeds the maximum value set by this parameter, the server will automatically create a new log file. Proper configuration helps avoid the excessively frequent creation of log files while preventing individual log files from becoming too large and difficult to manage.")
        else:
            setLogRotationAge(data)

def checkLogRotationSize(isSetting):
    """
    function : Check LogRotationSize
    input  : Bool
    output : NA
    """
    data = collectLogRotationSize()
    if data.db[0].strip() != "20MB":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of maximum size for individual log files.If the value of the 'log_rotation_size' parameter is set too low, it will result in frequent generation of log files, increasing management difficulty. If the parameter value is set too high, a single log file will record too many logs, which may lead to excessive disk space usage and is not conducive to log file management.")
        else:
            setLogRotationSize(data)

def checkClientMinMessages(isSetting):
    """
    function : Check ClientMinMessages
    input  : Bool
    output : NA
    """
    data = collectClientMinMessages()
    if data.db[0].strip().startswith("debug"):
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct client log level configuration.Log levels debug1 to debug5 are primarily used for debugging and are not recommended for use in production environments, as they can increase the amount of logs sent to clients. It is advised to keep the default value of 'notice'.")
        else:
            setClientMinMessages(data)

def checkLogMinMessages(isSetting):
    """
    function : Check LogMinMessages
    input  : Bool
    output : NA
    """
    data = collectLogMinMessages()
    if data.db[0].strip().startswith("debug"):
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure server log level configuration is correct.Log levels debug1 to debug5 are primarily used for debugging and are not recommended for use in production environments, as they can increase the amount of logs written to the server. It is advised to keep the default value of 'warning'.")
        else:
            setLogMinMessages(data)

def checkLogMinErrorStatement(isSetting):
    """
    function : Check LogMinErrorStatement
    input  : Bool
    output : NA
    """
    data = collectLogMinErrorStatement()
    if data.db[0].strip() != "error":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct logging configuration for SQL statements that generate errors.Since some SQL statements contain personal user information, ifSince some SQL statements contain personal user information, if record the erroneous SQL if there is no need to record the erroneous SQL statements, the parameter can be set to 'panic'.")
        else:
            setLogMinErrorStatement(data)

def checkLogConnections(isSetting):
    """
    function : Check LogConnections
    input  : Bool
    output : NA
    """
    data = collectLogConnections()
    if data.db[0].strip() != "on":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure logging of user login events is enabled.Enabling 'log_connections' allows for logging all user login attempts, aiding administrators in analyzing potential malicious connections or connection issues. However, as it records all connection attempts, it may lead to rapid growth of log files, increasing disk storage pressure.")
        else:
            setLogConnections(data)

def checkLogDisconnections(isSetting):
    """
    function : Check LogDisconnections
    input  : Bool
    output : NA
    """
    data = collectLogDisconnections()
    if data.db[0].strip() != "on":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure logging of user logout events is enabled.Enabling the 'log_disconnections' parameter helps analyze client connection disconnections, including the reasons for disconnection and session duration. At the same time, enabling this parameter may increase the volume of log records, and the costs of disk storage and log management need to be considered.")
        else:
            setLogDisconnections(data)

def checkLogErrorVerbosity(isSetting):
    """
    function : Check LogErrorVerbosity
    input  : Bool
    output : NA
    """
    data = collectLogErrorVerbosity()
    if data.db[0].strip() != "default":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of logging verbosity for server logs.Valid values include TERSE, DEFAULT, and VERBOSE.")
        else:
            setLogErrorVerbosity(data)

def checkLogHostname(isSeting):
    """
    function : Check LogHostname
    input  : Bool
    output : NA
    """
    data = collectLogHostname()
    if data.db[0].strip() != "off":
        if not isSeting:
            g_logger.log(
                "        Warning reason:Ensure logs do not record hostnames.Since resolving hostnames takes some time, it may result in additional performance overhead. Therefore, it is recommended to set 'log_hostname' to 'off', so that only the IP address is recorded in the connection log without logging the hostname.")
        else:
            setLogHostname(data)

def checkDebugPrintParse(isSetting):
    """
    function : Check DebugPrintParse
    input  : Bool
    output : NA
    """
    data = collectDebugPrintParse()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure debug printing switch for parse tree is turned off.When this parameter is set to 'on', the parse tree results of queries will be printed in the log, which may occupy a significant amount of log space and negatively impact query performance. In production environments, it is recommended to set the 'debug_print_parse' parameter to 'off' to prevent the printing of query parse tree results in the log.")
        else:
            setDebugPrintParse(data)

def checkDebugPrintPlan(isSetting):
    """
    function : Check DebugPrintPlan
    input  : Bool
    output : NA
    """
    data = collectDebugPrintPlan()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure debug printing switch for execution plans is turned off.By default, this parameter is set to 'off', indicating that the execution plan will not be printed. However, if it is set to 'on', the execution plan of queries will be printed in the log, which may occupy a large amount of log space and negatively impact query performance. Therefore, in production environments, it is recommended to set the 'debug_print_plan' parameter to 'off' to prevent the printing of the execution plan in the log.")
        else:
            setDebugPrintPlan(data)

def checkDebugPrintRewritten(isSetting):
    """
    function : Check DebugPrintRewritten
    input  : Bool
    output : NA
    """
    data = collectDebugPrintRewritten()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure debug printing switch for query rewriting is turned off.By default, this parameter is set to 'off', indicating that the query rewrite results will not be printed. However, if it is set to 'on', the results of query rewriting will be printed in the log, which may occupy a large amount of log space and negatively impact query performance. Therefore, in production environments, it is recommended to set the 'debug_print_rewritten' parameter to 'off' to prevent the printing of query rewrite results in the log.")
        else:
            setDebugPrintRewritten(data)


#############################################################################
def setErrorReportingAndLoggingConfiguration(isSetting=True):
    """
    function : Set Error Reporting And Logging Configuration
    input  : Bool
    output : NA
    """
    checkLoggingCollector(isSetting)
    checkLogFilename(isSetting)
    checkLogFileMode(isSetting)
    checkLogTruncateOnRotation(isSetting)
    checkLogRotationAge(isSetting)
    checkLogRotationSize(isSetting)
    checkClientMinMessages(isSetting)
    checkLogMinMessages(isSetting)
    checkLogMinErrorStatement(isSetting)
    checkLogConnections(isSetting)
    checkLogDisconnections(isSetting)
    checkLogErrorVerbosity(isSetting)
    checkLogHostname(isSetting)
    checkDebugPrintParse(isSetting)
    checkDebugPrintPlan(isSetting)
    checkDebugPrintRewritten(isSetting)


def setLoggingCollector(data):
    """
    function : Set Logging Collector
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter("logging_collector=on")
        if not re.search(r'Success to perform gs_guc!', output):            
            g_logger.log("Failed to set Logging Collector")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()

def setLogFilename(data):
    """
    function : Set Log Filename
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Filename")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogFileMode(data):
    """
    function : Set Log File Mode
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_file_mode=0600")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log File Mode")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogTruncateOnRotation(data):
    """
    function : Set Log Truncate On Rotation
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_truncate_on_rotation=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Truncate On Rotation")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogRotationAge(data):
    """
    function : Set Log Rotation Age
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_rotation_age=1d")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Rotation Age")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogRotationSize(data):
    """
    function : Set Log Rotation Size
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_rotation_size=20MB")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Rotation Size")
    except Exception as e:
        data.errormsg = e.__str__()

def setClientMinMessages(data):
    """
    function : Set Client Min Messages
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("client_min_messages=notice")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Client Min Messages")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogMinMessages(data):
    """
    function : Set Log Min Messages
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_min_messages=warning")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Min Messages")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogMinErrorStatement(data):
    """
    function : Set Log Min Error Statement
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_min_error_statement=error")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Min Error Statement")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogConnections(data):
    """
    function : Set Log Connections
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_connections=on")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Connections")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogDisconnections(data):
    """
    function : Set Log Disconnections
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_disconnections=on")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Disconnections")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogErrorVerbosity(data):
    """
    function : Set Log Error Verbosity
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_error_verbosity=default")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Error Verbosity")
    except Exception as e:
        data.errormsg = e.__str__()

def setLogHostname(data):
    """
    function : Set Log Hostname
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("log_hostname=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Log Hostname")
    except Exception as e:
        data.errormsg = e.__str__()

def setDebugPrintParse(data):
    """
    function : Set Debug Print Parse
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("debug_print_parse=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Debug Print Parse")
    except Exception as e:
        data.errormsg = e.__str__()

def setDebugPrintPlan(data):
    """
    function : Set Debug Print Plan
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("debug_print_plan=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Debug Print Plan")
    except Exception as e:
        data.errormsg = e.__str__()

def setDebugPrintRewritten(data):
    """
    function : Set Debug Print Rewritten
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("debug_print_rewritten=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Debug Print Rewritten")
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkBackupConfiguration(isSetting=False):
    """
    function : Check Backup Configuration
    input  : Bool
    output : NA
    """
    checkWalLevel(isSetting)
    checkArchiveMode(isSetting)


def checkWalLevel(isSetting):
    """
    function : Check WalLevel
    input  : Bool
    output : NA
    """
    data = collectWalLevel()
    if data.db[0].strip() != "hot_standby":
        if not isSetting:
            g_logger.log(
                "         Warning reason:Ensure correct configuration of WAL (Write-Ahead Logging) information recording level.The 'wal_level' determines the amount of information written to WAL. To enable read-only queries on a standby server, 'wal_level' must be set to 'hot_standby' on the primary server, and the 'hot_standby' parameter must be set to 'on' on the standby server.")
        else:
            setWalLevel(data)

def checkArchiveMode(isSetting):
    """
    function : Check ArchiveMode
    input  : Bool
    output : NA
    """
    data = collectArchiveMode()
    if not (data.db[0].strip() == "hot_standby" or (data.db[0].strip() == "archive" and data.db[1].strip() == "on")):
        if not isSetting:
            g_logger.log(
                "         Warning reason:Ensure archiving mode is enabled.After enabling archive mode, it is necessary to plan the disk space occupied by archived logs. The log archiving process may impact database performance.")


#############################################################################
def setBackupConfiguration(isSetting=True):
    """
    function : Set Backup Configuration
    input  : Bool
    output : NA
    """
    checkWalLevel(isSetting)


def setWalLevel(data):
    """
    function : Set Wal Level
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter("wal_level=hot_standby")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Wal Level")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
def checkRuntimeEnvironmentConfiguration(isSetting=False):
    """
    function : Check Runtime Environment Configuration
    input  : Bool
    output : NA
    """
    checkUmask(isSetting)
    checkHidepid()
    checkNtpd()


def checkUmask(isSetting):
    """
    function : Check Umask
    input  : Bool
    output : NA
    """
    data = collectUmask()
    if not data.output.strip() == "0077":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct file permission mask configuration.If the umask is set improperly, it may lead to overly restrictive or excessive permissions for newly created files, thereby affecting normal business operations or posing security risks.")
        else:
            setUmask()

def checkHidepid():
    """
    function : Check Hidepid
    input  : NA
    output : NA
    """
    data = collectHidepid()
    pattern = r'hidepid=(2|invisible)'
    if not (data.output and re.search(pattern, data.output)):
        g_logger.log(
            "        Warning reason:Ensure process information is hidden from other users.This ensures that only the root user can view all processes, while regular users can only see their own processes. This helps prevent the leakage of user process information and enhances the security of the database operating environment.")


def checkNtpd():
    """
    function : Check Ntpd
    input  : NA
    output : NA
    """
    data = collectNtpd()
    pattern = r'running'
    if not (data.output and re.search(pattern, data.output)):
        g_logger.log(
            "        Warning reason:Ensure NTP clock synchronization is enabled.Ensure that the system time is synchronized across all hosts on the database server. A lack of synchronization or significant differences in system time may prevent the database from operating normally.")


#############################################################################
def setRuntimeEnvironmentConfiguration(isSetting=True):
    """
    function : Set Runtime Environment Configuration
    input  : Bool
    output : NA
    """
    checkUmask(isSetting)

def setUmask():
    """
    function : Set Umask
    input  : NA
    output : NA
    """
    umask_value = '0077'
    home_dir = os.path.expanduser('~')
    bashrc_path = os.path.join(home_dir, '.bashrc')

    with open(bashrc_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    new_lines = []
    umask_found = False
    for line in lines:
        if line.strip().startswith('umask'):
            new_lines.append(f'umask {umask_value}\n')
            umask_found = True
        else:
            new_lines.append(line)

    if not umask_found:
        new_lines.append(f'umask {umask_value}\n')
    with open(bashrc_path, 'w', encoding='utf-8') as file:
        file.writelines(new_lines)

    os.system("source ~/.bashrc")


#############################################################################
def checkOtherConfigurations(isSetting=False):
    """
    function : Check Other Configurations
    input  : Bool
    output : NA
    """
    checkBackslashQuote(isSetting)
    checkAllowSystemTableMods(isSetting)


def checkBackslashQuote(isSetting):
    """
    function : Check BackslashQuote
    input  : Bool
    output : NA
    """
    data = collectBackslashQuote()
    if data.db[0].strip() not in ['safe_encoding', 'off']:
        if not isSetting:
            g_logger.log(
                "        Warning reason:Ensure correct configuration of the backslash_quote parameter.The use of backslash-escaped quotation marks can pose security risks, such as SQL injection attacks. To avoid this risk, it is recommended to configure the server to reject queries with backslash-escaped quotation marks. It is advisable to use the SQL standard method, which involves writing a single quotation mark twice ('').")
        else:
            setBackslashQuote(data)

def checkAllowSystemTableMods(isSetting):
    """
    function : Check AllowSystemTableMods
    input  : Bool
    output : NA
    """
    data = collectAllowSystemTableMods()
    if data.db[0].strip() != "off":
        if not isSetting:
            g_logger.log(
                "        Warning reason:Prohibit modification of system table structures.Although in some extreme cases, this parameter can help recover a damaged database, modifying the system table structure in a production environment may pose serious security risks, including data loss and system instability. Therefore, in a production environment, the 'allow_system_table_mods' parameter should be set to 'off'.")
        else:
            setAllowSystemTableMods(data)


#############################################################################
def setOtherConfigurations(isSetting=True):
    """
    function : Set Other Configurations
    input  : Bool
    output : NA
    """
    checkBackslashQuote(isSetting)
    checkAllowSystemTableMods(isSetting)


def setBackslashQuote(data):
    """
    function : Set Backslash Quote
    input  : Instantion
    output : NA
    """
    try:
        output = reloadNodeParamter("backslash_quote=safe_encoding")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Backslash Quote")
    except Exception as e:
        data.errormsg = e.__str__()

def setAllowSystemTableMods(data):
    """
    function : Set Allow System Table Mods
    input  : Instantion
    output : NA
    """
    try:
        output = setNodeParamter("allow_system_table_mods=off")
        if not re.search(r'Success to perform gs_guc!', output):
            g_logger.log("Failed to set Allow System Table Mods")
        restartNode()
    except Exception as e:
        data.errormsg = e.__str__()


#############################################################################
class CmdOptions():
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
        self.extrachecklist = []
        self.logFile = ""
        self.database = ""
        self.confFile = ""
        self.mtuValue = ""
        self.hostname = ""
        self.mppdbfile = ""


#########################################################
# Init global log
#########################################################
def initGlobals():
    """
    function : init Globals
    input  : NA
    output : NA
    """
    global g_logger
    global g_clusterInfo
    global g_readlist
    g_readlist = []

    g_logger = GaussLog(g_opts.logFile, "LocalCheckSE")

    g_clusterInfo = dbClusterInfo()
    if (g_opts.confFile != "" and g_opts.confFile is not None):
        g_clusterInfo.initFromXml(g_opts.confFile)


###########################################################################
# network card parameter:
###########################################################################
class netWork:
    """
    Class: netWork
    """

    def __init__(self):
        """
        function : Init class netWork
        input  : NA
        output : NA
        """
        self.netLevel = ""
        self.netNum = ""
        self.variables = dict()
        self.modeType = False
        self.nums = 0


def usage():
    """
Usage:
 python3 --help | -?
 python3 LocalCheckSE -t action [-l logfile] [-X xmlfile] [-V] [--database=database]
Common options:
 -t                                The type of action.
 -s                                the path of MPPDB file
 -l --log-file=logfile             The path of log file.
 -? --help                         Show this help screen.
 -X --xmlfile = xmlfile            Cluster config file
    --ntp-server                   NTP server node's IP.
    --database=database            Specify the database to check.
 -V --version
    """
    print(usage.__doc__)


def parseCommandLine():
    """
    function : Parse command line and save to global variables
    input  : NA
    output : NA
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:s:l:X:V?",
                                   ["help", "log-file=", "xmlfile=",
                                    "MTUvalue=", "hostname=", "database=",
                                    "ntp-server=", "version"])
    except Exception as e:
        usage()
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(e))

    if (len(args) > 0):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50000"]
                               % str(args[0]))

    global g_opts
    g_opts = CmdOptions()

    for (key, value) in opts:
        if (key == "-?" or key == "--help"):
            usage()
            sys.exit(0)
        elif (key == "-V" or key == "--version"):
            print("%s %s" % (sys.argv[0].split("/")[-1],
                             VersionInfo.COMMON_VERSION))
            sys.exit(0)
        elif (key == "-t"):
            g_opts.action = value
        elif (key == "-s"):
            g_opts.mppdbfile = value
        elif (key == "-X" or key == "--xmlfile"):
            g_opts.confFile = value
        elif (key == "-l" or key == "--log-file"):
            g_opts.logFile = os.path.realpath(value)
        elif (key == "--MTUvalue"):
            g_opts.mtuValue = value
        elif (key == "--hostname"):
            g_opts.hostname = value
        elif (key == "--database"):
            g_opts.database = value
        Parameter.checkParaVaild(key, value)


def checkParameter():
    """
    function : check parameter
    input  : NA
    output : NA
    """
    if (g_opts.action == ""):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 't' + '.')
    if (g_opts.action != ACTION_CHECK_Connection_configuration
            and g_opts.action != ACTION_CHECK_File_directory_security
            and g_opts.action != ACTION_CHECK_Security_authentication_configuration
            and g_opts.action != ACTION_CHECK_Account_password_management
            and g_opts.action != ACTION_CHECK_Permission_management
            and g_opts.action != ACTION_CHECK_Database_auditing
            and g_opts.action != ACTION_CHECK_Error_reporting_and_logging_configuration
            and g_opts.action != ACTION_CHECK_Backup_configuration
            and g_opts.action != ACTION_CHECK_Runtime_environment_configuration
            and g_opts.action != ACTION_CHECK_Other_configurations
            and g_opts.action != ACTION_SET_Connection_configuration
            and g_opts.action != ACTION_SET_File_directory_security
            and g_opts.action != ACTION_SET_Security_authentication_configuration
            and g_opts.action != ACTION_SET_Account_password_management
            and g_opts.action != ACTION_SET_Permission_management
            and g_opts.action != ACTION_SET_Database_auditing
            and g_opts.action != ACTION_SET_Error_reporting_and_logging_configuration
            and g_opts.action != ACTION_SET_Backup_configuration
            and g_opts.action != ACTION_SET_Runtime_environment_configuration
            and g_opts.action != ACTION_SET_Other_configurations):
        GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50004"] % "t")

    if (g_opts.logFile == ""):
        dirName = os.path.dirname(os.path.realpath(__file__))
        g_opts.logFile = os.path.join(dirName, ClusterConstants.LOCAL_LOG_FILE)


def getLocalIPAddr():
    """
    function: get local ip
    input : NA
    output: Ips
    """
    Ips = []

    if g_opts.confFile == "":
        Ips.append(DefaultValue.getIpByHostName())
        return Ips

    for node in g_clusterInfo.dbNodes:
        if (node.name == NetUtil.GetHostIpOrName()):
            Ips.append(node.backIps[0])

    return Ips


def doLocalCheck():
    """
    function: check SE item on local node
    input : NA
    output: NA
    """

    global netWorkBondInfo
    netWorkBondInfo = netWork()

    function_dict_false = {ACTION_CHECK_Connection_configuration: checkConnection,
                           ACTION_CHECK_File_directory_security: checkFileSecurity,
                           ACTION_CHECK_Security_authentication_configuration: checkSecurityAuthConf,
                           ACTION_CHECK_Account_password_management: checkAccountPasswordManagement,
                           ACTION_CHECK_Permission_management: checkPermissionManagement,
                           ACTION_CHECK_Database_auditing: checkDatabaseAuditing,
                           ACTION_CHECK_Error_reporting_and_logging_configuration: checkErrorReportingAndLoggingConfiguration,
                           ACTION_CHECK_Backup_configuration: checkBackupConfiguration,
                           ACTION_CHECK_Runtime_environment_configuration: checkRuntimeEnvironmentConfiguration,
                           ACTION_CHECK_Other_configurations: checkOtherConfigurations}
    function_keys_false = list(function_dict_false.keys())

    function_dict_true = {ACTION_SET_Connection_configuration: setConnection,
                          ACTION_SET_File_directory_security: setFileSecurity,
                          ACTION_SET_Security_authentication_configuration: setSecurityAuthenticationConfiguration,
                          ACTION_SET_Account_password_management: setAccountPasswordManagement,
                          ACTION_SET_Permission_management: setPermissionManagement,
                          ACTION_SET_Database_auditing: setDatabaseAuditing,
                          ACTION_SET_Error_reporting_and_logging_configuration: setErrorReportingAndLoggingConfiguration,
                          ACTION_SET_Backup_configuration: setBackupConfiguration,
                          ACTION_SET_Runtime_environment_configuration: setRuntimeEnvironmentConfiguration,
                          ACTION_SET_Other_configurations: setOtherConfigurations}
    function_keys_true = list(function_dict_true.keys())

    if (g_opts.action in function_keys_false):
        function_dict_false[g_opts.action](False)
    elif (g_opts.action in function_keys_true):
        function_dict_true[g_opts.action](True)
    else:
        g_logger.logExit(ErrorCode.GAUSS_500["GAUSS_50004"] % 't' +
                         " Value: %s." % g_opts.action)


if __name__ == '__main__':
    """
    main function
    """
    try:
        parseCommandLine()
        checkParameter()
        initGlobals()
    except Exception as e:
        GaussLog.exitWithError(str(e))

    try:
        nodeIps = []
        nodeIps = getLocalIPAddr()
        doLocalCheck()
        g_logger.closeLog()
    except Exception as e:
        g_logger.logExit(str(e))

    sys.exit(0)
