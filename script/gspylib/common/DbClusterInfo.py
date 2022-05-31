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
# Description  : DbClusterInfo.py is a utility to get cluster information
#############################################################################
import binascii
import os
import subprocess
import struct
import time
import types
import sys
import re
import pwd
import copy

sys.path.append(os.path.split(os.path.realpath(__file__))[0] + "/../../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.parallelTool import parallelTool
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_file.version_info import VersionInfo
from domain_utils.domain_common.cluster_constants import ClusterConstants
from base_utils.common.constantsbase import ConstantsBase
from base_utils.os.env_util import EnvUtil

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
# ID num
###########################
BASE_ID_CMSERVER = 1
BASE_ID_GTM = 1001
BASE_ID_CMAGENT = 10001
BASE_ID_DUMMYDATANODE = 3001
BASE_ID_COORDINATOR = 5001
BASE_ID_DATANODE = 6001
BASE_ID_ETCD = 7001
DIRECTORY_PERMISSION = 0o750

# For primary/standby instance When the ID > 7000 ,
# the new id is start from 40001
OLD_LAST_PRIMARYSTANDBY_BASEID_NUM = 7000
NEW_FIRST_PRIMARYSTANDBY_BASEID_NUM = 40000

# master instance default port
MASTER_BASEPORT_CMS = 5000
MASTER_BASEPORT_GTM = 6000
# cm agent has no port, just occupancy index 5
MASTER_BASEPORT_CMAGENT = 0
MASTER_BASEPORT_COO = 8000
MASTER_BASEPORT_DATA = 40000
MASTER_BASEPORT_ETCD = 2379
# standby instance default port
STANDBY_BASEPORT_CMS = 5500
STANDBY_BASEPORT_GTM = 6500
# cm agent has no port, just occupancy index 5
STANDBY_BASEPORT_CMAGENT = 0
STANDBY_BASEPORT_COO = 8500
STANDBY_BASEPORT_DATA = 45000
STANDBY_BASEPORT_ETCD = 2380

###########################
# instance type. only for CN/DN 
###########################
INSTANCE_TYPE_UNDEFINED = -1
# master 
MASTER_INSTANCE = 0
# standby 
STANDBY_INSTANCE = 1
# dummy standby 
DUMMY_STANDBY_INSTANCE = 2
#cascade standby
CASCADE_STANDBY = 3
DICT_INSTANCE = {MASTER_INSTANCE: "primary", STANDBY_INSTANCE: "standby",
                 CASCADE_STANDBY: "cascade_standby"}

###########################
# instance number
###########################
# max number of replicationfor CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
MIRROR_COUNT_REPLICATION_MAX = 9
# max number of azPriority for CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
AZPRIORITY_MAX = 10
# min number of azPriority for CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
AZPRIORITY_MIN = 1
# DB port set step size for CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
PORT_STEP_SIZE = 20

MIRROR_ID_AGENT = -3

# cluster type
CLUSTER_TYPE_SINGLE = "single"
CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY = "single-primary-multi-standby"
CLUSTER_TYPE_SINGLE_INST = "single-inst"

# default config version, it is used by gs_upgrade
BIN_CONFIG_VERSION = 2
BIN_CONFIG_VERSION_SINGLE = 101
BIN_CONFIG_VERSION_SINGLE_PRIMARY_MULTI_STANDBY = 201
BIN_CONFIG_VERSION_SINGLE_INST = 301

# page size
PAGE_SIZE = 8192
MAX_IP_NUM = 3
CONFIG_IP_NUM = 1

NODE_ID_LEN = 2
INSTANCE_ID_LEN = 8
SPACE_LEN = 1
STATE_LEN = 17
SEPERATOR_LEN = 1
IP_LEN = 16
PORT_LEN = 10


# The default network type is single plane
g_networkType = 0

# global param to cache gs_om query instance result.
global_cls_query_rst = {}


def ignoreCheck(Object, member, model):
    """
    funciton : Ignore checking the instance information of table.
    input : Object, Object, model
    output : boolean
    """
    INSTANCEINFO_IGNORE_TABLE = {}
    if (model == "replace"):
        # init instance ignore table for replace
        INSTANCEINFO_IGNORE_TABLE = {"listenIps": None,
                                     "haIps": None,
                                     "hostname": None,
                                     "mirrorId": None
                                     }
    elif (model == "changeIP"):
        # init instance ignore table for changeip
        INSTANCEINFO_IGNORE_TABLE = {"listenIps": None,
                                     "haIps": None,
                                     "hostname": None,
                                     "port": None,
                                     "haPort": None,
                                     "mirrorId": None
                                     }
    elif (model == "upgradectl"):
        # init instance ignore table for upgradectl
        INSTANCEINFO_IGNORE_TABLE = {
            "instanceRole": None,
            "instanceId": None,
            "mirrorId": None
        }
    elif (model == "manageCN"):
        # init instance ignore table for manageCN
        INSTANCEINFO_IGNORE_TABLE = {
            "instanceId": None,
            "mirrorId": None
        }
    elif (model == "expand"):
        # init instance ignore table for expand
        INSTANCEINFO_IGNORE_TABLE = {
            "mirrorId": None
        }
    elif (model == "compareCluster"):
        INSTANCEINFO_IGNORE_TABLE = {
            "listenIps": None,
            "haIps": None,
            "hostname": None,
            "port": None,
            "haPort": None,
            "mirrorId": None
        }
        if (hasattr(Object,
                    "instanceRole") and Object.instanceRole ==
                INSTANCE_ROLE_COODINATOR):
            INSTANCEINFO_IGNORE_TABLE["instanceId"] = None
    # init node ignore table
    DBNODEINFO_IGNORE_TABLE = {
        "backIps": None,
        "sshIps": None,
        "masterBasePorts": None,
        "standbyBasePorts": None,
        "dummyStandbyBasePort": None,
        "cmsNum": None,
        "cooNum": None,
        "dataNum": None,
        "gtmNum": None,
        "name": None,
        "virtualIp": None
    }
    # init cluster ignore table
    DBCLUSTERINFO_IGNORE_TABLE = {
        "xmlFile": None,
        "newNodes": None,
        "clusterRings": None
    }

    if (model == "upgradectl"):
        DBNODEINFO_IGNORE_TABLE.pop("backIps")
        DBNODEINFO_IGNORE_TABLE.pop("sshIps")
        DBNODEINFO_IGNORE_TABLE.pop("name")
        DBCLUSTERINFO_IGNORE_TABLE.pop("clusterRings")
    elif (model == "manageCN"):
        DBNODEINFO_IGNORE_TABLE.pop("backIps")
        DBNODEINFO_IGNORE_TABLE.pop("sshIps")
        DBNODEINFO_IGNORE_TABLE.pop("name")
        DBNODEINFO_IGNORE_TABLE["id"] = None
    if (isinstance(Object, instanceInfo)):
        if (member not in list(INSTANCEINFO_IGNORE_TABLE.keys())):
            return False
        elif (INSTANCEINFO_IGNORE_TABLE[member] is None or not callable(
                INSTANCEINFO_IGNORE_TABLE[member])):
            return True
        else:
            return INSTANCEINFO_IGNORE_TABLE[member](Object)
    elif (isinstance(Object, dbNodeInfo)):
        if (member not in list(DBNODEINFO_IGNORE_TABLE.keys())):
            return False
        elif (DBNODEINFO_IGNORE_TABLE[member] is None or not callable(
                DBNODEINFO_IGNORE_TABLE[member])):
            return True
        else:
            return INSTANCEINFO_IGNORE_TABLE[member](Object)
    elif (isinstance(Object, dbClusterInfo)):
        if (member not in list(DBCLUSTERINFO_IGNORE_TABLE.keys())):
            return False
        elif (DBCLUSTERINFO_IGNORE_TABLE[member] is None or not callable(
                DBCLUSTERINFO_IGNORE_TABLE[member])):
            return True
        else:
            return DBCLUSTERINFO_IGNORE_TABLE[member](Object)
    else:
        return False


def checkPathVaild(obtainpath):
    """
    function: check path vaild
    input : envValue
    output: NA
    """
    PATH_CHECK_LIST = [" ", "|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"",
                       "{", "}", "(", ")", "[", "]", "~", "*", "?", "!", "\n"]
    if not obtainpath.strip():
        return
    if any(ill_char in obtainpath for ill_char in PATH_CHECK_LIST):
        raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % obtainpath +
                        " There are illegal characters in the path.")


def obtainInstStr(objectList):
    '''
    function : Obtain information of instance.
    input : []
    output : String
    '''
    info = ""
    if (isinstance(objectList, list)):
        for obj in objectList:
            info += "%s\n" % str(obj)
    return info


def compareObject(Object_A, Object_B, instName, tempbuffer=None, model=None,
                  manageCNinfo=None):
    '''
    function : Compare object_A and Object_B.
    input : Object, Object, instName, tempbuffer, model, manageCNinfo
    output : boolean, tempbuffer
    '''
    if tempbuffer is None:
        tempbuffer = []
    if isinstance(Object_A, bytes) or isinstance(Object_A, str):
        if (Object_A != Object_B):
            tempbuffer.append(instName)
            tempbuffer.append(Object_A)
            tempbuffer.append(Object_B)
            return False, tempbuffer
    ### not the same type
    elif (type(Object_A) != type(Object_B)):
        tempbuffer.append(instName)
        tempbuffer.append(str(Object_A))
        tempbuffer.append(str(Object_B))
        return False, tempbuffer
    ### string, int, long, float, bool type
    elif (isinstance(Object_A, bytes)):
        if (Object_A != Object_B):
            tempbuffer.append(instName)
            tempbuffer.append(Object_A)
            tempbuffer.append(Object_B)
            return False, tempbuffer
    elif (isinstance(Object_A, type(None))):
        if (Object_A != Object_B):
            tempbuffer.append(instName)
            tempbuffer.append(Object_A)
            tempbuffer.append(Object_B)
            return False, tempbuffer
    elif (isinstance(Object_A, int) or isinstance(Object_A, int)
          or isinstance(Object_A, float) or isinstance(Object_A, bool)):
        if (Object_A != Object_B):
            tempbuffer.append(instName)
            tempbuffer.append(Object_A)
            tempbuffer.append(Object_B)
            return False, tempbuffer
    ### list type
    elif (isinstance(Object_A, list)):
        if (model == "manageCN"):
            if (len(Object_A) != len(Object_B)):
                theSame, tempbuffer = checkObject(Object_A, Object_B,
                                                  tempbuffer, manageCNinfo)
                if (not theSame):
                    return False, tempbuffer
                if (len(Object_A) != 0 and len(Object_B) != 0):
                    Object_A1 = []
                    Object_B1 = []
                    for Obj_A in Object_A:
                        for Obj_B in Object_B:
                            if (Obj_A.name == Obj_B.name):
                                Object_A1.append(Obj_A)
                                Object_B1.append(Obj_B)
                                continue
                    for idx in range(len(Object_A1)):
                        result, tempbuffer = compareObject(Object_A1[idx],
                                                           Object_B1[idx],
                                                           "%s[%d]" % (
                                                               instName, idx),
                                                           tempbuffer,
                                                           model,
                                                           manageCNinfo)
                        if (not result):
                            return False, tempbuffer
            else:
                for idx in range(len(Object_A)):
                    result, tempbuffer = compareObject(Object_A[idx],
                                                       Object_B[idx],
                                                       "%s[%d]" % (
                                                           instName, idx),
                                                       tempbuffer,
                                                       model,
                                                       manageCNinfo)
                    if (not result):
                        return False, tempbuffer
        else:
            if len(Object_A) != len(Object_B):
                tempbuffer.append(instName)
                tempbuffer.append(obtainInstStr(Object_A))
                tempbuffer.append(obtainInstStr(Object_B))
                return False, tempbuffer

            for idx in range(len(Object_A)):
                result, tempbuffer = compareObject(Object_A[idx],
                                                   Object_B[idx],
                                                   "%s[%d]" % (instName, idx),
                                                   tempbuffer,
                                                   model,
                                                   manageCNinfo)
                if (not result):
                    return False, tempbuffer
    ### function type 
    elif isinstance(Object_A, types.FunctionType) or \
            isinstance(Object_A, types.MethodType):
        return True, tempbuffer
    elif isinstance(Object_A, type(dbClusterInfo())) or \
            isinstance(Object_A, type(dbNodeInfo())) or \
            isinstance(Object_A, type(instanceInfo())):
        Object_A_list = dir(Object_A)
        Object_B_list = dir(Object_B)
        if (len(Object_A_list) != len(Object_B_list)):
            tempbuffer.append(instName)
            tempbuffer.append(str(Object_A))
            tempbuffer.append(str(Object_B))
            return False, tempbuffer
        for i in Object_A_list:
            if (i.startswith("_") or ignoreCheck(Object_A, i, model)):
                continue
            Inst_A = getattr(Object_A, i)
            try:
                Inst_B = getattr(Object_B, i)
            except Exception as e:
                tempbuffer.append(instName)
                tempbuffer.append(str(Object_A))
                tempbuffer.append(str(Object_B))
                return False, tempbuffer
            result, tempbuffer = compareObject(Inst_A, Inst_B, i, tempbuffer,
                                               model, manageCNinfo)
            if (not result):
                return False, tempbuffer
    else:
        tempbuffer.append(instName)
        tempbuffer.append(str(Object_A))
        tempbuffer.append(str(Object_B))
        return False, tempbuffer
    return True, tempbuffer


def checkObject(Object_A, Object_B, checkbuffer, manageCNinfo):
    """
    """
    Join = []
    if (len(Object_A)):
        Join.extend(Object_A)
    if (len(Object_B)):
        Join.extend(Object_B)

    # CN instance
    if (isinstance(Join[0], instanceInfo)):

        # check instance role
        if (Join[0].instanceRole != 3):
            raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])
        # xml must match action
        if (len(Object_A) == 1 and len(Object_B) == 0):
            if (manageCNinfo.mode != "delete"):
                raise Exception(
                    ErrorCode.GAUSS_528["GAUSS_52808"] % ("deletion", "add"))
        elif (len(Object_A) == 0 and len(Object_B) == 1):
            if (manageCNinfo.mode != "add"):
                raise Exception(ErrorCode.GAUSS_528["GAUSS_52808"] % (
                    "increased", "delete"))
        else:
            raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])

        # at most add or delete one CN
        if (len(manageCNinfo.nodeInfo) != 0 or len(manageCNinfo.cooInfo) != 0):
            raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])

        manageCNinfo.cooInfo.extend(Join)
    # GaussDB nodes
    elif (isinstance(Join[0], dbNodeInfo)):
        # get added or deleted node
        oa_names = [Obj_A.name for Obj_A in Object_A]
        ob_names = [Obj_B.name for Obj_B in Object_B]
        Object_AA = [Obj_A for Obj_A in Object_A if Obj_A.name not in ob_names]
        Object_BB = [Obj_B for Obj_B in Object_B if Obj_B.name not in oa_names]

        # xml must match action
        if (len(Object_AA) == 1 and len(Object_BB) == 0):
            if (manageCNinfo.mode != "delete"):
                raise Exception(
                    ErrorCode.GAUSS_528["GAUSS_52808"] % ("deletion", "add"))
        elif (len(Object_AA) == 0 and len(Object_BB) == 1):
            if (manageCNinfo.mode != "add"):
                raise Exception(ErrorCode.GAUSS_528["GAUSS_52808"] % (
                    "increased", "delete"))
        else:
            raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])

        # at most add or delete one node
        if (len(manageCNinfo.nodeInfo) != 0 or len(manageCNinfo.cooInfo) != 0):
            raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])

        if (len(Object_AA)):
            manageCNinfo.nodeInfo.extend(Object_AA)
        if (len(Object_BB)):
            manageCNinfo.nodeInfo.extend(Object_BB)
    else:
        raise Exception(ErrorCode.GAUSS_528["GAUSS_52809"])

    return True, checkbuffer


####################################################################
##read cluster functions
####################################################################

xmlRootNode = None

####################################################################


class queryCmd():
    def __init__(self, outputFile="", dataPathQuery=False, portQuery=False,
                 azNameQuery=False):
        self.outputFile = outputFile
        self.dataPathQuery = dataPathQuery
        self.portQuery = portQuery
        self.azNameQuery = azNameQuery
        self.clusterStateQuery = False


class peerInstanceInfo():
    """
    Peer instance information
    """

    def __init__(self):
        self.peerDataPath = ""
        self.peerHAIPs = []
        self.peerHAPort = 0
        self.peerRole = 0
        self.peer2DataPath = ""
        self.peer2HAIPs = []
        self.peer2HAPort = 0
        self.peer2Role = 0

    def __str__(self):
        """
        Construct a printable string representation of a instanceInfo
        """
        ret = "peerDataPath=%s,peerHAPort=%d,peerRole=%d" % (
            self.peerDataPath, self.peerHAPort, self.peerRole)
        if self.peer2DataPath:
            ret += ",peer2DataPath=%s" % self.peer2DataPath
        if self.peer2HAPort:
            ret += ",peer2HAPort=%d" % self.peer2HAPort
        if self.peer2Role:
            ret += ",peer2Role=%d" % self.peer2Role
        return ret

class instanceInfo():
    """
    Instance information
    """

    def __init__(self, instId=0, mirrorId=0):
        """
        Constructor
        """
        # instance id
        self.instanceId = instId
        self.mirrorId = mirrorId
        # host name
        self.hostname = ""
        # listen ip
        self.listenIps = []
        # ha ip
        self.haIps = []
        # port
        self.port = 0
        # It's pool port for coordinator, and ha port for other instance
        self.haPort = 0
        # data directory
        self.datadir = ""
        # xlog directory
        self.xlogdir = ""
        # ssd data directory
        self.ssdDir = ""
        # instance type
        self.instanceType = INSTANCE_TYPE_UNDEFINED
        # instance role
        self.instanceRole = INSTANCE_ROLE_UNDEFINED
        # instance rack info
        self.rack = ""
        # oltp zpaxos sub instance type
        self.subInstanceType = INSTANCE_ROLE_UNDEFINED

        self.level = 1
        # we use port and haPort to save peerPort/clientPort for etcd
        # datanode: use haPort to save replport
        # repl port
        self.replport = 0
        # sctp port
        self.sctpPort = 0
        # control port
        self.controlPort = 0
        # az name
        self.azName = ""
        self.clusterName = ""
        # peer port etcd
        self.peerPort = 0
        # client port etcd
        self.clientPort = 0
        # instance name
        self.name = ""
        # DB state Normal or other, use to save dynamic info
        self.state = ""
        # get staticConnections from database,use to save dynamic info
        self.staticConnections = ""
        # DB role such as Primary, Standby
        self.localRole = ""
        self.peerInstanceInfos = []
        self.syncNum = -1
        self.cascadeRole = "off"
        # dcf_data_path
        self.dcf_data_path = ""

    def __cmp__(self, target):
        """
        Type compare
        """
        if (type(self) != type(target)):
            return 1
        if (not isinstance(target, instanceInfo)):
            return 1
        if (not hasattr(target, "instanceId")):
            return 1
        else:
            return self.instanceId - target.instanceId

    def __str__(self):
        """
        Construct a printable string representation of a instanceInfo
        """
        ret = "InstanceId=%s,MirrorId=%s,Host=%s,Port=%s,DataDir=%s," \
              "XlogDir=%s,SsdDir=%s,InstanceType=%s,Role=%s,ListenIps=%s," \
              "HaIps=%s" % (
                  self.instanceId, self.mirrorId, self.hostname, self.port,
                  self.datadir, self.xlogdir, self.ssdDir, self.instanceType,
                  self.instanceRole, self.listenIps, self.haIps)
        if self.rack:
            ret += ",rack=%s" % self.rack
        if self.replport:
            ret += ",replport=%s" % self.replport
        if self.sctpPort:
            ret += ",sctpPort=%s" % self.sctpPort
        if self.controlPort:
            ret += ",controlPort=%s" % self.controlPort
        if self.azName:
            ret += ",azName=%s" % self.azName
        if self.clusterName:
            ret += ",clusterName=%s" % self.clusterName
        if self.peerPort:
            ret += ",peerPort=%s" % self.peerPort
        if self.clientPort:
            ret += ",clientPort=%s" % self.clientPort
        if self.name:
            ret += ",name=%s" % self.name
        return ret


class dbNodeInfo():
    """
    Instance info on a node
    """

    def __init__(self, nodeId=0, name=""):
        """
        Constructor
        """
        # node id
        self.id = nodeId
        # node name
        self.name = name
        self.backIps = []
        self.virtualIp = []
        self.sshIps = []
        # instance number
        self.cmsNum = 0
        self.cooNum = 0
        self.dataNum = 0
        self.gtmNum = 0
        self.etcdNum = 0
        # cm_servers instance
        self.cmservers = []
        # cn instance
        self.coordinators = []
        # DB instance
        self.datanodes = []
        # gtm instance
        self.gtms = []
        # cm_agent instance
        self.cmagents = []
        # etcd instance
        self.etcds = []
        # cm_server/cm_agent data directory
        self.cmDataDir = ""
        self.dummyStandbyBasePort = 0
        self.masterBasePorts = [MASTER_BASEPORT_CMS, MASTER_BASEPORT_GTM,
                                MASTER_BASEPORT_COO,
                                MASTER_BASEPORT_DATA, MASTER_BASEPORT_ETCD,
                                MASTER_BASEPORT_CMAGENT]
        self.standbyBasePorts = [STANDBY_BASEPORT_CMS, STANDBY_BASEPORT_GTM,
                                 STANDBY_BASEPORT_COO,
                                 STANDBY_BASEPORT_DATA, STANDBY_BASEPORT_ETCD,
                                 STANDBY_BASEPORT_CMAGENT]
        # azName
        self.azName = ""
        self.azPriority = 1
        self.standbyDnNum = 0
        self.dummyStandbyDnNum = 0
        self.cascadeRole = "off"

    def __cmp__(self, target):
        """
        Type compare
        """
        if (type(self) != type(target)):
            return 1
        if (not isinstance(target, dbNodeInfo)):
            return 1
        if (not hasattr(target, "id")):
            return 1
        else:
            return self.id - target.id

    def __str__(self):
        """
        function : Construct a printable string representation of a dbNodeInfo
        input : NA
        output : String
        """
        retStr = "HostName=%s,backIps=%s" % (self.name, self.backIps)
        # cm_server instance information
        for cmsInst in self.cmservers:
            retStr += "\n%s" % str(cmsInst)
        # cm_agent instance information
        for cmaInst in self.cmagents:
            retStr += "\n%s" % str(cmaInst)
        # gtm instance information
        for gtmInst in self.gtms:
            retStr += "\n%s" % str(gtmInst)
        # cn instance information
        for cooInst in self.coordinators:
            retStr += "\n%s" % str(cooInst)
        # DB instance information
        for dataInst in self.datanodes:
            retStr += "\n%s" % str(dataInst)
        # etcd instance information
        for dataInst in self.etcds:
            retStr += "\n%s" % str(dataInst)

        return retStr

    def setDnDetailNum(self):
        self.dataNum = self.getDnNum(MASTER_INSTANCE)
        self.standbyDnNum = self.getDnNum(STANDBY_INSTANCE)
        self.dummyStandbyDnNum = self.getDnNum(DUMMY_STANDBY_INSTANCE)

    def getDnNum(self, dntype):
        """
        function: get DB num
        input: dntype
        output:dn num
        """
        count = 0
        for dnInst in self.datanodes:
            if (dnInst.instanceType == dntype):
                count += 1
        return count

    def appendInstance(self, instId, mirrorId, instRole, instanceType,
                       listenIps=None,
                       haIps=None, datadir="", ssddir="", level=1,
                       xlogdir="", syncNum=-1, dcf_data=""):
        """
        function : Classify the instance of cmserver/gtm
        input : int,int,String,String
        output : NA
        """
        if not self.__checkDataDir(datadir, instRole):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51638"] % \
                            self.name + " Data directory[%s] is "
                                        "conflicting." % datadir)

        dbInst = instanceInfo(instId, mirrorId)
        dbInst.hostname = self.name
        dbInst.datadir = os.path.realpath(datadir)

        if (instRole == INSTANCE_ROLE_DATANODE):
            dbInst.xlogdir = xlogdir
        else:
            dbInst.xlogdir = ""
        dbInst.instanceType = instanceType
        dbInst.instanceRole = instRole
        if (listenIps is not None):
            if (len(listenIps) == 0):
                dbInst.listenIps = self.backIps[:]
            else:
                dbInst.listenIps = listenIps[:]

        if (haIps is not None):
            if (len(haIps) == 0):
                dbInst.haIps = self.backIps[:]
            else:
                dbInst.haIps = haIps[:]
        # cm_server
        if (instRole == INSTANCE_ROLE_CMSERVER):
            dbInst.datadir = os.path.join(self.cmDataDir, "cm_server")
            dbInst.port = self.__assignNewInstancePort(self.cmservers,
                                                       instRole, instanceType)
            dbInst.level = level
            dbInst.haPort = dbInst.port + 1
            self.cmservers.append(dbInst)
        # gtm
        elif (instRole == INSTANCE_ROLE_GTM):
            dbInst.port = self.__assignNewInstancePort(self.gtms, instRole,
                                                       instanceType)
            dbInst.haPort = dbInst.port + 1
            self.gtms.append(dbInst)
        # cn
        elif (instRole == INSTANCE_ROLE_COODINATOR):
            dbInst.port = self.__assignNewInstancePort(self.coordinators,
                                                       instRole, instanceType)
            dbInst.haPort = dbInst.port + 1
            dbInst.ssdDir = ssddir
            self.coordinators.append(dbInst)
        # dn
        elif (instRole == INSTANCE_ROLE_DATANODE):
            dbInst.port = self.__assignNewInstancePort(self.datanodes,
                                                       instRole, instanceType)
            dbInst.haPort = dbInst.port + 1
            dbInst.ssdDir = ssddir
            dbInst.syncNum = syncNum
            dbInst.dcf_data_path = dcf_data
            self.datanodes.append(dbInst)
        # cm_agent
        elif (instRole == INSTANCE_ROLE_CMAGENT):
            dbInst.datadir = os.path.join(self.cmDataDir, "cm_agent")
            self.cmagents.append(dbInst)
        # etcd
        elif (instRole == INSTANCE_ROLE_ETCD):
            dbInst.port = self.__assignNewInstancePort(self.etcds, instRole,
                                                       instanceType)
            dbInst.haPort = self.__assignNewInstancePort(self.etcds, instRole,
                                                         STANDBY_INSTANCE)
            self.etcds.append(dbInst)

    def __checkDataDir(self, datadir, instRole):
        """
        function : Check whether the instance path is the same as with the
        parameter of datadir
        input : String,String
        output : boolean
        """
        if (datadir == ""):
            return (
                    instRole == INSTANCE_ROLE_CMSERVER or instRole ==
                    INSTANCE_ROLE_CMAGENT)
        checkPathVaild(datadir)
        # cm_server
        for cmsInst in self.cmservers:
            if (cmsInst.datadir == datadir):
                return False
        # cn
        for cooInst in self.coordinators:
            if (cooInst.datadir == datadir):
                return False
        # dn
        for dataInst in self.datanodes:
            if (dataInst.datadir == datadir):
                return False
        # gtm
        for gtmInst in self.gtms:
            if (gtmInst.datadir == datadir):
                return False
        # etcd
        for etcd in self.etcds:
            if (etcd.datadir == datadir):
                return False
        # cm_agent
        for cmaInst in self.cmagents:
            if (cmaInst.datadir == datadir):
                return False

        return True

    def __assignNewInstancePort(self, instList, instRole, instanceType):
        """
        function : Assign a new port for the instance
        input : [],String ,String
        output : int 
        """
        port = 0
        # master instance
        if instanceType == MASTER_INSTANCE:
            port = self.masterBasePorts[instRole]
        # standby instance
        elif instanceType == STANDBY_INSTANCE:
            port = self.standbyBasePorts[instRole]
        # DB dummy standby instance
        elif instanceType == DUMMY_STANDBY_INSTANCE:
            port = self.dummyStandbyBasePort
        # cn and cm_agent instance
        elif instanceType == INSTANCE_TYPE_UNDEFINED:
            port = self.masterBasePorts[instRole]
            return port
        for inst in instList:
            if (inst.instanceType == instanceType):
                port += 2

        return port


class dbClusterInfo():
    """
    Cluster info
    """

    def __init__(self, checkSctpPort=False):
        """
        Constructor
        """
        self.name = ""
        self.appPath = ""
        self.logPath = ""
        self.xmlFile = ""
        self.dbNodes = []
        self.newNodes = []
        self.cmsFloatIp = ""
        self.__newInstanceId = [BASE_ID_CMSERVER, BASE_ID_GTM, BASE_ID_ETCD,
                                BASE_ID_COORDINATOR, BASE_ID_DATANODE,
                                BASE_ID_CMAGENT]
        self.__newDummyStandbyId = BASE_ID_DUMMYDATANODE
        self.__newMirrorId = 0
        self.clusterRings = []
        self.clusterType = CLUSTER_TYPE_SINGLE_INST
        self.checkSctpPort = checkSctpPort
        self.clusterName = ""
        self.toolPath = ""
        self.agentPath = ""
        self.agentLogPath = ""
        self.tmpPath = ""
        self.managerPath = ""
        self.replicaNum = 0
        self.corePath = ""

        # add azName
        self.azName = ""
        self.cascadeRole = "off"

        self.version = 0
        self.installTime = 0
        self.localNodeId = 0
        self.nodeCount = 0
        # cluster properties
        self.replicationCount = 0
        self.quorumMode = ""
        self.gtmcount = 0
        self.etcdcount = 0
        self.cmscount = 0
        self.__newGroupId = 0
        self.cncount = 0
        self.masterDnCount = 0
        self.standbyDnCount = 0
        self.dummyStandbyDnCount = 0
        self.cm_state_list = list()
        # add for dcf
        self.enable_dcf = ""
        self.dcf_config = ""

    def __str__(self):
        """
        function : Construct a printable string representation of a
        dbClusterInfo
        input : NA
        output : String
        """
        retStr = "ClusterName=%s,AppPath=%s,LogPath=%s,ClusterType=%s" % \
                 (self.name, self.appPath, self.logPath, self.clusterType)

        for dbNode in self.dbNodes:
            retStr += "\n%s" % str(dbNode)

        return retStr

    def check_conf_cm_state(self):
        """
        Save CM instance state
        """
        if not self.cm_state_list:
            return True
        state_result = self.cm_state_list[0]
        for state in self.cm_state_list[1:]:
            state_result ^= state
            if state_result:
                return False
        return True

    @staticmethod
    def readClustercorePath(xmlFile):
        """
        function : Read corefile path from default xml file
        input : String
        output : String
        """
        ClusterConfigFile.setDefaultXmlFile(xmlFile)
        # read corefile path from xml file
        (retStatus, retValue) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(xmlFile), "corePath", "cluster")
        if retStatus != 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"]
                            % "corePath" + " Error: \n%s" % retValue)
        corepath = os.path.normpath(retValue)
        checkPathVaild(corepath)
        return corepath


    def initFromStaticConfig(self, user, static_config_file="",
                             isLCCluster=False, ignoreLocalEnv=False):
        """
        function : Init cluster from static configuration file
        input : String,String
        output : NA
        """
        # check Os user
        self.__checkOsUser(user)
        # get static_config_file
        if (static_config_file == ""):
            staticConfigFile = self.__getStaticConfigFilePath(user)
        else:
            staticConfigFile = static_config_file
        # read static_config_file 
        self.__readStaticConfigFile(staticConfigFile, user, isLCCluster,
                                    ignoreLocalEnv=ignoreLocalEnv)

    def queryNodeInfo(self, sshtool, localHostName, nodeId, fileName="", azName=""):
        """
        get cluster node info, if nodeid is 0, we get all node info,
        else ony get one node info
        """
        i = 0
        (clusterState, syncInfo) = self.__getDnSenderStatus(sshtool,
                                                            localHostName)
        outText = \
            "--------------------------------------------------------------" \
            "---------\n\n"
        outText = outText + ("cluster_state             : %s\n" % clusterState)
        outText = outText + "redistributing            : No\n\n"
        outText = outText + \
                  "-------------------------------------" \
                  "----------------------------------\n\n"
        for dbNode in self.dbNodes:
            if dbNode.id == nodeId or nodeId == 0:
                for dnInst in dbNode.datanodes:
                    # filter by azName
                    if azName and dnInst.azName != azName:
                        continue
                    outText = outText + (
                            "node                      : %u\n" % dbNode.id)
                    outText = outText + (
                            "node_name                 : %s\n" % dbNode.name)
                    outText = outText + (
                            "instance_id               : %u\n" %
                            dnInst.instanceId)
                    outText = outText + ("node_ip                   : %s\n" %
                                         dnInst.listenIps[0])
                    outText = outText + (
                            "data_path                 : %s\n" %
                            dnInst.datadir)
                    outText = outText + (
                            "instance_port             : %s\n" %
                            dnInst.port)
                    outText = outText + "type                      : " \
                                        "Datanode\n"
                    outText = outText + (
                            "instance_state            : %s\n" %
                            dnInst.state)
                    outText = outText + (
                            "az_name                   : %s\n" %
                            dnInst.azName)
                    if dnInst.localRole == "Primary":
                        outText = outText + (
                                "static_connections        : %s\n" %
                                dnInst.staticConnections)
                        outText = outText + (
                              "HA_state                  : %s\n" %
                              clusterState)
                    outText = outText + (
                              "instance_role             : %s\n" %
                            dnInst.localRole)
                    if dnInst.localRole == "Primary":
                        outText = outText + "\n------------------------" \
                                            "---------------" \
                                            "--------------------------------\n\n"
                        continue
                    for i_loop in syncInfo:
                        if i_loop[0] == dnInst.listenIps[0]:
                            if i_loop[11] == '':
                                i_loop[11] = 'Unknown'
                            outText = outText + (
                                      "HA_state                  : %s\n" %
                                      i_loop[1])
                            outText = outText + (
                                      "sender_sent_location      : %s\n" %
                                      i_loop[2])
                            outText = outText + (
                                      "sender_write_location     : %s\n" %
                                      i_loop[3])
                            outText = outText + (
                                      "sender_flush_location     : %s\n" %
                                      i_loop[4])
                            outText = outText + (
                                      "sender_replay_location    : %s\n" %
                                      i_loop[5])
                            outText = outText + (
                                      "receiver_received_location: %s\n" %
                                      i_loop[6])
                            outText = outText + (
                                      "receiver_write_location   : %s\n" %
                                      i_loop[7])
                            outText = outText + (
                                      "receiver_flush_location   : %s\n" %
                                      i_loop[8])
                            outText = outText + (
                                      "receiver_replay_location  : %s\n" %
                                      i_loop[9])
                            outText = outText + (
                                      "sync_percent              : %s\n" %
                                      i_loop[10])
                            outText = outText + (
                                      "sync_state                : %s\n" %
                                      i_loop[11])
                            if dnInst.localRole == "Cascade Standby":
                                outText = outText + (
                                      "upstream_nodeIp           : %s\n" %
                                      i_loop[12])
                            break
                    outText = outText + "\n------------------------" \
                                        "---------------" \
                                    "--------------------------------\n\n"
                if nodeId != 0:
                    break
            else:
                i += 1
                continue
        if i >= len(self.dbNodes):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51612"] % nodeId)
        self.__fprintContent(outText, fileName)

    def printStaticConfig(self, fileName=""):
        """
        function : printStaticConfig
        input : String
        output : NA
        """
        try:
            # read static_config_file
            outText = "NodeHeader:\n"
            outText = outText + ("version:%u\n" % self.version)
            outText = outText + ("time:%ld\n" % self.installTime)
            outText = outText + ("nodeCount:%u\n" % self.nodeCount)
            outText = outText + ("node:%u\n" % self.localNodeId)
            outText = outText + ("=" * 60 + "\n")
            dnTotalNum = self.__getDnInstanceNum()
            for dbNode in self.dbNodes:
                outText = outText + ("azName:%s\n" % dbNode.azName)
                outText = outText + ("azPriority:%u\n" % dbNode.azPriority)
                outText = outText + ("node :%u\n" % dbNode.id)
                outText = outText + ("nodeName:%s\n" % dbNode.name)

                outText = outText + "ssh channel :\n"
                j = 0
                for sshIp in dbNode.sshIps:
                    outText = outText + ("sshChannel %u:%s\n" % (
                        j + 1, dbNode.sshIps[j]))
                    j = j + 1
                outText = outText + (
                        "datanodeCount :%u\n" % len(dbNode.datanodes))
                j = 0
                for dnInst in dbNode.datanodes:
                    j = j + 1
                    outText = outText + ("datanodeInstanceType :%s\n" %
                                         DICT_INSTANCE[dnInst.instanceType])
                    outText = outText + ("datanode %u:\n" % j)
                    outText = outText + (
                            "datanodeLocalDataPath :%s\n" % dnInst.datadir)
                    outText = outText + (
                            "datanodeXlogPath :%s\n" % dnInst.xlogdir)
                    k = 0
                    for listenIp in dnInst.listenIps:
                        k = k + 1
                        outText = outText + (
                                "datanodeListenIP %u:%s\n" % (k, listenIp))
                    outText = outText + ("datanodePort :%u\n" % dnInst.port)
                    k = 0
                    for haIp in dnInst.haIps:
                        k = k + 1
                        outText = outText + (
                                "datanodeLocalHAIP %u:%s\n" % (k, haIp))
                    outText = outText + (
                            "datanodeLocalHAPort :%u\n" % dnInst.haPort)
                    outText = outText + (
                            "dn_replication_num: %u\n" % dnTotalNum)
                    maxPeerNum = MIRROR_COUNT_REPLICATION_MAX if \
                        self.nodeCount > MIRROR_COUNT_REPLICATION_MAX \
                        else self.nodeCount
                    for k in range(maxPeerNum - 1):
                        outText = outText + ("datanodePeer%uDataPath :%s\n" %
                                             (k, dnInst.peerInstanceInfos[k].peerDataPath))
                        m = 0
                        for peerHaIP in dnInst.peerInstanceInfos[k].peerHAIPs:
                            m += 1
                            outText = outText + ("datanodePeer%uHAIP %u:%s\n" % (k, m, peerHaIP))
                        outText = outText + ("datanodePeer%uHAPort :%u\n" %
                                             (k, dnInst.peerInstanceInfos[k].peerHAPort))

                    outText = outText + ("=" * 60 + "\n")
            self.__fprintContent(outText, fileName)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51652"] % str(e))

    def queryClsInfoParallel(self, hostName, sshtools, mpprcFile, querytype):
        """
        function : queryClsInfoParallel
                   Query cluster information in parallel.
        input : String
        output : Map
        """
        dbInfoList = []
        index = 0
        for dbNode in self.dbNodes:
            for dnInst in dbNode.datanodes:
                sshtool = None
                if (dbNode.name != hostName):
                    sshtool = sshtools[index]
                    index += 1
                querycmd = ""
                if querytype == "status":
                    querycmd = "gs_ctl query -D %s" % dnInst.datadir
                elif querytype == "port":
                    querycmd = "gs_guc check -D %s -c port" % dnInst.datadir
                dbName = dbNode.name
                dbInfoList.append({
                    "name": dbName,
                    "command": querycmd,
                    "sshtool": sshtool
                })

        def queryInstance(dbInfo):
            dnName = dbInfo["name"]
            command = dbInfo["command"]
            sshtool = dbInfo["sshtool"]
            status = 0
            output = ""

            if dnName != hostName:
                (statusMap, output) = sshtool.getSshStatusOutput(
                    command, [dnName], mpprcFile)
                if statusMap[dnName] != 'Success':
                    status = -1
            else:
                (status, output) = subprocess.getstatusoutput(command)

            global_cls_query_rst[dnName+command.split()[-1]] = [status, output]

        global global_cls_query_rst
        parallelTool.parallelExecute(queryInstance, dbInfoList)

        return global_cls_query_rst

    def queryClsInfo(self, hostName, sshtools, mpprcFile, cmd):
        try:
            clusterState = 'Normal'
            roleStatusArray = []
            dbStateArray = []
            maxNodeNameLen = 0
            maxDataPathLen = 0
            maxAzNameLen = 0
            dnNodeCount = 0
            roleStatus = ""
            dbState = ""
            primaryDbNum = 0
            primaryDbState = ""
            portMap = {}

            queryClsResult = copy.deepcopy(self.queryClsInfoParallel(hostName, sshtools, mpprcFile,
                                                                     "status"))

            for dbNode in self.dbNodes:
                for dnInst in dbNode.datanodes:
                    (status, output) = queryClsResult.get(dbNode.name + dnInst.datadir)
                    if status != 0 or output.find("exc_sql failed") > 0:
                        if output.find(
                                "could not connect to the local server") \
                                > 0 or output.find(
                            "Is server running") > 0:
                            roleStatus = "Down"
                            dbState = "Manually stopped"
                        else:
                            roleStatus = "Unknown"
                            dbState = "Unknown"
                    else:
                        res = re.findall(r'local_role\s*:\s*(\w+)', output)
                        roleStatus = res[0]
                        res = re.findall(r'db_state\s*:\s*(\w+)', output)
                        dbState = res[0]

                    if (dbState == "Need"):
                        detailInformation = re.findall(
                            r'detail_information\s*:\s*(\w+)', output)
                        dbState = "Need repair(%s)" % detailInformation[0]
                    roleStatusArray.append(roleStatus)
                    dbStateArray.append(dbState)
                    nodeNameLen = len(dbNode.name)
                    dataPathLen = len(dbNode.datanodes[0].datadir)
                    azNameLen = len(dbNode.azName)
                    maxNodeNameLen = maxNodeNameLen if maxNodeNameLen > \
                                                       nodeNameLen else \
                        nodeNameLen
                    maxDataPathLen = maxDataPathLen if maxDataPathLen > \
                                                       dataPathLen else \
                        dataPathLen
                    maxAzNameLen = maxAzNameLen if maxAzNameLen > azNameLen \
                        else azNameLen
                    dnNodeCount += 1
                    if roleStatus == "Primary":
                        primaryDbNum += 1
                        primaryDbState = dbState
                    else:
                        if roleStatus != "Standby" and \
                                roleStatus != "Secondary" and \
                                roleStatus != "Cascade":
                            clusterState = 'Degraded'
                        if dbState != "Normal":
                            clusterState = 'Degraded'

                    portMap[dbNode.name] = dnInst.port
            if dnNodeCount == 1:
                clusterState = "Unavailable" if dbState != "Normal" \
                    else "Normal"
            else:
                if primaryDbState != "Normal" or primaryDbNum != 1:
                    clusterState = "Unavailable"
            outText = ""
            if cmd.clusterStateQuery:
                outText = \
                    "-------------------------------------------------" \
                    "----------------------\n\n" \
                    "cluster_name    : %s\ncluster_state   : %s\nredistributing  : No\n\n" % \
                    (self.name, clusterState)
                outText = outText + \
                          "-------------------------------------------" \
                          "----------------------------\n"
                self.__fprintContent(outText, cmd.outputFile)
                return
            outText = "[   Cluster State   ]\n\ncluster_state   : " \
                      "%s\nredistributing  : No\n" % clusterState
            outText = outText + "current_az      : AZ_ALL\n\n[  Datanode " \
                                "State   ]\n\n"
            nodeLen = NODE_ID_LEN + SPACE_LEN + maxNodeNameLen + SPACE_LEN
            instanceLen = INSTANCE_ID_LEN + SPACE_LEN + (
                maxDataPathLen if cmd.dataPathQuery else 4)

            if cmd.azNameQuery:
                nodeLen += maxAzNameLen + SPACE_LEN
            if cmd.portQuery:
                instanceLen += 7

            outText = outText + "%-*s%-*s%-*s%-*s%s\n" % (
                nodeLen, "    node", IP_LEN, "node_ip", PORT_LEN, "port", instanceLen, "instance",
                "state")
            maxLen = nodeLen + instanceLen + IP_LEN + SPACE_LEN + PORT_LEN + SPACE_LEN + \
                 STATE_LEN + SPACE_LEN + SEPERATOR_LEN
            seperatorLine = "-" * maxLen
            outText = outText + seperatorLine + "\n"
            i = 0
            for dbNode in self.dbNodes:
                for dnInst in dbNode.datanodes:
                    if cmd.azNameQuery:
                        outText = outText + (
                                "%-*s " % (maxAzNameLen, dbNode.azName))
                    outText = outText + ("%-2u " % dbNode.id)
                    outText = outText + (
                            "%-*s " % (maxNodeNameLen, dbNode.name))
                    outText = outText + ("%-15s " % dnInst.listenIps[0])

                    outText = outText + ("%-10u " % dnInst.port)

                    outText = outText + ("%u " % dnInst.instanceId)

                    if cmd.dataPathQuery:
                        outText = outText + (
                                "%-*s " % (maxDataPathLen, dnInst.datadir))
                    else:
                        outText = outText + "    "
                    outText = outText + (
                            "%3s " % self.__getDnRole(dnInst.instanceType))
                    if dnNodeCount == 1:
                        outText = outText + ("%-7s" % "Primary")
                    else:
                        outText = outText + ("%-7s" % roleStatusArray[i])
                    outText = outText + (" %s" % dbStateArray[i])

                    outText = outText + "\n"
                    i += 1
            self.__fprintContent(outText, cmd.outputFile)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51652"] % str(e))
        
    def __getDnRole(self, instanceType):
        """
        function : Get DnRole by instanceType
        input : Int
        output : String
        """
        if instanceType == MASTER_INSTANCE:
            return "P"
        elif instanceType == STANDBY_INSTANCE:
            return "S"
        elif instanceType == CASCADE_STANDBY:
            return "C"
        elif instanceType == DUMMY_STANDBY_INSTANCE:
            return "R"
        else:
            return ""

    def __getDnInstanceNum(self):
        dnInsNum = 0
        for dbNode in self.dbNodes:
            dnInsNum += len(dbNode.datanodes)
        return dnInsNum

    def __getDnSenderStatus(self, sshtool, localHostName):
        sql_get = "select a.client_addr, b.state, b.sender_sent_location," \
                  "b.sender_write_location, b.sender_flush_location," \
                  "b.sender_replay_location, b.receiver_received_location," \
                  "b.receiver_write_location, b.receiver_flush_location," \
                  "b.receiver_replay_location, b.sync_percent, b.sync_state " \
                  "from pg_stat_replication a inner join " \
                  "pg_stat_get_wal_senders() b on a.pid = b.pid;"
        syncInfo = []
        clusterState = "Normal"
        primaryDbState = "Normal"
        primaryDbNum = 0
        dnNodeCount = 0
        for dbNode in self.dbNodes:
            for dnInst in dbNode.datanodes:
                dnNodeCount += 1
                self.__getDnState(dnInst, dbNode, localHostName, sshtool)
                if dnInst.localRole == "Primary":
                    primaryDbState = dnInst.state
                    primaryDbNum += 1
                    output = ""
                    if dbNode.name != localHostName:
                        cmd = "[need_replace_quotes] gsql -m -d postgres -p " \
                              "%s -A -t -c \"%s\"" % \
                              (dnInst.port, sql_get)
                        (statusMap, output) = sshtool.getSshStatusOutput(cmd, [
                            dbNode.name])
                        if statusMap[dbNode.name] != 'Success' or output.find(
                                "failed to connect") >= 0:
                            continue
                        else:
                            output = output.split('\n')[1:-1]
                    else:
                        cmd = "gsql -m -d postgres -p %s -A -t -c \"%s\"" % (
                            dnInst.port, sql_get)
                        (status, output) = subprocess.getstatusoutput(cmd)
                        if status != 0 or output.find(
                                "failed to connect") >= 0:
                            continue
                        else:
                            output = output.split('\n')
                    if not len(output):
                        continue
                    for col_loop in output:
                        syncInfo.append(col_loop.split('|'))
                elif dnInst.localRole == "Cascade Standby":
                    subsql = "select state, sender_sent_location, sender_write_location," \
                             "sender_flush_location, sender_replay_location," \
                             "receiver_received_location, receiver_write_location," \
                             "receiver_flush_location, receiver_replay_location," \
                             "sync_percent, channel from pg_stat_get_wal_receiver();"
                    if dbNode.name != localHostName:
                        cmd = "[need_replace_quotes] gsql -m -d postgres -p " \
                              "%s -A -t -c \"%s\"" % \
                              (dnInst.port, subsql)
                        (statusMap, cascadeOutput) = sshtool.getSshStatusOutput(cmd, [
                            dbNode.name])
                        if statusMap[dbNode.name] != 'Success' or cascadeOutput.find(
                                "failed to connect") >= 0:
                            continue
                        else:
                            cascadeOutput = cascadeOutput.split('\n')[1:-1]
                    else:
                        cmd = "gsql -m -d postgres -p %s -A -t -c \"%s\"" % (
                            dnInst.port, subsql)
                        (status, cascadeOutput) = subprocess.getstatusoutput(cmd)
                        if status != 0 or cascadeOutput.find(
                                "failed to connect") >= 0:
                            continue
                        else:
                            cascadeOutput = cascadeOutput.split('\n')
                    if not len(cascadeOutput):
                        continue
                    for col_loop in cascadeOutput:
                        col_loop = col_loop.split('|')
                        cascadeIps = col_loop[-1].split('<--')
                        col_loop.insert(0, cascadeIps[0].split(':')[0])
                        col_loop.insert(11, "Async")
                        col_loop[-1] = cascadeIps[-1]
                        syncInfo.append(col_loop)
                else:
                    if dnInst.localRole != "Standby" and \
                            dnInst.localRole != "Secondary":
                        clusterState = "Degraded"
                    if dnInst.state != "Normal":
                        clusterState = "Degraded"
        if dnNodeCount == 1:
            clusterState = "Unavailable" if dnInst.state != "Normal" \
                else "Normal"
        else:
            if primaryDbState != "Normal" or primaryDbNum != 1:
                clusterState = "Unavailable"
        return (clusterState, syncInfo)

    def __getDnState(self, dnInst, dbNode, localHostName, sshtool):
        sql = "select local_role, static_connections, db_state from " \
              "pg_stat_get_stream_replications();"
        if dbNode.name != localHostName:
            # [SUCCESS] hostname:\n when ssh, The third line is the sql result
            minValidLine = 3
            cmd = "[need_replace_quotes] gsql -m -d postgres -p %s -c " \
                  "\"%s\"" % (
                      dnInst.port, sql)
            (statusMap, output) = sshtool.getSshStatusOutput(cmd,
                                                             [dbNode.name])
            dnDown = output.find("failed to connect") >= 0
            if statusMap[dbNode.name] != 'Success' or dnDown:
                dnInst.localRole = "Down" if dnDown else "Unknown"
                dnInst.staticConnections = 0
                dnInst.state = "Manually stopped" if dnDown else "Unknown"
            else:
                lineSplitRes = output.split("\n")
                if len(lineSplitRes) <= minValidLine or len(
                        lineSplitRes[minValidLine].split("|")) != 3:
                    dnInst.localRole = "Unknown"
                    dnInst.staticConnections = 0
                    dnInst.state = "Unknown"
                else:
                    columnRes = lineSplitRes[minValidLine].split("|")
                    dnInst.localRole = columnRes[0].strip()
                    dnInst.staticConnections = columnRes[1].strip()
                    dnInst.state = columnRes[2].strip()
        else:
            # The second line is the sql result
            minValidLine = 2
            cmd = "gsql -m -d postgres -p %s -c \"%s\"" % (dnInst.port, sql)
            (status, output) = subprocess.getstatusoutput(cmd)
            dnDown = output.find("failed to connect") >= 0
            if status != 0 or dnDown:
                dnInst.localRole = "Down" if dnDown else "Unknown"
                dnInst.staticConnections = 0
                dnInst.state = "Manually stopped" if dnDown else "Unknown"
            else:
                lineSplitRes = output.split("\n")
                if len(lineSplitRes) <= minValidLine or len(
                        lineSplitRes[minValidLine].split("|")) != 3:
                    dnInst.localRole = "Unknown"
                    dnInst.staticConnections = 0
                    dnInst.state = "Unknown"
                else:
                    columnRes = lineSplitRes[minValidLine].split("|")
                    dnInst.localRole = columnRes[0].strip()
                    dnInst.staticConnections = columnRes[1].strip()
                    dnInst.state = columnRes[2].strip()

    def __fprintContent(self, content, fileName):
        if fileName != "":
            FileUtil.createFileInSafeMode(fileName)
            with open(fileName, "a") as fp:
                fp.write(content)
                fp.flush()
        sys.stdout.write(content)

    def __checkOsUser(self, user):
        """
        function : Check os user
        input : String
        output : NA
        """
        try:
            user = pwd.getpwnam(user).pw_gid
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"] % user)

    def __getStaticConfigFilePath(self, user):
        """
        function : get the path of static configuration file. 
        input : String
        output : String
        """
        gaussHome = self.__getEnvironmentParameterValue("GAUSSHOME", user)
        if (gaussHome == ""):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            ("installation path of designated user [%s]" %
                             user))

        checkPathVaild(gaussHome)
        # if under upgrade, and use chose strategy, we may get a wrong path,
        # so we will use the realpath of gausshome
        commitid = VersionInfo.getCommitid()
        appPath = gaussHome + "_" + commitid
        staticConfigFile = "%s/bin/cluster_static_config" % appPath
        staticConfigBak = "%s/bin/cluster_static_config_bak" % appPath
        staticConfig = "%s/bin/cluster_static_config" % os.path.realpath(
            gaussHome)
        if os.path.exists(staticConfig):
            return staticConfig
        elif (os.path.exists(staticConfigFile)):
            return staticConfigFile
        elif (os.path.exists(staticConfigBak)):
            return staticConfigBak

        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            ("static configuration file [%s] of "
                             "designated user [%s]" % (staticConfig, user)))

    def __getEnvironmentParameterValue(self, environmentParameterName, user):
        """
        function :Get the environment parameter. 
        !!!!Do not call this function in preinstall.py script.
        because we determine if we are using env separate version by the
        value of MPPDB_ENV_SEPARATE_PATH
        input : String,String 
        output : String
        """
        # get mpprc file
        mpprcFile = EnvUtil.getEnvironmentParameterValue('MPPDB_ENV_SEPARATE_PATH', user)
        if mpprcFile is not None and mpprcFile != "":
            mpprcFile = mpprcFile.replace("\\", "\\\\").replace('"', '\\"\\"')
            checkPathVaild(mpprcFile)
            userProfile = mpprcFile
        else:
            userProfile = ClusterConstants.BASHRC
        # build shell command
        if (os.getuid() == 0):
            cmd = "su - %s -c 'source %s;echo $%s' 2>/dev/null" % (
                user, userProfile, environmentParameterName)
        else:
            cmd = "source %s;echo $%s 2>/dev/null" % (userProfile,
                                                      environmentParameterName)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                            % cmd + " Error: \n%s" % output)
        env_path = output.split("\n")[0]
        checkPathVaild(env_path)
        return env_path

    def __getStatusByOM(self, user):
        """
        function :Get the environment parameter.
        !!!!Do not call this function in preinstall.py script.
        because we determine if we are using env separate version by the
        value of MPPDB_ENV_SEPARATE_PATH
        input : String,String
        output : String
        """
        # get mpprc file
        mpprcFile = EnvUtil.getEnvironmentParameterValue('MPPDB_ENV_SEPARATE_PATH', user)
        if mpprcFile is not None and mpprcFile != "":
            mpprcFile = mpprcFile.replace("\\", "\\\\").replace('"', '\\"\\"')
            checkPathVaild(mpprcFile)
            userProfile = mpprcFile
        else:
            userProfile = ClusterConstants.BASHRC
        # build shell command
        if os.getuid() == 0:
            cmd = "su - %s -c 'source %s;gs_om -t status --detail" % (
                user, userProfile)
        else:
            cmd = "source %s;gs_om -t status --detail" % (userProfile)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                            % cmd + " Error: \n%s" % output)
        return [i for i in output.strip().split("\n") if i]

    def __readStaticConfigFile(self, staticConfigFile, user, isLCCluster=False,
                               ignoreLocalEnv=False):
        """
        function : read cluster information from static configuration file
        input : String,String
        output : NA
        """
        fp = None
        try:
            # get env parameter
            gauss_env = self.__getEnvironmentParameterValue("GAUSS_ENV", user)
            self.name = self.__getEnvironmentParameterValue("GS_CLUSTER_NAME",
                                                            user)
            self.appPath = self.__getEnvironmentParameterValue("GAUSSHOME",
                                                               user)
            logPathWithUser = self.__getEnvironmentParameterValue("GAUSSLOG",
                                                                  user)

            if not ignoreLocalEnv:
                if gauss_env == "2" and self.name == "":
                    raise Exception(ErrorCode.GAUSS_503["GAUSS_50300"]
                                    % ("cluster name of designated user"
                                       " [%s]" % user))
                if self.appPath == "":
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                                    ("installation path of designated user "
                                     "[%s]" % user))
                if logPathWithUser == "":
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                                    ("log path of designated user [%s]" %
                                     user))

            splitMark = "/%s" % user
            # set log path without user
            # find the path from right to left
            self.logPath = logPathWithUser[
                           0:(logPathWithUser.rfind(splitMark))]
            staticConfigFilePath = os.path.split(staticConfigFile)[0]
            versionFile = os.path.join(
                staticConfigFilePath, "upgrade_version")
            version, number, commitid = VersionInfo.get_version_info(
                versionFile)
            try:
                # read static_config_file
                fp = open(staticConfigFile, "rb")
                if float(number) <= 92.200:
                    info = fp.read(32)
                    (crc, lenth, version, currenttime, nodeNum,
                     localNodeId) = struct.unpack("=qIIqiI", info)
                else:
                    info = fp.read(28)
                    (crc, lenth, version, currenttime, nodeNum,
                     localNodeId) = struct.unpack("=IIIqiI", info)
                self.version = version
                self.installTime = currenttime
                self.localNodeId = localNodeId
                self.nodeCount = nodeNum
            except Exception as e:
                if fp:
                    fp.close()
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                                % staticConfigFile + " Error:\n" + str(e))
            if version <= 100:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % \
                                ("cluster static config version[%s]" % version,
                                 "the new version[%s]" % BIN_CONFIG_VERSION))
            elif version >= 101 and version <= 200:
                self.clusterType = CLUSTER_TYPE_SINGLE
                if BIN_CONFIG_VERSION_SINGLE != version:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % \
                                    ("cluster static config version[%s]"
                                     % version, "the new version[%s]"
                                     % BIN_CONFIG_VERSION_SINGLE))
            elif version >= 201 and version <= 300:
                # single primary multi standy
                self.clusterType = CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
                if (BIN_CONFIG_VERSION_SINGLE_PRIMARY_MULTI_STANDBY
                        != version):
                    raise Exception(
                        ErrorCode.GAUSS_516["GAUSS_51637"]
                        % ("cluster static config version[%s]" % version,
                           "the new version[%s]"
                           % BIN_CONFIG_VERSION_SINGLE_PRIMARY_MULTI_STANDBY))
            elif version >= 301 and version <= 400:
                # single inst
                self.clusterType = CLUSTER_TYPE_SINGLE_INST
                if BIN_CONFIG_VERSION_SINGLE_INST != version:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % \
                                    ("cluster static config version[%s]"
                                     % version, "the new version[%s]"
                                     % BIN_CONFIG_VERSION_SINGLE_INST))

            self.dbNodes = []
            try:
                for i in range(nodeNum):
                    offset = (fp.tell() // PAGE_SIZE + 1) * PAGE_SIZE
                    fp.seek(offset)
                    dbNode = self.__unPackNodeInfo(fp, number, isLCCluster)
                    self.dbNodes.append(dbNode)
                fp.close()
            except Exception as e:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                                staticConfigFile + " Error:\nThe content is "
                                                   "not correct.")
        except Exception as e:
            if (fp):
                fp.close()
            raise Exception(str(e))

    def __unPackNodeInfo(self, fp, number, isLCCluster=False):
        """
        function : unpack a node config info
        input : file
        output : Object
        """
        if float(number) <= 92.200:
            info = fp.read(76)
            (crc, nodeId, nodeName) = struct.unpack("=qI64s", info)
        else:
            info = fp.read(72)
            (crc, nodeId, nodeName) = struct.unpack("=II64s", info)
        nodeName = nodeName.decode().strip('\x00')
        dbNode = dbNodeInfo(nodeId, nodeName)
        info = fp.read(68)
        (azName, azPriority) = struct.unpack("=64sI", info)
        dbNode.azName = azName.decode().strip('\x00')
        dbNode.azPriority = azPriority

        # get backIps
        self.__unPackIps(fp, dbNode.backIps)
        # get sshIps
        self.__unPackIps(fp, dbNode.sshIps)
        if (not isLCCluster):
            # get cm_server information
            self.__unPackCmsInfo(fp, dbNode)
            # get cm_agent information
            self.__unpackAgentInfo(fp, dbNode)
            # get gtm information
            self.__unpackGtmInfo(fp, dbNode)
            info = fp.read(404)
            # get cn information
            self.__unpackCooInfo(fp, dbNode)
        # get DB information
        self.__unpackDataNode(fp, dbNode)
        if (not isLCCluster):
            # get etcd information
            self.__unpackEtcdInfo(fp, dbNode)
            info = fp.read(8)
        # set DB azName for OLAP
        for inst in dbNode.datanodes:
            inst.azName = dbNode.azName

        return dbNode

    def __unpackEtcdInfo(self, fp, dbNode):
        """
        function : unpack the info of etcd
        input : file,Object
        output : NA
        """
        etcdInst = instanceInfo()
        etcdInst.instanceRole = INSTANCE_ROLE_ETCD
        etcdInst.hostname = dbNode.name
        etcdInst.instanceType = INSTANCE_TYPE_UNDEFINED
        info = fp.read(1100)
        (etcdNum, etcdInst.instanceId, etcdInst.mirrorId, etcdhostname,
         etcdInst.datadir) = struct.unpack("=IIi64s1024s", info)
        etcdInst.datadir = etcdInst.datadir.decode().strip('\x00')
        self.__unPackIps(fp, etcdInst.listenIps)
        info = fp.read(4)
        (etcdInst.port,) = struct.unpack("=I", info)
        self.__unPackIps(fp, etcdInst.haIps)
        info = fp.read(4)
        (etcdInst.haPort,) = struct.unpack("=I", info)
        if (etcdNum == 1):
            dbNode.etcdNum = 1
            dbNode.etcds.append(etcdInst)
            self.etcdcount += 1
        else:
            dbNode.etcdNum = 0
            dbNode.etcds = []

    def __unPackIps(self, fp, ips):
        """
        function : Unpack the info of ips
        input : file,[]
        output : NA
        """
        info = fp.read(4)
        (n,) = struct.unpack("=i", info)
        for i in range(int(n)):
            info = fp.read(128)
            (currentIp,) = struct.unpack("=128s", info)
            currentIp = currentIp.decode().strip('\x00')
            ips.append(str(currentIp.strip()))
        info = fp.read(128 * (MAX_IP_NUM - n))

    def __unPackCmsInfo(self, fp, dbNode):
        """
        function : Unpack the info of CMserver
        input : file Object
        output : NA
        """
        cmsInst = instanceInfo()
        cmsInst.instanceRole = INSTANCE_ROLE_CMSERVER
        cmsInst.hostname = dbNode.name
        info = fp.read(1164)
        (cmsInst.instanceId, cmsInst.mirrorId, dbNode.cmDataDir, cmsInst.level,
         self.cmsFloatIp) = struct.unpack("=II1024sI128s", info)
        dbNode.cmDataDir = dbNode.cmDataDir.decode().strip('\x00')
        self.cmsFloatIp = self.cmsFloatIp.decode().strip('\x00')
        cmsInst.datadir = "%s/cm_server" % dbNode.cmDataDir
        self.__unPackIps(fp, cmsInst.listenIps)
        info = fp.read(4)
        (cmsInst.port,) = struct.unpack("=I", info)
        self.__unPackIps(fp, cmsInst.haIps)
        info = fp.read(8)
        (cmsInst.haPort, cmsInst.instanceType) = struct.unpack("=II", info)
        if (cmsInst.instanceType == MASTER_INSTANCE):
            dbNode.cmsNum = 1
        elif (cmsInst.instanceType == STANDBY_INSTANCE):
            dbNode.cmsNum = 0
        else:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51204"]
                            % ("CMServer", cmsInst.instanceType))
        info = fp.read(4 + 128 * MAX_IP_NUM + 4)

        if (cmsInst.instanceId):
            dbNode.cmservers.append(cmsInst)
            self.cmscount += 1
        else:
            dbNode.cmservers = []

    def __unpackAgentInfo(self, fp, dbNode):
        """
        function : Unpack the info of agent. It should be called after
        __unPackCmsInfo, because dbNode.cmDataDir
                   get value in __unPackCmsInfo
        input : file Object
        output : NA
        """
        cmaInst = instanceInfo()
        cmaInst.instanceRole = INSTANCE_ROLE_CMAGENT
        cmaInst.hostname = dbNode.name
        cmaInst.instanceType = INSTANCE_TYPE_UNDEFINED
        info = fp.read(8)
        (cmaInst.instanceId, cmaInst.mirrorId) = struct.unpack("=Ii", info)
        self.__unPackIps(fp, cmaInst.listenIps)
        cmaInst.datadir = "%s/cm_agent" % dbNode.cmDataDir
        dbNode.cmagents.append(cmaInst)

    def __unpackGtmInfo(self, fp, dbNode):
        """      
        function : Unpack the info of gtm
        input : file Object
        output : NA
        """
        gtmInst = instanceInfo()
        gtmInst.instanceRole = INSTANCE_ROLE_GTM
        gtmInst.hostname = dbNode.name
        info = fp.read(1036)
        (gtmInst.instanceId, gtmInst.mirrorId, gtmNum,
         gtmInst.datadir) = struct.unpack("=III1024s", info)
        gtmInst.datadir = gtmInst.datadir.decode().strip('\x00')
        self.__unPackIps(fp, gtmInst.listenIps)
        info = fp.read(8)
        (gtmInst.port, gtmInst.instanceType) = struct.unpack("=II", info)
        if (gtmInst.instanceType == MASTER_INSTANCE):
            dbNode.gtmNum = 1
        elif (gtmInst.instanceType == STANDBY_INSTANCE):
            dbNode.gtmNum = 0
        else:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51204"] % (
                "GTM", gtmInst.instanceType))
        self.__unPackIps(fp, gtmInst.haIps)
        info = fp.read(4)
        (gtmInst.haPort,) = struct.unpack("=I", info)
        info = fp.read(1024 + 4 + 128 * MAX_IP_NUM + 4)

        if (gtmNum == 1):
            dbNode.gtms.append(gtmInst)
            self.gtmcount += 1
        else:
            dbNode.gtms = []

    def __unpackCooInfo(self, fp, dbNode):
        """      
        function : Unpack the info of coordinator
        input : file Object
        output : NA
        """
        cooInst = instanceInfo()
        cooInst.instanceRole = INSTANCE_ROLE_COODINATOR
        cooInst.hostname = dbNode.name
        cooInst.instanceType = INSTANCE_TYPE_UNDEFINED
        info = fp.read(2060)
        (cooInst.instanceId, cooInst.mirrorId, cooNum, cooInst.datadir,
         cooInst.ssdDir) = struct.unpack("=IiI1024s1024s", info)
        cooInst.datadir = cooInst.datadir.decode().strip('\x00')
        cooInst.ssdDir = cooInst.ssdDir.decode().strip('\x00')
        self.__unPackIps(fp, cooInst.listenIps)
        info = fp.read(8)
        (cooInst.port, cooInst.haPort) = struct.unpack("=II", info)
        if (cooNum == 1):
            dbNode.cooNum = 1
            dbNode.coordinators.append(cooInst)
        else:
            dbNode.cooNum = 0
            dbNode.coordinators = []

    def __unpackDataNode(self, fp, dbNode):
        """  
        function : Unpack the info of datanode
        input : file Object
        output : NA
        """
        info = fp.read(4)
        (dataNodeNums,) = struct.unpack("=I", info)
        dbNode.dataNum = 0

        dbNode.datanodes = []
        for i in range(dataNodeNums):
            dnInst = instanceInfo()
            dnInst.instanceRole = INSTANCE_ROLE_DATANODE
            dnInst.hostname = dbNode.name
            # In the upgrade scenario, there are two different read methods
            # for static config file.
            # First, use the new read mode, and judge that if the new read
            # mode is not correct,
            # then rollback by fp.seek(), and exchange its(xlogdir) value
            # with ssddir.
            info = fp.read(2056)
            (dnInst.instanceId, dnInst.mirrorId, dnInst.datadir,
             dnInst.xlogdir) = struct.unpack("=II1024s1024s", info)
            dnInst.datadir = dnInst.datadir.decode().strip('\x00')
            dnInst.xlogdir = dnInst.xlogdir.decode().strip('\x00')

            info = fp.read(1024)
            (dnInst.ssdDir) = struct.unpack("=1024s", info)
            dnInst.ssdDir = dnInst.ssdDir[0].decode().strip('\x00')
            # if notsetXlog,ssdDir should not be null.use by upgrade.
            if dnInst.ssdDir != "" and dnInst.ssdDir[0] != '/':
                fp.seek(fp.tell() - 1024)
                dnInst.ssdDir = dnInst.xlogdir
                dnInst.xlogdir = ""

            self.__unPackIps(fp, dnInst.listenIps)
            info = fp.read(8)
            (dnInst.port, dnInst.instanceType) = struct.unpack("=II", info)
            if (dnInst.instanceType == MASTER_INSTANCE):
                dbNode.dataNum += 1
            elif (dnInst.instanceType in [STANDBY_INSTANCE,
                                          DUMMY_STANDBY_INSTANCE, CASCADE_STANDBY]):
                pass
            else:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51204"]
                                % ("DN", dnInst.instanceType))
            self.__unPackIps(fp, dnInst.haIps)
            info = fp.read(4)
            (dnInst.haPort,) = struct.unpack("=I", info)
            if (
                    self.clusterType ==
                    CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY or
                    self.clusterType == CLUSTER_TYPE_SINGLE_INST):
                maxStandbyCount = MIRROR_COUNT_REPLICATION_MAX - 1
                for j in range(maxStandbyCount):
                    peerDbInst = peerInstanceInfo()
                    info = fp.read(1024)
                    (peerDbInst.peerDataPath,) = struct.unpack("=1024s", info)
                    peerDbInst.peerDataPath = \
                        peerDbInst.peerDataPath.decode().strip('\x00')
                    self.__unPackIps(fp, peerDbInst.peerHAIPs)
                    info = fp.read(8)
                    (peerDbInst.peerHAPort,
                     peerDbInst.peerRole) = struct.unpack("=II", info)
                    dnInst.peerInstanceInfos.append(peerDbInst)
            else:
                peerDbInst = peerInstanceInfo()
                info = fp.read(1024)
                (peerDbInst.peerDataPath,) = struct.unpack("=1024s", info)
                peerDbInst.peerDataPath = \
                    peerDbInst.peerDataPath.decode().strip('\x00')
                self.__unPackIps(fp, peerDbInst.peerHAIPs)
                info = fp.read(8)
                (peerDbInst.peerHAPort, peerDbInst.peerRole) = \
                    struct.unpack("=II", info)
                info = fp.read(1024)
                (peerDbInst.peerData2Path,) = struct.unpack("=1024s", info)
                peerDbInst.peerData2Path = \
                    peerDbInst.peerDataPath.decode().strip('\x00')
                self.__unPackIps(fp, peerDbInst.peer2HAIPs)
                info = fp.read(8)
                (peerDbInst.peer2HAPort, peerDbInst.peer2Role) = \
                    struct.unpack("=II", info)
                dnInst.peerInstanceInfos.append(peerDbInst)
            dbNode.datanodes.append(dnInst)

    def initFromStaticConfigWithoutUser(self, staticConfigFile):
        """ 
        function : Init cluster from static config with out user
        input : file Object
        output : NA
        """
        fp = None
        try:
            staticConfigFilePath = os.path.split(staticConfigFile)[0]
            versionFile = os.path.join(
                staticConfigFilePath, "upgrade_version")
            version, number, commitid = VersionInfo.get_version_info(
                versionFile)
            # read cluster info from static config file
            fp = open(staticConfigFile, "rb")
            if float(number) <= 92.200:
                info = fp.read(32)
                (crc, lenth, version, currenttime, nodeNum,
                 localNodeId) = struct.unpack("=qIIqiI", info)
            else:
                info = fp.read(28)
                (crc, lenth, version, currenttime, nodeNum,
                 localNodeId) = struct.unpack("=IIIqiI", info)
            if (version <= 100):
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"]
                                % ("cluster static config version[%s]"
                                   % version, "the new version[%s]"
                                   % BIN_CONFIG_VERSION))
            elif (version >= 101 and version <= 200):
                self.clusterType = CLUSTER_TYPE_SINGLE
                if (BIN_CONFIG_VERSION_SINGLE != version):
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"]
                                    % ("cluster static config version[%s]"
                                       % version, "the new version[%s]"
                                       % BIN_CONFIG_VERSION_SINGLE))
            elif (version >= 201 and version <= 300):
                self.clusterType = CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY
                if (
                        BIN_CONFIG_VERSION_SINGLE_PRIMARY_MULTI_STANDBY !=
                        version):
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % (
                        "cluster static config version[%s]" % version,
                        "the new version[%s]"
                        % BIN_CONFIG_VERSION_SINGLE_PRIMARY_MULTI_STANDBY))
            elif (version >= 301 and version <= 400):
                self.clusterType = CLUSTER_TYPE_SINGLE_INST
                if (BIN_CONFIG_VERSION_SINGLE_INST != version):
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"]
                                    % ("cluster static config version[%s]"
                                       % version, "the new version[%s]"
                                       % BIN_CONFIG_VERSION_SINGLE_INST))

            self.dbNodes = []
            for i in range(nodeNum):
                offset = (fp.tell() // PAGE_SIZE + 1) * PAGE_SIZE
                fp.seek(offset)
                dbNode = self.__unPackNodeInfo(fp, number)
                self.dbNodes.append(dbNode)
            fp.close()
        except Exception as e:
            if (fp):
                fp.close()
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51203"]
                            % "cluster" + " Error: \n%s" % str(e))

    def __appendInstanceId(self, static_config_file):
        """ 
        function : instance id append to the old cluster.
        input : file Object
        output : NA
        """
        try:
            # init oldClusterInfo
            oldClusterInfo = dbClusterInfo()
            oldClusterInfo.initFromStaticConfigWithoutUser(static_config_file)

            # get max CN/CMA/master-standby DN/dummy DN instanceId of old
            # cluster.
            # CMS/GTM/ETCD instanceId and nodeId will not be changed.
            maxCNInstanceId = 0
            maxCMAInstanceId = 0
            maxMasterDNInstanceId = 0
            maxDummyDNInstanceId = 0
            # new DB mirrorId shoud be refreshed.
            # CN mirrorId is const -1, so no need to refresh.
            # CMA mirrorId is const-3, so no need to refresh.
            # ETCD mirrorId is const -5, so no need to refresh.
            # CMS and GTM of new cluster will not simultaneous exist with
            # old cluster,
            # so no need to refresh.
            maxMirrorId = 0
            for olddbNode in oldClusterInfo.dbNodes:
                for oldcnInst in olddbNode.coordinators:
                    if (oldcnInst.instanceId > maxCNInstanceId):
                        maxCNInstanceId = oldcnInst.instanceId
                for oldcmaInst in olddbNode.cmagents:
                    if (oldcmaInst.instanceId > maxCMAInstanceId):
                        maxCMAInstanceId = oldcmaInst.instanceId
                for olddnInst in olddbNode.datanodes:
                    if (olddnInst.instanceType == MASTER_INSTANCE and
                            olddnInst.instanceId > maxMasterDNInstanceId):
                        maxMasterDNInstanceId = olddnInst.instanceId
                    elif (olddnInst.instanceType == DUMMY_STANDBY_INSTANCE and
                          olddnInst.instanceId > maxDummyDNInstanceId):
                        maxDummyDNInstanceId = olddnInst.instanceId
                    if (olddnInst.mirrorId > maxMirrorId):
                        maxMirrorId = olddnInst.mirrorId
                for oldcmsInst in olddbNode.cmservers:
                    if (oldcmsInst.mirrorId > maxMirrorId):
                        maxMirrorId = oldcmsInst.mirrorId
                for oldetcdInst in olddbNode.etcds:
                    if (oldetcdInst.mirrorId > maxMirrorId):
                        maxMirrorId = oldetcdInst.mirrorId

            maxCNInstanceId += 1
            maxCMAInstanceId += 1
            maxMasterDNInstanceId += 2
            maxDummyDNInstanceId += 1
            maxMirrorId += 1
            mirrorIdDict = {}

            for newdbNode in self.dbNodes:
                if (len(newdbNode.coordinators) > 0):
                    ## refresh CN instanceId here
                    newdbNode.coordinators[0].instanceId = maxCNInstanceId
                    maxCNInstanceId += 1

                if (len(newdbNode.cmagents) > 0):
                    ## refresh CMA instanceId here
                    newdbNode.cmagents[0].instanceId = maxCMAInstanceId
                    maxCMAInstanceId += 1

                for dnInst in newdbNode.datanodes:
                    if (dnInst.instanceType == MASTER_INSTANCE):
                        masterInst = dnInst
                        ## refresh master instanceId here
                        dnInst.instanceId = maxMasterDNInstanceId
                        maxMasterDNInstanceId += 1

                        ## get related standby and dummy-standby instances
                        for dbNode in self.dbNodes:
                            for inst in dbNode.datanodes:
                                if (inst.mirrorId == dnInst.mirrorId and
                                        inst.instanceType == STANDBY_INSTANCE):
                                    standbyInst = inst
                                    ## refresh related standby instanceId here
                                    inst.instanceId = maxMasterDNInstanceId
                                    maxMasterDNInstanceId += 1

                                elif (inst.mirrorId == dnInst.mirrorId and
                                      inst.instanceType ==
                                      DUMMY_STANDBY_INSTANCE):
                                    dummyInst = inst
                                    ## refresh related dummy-standby
                                    # instanceId here
                                    inst.instanceId = maxDummyDNInstanceId
                                    maxDummyDNInstanceId += 1

                        ## refresh mirrorId here,Must refresh it at last.
                        mirrorIdDict[maxMirrorId] = [masterInst, standbyInst,
                                                     dummyInst]
                        maxMirrorId += 1

            for mirrorId in list(mirrorIdDict.keys()):
                mirrorIdDict[mirrorId][0].mirrorId = mirrorId
                mirrorIdDict[mirrorId][1].mirrorId = mirrorId
                mirrorIdDict[mirrorId][2].mirrorId = mirrorId
        except Exception as e:
            raise Exception(str(e))

    def setInstId(self, instList, nodeIdInstIdDict, newNodeId, newInstId):
        """
        instList                  instance list
        nodeIdInstIdDict          node id and instance id dict
        newNodeId                 new node id
        newInstId                 new instance id
        
        """
        for inst in instList:
            if (newNodeId in list(nodeIdInstIdDict.keys())):
                inst.instanceId = nodeIdInstIdDict[newNodeId]
            # the New agent instance
            else:
                inst.instanceId = newInstId
                newInstId += 1
        return newInstId

    def refreshInstIdByInstType(self, oldNodesList, newNodesList,
                                instType="cmagent"):
        """
        """
        nodeIdInstanceIdDict = {}
        # get the node id and cmagent/cmserver/gtm/etcd/cn instance id dict
        for oldNode in oldNodesList:
            if (instType == "cmagent"):
                for cmaInst in oldNode.cmagents:
                    nodeIdInstanceIdDict[oldNode.id] = cmaInst.instanceId
            elif (instType == "cmserver"):
                for cmsInst in oldNode.cmservers:
                    nodeIdInstanceIdDict[oldNode.id] = cmsInst.instanceId
            elif (instType == "gtm"):
                for gtmInst in oldNode.gtms:
                    nodeIdInstanceIdDict[oldNode.id] = gtmInst.instanceId
            elif (instType == "etcd"):
                for etcdInst in oldNode.etcds:
                    nodeIdInstanceIdDict[oldNode.id] = etcdInst.instanceId
            elif (instType == "cn"):
                for cnInst in oldNode.coordinators:
                    # warm-standby: the number of nodes is same,so refrush
                    # by id
                    # addcn out cluster:refrush by id or nodename
                    # addcn in cluster:refrush by id or nodename
                    # deletecn out cluster:refrush by nodename
                    # deletecn in cluster:refrush by id or nodename
                    # expand:refrush by id or nodename
                    # shink in tail:refrush by id or nodename
                    # shink in mid:refrush by nodename
                    if (len(oldNodesList) == len(newNodesList)):
                        nodeIdInstanceIdDict[oldNode.id] = cnInst.instanceId
                    else:
                        nodeIdInstanceIdDict[oldNode.name] = cnInst.instanceId

        # sort instance id lists and set newInstId = the max ID num + 1
        instIDList = list(nodeIdInstanceIdDict.values())
        instIDList.sort()
        if (len(instIDList) > 0):
            newInstId = instIDList[-1] + 1
        else:
            newInstId = 1

        # refresh instance id by oldClusterInfo
        for newNode in newNodesList:
            if (instType == "cmagent"):
                newInstId = self.setInstId(newNode.cmagents,
                                           nodeIdInstanceIdDict, newNode.id,
                                           newInstId)
            elif (instType == "cmserver"):
                newInstId = self.setInstId(newNode.cmservers,
                                           nodeIdInstanceIdDict, newNode.id,
                                           newInstId)
            elif (instType == "gtm"):
                newInstId = self.setInstId(newNode.gtms, nodeIdInstanceIdDict,
                                           newNode.id, newInstId)
            elif (instType == "etcd"):
                newInstId = self.setInstId(newNode.etcds, nodeIdInstanceIdDict,
                                           newNode.id, newInstId)
            elif (instType == "cn"):
                if (len(oldNodesList) == len(newNodesList)):
                    newInstId = self.setInstId(newNode.coordinators,
                                               nodeIdInstanceIdDict,
                                               newNode.id, newInstId)
                else:
                    newInstId = self.setInstId(newNode.coordinators,
                                               nodeIdInstanceIdDict,
                                               newNode.name, newInstId)

    def flushCNInstanceId(self, oldNodesList, newNodesList):
        """ 
        function : Refresh CN instance id
        input : oldNodesList:                :The cluster nodes list from
        static_config_file
                newNodesList:                :The cluster nodes list from
                new oldes
        output : NA
        """
        self.refreshInstIdByInstType(oldNodesList, newNodesList, "cn")

    def getMaxStandbyAndDummyDNInstanceId(self, oldNodesList):
        """ 
        function : get max standby and dummy DB instanceId of old cluster.
        input : oldNodesList:                :The cluster nodes list from
        static_config_file
        output : NA
        """
        # get max standby and dummy DB instanceId of old cluster.
        maxStandbyDNInstanceId = 0
        maxDummyDNInstanceId = 0
        for oldNode in oldNodesList:
            for olddnInst in oldNode.datanodes:
                if (olddnInst.instanceType == STANDBY_INSTANCE and
                        olddnInst.instanceId > maxStandbyDNInstanceId):
                    maxStandbyDNInstanceId = olddnInst.instanceId
                elif (olddnInst.instanceType == DUMMY_STANDBY_INSTANCE and
                      olddnInst.instanceId > maxDummyDNInstanceId):
                    maxDummyDNInstanceId = olddnInst.instanceId
        return (maxStandbyDNInstanceId, maxDummyDNInstanceId)

    def flushDNInstanceId(self, oldNodesList, newNodesList):
        """ 
        function : Refresh DB instance id. When refresh DB id, the node id
        has been refreshed.
        input : oldNodesList:                :The cluster nodes list from
        static_config_file
                newNodesList:                :The cluster nodes list from
                new oldes
        output : NA
        """
        # get all old node id list
        oldNodeIdList = []
        for oldNode in oldNodesList:
            oldNodeIdList.append(oldNode.id)

        # get max standby and dummy DB instanceId of old cluster.
        (maxStandbyDNInstanceId,
         maxDummyDNInstanceId) = self.getMaxStandbyAndDummyDNInstanceId(
            oldNodesList)
        # set next primary/standby and dummy DB instanceId
        maxMasterDNInstanceId = maxStandbyDNInstanceId + 1
        maxDummyDNInstanceId += 1

        # refresh DB instance id of new nodes by oldNodesList and
        # maxMasterDNInstanceId/maxDummyDNInstanceId
        oldLen = len(oldNodesList)
        newLen = len(newNodesList)
        minLen = 0
        maxLen = 0
        if (oldLen > newLen):
            maxLen = oldLen
            minLen = newLen
        else:
            maxLen = newLen
            minLen = oldLen

        # refresh DB id one by one by old node
        i = 0
        for newNode in newNodesList[0:minLen]:
            # refresh DB instanceId if DB numbers not equal. Only for move
            # DB instance
            if (len(oldNodesList[i].datanodes) != len(newNode.datanodes)):
                break
            else:
                # refresh DB instanceId one by one (primary/standby/dummy in
                # cluster_static_config )
                instid = 0
                for dnInst in newNode.datanodes:
                    dnInst.instanceId = oldNodesList[i].datanodes[
                        instid].instanceId
                    instid += 1
                i += 1

        # refresh the new node DB id
        for newNode in newNodesList[minLen:maxLen]:
            for dnInst in newNode.datanodes:
                if (dnInst.instanceType == MASTER_INSTANCE):
                    ## get standby/dummy instances
                    standbyInsts = []
                    dummyStandbyInsts = []
                    peerInsts = self.getPeerInstance(dnInst)
                    for inst in peerInsts:
                        if (inst.instanceType == STANDBY_INSTANCE):
                            standbyInsts.append(inst)
                        elif (inst.instanceType == DUMMY_STANDBY_INSTANCE):
                            dummyStandbyInsts.append(inst)

                    ## refresh master instanceId here
                    dnInst.instanceId = maxMasterDNInstanceId
                    maxMasterDNInstanceId += 1

                    ## refresh standby/dummy instanceId here. Only do it
                    # under new dbnodes list
                    for tmpNode in newNodesList[minLen:maxLen]:
                        for tmpdnInst in tmpNode.datanodes:
                            if (tmpdnInst.instanceType == STANDBY_INSTANCE):
                                for standbyInst in standbyInsts:
                                    if (tmpdnInst.instanceId ==
                                            standbyInst.instanceId):
                                        ## refresh standby instanceId here
                                        tmpdnInst.instanceId = \
                                            maxMasterDNInstanceId
                                        maxMasterDNInstanceId += 1
                            elif (
                                    tmpdnInst.instanceType ==
                                    DUMMY_STANDBY_INSTANCE):
                                for dummyStandbyInst in dummyStandbyInsts:
                                    if (tmpdnInst.instanceId ==
                                            dummyStandbyInst.instanceId):
                                        ## refresh standby instanceId here
                                        tmpdnInst.instanceId = \
                                            maxDummyDNInstanceId
                                        maxDummyDNInstanceId += 1

    def __check_cms_config(self):
        """
        Check cm_server config
        """
        if self.cmscount > 0 and len(self.dbNodes) < 2:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] +
                            "The cm_server instance can be "
                            "configured only on three or more nodes.")
        if 0 < self.cmscount < 2:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] +
                            "At least three cm_server instances are required.")

    def initFromXml(self, xmlFile):
        """
        function : Init cluster from xml config file
        input : file Object for OLAP
                dbClusterInfo instance
                inherit: instance id inherit from the old cluster.
                append: instance id append to the old cluster.
        output : NA
        """
        if (not os.path.exists(xmlFile)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"]
                            % "XML configuration file")

        self.xmlFile = xmlFile

        # Set the environment variable, then the readcluster command can
        # read from it.
        os.putenv(ClusterConstants.ENV_CLUSTERCONFIG, xmlFile)
        # parse xml file
        global xmlRootNode
        try:
            xmlRootNode = ClusterConfigFile.initParserXMLFile(xmlFile)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51234"]
                            % xmlFile + " Error:\n%s" % str(e))

        self.__readClusterGlobalInfo()
        if self.__read_and_check_config_item(xmlRootNode, "clusterType", "cluster") == \
                "single-inst-one-node":
            self.__read_cluster_node_info_for_one()
        else:
            self.__readClusterNodeInfo()
        self.__checkAZForSingleInst()
        IpPort = self.__checkInstancePortandIP()
        self.__check_cms_config()
        return IpPort

    def __read_cluster_node_info_for_one(self):
        """
        function : Read cluster node info.
        input : NA
        output : NA
        """
        # read cluster node info.
        (_, node_name) = ClusterConfigFile.readOneClusterConfigItem(xmlRootNode,
                                                                    "nodeNames",
                                                                    "cluster")
        if [node_name] != self.__getAllHostnamesFromDEVICELIST():
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] +
                            " The number of nodeNames and DEVICE are not same.")
        # Get basic info of node: name, ip and master instance number etc.
        self.dbNodes = []
        db_node = dbNodeInfo(1, node_name)
        self.__readNodeBasicInfo(db_node, [node_name])
        self.dbNodes.append(db_node)
        # Get datanode info
        for i in range(db_node.dataNum):
            db_inst = instanceInfo(BASE_ID_DUMMYDATANODE + i, 1)
            db_inst.hostname = node_name
            db_inst.datadir = self.__readNodeStrValue(node_name, "dataNode%s" % (i+1))
            db_inst.instanceType = MASTER_INSTANCE if i == 0 else STANDBY_INSTANCE
            db_inst.instanceRole = INSTANCE_ROLE_DATANODE
            db_inst.listenIps = db_node.backIps[:]
            db_inst.haIps = db_node.backIps[:]
            db_inst.port = self.__readNodeIntValue(node_name, "dataPortBase%s" % (i+1))
            db_inst.haPort = db_inst.port + 1
            db_inst.ssdDir = ""
            db_inst.syncNum = -1
            db_inst.azName = db_node.azName
            self.dbNodes[0].datanodes.append(db_inst)
        self.dbNodes[0].appendInstance(1, MIRROR_ID_AGENT, INSTANCE_ROLE_CMAGENT,
                                       INSTANCE_TYPE_UNDEFINED, [], None, "")

    def getClusterNodeNames(self):
        """
        function : Get the cluster's node names.
        input : NA
        output : NA
        """
        return [dbNode.name for dbNode in self.dbNodes]

    def getClusterNodeIds(self):
        """
        function : Get the cluster's node names.
        input : NA
        output : NA
        """
        return [dbNode.id for dbNode in self.dbNodes]

    def getdataNodeInstanceType(self, nodeId=-1):
        """
        function: get the dataNode's instanceType
        input:  NA
        output: NA
        """
        for dbNode in self.dbNodes:
            if nodeId == dbNode.id:
                for dataNode in dbNode.datanodes:
                    return dataNode.instanceType

    def getHostNameByNodeId(self, nodeId=-1):
        """
        function: get the dataNode's name by nodeId
        input:  NA
        output: NA
        """
        for dbNode in self.dbNodes:
            if nodeId == dbNode.id:
                return dbNode.name

    def get_cluster_directory_dict(self):
        """
        function : Get cluster all directorys
        input : NA
        output : List
        """
        cluster_dirs = dict()
        cluster_dirs["appPath"] = [self.appPath]
        cluster_dirs["logPath"] = [self.logPath]
        # get cluster all directorys
        for db_node in self.dbNodes:
            # including cm_server, cm_agent, cn, dn, gtm, etcd, ssd
            cn_dict =  dict(data_dir="", ssd="")
            dn_dict = dict(data_dir=list(), ssd=list(), xlog_dir=list())
            node_dict = dict(cm_server="", cm_agent="", cn=cn_dict,
                             dn=dn_dict, gtm="", etcd="", ssd="")
            if db_node.cmservers:
                node_dict["cm_server"] = db_node.cmservers[0].datadir
            if db_node.cmagents:
                node_dict["cm_agent"] = db_node.cmagents[0].datadir
            if db_node.gtms:
                node_dict["gtm"] = db_node.gtms[0].datadir
            if db_node.coordinators:
                node_dict["cn"]["data_dir"] = db_node.coordinators[0].datadir
                if db_node.coordinators[0].ssdDir:
                    node_dict["cn"]["ssd"] = db_node.coordinators[0].ssdDir
            for dbInst in db_node.datanodes:
                node_dict["dn"]["data_dir"].append(dbInst.datadir)
                node_dict["dn"]["xlog_dir"].append(dbInst.xlogdir)
                if dbInst.ssdDir:
                    node_dict["dn"]["ssd"].append(dbInst.ssdDir)
            if db_node.etcds:
                node_dict["etcd"] = db_node.etcds[0].datadir
            cluster_dirs[db_node.name] = node_dict
        return cluster_dirs


    def getClusterDirectorys(self, hostName="", ignore=True):
        """
        function : Get cluster all directorys
        input : NA
        output : List
        """
        clusterDirs = {}
        clusterDirs["appPath"] = [self.appPath]
        if (ignore):
            clusterDirs["logPath"] = [self.logPath]
        # get cluster all directorys
        for dbNode in self.dbNodes:
            nodeName = dbNode.name
            if (hostName != ""):
                if (hostName != nodeName):
                    continue
            nodeDirs = []
            # including cm_server, cm_agent, cn, dn, gtm, etcd, ssd
            nodeDirs.append(dbNode.cmDataDir)
            for dbInst in dbNode.cmservers:
                nodeDirs.append(dbInst.datadir)
            for dbInst in dbNode.cmagents:
                nodeDirs.append(dbInst.datadir)
            for dbInst in dbNode.gtms:
                nodeDirs.append(dbInst.datadir)
            for dbInst in dbNode.coordinators:
                nodeDirs.append(dbInst.datadir)
                if (len(dbInst.ssdDir) != 0):
                    nodeDirs.append(dbInst.ssdDir)
            for dbInst in dbNode.datanodes:
                nodeDirs.append(dbInst.datadir)
                nodeDirs.append(dbInst.xlogdir)
                if (len(dbInst.ssdDir) != 0):
                    nodeDirs.append(dbInst.ssdDir)
            for dbInst in dbNode.etcds:
                nodeDirs.append(dbInst.datadir)
            clusterDirs[nodeName] = nodeDirs
        return clusterDirs

    def getDbNodeByName(self, name):
        """
        function : Get node by name.
        input : nodename
        output : []
        """
        for dbNode in self.dbNodes:
            if (dbNode.name == name):
                return dbNode

        return None

    def getPeerInstance(self, dbInst):
        """  
        function : Get peer instance of specified instance.
        input : []
        output : []
        """
        instances = []
        for dbNode in self.dbNodes:
            for inst in dbNode.datanodes:
                if (inst.mirrorId == dbInst.mirrorId and
                        inst.instanceId != dbInst.instanceId):
                    instances.append(inst)
        if instances:
            instances.sort(key=lambda inst: inst.instanceId)
        return instances

    def getClusterBackIps(self):
        """
        function : Get cluster back IP.
        input : NA
        output : []
        """
        backIps = []
        backIpNum = []
        # get backIp number
        for dbNode in self.dbNodes:
            backIpNum.append(len(dbNode.backIps))
        if max(backIpNum) != min(backIpNum):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51227"] % "backIps")
        for num in range(backIpNum[0]):
            ips = []
            for dbNode in self.dbNodes:
                ips.append(dbNode.backIps[num])
            backIps.extend(ips)
        return backIps

    def getClusterSshIps(self):
        """
        function : Get cluster ssh IP.
        input : NA
        output : []
        """
        sshIps = []
        sshIpNum = []
        # get sshIp number
        for dbNode in self.dbNodes:
            sshIpNum.append(len(dbNode.sshIps))
        if max(sshIpNum) != min(sshIpNum):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51227"] % "sshIps")
        for num in range(sshIpNum[0]):
            ips = []
            for dbNode in self.dbNodes:
                ips.append(dbNode.sshIps[num])
            sshIps.append(ips)
        return sshIps

    def getazNames(self):
        """
        """
        azMap = {}
        azNames = []
        for dbNode in self.dbNodes:
            azMap[dbNode.azName] = []
            if (dbNode.azName not in azNames):
                azNames.append(dbNode.azName)
        for dbNode in self.dbNodes:
            azMap[dbNode.azName].append(dbNode.azPriority)
        for azName in azNames:
            azMap[azName] = max(azMap[azName])
        azNames = sorted(azMap, key=lambda x: azMap[x])
        return azNames

    def getNodeNameByBackIp(self, backIp):
        """
        function : Get Nodename by backip.
        input : String
        output : String
        """
        nodeName = ""
        for dbNode in self.dbNodes:
            if (backIp in dbNode.backIps):
                nodeName = dbNode.name
                break
        return nodeName

    def __checkInstancePortandIP(self):
        """
        function : Check instance Port and IP.
        input : NA
        output : NA
        """
        nodeipport = {}
        for dbNode in self.dbNodes:
            nodeips = []
            nodeports = []
            cmsListenIPs = []
            ipCheckMap = {}
            backIP1 = dbNode.backIps[0]
            nodeips.extend(dbNode.backIps)
            nodeips.extend(dbNode.sshIps)
            # get node ip and node port from cmserver
            for cmsInst in dbNode.cmservers:
                nodeips.extend(cmsInst.listenIps)
                nodeips.extend(cmsInst.haIps)
                cmsListenIPs = cmsInst.listenIps
                ipCheckMap["cmServerListenIp1"] = cmsInst.listenIps[0]
                ipCheckMap["cmServerHaIp1"] = cmsInst.haIps[0]
                nodeports.append(cmsInst.port)
                nodeports.append(cmsInst.haPort)
            # get node ip and node port from gtm
            for gtmInst in dbNode.gtms:
                nodeips.extend(gtmInst.listenIps)
                nodeips.extend(gtmInst.haIps)
                nodeports.append(gtmInst.port)
                nodeports.append(gtmInst.haPort)
            # get node ip and node port from cn
            for cooInst in dbNode.coordinators:
                nodeips.extend(cooInst.listenIps)
                nodeips.extend(cooInst.haIps)
                nodeports.append(cooInst.port)
                nodeports.append(cooInst.haPort)
            # get node ip and node port from dn
            for dnInst in dbNode.datanodes:
                nodeips.extend(dnInst.listenIps)
                nodeips.extend(dnInst.haIps)
                nodeports.append(dnInst.port)
                nodeports.append(dnInst.haPort)
                if (self.checkSctpPort):
                    nodeports.append(dnInst.port +
                                     dbNode.getDnNum(dnInst.instanceType) * 2)
            # get node ip and node port from etcd
            for etcdInst in dbNode.etcds:
                nodeips.extend(etcdInst.listenIps)
                nodeips.extend(etcdInst.haIps)
                nodeports.append(etcdInst.port)
                nodeports.append(etcdInst.haPort)
                ipCheckMap["etcdListenIp1"] = etcdInst.listenIps[0]
                ipCheckMap["etcdHaIp1"] = etcdInst.haIps[0]
                if (len(etcdInst.listenIps) > 1):
                    etcdListenIp2 = etcdInst.listenIps[1]
                    if (etcdListenIp2 != backIP1):
                        raise Exception(ErrorCode.GAUSS_512["GAUSS_51220"] % (
                                "%s with etcdListenIp2" % etcdListenIp2) +
                                        " Error: \nThe IP address must be "
                                        "the same as the backIP1 %s." %
                                        backIP1)

            # CMS IP must be consistent with CMA IP
            cmaListenIPs = dbNode.cmagents[0].listenIps
            if (cmsListenIPs and cmsListenIPs != cmaListenIPs):
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51220"] % (
                        "%s with cm_server" % cmsListenIPs) +
                                " Error: \nThe IP address must be the same "
                                "as the cm_agent %s." % cmaListenIPs)
            if (g_networkType == 1):
                # Check
                ipCheckMap["cmAgentConnectIp1"] = cmaListenIPs[0]
                if (len(set(ipCheckMap.values())) != 1):
                    errMsg = " Error: \nThe following IPs must be consistent:"
                    for ipConfigItem in list(ipCheckMap.keys()):
                        errMsg += "\n%s: %s" % (
                            ipConfigItem, ipCheckMap[ipConfigItem])
                    raise Exception(ErrorCode.GAUSS_512["GAUSS_51220"] % (
                        "with cm and etcd") + errMsg)
            # create a dictionary 
            nodeipport[dbNode.name] = [nodeips, nodeports]
            # check port and ip
            self.__checkPortandIP(nodeips, nodeports, dbNode.name)
        return nodeipport

    def __checkPortandIP(self, ips, ports, name):
        """  
        function : Check  port and IP.
        input : String,int,string
        output : NA
        """
        ipsCopy = list(set(ips))
        portsCopy = list(set(ports))
        for port in portsCopy:
            if (not self.__isPortValid(port)):
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51233"]
                                % (port, name) + " Please check it.")

        for ip in ipsCopy:
            if (not self.__isIpValid(ip)):
                raise Exception(ErrorCode.GAUSS_506["GAUSS_50603"] + \
                                "The IP address is: %s." % ip + " Please "
                                                                "check it.")

    @staticmethod
    def __read_and_check_config_item(root_node, para, root_type, error_ignore=False):
        """
        function : Read one cluster configuration item and check path valid
        input : root_node: RootNode
                para: param_name
                root_type: clusterType or node
                error_ignore: boolean
        output : String
        """
        status, output = ClusterConfigFile.readOneClusterConfigItem(
            root_node, para, root_type)
        if status != 0 and not error_ignore:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % para + " Error: \n%s" % output)
        if output.strip() and para in ["gaussdbAppPath", "gaussdbLogPath"]:
            output = os.path.normpath(output.strip())
        else:
            output = output.strip()

        if output:
            checkPathVaild(output)
        return output

    def __readClusterGlobalInfo(self):
        """
        Read cluster info from xml config's <CLUSTER> tag except nodeNames,
        clusterRings and sqlExpandNames info
        :return: NA
        """
        global g_networkType
        self.clusterType = CLUSTER_TYPE_SINGLE_INST

        # Read cluster name
        self.name = self.__read_and_check_config_item(xmlRootNode, "clusterName", "cluster")
        # Read application install path
        self.appPath = self.__read_and_check_config_item(xmlRootNode, "gaussdbAppPath", "cluster")
        # Read application log path
        self.logPath = self.__read_and_check_config_item(xmlRootNode, "gaussdbLogPath",
                                                         "cluster", error_ignore=True)
        if not self.logPath:
            self.logPath = "/var/log/gaussdb"
        if not os.path.isabs(self.logPath):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50213"] % \
                            ("%s log path(%s)" % (
                                VersionInfo.PRODUCT_NAME, self.logPath)))
        # Read enable_dcf
        ret_status, self.enable_dcf = ClusterConfigFile.readOneClusterConfigItem(xmlRootNode,
                                                               "enable_dcf",
                                                               "cluster")
        if self.enable_dcf not in ['', 'on', 'off']:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50011"] %
                                ('enable_dcf', self.enable_dcf))
        if self.enable_dcf == 'on':
            (ret_status, ret_value) = ClusterConfigFile.readOneClusterConfigItem(
                xmlRootNode, "dcf_config", "CLUSTER")
            if ret_status == 0:
                self.dcf_config = ret_value.strip()
                if self.dcf_config.count('role') - self.dcf_config.count('PASSIVE') < 3:
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50011"] %
                                    ('dcf_config', self.dcf_config))
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                                'dcf_config' + " Error: \n%s" % ret_value)

        # Read network type
        (retStatus, retValue) = ClusterConfigFile.readOneClusterConfigItem(
            xmlRootNode, "networkType", "cluster")
        if retStatus == 0:
            if retValue.isdigit() and int(retValue) in [0, 1]:
                g_networkType = int(retValue)
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                  "cluster network type" + " Error: \nThe parameter value must be 0 or 1.")
        elif retStatus == 2:
            g_networkType = 0
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                            "cluster network type" + " Error: \n%s" % retValue)

        if "HOST_IP" in os.environ.keys():
            self.corePath = self.__read_and_check_config_item(xmlRootNode, "corePath",
                                                              "cluster", True)

    def __getAllHostnamesFromDEVICELIST(self):
        """
        function : Read all host name from <DEVICELIST>
        input : Na
        output : str
        """
        if not xmlRootNode.findall('DEVICELIST'):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"] % 'DEVICELIST')
        DeviceArray = xmlRootNode.findall('DEVICELIST')[0]
        DeviceNodeList = DeviceArray.findall('DEVICE')
        allNodeName = []
        for dev in DeviceNodeList:
            paramList = dev.findall('PARAM')
            for param in paramList:
                thisname = param.attrib['name']
                if (thisname == 'name'):
                    value = param.attrib['value']
                    allNodeName.append(value)
        return allNodeName

    def __readClusterNodeInfo(self):
        """
        function : Read cluster node info.
        input : NA
        output : NA
        """
        # read cluster node info.
        (retStatus, retValue) = ClusterConfigFile.readOneClusterConfigItem(xmlRootNode,
                                                         "nodeNames",
                                                         "cluster")
        if (retStatus != 0):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                            % "node names" + " Error: \n%s" % retValue)
        nodeNames = []
        nodeNames_tmp = retValue.split(",")
        for nodename in nodeNames_tmp:
            nodeNames.append(nodename.strip())
        if (len(nodeNames) == 0):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                            "cluster configuration" + " There is no node in "
                                                      "cluster configuration"
                                                      " file.")

        if (len(nodeNames) != len(list(set(nodeNames)))):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                            "cluster configuration" + " There contains "
                                                      "repeated node in "
                                                      "cluster configuration "
                                                      "file.")

        # Check node names
        nodeNameList = self.__getAllHostnamesFromDEVICELIST()
        if len(nodeNameList) != len(nodeNames):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] + \
                            " The number of nodeNames and DEVICE are not "
                            "same.")
        for nodeName in nodeNames:
            if nodeName not in nodeNameList:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] + \
                                " Can not found DEVICE for [%s]." % nodeName)
        # Get basic info of node: name, ip and master instance number etc.
        self.dbNodes = []
        i = 1
        for name in nodeNames:
            dbNode = dbNodeInfo(i, name)
            self.__readNodeBasicInfo(dbNode, nodeNames)
            self.dbNodes.append(dbNode)
            i += 1

        # Get cm server info
        for dbNode in self.dbNodes:
            self.__readCmsConfig(dbNode)

        # Get datanode info
        for dbNode in self.dbNodes:
            self.__readDataNodeConfig(dbNode)

        # Get cm agent info
        for dbNode in self.dbNodes:
            self.__readCmaConfig(dbNode)

        # set DB port for OLAP
        for node in self.dbNodes:
            for inst in node.datanodes:
                inst.azName = node.azName
        self.__setNodePortForSinglePrimaryMultiStandby()

    def __getPeerInstance(self, dbInst):
        """
        function : Get peer instance of specified instance.
        input : []
        output : []
        """
        instances = []
        if (dbInst.instanceRole == INSTANCE_ROLE_CMSERVER):
            for dbNode in self.dbNodes:
                for inst in dbNode.cmservers:
                    if (inst.mirrorId == dbInst.mirrorId and
                            inst.instanceId != dbInst.instanceId):
                        instances.append(inst)
        elif (dbInst.instanceRole == INSTANCE_ROLE_GTM):
            for dbNode in self.dbNodes:
                for inst in dbNode.gtms:
                    if (inst.mirrorId == dbInst.mirrorId and
                            inst.instanceId != dbInst.instanceId):
                        instances.append(inst)
        elif (dbInst.instanceRole == INSTANCE_ROLE_COODINATOR):
            for dbNode in self.dbNodes:
                for inst in dbNode.coordinators:
                    if (inst.mirrorId == dbInst.mirrorId and
                            inst.instanceId != dbInst.instanceId):
                        instances.append(inst)
        elif (dbInst.instanceRole == INSTANCE_ROLE_DATANODE):
            for dbNode in self.dbNodes:
                for inst in dbNode.datanodes:
                    if (inst.mirrorId == dbInst.mirrorId and
                            inst.instanceId != dbInst.instanceId):
                        instances.append(inst)

        return instances

    def __setNodePortForSinglePrimaryMultiStandby(self):
        """
        function : set the standy DB port.
        input : []
        output : NA
        """
        for dbNode in self.dbNodes:
            i = 0
            for dbInst in dbNode.datanodes:
                if (dbInst.instanceType == MASTER_INSTANCE):
                    dbInst.port = dbNode.masterBasePorts[
                                      INSTANCE_ROLE_DATANODE] + i * \
                                  PORT_STEP_SIZE
                    dbInst.haPort = dbInst.port + 1
                    peerInsts = self.__getPeerInstance(dbInst)
                    for j in range(len(peerInsts)):
                        peerInsts[j].port = dbInst.port
                        peerInsts[j].haPort = peerInsts[j].port + 1
                    i += 1
            # flush CMSERVER instance port
            i = 0
            cmsbaseport = 0
            for dbInst in dbNode.cmservers:
                if (dbInst.instanceType == MASTER_INSTANCE):
                    cmsbaseport = dbNode.masterBasePorts[
                        INSTANCE_ROLE_CMSERVER]
                    dbInst.port = cmsbaseport + i * PORT_STEP_SIZE
                    dbInst.haPort = dbInst.port + 1
                    peerInsts = self.__getPeerInstance(dbInst)
                    for j in range(len(peerInsts)):
                        peerInsts[j].port = cmsbaseport
                        peerInsts[j].haPort = peerInsts[j].port + 1
                    i += 1
            # flush GTM instance port
            i = 0
            gtmbaseport = 0
            for dbInst in dbNode.gtms:
                if (dbInst.instanceType == MASTER_INSTANCE):
                    gtmbaseport = dbNode.masterBasePorts[INSTANCE_ROLE_GTM]
                    dbInst.port = gtmbaseport + i * PORT_STEP_SIZE
                    dbInst.haPort = dbInst.port + 1
                    peerInsts = self.__getPeerInstance(dbInst)
                    for j in range(len(peerInsts)):
                        peerInsts[j].port = gtmbaseport
                        peerInsts[j].haPort = peerInsts[j].port + 1
                    i += 1

    def set_cm_info_for_node(self, node, node_names):
        """
        Set CM information for node
        """
        for node_name in node_names:
            if node.cmDataDir.replace(" ", "").find("," + node_name.replace(" ", "") + ",") >= 0:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51235"] %
                                node.cmDataDir +
                                " The cmDir only need one path while you configure "
                                "it with primary and standby cmDir, "
                                "please modify it and try again. "
                                "You can examine the install guide "
                                "for more information to configure xml file.")

        # Get base port
        if node.cmsNum > 0:
            node.masterBasePorts[INSTANCE_ROLE_CMSERVER] = \
                self.__readNodeIntValue(node.name, "cmServerPortBase",
                                        True, MASTER_BASEPORT_CMS)
            if self.isSingleInstCluster():
                node.standbyBasePorts[INSTANCE_ROLE_CMSERVER] = \
                    node.masterBasePorts[INSTANCE_ROLE_CMSERVER]

    def get_local_node_info(self):
        """
        Get local node info
        """
        local_node = [node for node in self.dbNodes if node.id == self.localNodeId]
        return local_node[0] if local_node else None

    def __readNodeBasicInfo(self, dbNode, nodenames):
        """
        function : Read basic info of specified node.
        input : []
        output : NA
        """
        # get backIp
        dbNode.backIps = self.__readNodeIps(dbNode.name, "backIp")
        if (len(dbNode.backIps) == 0):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51207"] % dbNode.name)
        # get sshIp
        dbNode.sshIps = self.__readNodeIps(dbNode.name, "sshIp")
        if (len(dbNode.sshIps) == 0):
            dbNode.sshIps = dbNode.backIps[:]
        # get virtualIp
        dbNode.virtualIp = self.__readVirtualIp(dbNode.name, "virtualIp")

        # Get cm_server number
        dbNode.cmsNum = self.__readNodeIntValue(dbNode.name, "cmsNum", True, 0)
        # Get gtm number
        dbNode.gtmNum = self.__readNodeIntValue(dbNode.name, "gtmNum", True, 0)
        # Get etcd number
        dbNode.etcdNum = self.__readNodeIntValue(dbNode.name, "etcdNum", True,
                                                 0)
        # Get cn number
        dbNode.cooNum = self.__readNodeIntValue(dbNode.name, "cooNum", True, 0)
        # Get DB number
        dbNode.dataNum = self.__readNodeIntValue(dbNode.name, "dataNum", True,
                                                 0)
        # read cm directory for server and agent
        try:
            dbNode.cmDataDir = self.__readNodeStrValue(dbNode.name, "cmDir")
            self.cm_state_list.append(True)
        except Exception as _:
            self.cm_state_list.append(False)
            if not self.check_conf_cm_state():
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51230"] %
                                ("CM", "has same configure."))
        if self.check_conf_cm_state():
            self.set_cm_info_for_node(dbNode, nodenames)

        # check dataNum
        if dbNode.dataNum < 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51208"] % ("dn", dbNode.dataNum))

        # Get base port
        if dbNode.dataNum > 0:
            dbNode.masterBasePorts[INSTANCE_ROLE_DATANODE] = \
                self.__readNodeIntValue(dbNode.name, "dataPortBase",
                                        True, MASTER_BASEPORT_DATA)
            dbNode.standbyBasePorts[INSTANCE_ROLE_DATANODE] = \
                dbNode.masterBasePorts[INSTANCE_ROLE_DATANODE]

        # Get az name
        dbNode.azName = self.__readNodeStrValue(dbNode.name, "azName")
        # check azName
        # Get az Priority
        dbNode.azPriority = self.__readNodeIntValue(dbNode.name, "azPriority",
                                                    True, 0)
        # get cascadeRole
        dbNode.cascadeRole = self.__readNodeStrValue(dbNode.name, "cascadeRole",
                                                     True, "off")
        if (dbNode.azPriority < AZPRIORITY_MIN or
                dbNode.azPriority > AZPRIORITY_MAX):
            raise Exception(ErrorCode.GAUSS_532["GAUSS_53206"] % "azPriority")

        if not dbNode.azName:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51212"] % ("azName"))
        if dbNode.azPriority < 1:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51208"]
                            % ("azPriority", dbNode.azPriority))

    def __getCmsCountFromWhichConfiguredNode(self, masterNode):
        """
        function : get the count of cmservers if current node configured
        cmserver
        input : masterNode
        output : cmsCount
        """
        cmsList = self.__readNodeStrValue(masterNode.name, "cmServerRelation",
                                          True, "").split(",")
        if (len(cmsList) == 0):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                            % ("CMServer configuration on host [%s]"
                               % str(masterNode.name))
                            + " The information of %s is wrong."
                            % "cmServerRelation")
        cmsCount = len(cmsList)
        return cmsCount

    def __readCmsConfig(self, masterNode):
        """
        function : Read cm server config on node.
        input : []
        output : NA
        """
        self.__readCmsConfigForMutilAZ(masterNode)

    def __readCmsConfigForMutilAZ(self, masterNode):
        """
        """
        cmsListenIps = None
        cmsHaIps = None
        if (masterNode.cmsNum > 0):
            self.cmscount = self.__getCmsCountFromWhichConfiguredNode(
                masterNode)
            cmsListenIps = self.__readInstanceIps(masterNode.name,
                                                  "cmServerListenIp",
                                                  self.cmscount)
            cmsHaIps = self.__readInstanceIps(masterNode.name, "cmServerHaIp",
                                              self.cmscount)

        for i in range(masterNode.cmsNum):
            level = self.__readNodeIntValue(masterNode.name, "cmServerlevel")
            hostNames = []
            hostNames_tmp = \
                self.__readNodeStrValue(masterNode.name,
                                        "cmServerRelation").split(",")
            for hostname in hostNames_tmp:
                hostNames.append(hostname.strip())

            instId = self.__assignNewInstanceId(INSTANCE_ROLE_CMSERVER)
            mirrorId = self.__assignNewMirrorId()
            instIndex = i * self.cmscount
            masterNode.appendInstance(instId, mirrorId, INSTANCE_ROLE_CMSERVER,
                                      MASTER_INSTANCE, cmsListenIps[instIndex],
                                      cmsHaIps[instIndex], "", "", level)

            for j in range(1, self.cmscount):
                dbNode = self.getDbNodeByName(hostNames[j])
                if dbNode is None:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                                    % ("CMServer configuration on host [%s]"
                                       % masterNode.name)
                                    + " There is no host named %s."
                                    % hostNames[j])
                instId = self.__assignNewInstanceId(INSTANCE_ROLE_CMSERVER)
                instIndex += 1
                dbNode.appendInstance(instId, mirrorId, INSTANCE_ROLE_CMSERVER,
                                      STANDBY_INSTANCE,
                                      cmsListenIps[instIndex],
                                      cmsHaIps[instIndex], "", "", level)

    def __getDataNodeCount(self, masterNode):
        """
        function : get the count of data nodes
        input : masterNode
        output : dataNodeCount
        """
        dataNodeList = self.__readNodeStrValue(masterNode.name,
                                               "dataNode1",
                                               True, "").split(",")
        dnListLen = len(dataNodeList)
        dataNodeCount = (dnListLen + 1) // 2
        return dataNodeCount

    def __readDataNodeConfig(self, masterNode):
        """   
        function : Read datanode config on node.
        input : []
        output : NA
        """
        self.__readDataNodeConfigForMutilAZ(masterNode)

    def __readDataNodeConfigForMutilAZ(self, masterNode):
        """
        """
        dnListenIps = None
        dnHaIps = None
        mirror_count_data = self.__getDataNodeCount(masterNode)
        if masterNode.dataNum > 0:
            dnListenIps = self.__readInstanceIps(masterNode.name,
                                                 "dataListenIp",
                                                 masterNode.dataNum *
                                                 mirror_count_data)
            dnHaIps = self.__readInstanceIps(masterNode.name, "dataHaIp",
                                             masterNode.dataNum *
                                             mirror_count_data)

        dnInfoLists = [[] for row in range(masterNode.dataNum)]
        xlogInfoLists = [[] for row in range(masterNode.dataNum)]
        dcf_data_lists = [[] for row in range(masterNode.dataNum)]
        ssdInfoList = [[] for row in range(masterNode.dataNum)]
        syncNumList = [-1 for row in range(masterNode.dataNum)]
        totalDnInstanceNum = 0
        # Whether the primary and standby have SET XLOG PATH , must be
        # synchronized
        has_xlog_path = 0
        for i in range(masterNode.dataNum):
            dnInfoList = []
            key = "dataNode%d" % (i + 1)
            dnInfoList_tmp = self.__readNodeStrValue(masterNode.name,
                                                     key).split(",")
            for dnInfo in dnInfoList_tmp:
                dnInfoList.append(dnInfo.strip())
            dnInfoListLen = len(dnInfoList)
            if dnInfoListLen != 2 * mirror_count_data - 1:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                                ("database node configuration on host [%s]"
                                 % masterNode.name)
                                + " The information of [%s] is wrong." % key)
            totalDnInstanceNum += (dnInfoListLen + 1) // 2
            dnInfoLists[i].extend(dnInfoList)

            # If not set dataNodeXlogPath in xmlfile,just set
            # xlogInfoListLen = 0,Used for judgement.
            # If set dataNodeXlogPath in xmlfile,each datanode needs to have
            # a corresponding xlogdir.
            xlogInfoList = []
            xlogkey = "dataNodeXlogPath%d" % (i + 1)
            xlogInfoList_tmp = self.__readNodeStrValue(masterNode.name,
                                                       xlogkey).split(",")
            for xlogInfo in xlogInfoList_tmp:
                xlogInfoList.append(xlogInfo.strip())

            # This judgment is necessary,if not set dataNodeXlogPath,
            # xlogInfoListLen will equal 1.
            # Because dninfolist must be set, it does not need extra judgment.
            if xlogInfoList_tmp == ['']:
                xlogInfoListLen = 0
            else:
                xlogInfoListLen = len(xlogInfoList)

            if i == 0:
                has_xlog_path = xlogInfoListLen

            if xlogInfoListLen != has_xlog_path:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                                ("database node configuration on host [%s]"
                                 % masterNode.name)
                                + " The information of [%s] is wrong."
                                % xlogkey)

            if (xlogInfoListLen != 0 and xlogInfoListLen != (
                    dnInfoListLen + 1) // 2):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                                ("database node configuration on host [%s]"
                                 % masterNode.name)
                                + " The information of [%s] is wrong."
                                % xlogkey)
            xlogInfoLists[i].extend(xlogInfoList)
            dcf_data_list = []
            if self.enable_dcf == "on":
                if self.cmscount < 3:
                    raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] +
                                    "At least three cm_server instances are required.")
                for dcf_info in range(0, mirror_count_data * 2, 2):
                    dcf_data_list.append(dnInfoList_tmp[dcf_info] + '/dcf_data')
                dcf_data_lists[i].extend(dcf_data_list)
            else:
                dcf_data_list = ['' for i in range(mirror_count_data)]

            key = "ssdDNDir%d" % (i + 1)
            # ssd doesn't supply ,so set ssddir value to empty
            ssddirList = []
            if self.enable_dcf == "":
                i = 0
            ssdInfoList[i].extend(ssddirList)

            # dataNode syncNum
            key = "dataNode%d_syncNum" % (i + 1)
            syncNum_temp = self.__readNodeStrValue(masterNode.name, key)
            if syncNum_temp is not None:
                syncNum = int(syncNum_temp)
                if syncNum < 0 or syncNum >= totalDnInstanceNum:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                                    ("database node configuration on host [%s]"
                                     % masterNode.name)
                                    + " The information of [%s] is wrong."
                                    % key)
                syncNumList[i] = syncNum

        # check ip num
        if dnListenIps is not None and len(dnListenIps[0]) != 0:
            colNum = len(dnListenIps[0])
            rowNum = len(dnListenIps)
            for col in range(colNum):
                ipNum = 0
                for row in range(rowNum):
                    if dnListenIps[row][col] != "":
                        ipNum += 1
                    else:
                        break
                if ipNum != totalDnInstanceNum:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % \
                                    ("IP number of dataListenIp",
                                     "instance number"))

        if dnHaIps is not None and len(dnHaIps[0]) != 0:
            colNum = len(dnHaIps[0])
            rowNum = len(dnHaIps)
            for col in range(colNum):
                ipNum = 0
                for row in range(rowNum):
                    if dnHaIps[row][col] != "":
                        ipNum += 1
                    else:
                        break
                if ipNum != totalDnInstanceNum:
                    raise Exception(ErrorCode.GAUSS_516["GAUSS_51637"] % \
                                    ("IP number of dataHaIps",
                                     "instance number"))

        instIndex = 0
        for i in range(masterNode.dataNum):
            dnInfoList = dnInfoLists[i]

            # Because xlog may not be set to prevent the array from crossing
            # the boundary
            if xlogInfoListLen != 0:
                xlogInfoList = xlogInfoLists[i]
            groupId = self.__assignNewGroupId()
            if len(ssdInfoList[i]) > 1:
                ssddirList = ssdInfoList[i]
            # master datanode
            instId = self.__assignNewInstanceId(INSTANCE_ROLE_DATANODE)
            # ssd doesn't supply ,this branch will not arrive when len(
            # ssdInfoList[i])  is 0
            if len(ssdInfoList[i]) > 1:
                if xlogInfoListLen == 0:
                    if self.enable_dcf == "on":
                        masterNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              MASTER_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[0], ssddirList[0],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                    else:
                        masterNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  MASTER_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[0], ssddirList[0],
                                                  syncNum=syncNumList[i])
                else:
                    masterNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              MASTER_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[0], ssddirList[0],
                                              xlogdir=xlogInfoList[0],
                                              syncNum=syncNumList[i])
            else:
                if xlogInfoListLen == 0:
                    if self.enable_dcf == "on":
                        masterNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              MASTER_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[0],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                    else:
                        masterNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  MASTER_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[0],
                                                  syncNum=syncNumList[i])
                else:
                    masterNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              MASTER_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[0],
                                              xlogdir=xlogInfoList[0],
                                              syncNum=syncNumList[i])

            instIndex += 1

            for nodeLen in range((len(dnInfoList) + 1) // 2 - 1):
                dbNode = self.getDbNodeByName(dnInfoList[nodeLen * 2 + 1])
                if dbNode is None:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                                    % ("database node configuration on "
                                       "host [%s]" % str(masterNode.name))
                                    + " There is no host named %s."
                                    % dnInfoList[nodeLen * 2 + 1])
                instId = self.__assignNewInstanceId(INSTANCE_ROLE_DATANODE)

                # ssd doesn't supply ,this branch will not arrive when len(
                # ssdInfoList[i])  is 0
                if len(ssdInfoList[i]) > 1:
                    if xlogInfoListLen == 0:
                        if self.enable_dcf == "on":
                            dbNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              STANDBY_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[nodeLen * 2 + 2],
                                              ssddirList[nodeLen * 2 + 1],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                        else:
                            dbNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  STANDBY_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[nodeLen * 2 + 2],
                                                  ssddirList[nodeLen * 2 + 1],
                                                  syncNum=syncNumList[i])
                    else:
                        if self.enable_dcf == "on":
                            dbNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              STANDBY_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[nodeLen * 2 + 2],
                                              ssddirList[nodeLen * 2 + 1],
                                              xlogdir=xlogInfoList[nodeLen + 1],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                        else:
                            dbNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  STANDBY_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[nodeLen * 2 + 2],
                                                  ssddirList[nodeLen * 2 + 1],
                                                  xlogdir=xlogInfoList[nodeLen + 1],
                                                  syncNum=syncNumList[i])
                else:
                    if xlogInfoListLen == 0:
                        if self.enable_dcf == "on":
                            dbNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              STANDBY_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[nodeLen * 2 + 2],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                        else:
                            dbNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  STANDBY_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[nodeLen * 2 + 2],
                                                  syncNum=syncNumList[i])
                    else:
                        if self.enable_dcf == "on":
                            dbNode.appendInstance(instId, groupId,
                                              INSTANCE_ROLE_DATANODE,
                                              STANDBY_INSTANCE,
                                              dnListenIps[instIndex],
                                              dnHaIps[instIndex],
                                              dnInfoList[nodeLen * 2 + 2],
                                              xlogdir=xlogInfoList[nodeLen + 1],
                                              syncNum=syncNumList[i],
                                              dcf_data=dcf_data_list[0])
                        else:
                            dbNode.appendInstance(instId, groupId,
                                                  INSTANCE_ROLE_DATANODE,
                                                  STANDBY_INSTANCE,
                                                  dnListenIps[instIndex],
                                                  dnHaIps[instIndex],
                                                  dnInfoList[nodeLen * 2 + 2],
                                                  xlogdir=xlogInfoList[nodeLen + 1],
                                                  syncNum=syncNumList[i])
                if dbNode.cascadeRole == "on":
                    if self.enable_dcf != "on":
                        for inst in dbNode.datanodes:
                            inst.instanceType = CASCADE_STANDBY
                    else:
                        raise Exception(ErrorCode.GAUSS_512["GAUSS_51244"] %
                                        "In DCF mode cascadeRole")
                instIndex += 1

        for inst in masterNode.datanodes:
            inst.azName = masterNode.azName

    def __readCmaConfig(self, dbNode):
        """ 
        function : Read cm agent config on node.
        input : []
        output : NA
        """
        agentIps = self.__readInstanceIps(dbNode.name, "cmAgentConnectIp", 1)
        instId = self.__assignNewInstanceId(INSTANCE_ROLE_CMAGENT)
        dbNode.appendInstance(instId, MIRROR_ID_AGENT, INSTANCE_ROLE_CMAGENT,
                              INSTANCE_TYPE_UNDEFINED, agentIps[0], None, "")

    def __assignNewInstanceId(self, instRole):
        """
        function : Assign a new id for instance.
        input : String
        output : NA
        """
        newId = self.__newInstanceId[instRole]
        if (INSTANCE_ROLE_DATANODE == instRole):
            if (newId == OLD_LAST_PRIMARYSTANDBY_BASEID_NUM):
                self.__newInstanceId[instRole] = \
                    self.__newInstanceId[instRole] + 1 + \
                    (NEW_FIRST_PRIMARYSTANDBY_BASEID_NUM
                     - OLD_LAST_PRIMARYSTANDBY_BASEID_NUM)
            else:
                self.__newInstanceId[instRole] += 1
        else:
            self.__newInstanceId[instRole] += 1
        return newId

    def __assignNewMirrorId(self):
        """   
        function : Assign a new mirror id.
        input : NA
        output : NA
        """
        self.__newMirrorId += 1

        return self.__newMirrorId

    def __assignNewGroupId(self):
        """"""
        self.__newGroupId += 1
        return self.__newGroupId

    def __readNodeIps(self, nodeName, prefix):
        """  
        function : Read ip for node, such as backIp1, sshIp1 etc..
        input : String,String
        output : NA
        """
        ipList = []
        n = 1

        if (prefix == "cooListenIp"):
            n = 3
        elif (prefix == "etcdListenIp"):
            n = 2

        for i in range(1, CONFIG_IP_NUM + n):
            key = "%s%d" % (prefix, i)
            value = self.__readNodeStrValue(nodeName, key, True, "")
            if (value == ""):
                break
            ipList.append(value)

        return ipList

    def __readVirtualIp(self, nodeName, prefix):
        """
        function : Read  virtual ip only for node.
        input : String,String
        output : NA
        """
        ipList = []
        value = self.__readNodeStrValue(nodeName, prefix, True, "")
        if (value != ""):
            valueIps = value.split(",")
            for ip in valueIps:
                ip = ip.strip()
                if ip not in ipList:
                    ipList.append(ip)
        return ipList

    def __isIpValid(self, ip):
        """  
        function : check if the input ip address is valid
        input : String
        output : NA
        """
        IpValid = re.match(
            "^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|["
            "1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|["
            "1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{"
            "1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}["
            "0-9]{1}|[0-9])$",
            ip)
        if IpValid:
            if (IpValid.group() == ip):
                return True
            else:
                return False
        else:
            return False

    def __isPortValid(self, port):
        """   
        function :Judge if the port is valid
        input : int
        output : boolean
        """
        if (port < 0 or port > 65535):
            return False
        elif (port >= 0 and port <= 1023):
            return False
        else:
            return True

    def __readInstanceIps(self, nodeName, prefix, InstCount):
        """  
        function :Read instance ips
        input : String,String,int
        output : NA
        """
        multiIpList = self.__readNodeIps(nodeName, prefix)

        mutilIpCount = len(multiIpList)
        if (mutilIpCount == 0):
            return [[] for row in range(InstCount)]

        instanceIpList = [["" for col in range(mutilIpCount)] for row in
                          range(InstCount)]
        for i in range(mutilIpCount):
            ipList = []
            ipList_tmp = multiIpList[i].split(",")
            for ip in ipList_tmp:
                ipList.append(ip.strip())
            ipNum = len(ipList)
            if (ipNum != InstCount):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                                % ("[%s] of node [%s]" % (prefix, nodeName))
                                + " The count of IP is wrong.")
            for j in range(ipNum):
                instanceIpList[j][i] = ipList[j]

        return instanceIpList

    def __readNodeIntValue(self, nodeName, key, nullable=False, defValue=0):
        """ 
        function :Read integer value of specified node
        input : String,int
        output : NA
        """
        value = defValue

        strValue = self.__readNodeStrValue(nodeName, key, nullable, "")
        if (strValue != ""):
            value = int(strValue)
        return value

    def __readNodeStrValue(self, nodeName, key, nullable=False, defValue=""):
        """   
        function : Read string of specified node
        input : String,int
        output : defValue
        """
        (retStatus, retValue) = ClusterConfigFile.readOneClusterConfigItem(xmlRootNode, key,
                                                         "node", nodeName)
        if (retStatus == 0):
            return str(retValue).strip()
        elif (retStatus == 2 and nullable):
            return defValue
        # When upgrade,may be not set XLOGPATH in xml.Make special judgment
        # for xlog scenario.
        elif (retStatus == 2 and "dataNodeXlogPath" in key):
            return defValue
        elif (retStatus == 2 and "syncNum" in key):
            return None
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % \
                            ("[%s] of node [%s]" % (key, nodeName)) + \
                            " Return status: %d. value: %s. Check whether "
                            "the dataNum is correct first."
                            % (retStatus, retValue))

    def __checkAZForSingleInst(self):
        """
        function : check az names and DB replication
        input : NA
        output : NA
        """

        # Get DB standys num
        # The number of standbys for each DB instance must be the same
        peerNum = 0
        for dbNode in self.dbNodes:
            for inst in dbNode.datanodes:
                if (inst.instanceType == MASTER_INSTANCE):
                    peerInsts = self.getPeerInstance(inst)
                    if (peerNum == 0):
                        peerNum = len(peerInsts)
                    elif (peerNum != len(peerInsts)):
                        raise Exception(ErrorCode.GAUSS_532["GAUSS_53200"])

        if peerNum > 8:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51230"] % (
                "database node standbys", "be less than 9") + " Please set it.")

    def __getDNPeerInstance(self, dbInst):
        """  
        function : Get DB peer instance of specified instance when write
        static configuration file.
        input : []
        output : []
        """
        instances = []
        instIdLst = []

        for dbNode in self.dbNodes:
            for inst in dbNode.datanodes:
                if (inst.mirrorId == dbInst.mirrorId and inst.instanceId !=
                        dbInst.instanceId):
                    instances.append(inst)
                    instIdLst.append(inst.instanceId)

        # In a primary multi-standby cluster,
        # since the CM update system table depends on the DB read/write
        # sequence in the static configuration file,
        # we must sort the DN's standby list by instanceId.
        if dbInst.instanceType == MASTER_INSTANCE:
            instIdLst.sort()
            instanceLst = []
            for instId in instIdLst:
                for inst in instances:
                    if (inst.instanceId == instId):
                        instanceLst.append(inst)
            return instanceLst
        else:
            return instances

    def saveToStaticConfig(self, filePath, localNodeId, dbNodes=None,
                           upgrade=False):
        """ 
        function : Save cluster info into to static config 
        input : String,int
        output : NA
        """
        fp = None
        number = None
        if not self.dbNodes and dbNodes:
            self.dbNodes = dbNodes
        if upgrade:
            staticConfigFilePath = os.path.split(filePath)[0]
            versionFile = os.path.join(
                staticConfigFilePath, "upgrade_version")
            version, number, commitid = VersionInfo.get_version_info(
                versionFile)
        try:
            if (dbNodes is None):
                dbNodes = self.dbNodes
            FileUtil.createFileInSafeMode(filePath)
            fp = open(filePath, "wb")
            # len
            info = struct.pack("I", 28)
            # version
            info += struct.pack("I", BIN_CONFIG_VERSION_SINGLE_INST)
            # time
            info += struct.pack("q", int(time.time()))
            # node count
            info += struct.pack("I", len(dbNodes))
            # local node
            info += struct.pack("I", localNodeId)

            crc = binascii.crc32(info)
            if upgrade:
                if float(number) <= 92.200:
                    info = struct.pack("q", crc) + info
                else:
                    info = struct.pack("I", crc) + info
            else:
                info = struct.pack("I", crc) + info
            fp.write(info)

            for dbNode in dbNodes:
                offset = (fp.tell() // PAGE_SIZE + 1) * PAGE_SIZE
                fp.seek(offset)

                info = self.__packNodeInfo(dbNode, number, upgrade=upgrade)
                fp.write(info)
            endBytes = PAGE_SIZE - fp.tell() % PAGE_SIZE
            if (endBytes != PAGE_SIZE):
                info = struct.pack("%dx" % endBytes)
                fp.write(info)
            fp.flush()
            fp.close()
            os.chmod(filePath, DIRECTORY_PERMISSION)
        except Exception as e:
            if fp:
                fp.close()
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % \
                            "static configuration file"
                            + " Error: \n%s" % str(e))

    def __packNodeInfo(self, dbNode, number, upgrade=False):
        """ 
        function : Pack the info of node 
        input : []
        output : String
        """
        # node id 
        info = struct.pack("I", dbNode.id)
        # node name
        info += struct.pack("64s", dbNode.name.encode("utf-8"))
        # az info
        info += struct.pack("64s", dbNode.azName.encode("utf-8"))
        info += struct.pack("I", dbNode.azPriority)
        # backIp
        info += self.__packIps(dbNode.backIps)
        # sshIp
        info += self.__packIps(dbNode.sshIps)
        # cm_server
        info += self.__packCmsInfo(dbNode)
        # cm_agent
        info += self.__packAgentInfo(dbNode)
        # gtm
        info += self.__packGtmInfo(dbNode)
        # cancel save gtmProxy info,need a placeholder
        info += self.__packGtmProxyInfo(dbNode)
        # cn
        info += self.__packCooInfo(dbNode)
        # dn
        info += self.__packDataNode(dbNode)
        # etcd
        info += self.__packEtcdInfo(dbNode)
        # cancel save sctp begin/end port,need a placeholder
        info += struct.pack("I", 0)
        info += struct.pack("I", 0)
        crc = binascii.crc32(info)

        if upgrade:
            if float(number) <= 92.200:
                return struct.pack("q", crc) + info
            else:
                return struct.pack("I", crc) + info
        else:
            return struct.pack("I", crc) + info

    def __packEtcdInfo(self, dbNode):
        """  
        function : Pack the info of etcd
        input : []
        output : String
        """
        n = len(dbNode.etcds)

        info = "".encode()
        if (n == 0):
            # etcd count
            info += struct.pack("I", 0)
            # etcd id
            info += struct.pack("I", 0)
            # etcd mirror id
            info += struct.pack("i", 0)
            # etcd name
            info += struct.pack("64x")
            # datadir
            info += struct.pack("1024x")
            # listen ip
            info += self.__packIps([])
            # listn port
            info += struct.pack("I", 0)
            # ha ip
            info += self.__packIps([])
            # ha port
            info += struct.pack("I", 0)
        elif (n == 1):
            etcdInst = dbNode.etcds[0]
            # etcd count
            info += struct.pack("I", 1)
            # etcd id
            info += struct.pack("I", etcdInst.instanceId)
            # etcd mirror id
            info += struct.pack("i", etcdInst.mirrorId)
            # etcd name
            info += struct.pack("64s", "etcd_%d".encode(
                "utf-8") % etcdInst.instanceId)
            # datadir
            info += struct.pack("1024s", etcdInst.datadir.encode("utf-8"))
            # listen ip
            info += self.__packIps(etcdInst.listenIps)
            # listn port
            info += struct.pack("I", etcdInst.port)
            # ha ip
            info += self.__packIps(etcdInst.haIps)
            # ha port
            info += struct.pack("I", etcdInst.haPort)
        else:
            pass

        return info

    def __packCmsInfo(self, dbNode):
        """ 
        function : Pack the info of cm server
        input : []
        output : String
        """
        n = len(dbNode.cmservers)

        info = "".encode()
        if (n == 0):
            # cm server id
            info += struct.pack("I", 0)
            # cm_server mirror id
            info += struct.pack("I", 0)
            # datadir
            info += struct.pack("1024s", dbNode.cmDataDir.encode("utf-8"))
            # cm server level
            info += struct.pack("I", 0)
            # float ip
            info += struct.pack("128x")
            # listen ip
            info += self.__packIps([])
            # listen port
            info += struct.pack("I", 0)
            # local ha ip
            info += self.__packIps([])
            # local ha port
            info += struct.pack("I", 0)
            # is primary
            info += struct.pack("I", 0)
            # peer ha ip
            info += self.__packIps([])
            # peer ha port
            info += struct.pack("I", 0)
        elif (n == 1):
            cmsInst = dbNode.cmservers[0]
            # cm server id
            info += struct.pack("I", cmsInst.instanceId)
            # cm_server mirror id
            info += struct.pack("I", cmsInst.mirrorId)
            # datadir
            info += struct.pack("1024s", dbNode.cmDataDir.encode("utf-8"))
            # cm server level
            info += struct.pack("I", cmsInst.level)
            info += struct.pack("128s", self.cmsFloatIp.encode("utf-8"))
            # listen ip
            info += self.__packIps(cmsInst.listenIps)
            # listen port
            info += struct.pack("I", cmsInst.port)
            # local ha ip
            info += self.__packIps(cmsInst.haIps)
            # local ha port
            info += struct.pack("I", cmsInst.haPort)
            # instance type
            info += struct.pack("I", cmsInst.instanceType)
            instances = self.getPeerInstance(cmsInst)
            peerInst = instances[0]
            # peer ha ip
            info += self.__packIps(peerInst.haIps)
            # peer ha port
            info += struct.pack("I", peerInst.haPort)
        else:
            pass

        return info

    def __packAgentInfo(self, dbNode):
        """ 
        function : Pack the info of agent
        input : []
        output : String
        """
        n = len(dbNode.cmagents)

        info = "".encode()
        if (n == 1):
            cmaInst = dbNode.cmagents[0]
            # Agent id
            info += struct.pack("I", cmaInst.instanceId)
            # Agent mirror id
            info += struct.pack("i", cmaInst.mirrorId)
            # agent ips
            info += self.__packIps(cmaInst.listenIps)

        return info

    def __packGtmInfo(self, dbNode):
        """ 
        function : Pack the info of gtm
        input : []
        output : String
        """
        n = len(dbNode.gtms)

        info = "".encode()
        if (n == 0):
            # gtm id
            info += struct.pack("I", 0)
            # gtm mirror id
            info += struct.pack("I", 0)
            # gtm count
            info += struct.pack("I", 0)
            # datadir
            info += struct.pack("1024x")
            # listen ip
            info += self.__packIps([])
            # listn port
            info += struct.pack("I", 0)
            #  instance type
            info += struct.pack("I", 0)
            # loacl ha ip
            info += self.__packIps([])
            # local ha port
            info += struct.pack("I", 0)
            # peer gtm datadir
            info += struct.pack("1024x")
            # peer ha ip
            info += self.__packIps([])
            # peer ha port
            info += struct.pack("I", 0)
        elif (n == 1):
            gtmInst = dbNode.gtms[0]
            # gtm id
            info += struct.pack("I", gtmInst.instanceId)
            # gtm mirror id
            info += struct.pack("I", gtmInst.mirrorId)
            # gtm count
            info += struct.pack("I", 1)
            # datadir
            info += struct.pack("1024s", gtmInst.datadir.encode("utf-8"))
            # listen ip
            info += self.__packIps(gtmInst.listenIps)
            # listn port
            info += struct.pack("I", gtmInst.port)
            #  instance type
            info += struct.pack("I", gtmInst.instanceType)
            # loacl ha ip
            info += self.__packIps(gtmInst.haIps)
            # local ha port
            info += struct.pack("I", gtmInst.haPort)
            # peer gtm datadir
            info += struct.pack("1024x")
            # peer ha ip
            info += self.__packIps([])
            # peer ha port
            info += struct.pack("I", 0)

        else:
            pass

        return info

    def __packGtmProxyInfo(self, dbNode):
        """  
        function : Pack the info of gtm proxy
        input : []
        output : String
        """
        info = "".encode()
        info += struct.pack("I", 0)
        info += struct.pack("I", 0)
        info += struct.pack("I", 0)
        info += self.__packIps([])
        info += struct.pack("I", 0)
        return info

    def __packCooInfo(self, dbNode):
        """  
        function : Pack the info of coordinator
        input : []
        output : String
        """
        n = len(dbNode.coordinators)

        info = "".encode()
        if (n == 0):
            # coordinator id
            info += struct.pack("I", 0)
            # coordinator mirror id
            info += struct.pack("i", 0)
            # coordinator count
            info += struct.pack("I", 0)
            # datadir
            info += struct.pack("1024x")
            # ssdDir
            info += struct.pack("1024x")
            # listen ip
            info += self.__packIps([])
            # listn port 
            info += struct.pack("I", 0)
            # ha port
            info += struct.pack("I", 0)
        elif (n == 1):
            cooInst = dbNode.coordinators[0]
            # coordinator id
            info += struct.pack("I", cooInst.instanceId)
            # coordinator mirror id
            info += struct.pack("i", cooInst.mirrorId)
            # coordinator count
            info += struct.pack("I", 1)
            # datadir
            info += struct.pack("1024s", cooInst.datadir.encode("utf-8"))
            # ssdDir
            info += struct.pack("1024s", cooInst.ssdDir.encode("utf-8"))
            # listen ip
            info += self.__packIps(cooInst.listenIps)
            # listn port
            info += struct.pack("I", cooInst.port)
            # ha port
            info += struct.pack("I", cooInst.haPort)
        else:
            pass

        return info

    def __packDataNode(self, dbNode):
        """   
        function : Pack the info of datanode
        input : []
        output : String
        """

        info = struct.pack("I", len(dbNode.datanodes))
        for dnInst in dbNode.datanodes:
            instances = self.__getDNPeerInstance(dnInst)
            # datanode id
            info += struct.pack("I", dnInst.instanceId)
            # datanode id
            info += struct.pack("I", dnInst.mirrorId)
            # datadir
            info += struct.pack("1024s", dnInst.datadir.encode("utf-8"))
            # xlogdir
            info += struct.pack("1024s", dnInst.xlogdir.encode("utf-8"))
            # ssdDir
            info += struct.pack("1024s", dnInst.ssdDir.encode("utf-8"))
            # listen ip
            info += self.__packIps(dnInst.listenIps)
            # port
            info += struct.pack("I", dnInst.port)
            # instance type
            info += struct.pack("I", dnInst.instanceType)
            # loacl ha ip
            info += self.__packIps(dnInst.haIps)
            # local ha port
            info += struct.pack("I", dnInst.haPort)

            maxStandbyCount = MIRROR_COUNT_REPLICATION_MAX - 1

            n = len(instances)
            for i in range(n):
                peerInst = instances[i]
                # peer1 datadir
                info += struct.pack("1024s", peerInst.datadir.encode("utf-8"))
                # peer1 ha ip
                info += self.__packIps(peerInst.haIps)
                # peer1 ha port
                info += struct.pack("I", peerInst.haPort)
                # instance type
                info += struct.pack("I", peerInst.instanceType)
            for i in range(n, maxStandbyCount):
                # peer1 datadir
                info += struct.pack("1024x")
                # peer1 ha ip
                info += self.__packIps([])
                # peer1 ha port
                info += struct.pack("I", 0)
                # instance type
                info += struct.pack("I", 0)
        return info

    def __packIps(self, ips):
        """
        function : Pack the info of ips
        input : []
        output : String
        """
        n = len(ips)

        info = struct.pack("I", n)
        for i in range(n):
            info += struct.pack("128s", ips[i].encode("utf-8"))
        for i in range(n, MAX_IP_NUM):
            info += struct.pack("128x")

        return info

    def isSingleInstCluster(self):
        return self.clusterType == CLUSTER_TYPE_SINGLE_INST

    def isSingleNode(self):
        return (self.__getDnInstanceNum() <= 1)

    def doRefreshConf(self, user, localHostName, sshtool):
        self.__createDynamicConfig(user, localHostName, sshtool)
        self.__create_simple_datanode_config(user, localHostName, sshtool)
        self.__reset_replconninfo(user, sshtool)

    def __createDynamicConfig(self, user, localHostName, sshtool):
        """
        function : Save cluster info into to dynamic config
        input : String,int
        output : NA
        """
        # only one dn, no need to write primary or stanby node info
        dynamicConfigFile = self.__getDynamicConfig(user)
        if os.path.exists(dynamicConfigFile):
            cmd = "rm -f %s" % dynamicConfigFile
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_504["GAUSS_50407"] +
                                " Error: \n%s." % str(output) +
                                "The cmd is %s" % cmd)
        fp = None
        try:
            FileUtil.createFileInSafeMode(dynamicConfigFile)
            fp = open(dynamicConfigFile, "wb")
            # len
            info = struct.pack("I", 24)
            # version
            info += struct.pack("I", BIN_CONFIG_VERSION_SINGLE_INST)
            # time
            info += struct.pack("q", int(time.time()))
            # node count
            info += struct.pack("I", len(self.dbNodes))
            crc = binascii.crc32(info)
            info = struct.pack("I", crc) + info
            fp.write(info)
            primaryDnNum = 0
            for dbNode in self.dbNodes:
                offset = (fp.tell() // PAGE_SIZE + 1) * PAGE_SIZE
                fp.seek(offset)
                (primaryNodeNum, info) = self.__packDynamicNodeInfo(
                    dbNode, localHostName, sshtool)
                primaryDnNum += primaryNodeNum
                fp.write(info)
            if primaryDnNum != 1:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51230"] %
                                ("master dn", "equal to 1"))
            endBytes = PAGE_SIZE - fp.tell() % PAGE_SIZE
            if endBytes != PAGE_SIZE:
                info = struct.pack("%dx" % endBytes)
                fp.write(info)
            fp.flush()
            fp.close()
            os.chmod(dynamicConfigFile, ConstantsBase.KEY_FILE_PERMISSION)
        except Exception as e:
            if fp:
                fp.close()
            cmd = "rm -f %s" % dynamicConfigFile
            subprocess.getstatusoutput(cmd)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % \
                            "dynamic configuration file"
                            + " Error: \n%s" % str(e))
        try:
            self.__sendDynamicCfgToAllNodes(localHostName,
                                            dynamicConfigFile,
                                            dynamicConfigFile)
        except Exception as e:
            cmd = "rm -f %s" % dynamicConfigFile
            sshtool.getSshStatusOutput(cmd, self.getClusterNodeNames())
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % \
                            "dynamic configuration file" +
                            " Error: \n%s" % str(e))

    def __create_simple_datanode_config(self, user, localhostname, sshtool):
        simpleDNConfig = self.__getDynamicSimpleDNConfig(user)
        if os.path.exists(simpleDNConfig):
            cmd = "rm -f %s" % simpleDNConfig
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_504["GAUSS_50407"] +
                                " Error: \n%s." % str(output) +
                                "The cmd is %s" % cmd)
        output_list = self.__getStatusByOM(user)
        output_num = 0
        pattern = re.compile("(\d+) (.*) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (.*)")
        if not self.hasNoCm():
            output_list = [i for i in output_list if i]
            output_list = output_list[-1].split('|')
        for contont in output_list:
            if pattern.search(contont):
                output_num += 1
        tempstatus = output_list[-output_num:]
        statusdic = {'Primary': 0, 'Standby': 1, 'Cascade': 3, 'Unknown': 9}
        try:
            with open(simpleDNConfig, "w") as fp:
                for dninfo in tempstatus:
                    dnstatus = dninfo.split()[7]
                    dnname = dninfo.split()[1]
                    if dnstatus not in statusdic:
                        fp.write("%s=%d\n" %
                                 (dnname, statusdic['Unknown']))
                    else:
                        fp.write("%s=%d\n" %
                                 (dnname, statusdic[dnstatus]))
        except Exception as e:
            cmd = "rm -f %s" % simpleDNConfig
            subprocess.getstatusoutput(cmd)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] %
                            "dynamic configuration file"
                            + " Error: \n%s" % str(e))
        try:
            self.__sendDynamicCfgToAllNodes(localhostname,
                                            simpleDNConfig,
                                            simpleDNConfig)
        except Exception as e:
            cmd = "rm -f %s" % simpleDNConfig
            sshtool.getSshStatusOutput(cmd, self.getClusterNodeNames())
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] %
                            "dynamic configuration file" +
                            " Error: \n%s" % str(e))

    def __reset_replconninfo(self, user, sshtool):
        # add for cascade
        local_script = os.path.dirname(os.path.realpath(__file__)) \
                       + '/../../local/Resetreplconninfo.py'
        cmd = "python3 %s -U %s -t reset" % (local_script, user)
        sshtool.setTimeOut(120)
        for node in self.getClusterNodeNames():
            (status, output) = sshtool.getSshStatusOutput(cmd, [node])
            if status[node] != 'Success':
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"]
                                % cmd + "Error:\n%s" % output)

    def __packDynamicNodeInfo(self, dbNode, localHostName, sshtool):
        # node id
        info = struct.pack("I", dbNode.id)
        # node name
        info += struct.pack("64s", dbNode.name.encode("utf-8"))
        info += struct.pack("I", len(dbNode.datanodes))
        primaryNum = 0
        for dnInst in dbNode.datanodes:
            self.__getDnState(dnInst, dbNode, localHostName, sshtool)
            instanceType = 0
            if dnInst.localRole == "Primary":
                instanceType = MASTER_INSTANCE
                primaryNum += 1
            elif dnInst.localRole == "Cascade Standby":
                instanceType = CASCADE_STANDBY
            else:
                instanceType = STANDBY_INSTANCE
            info += struct.pack("I", dnInst.instanceId)
            # datanode id
            info += struct.pack("I", dnInst.mirrorId)
            # instanceType such as master, standby, dumpstandby
            info += struct.pack("I", instanceType)
            # datadir
            info += struct.pack("1024s", dnInst.datadir.encode("utf-8"))
        info += struct.pack("I", 0)
        info += struct.pack("I", 0)
        crc = binascii.crc32(info)
        return (primaryNum, struct.pack("I", crc) + info)

    def __getClusterSwitchTime(self, dynamicConfigFile):
        """
        function : get cluster version information
                   from static configuration file
        input : String
        output : version
        """
        fp = None
        try:
            fp = open(dynamicConfigFile, "rb")
            info = fp.read(24)
            (crc, lenth, version, switchTime, nodeNum) = \
                struct.unpack("=IIIqi", info)
            fp.close()
        except Exception as e:
            if fp:
                fp.close()
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"]
                            + " Error: \n%s." % str(e))
        return switchTime

    def __getDynamicConfig(self, user):
        gaussHome = self.__getEnvironmentParameterValue("GAUSSHOME", user)
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            ("installation path of designated user [%s]"
                             % user))
        # if under upgrade, and use chose strategy, we may get a wrong path,
        # so we will use the realpath of gausshome
        gaussHome = os.path.realpath(gaussHome)
        dynamicConfigFile = "%s/bin/cluster_dynamic_config" % gaussHome
        return dynamicConfigFile
    def __getDynamicSimpleDNConfig(self, user):
        gaussHome = self.__getEnvironmentParameterValue("GAUSSHOME", user)
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            ("installation path of designated user [%s]"
                             % user))
        # if under upgrade, and use chose strategy, we may get a wrong path,
        # so we will use the realpath of gausshome
        gaussHome = os.path.realpath(gaussHome)
        dynamicSimpleDNConfigFile = "%s/bin/cluster_dnrole_config" % gaussHome
        return dynamicSimpleDNConfigFile

    def dynamicConfigExists(self, user):
        dynamicConfigFile = self.__getDynamicConfig(user)
        return os.path.exists(dynamicConfigFile)

    def checkClusterDynamicConfig(self, user, localHostName):
        """
        function : make all the node dynamic config file is newest.
        input : String
        output : none
        """
        if self.__getDnInstanceNum() <= 1:
            return
        gaussHome = self.__getEnvironmentParameterValue("GAUSSHOME", user)
        if gaussHome == "":
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % \
                            ("installation path of designated user [%s]"
                             % user))
        # if under upgrade, and use chose strategy, we may get a wrong path,
        # so we will use the realpath of gausshome
        gaussHome = os.path.realpath(gaussHome)
        dynamicConfigFile = "%s/bin/cluster_dynamic_config" % gaussHome
        lastSwitchTime = 0
        lastDynamicConfigFile = ""
        fileConsistent = False
        fileExist = False
        if os.path.exists(dynamicConfigFile):
            lastSwitchTime = self.__getClusterSwitchTime(dynamicConfigFile)
            lastDynamicConfigFile = dynamicConfigFile
            fileExist = True
            fileConsistent = True
        for dbNode in self.dbNodes:
            remoteDynamicConfigFile = "%s/bin/cluster_dynamic_config_%s" \
                                      % (gaussHome, dbNode.name)
            if dbNode.name != localHostName:
                cmd = "scp %s:%s %s" % (
                    dbNode.name, dynamicConfigFile, remoteDynamicConfigFile)
                status, output = subprocess.getstatusoutput(cmd)
                if status:
                    if output.find("No such file or directory") >= 0:
                        fileConsistent = False
                        continue
                    raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                    + " Error:\n" + output)
                if os.path.exists(remoteDynamicConfigFile):
                    fileExist = True
                    switchTime = self.__getClusterSwitchTime(
                        remoteDynamicConfigFile)
                    if switchTime > lastSwitchTime:
                        lastSwitchTime = switchTime
                        lastDynamicConfigFile = remoteDynamicConfigFile
                        fileConsistent = False
                    elif switchTime < lastSwitchTime:
                        fileConsistent = False
        # if dynamic config file exist, but file time is not same,
        # send the valid file to all nodes
        if fileExist:
            if not fileConsistent:
                self.__sendDynamicCfgToAllNodes(localHostName,
                                                lastDynamicConfigFile,
                                                dynamicConfigFile)
            cleanCmd = "rm -f %s/bin/cluster_dynamic_config_*" % gaussHome
            subprocess.getstatusoutput(cleanCmd)

    def __sendDynamicCfgToAllNodes(self,
                                   localHostName,
                                   sourceFile,
                                   targetFile):
        status = 0
        output = ""
        for dbNode in self.dbNodes:
            if dbNode.name == localHostName:
                if sourceFile != targetFile:
                    cmd = "cp -f  %s %s" % (sourceFile, targetFile)
                    status, output = subprocess.getstatusoutput(cmd)
            else:
                cmd = "scp %s %s:%s" % (sourceFile, dbNode.name, targetFile)
                status, output = subprocess.getstatusoutput(cmd)
            if status:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error:\n" + output)

    def readDynamicConfig(self, user):
        """
        function : read cluster information from dynamic configuration file
                   only used for start cluster after switchover
        input : String
        output : NA
        """
        fp = None
        try:
            self.name = self.__getEnvironmentParameterValue("GS_CLUSTER_NAME",
                                                            user)
            self.appPath = self.__getEnvironmentParameterValue("GAUSSHOME",
                                                               user)
            logPathWithUser = self.__getEnvironmentParameterValue("GAUSSLOG",
                                                                  user)
            splitMark = "/%s" % user
            # set log path without user
            # find the path from right to left
            self.logPath = \
                logPathWithUser[0:(logPathWithUser.rfind(splitMark))]
            dynamicConfigFile = self.__getDynamicConfig(user)
            # read dynamic_config_file
            dynamicConfigFilePath = os.path.split(dynamicConfigFile)[0]
            versionFile = os.path.join(
                dynamicConfigFilePath, "upgrade_version")
            version, number, commitid = VersionInfo.get_version_info(
                versionFile)
            fp = open(dynamicConfigFile, "rb")
            if float(number) <= 92.200:
                info = fp.read(28)
                (crc, lenth, version, currenttime, nodeNum) = \
                    struct.unpack("=qIIqi", info)
            else:
                info = fp.read(24)
                (crc, lenth, version, currenttime, nodeNum) = \
                    struct.unpack("=IIIqi", info)
            totalMaterDnNum = 0
            for i in range(nodeNum):
                offset = (fp.tell() // PAGE_SIZE + 1) * PAGE_SIZE
                fp.seek(offset)
                (dbNode, materDnNum) = self.__unpackDynamicNodeInfo(fp, number)
                totalMaterDnNum += materDnNum
                self.dbNodes.append(dbNode)
            if totalMaterDnNum != 1:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51230"] %
                                ("master dn", "1"))
            fp.close()
        except Exception as e:
            if fp:
                fp.close()
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                            dynamicConfigFile + " Error:\n" + str(e))

    def __unpackDynamicNodeInfo(self, fp, number):
        if float(number) <= 92.200:
            info = fp.read(76)
            (crc, nodeId, nodeName) = struct.unpack("=qI64s", info)
        else:
            info = fp.read(72)
            (crc, nodeId, nodeName) = struct.unpack("=II64s", info)
        nodeName = nodeName.decode().strip('\x00')
        dbNode = dbNodeInfo(nodeId, nodeName)
        info = fp.read(4)
        (dataNodeNums,) = struct.unpack("=I", info)
        dbNode.datanodes = []
        materDnNum = 0
        for i in range(dataNodeNums):
            dnInst = instanceInfo()
            dnInst.hostname = nodeName
            info = fp.read(12)
            (dnInst.instanceId, dnInst.mirrorId, dnInst.instanceType) = \
                struct.unpack("=III", info)
            if dnInst.instanceType == MASTER_INSTANCE:
                materDnNum += 1
            elif dnInst.instanceType not in [STANDBY_INSTANCE,
                                             DUMMY_STANDBY_INSTANCE, CASCADE_STANDBY]:
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51204"] %
                                ("DN", dnInst.instanceType))
            info = fp.read(1024)
            (datadir,) = struct.unpack("=1024s", info)
            dnInst.datadir = datadir.decode().strip('\x00')
            dbNode.datanodes.append(dnInst)
        return (dbNode, materDnNum)

    def hasNoCm(self):
        """
        function:check whether cm exist
        :return:True or False
        """
        return self.cmscount < 1
