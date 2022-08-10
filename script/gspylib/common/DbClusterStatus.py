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
# Description  : DbClusterStatus.py is a utility to get cluster status
#               information.
#############################################################################
import os
import sys


sys.path.append(sys.path[0] + "/../../")
from gspylib.common.Common import DefaultValue, ClusterInstanceConfig
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.ErrorCode import ErrorCode
from domain_utils.cluster_os.cluster_user import ClusterUser
from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants

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

# Global parameter
g_clusterInfo = None
g_instanceInfo = None
g_clusterInfoInitialized = False
g_deletedCNId = []


class StatusReport():
    """
    classdocs
    """

    def __init__(self):
        """
        Constructor
        """
        self.nodeCount = 0
        self.cooNormal = 0
        self.cooAbnormal = 0
        self.gtmPrimary = 0
        self.gtmStandby = 0
        self.gtmAbnormal = 0
        self.gtmDown = 0
        self.dnPrimary = 0
        self.dnStandby = 0
        self.dn_cascade_standby = 0
        self.dn_main_standby = 0
        self.dnDummy = 0
        self.dnBuild = 0
        self.dnAbnormal = 0
        self.dnDown = 0
        self.fencedUDFNormal = 0
        self.fencedUDFAbnormal = 0


class DbInstanceStatus():
    """
    classdocs
    """

    def __init__(self, nodeId, instId=0):
        """
        Constructor
        """
        self.nodeId = nodeId
        self.nodeIp = ""
        self.instanceId = instId
        self.datadir = ""
        self.type = ""
        self.status = ""
        self.detail_status = ""
        self.haStatus = ""
        self.detail_ha = ""
        self.connStatus = ""
        self.detail_conn = ""
        self.syncStatus = ""
        self.reason = ""

    def __str__(self):
        """
        """
        retStr = "nodeId=%s,instanceId=%s,datadir=%s,type=%s,status=%s," \
                 "haStatus=%s,connStatus=%s,syncStatus=%s,reason=%s" % \
                 (self.nodeId, self.instanceId, self.datadir, self.type,
                  self.status, self.haStatus, self.connStatus,
                  self.syncStatus, self.reason)

        return retStr

    def isInstanceHealthy(self):
        """  
        function : Check if instance is healthy
        input : NA
        output : boolean
        """
        # check DB instance
        if self.type == DbClusterStatus.INSTANCE_TYPE_DATANODE:
            if self.status == DbClusterStatus.INSTANCE_STATUS_PRIMARY:
                return True
            elif self.status == DbClusterStatus.INSTANCE_STATUS_DUMMY:
                return True
            elif self.status == DbClusterStatus.INSTANCE_STATUS_STANDBY:
                if self.haStatus != DbClusterStatus.HA_STATUS_NORMAL:
                    return False
            elif self.status == DbClusterStatus.INSTANCE_STATUS_CASCADE_STANDBY:
                if self.haStatus != DbClusterStatus.HA_STATUS_NORMAL:
                    return False
            elif self.status == DbClusterStatus.INSTANCE_STATUS_MAIN_STANDBY:
                return True
            else:
                return False

        return True


class DbNodeStatus():
    """
    classdocs
    """

    def __init__(self, nodeId):
        """
        Constructor
        """
        self.id = nodeId
        self.name = ""
        self.version = ""
        self.coordinators = []
        self.gtms = []
        self.datanodes = []

        self.cmservers = []
        self.primaryDNs = []
        self.standbyDNs = []
        self.dummies = []
        self.fencedUDFs = []
        self.etcds = []

    def __str__(self):
        """
        """
        retStr = "NodeId=%s,HostName=%s" % (self.id, self.name)

        for cmsInst in self.cmservers:
            retStr += "\n%s" % str(cmsInst)
        for gtmInst in self.gtms:
            retStr += "\n%s" % str(gtmInst)
        for cooInst in self.coordinators:
            retStr += "\n%s" % str(cooInst)
        for dataInst in self.datanodes:
            retStr += "\n%s" % str(dataInst)
        for dataInst in self.etcds:
            retStr += "\n%s" % str(dataInst)
        for udfInst in self.fencedUDFs:
            retStr += "\n%s" % str(udfInst)

        return retStr

    def isNodeHealthy(self):
        """     
        function : Check if node is healthy
        input : NA
        output : boolean
        """
        # get CN, DB and gtm instance
        instances = self.datanodes
        # check if node is healthy
        for inst in instances:
            if (not inst.isInstanceHealthy()):
                return False

        return True

    def getNodeStatusReport(self):
        """    
        function :  Get the status report of node
        input : NA
        output : report
        """
        # init class StatusReport
        report = StatusReport()
        for inst in self.coordinators:
            if (inst.status == DbClusterStatus.INSTANCE_STATUS_NORMAL):
                report.cooNormal += 1
            else:
                report.cooAbnormal += 1

        for inst in self.gtms:
            if (inst.status == DbClusterStatus.INSTANCE_STATUS_PRIMARY):
                report.gtmPrimary += 1
            elif (inst.status == DbClusterStatus.INSTANCE_STATUS_STANDBY):
                if (inst.connStatus == DbClusterStatus.CONN_STATUS_NORMAL):
                    report.gtmStandby += 1
                else:
                    report.gtmAbnormal += 1
            elif (inst.status == DbClusterStatus.INSTANCE_STATUS_DOWN):
                report.gtmDown += 1
            else:
                report.gtmAbnormal += 1

        for inst in self.datanodes:
            if (inst.status == DbClusterStatus.INSTANCE_STATUS_PRIMARY):
                report.dnPrimary += 1
            elif (inst.status == DbClusterStatus.INSTANCE_STATUS_STANDBY):
                if (inst.haStatus == DbClusterStatus.HA_STATUS_NORMAL):
                    report.dnStandby += 1
                elif (inst.haStatus == DbClusterStatus.HA_STATUS_BUILD):
                    report.dnBuild += 1
                else:
                    report.dnAbnormal += 1
            elif (inst.status == DbClusterStatus.INSTANCE_STATUS_DOWN):
                report.dnDown += 1
            elif (inst.status == DbClusterStatus.INSTANCE_STATUS_DUMMY):
                report.dnDummy += 1
            elif inst.status == DbClusterStatus.INSTANCE_STATUS_CASCADE_STANDBY:
                report.dn_cascade_standby += 1
            elif inst.status == DbClusterStatus.INSTANCE_STATUS_MAIN_STANDBY:
                report.dn_main_standby += 1
            else:
                report.dnAbnormal += 1

        # check fenced UDF instance
        for inst in self.fencedUDFs:
            if (inst.status == DbClusterStatus.INSTANCE_STATUS_NORMAL):
                report.fencedUDFNormal += 1
            else:
                report.fencedUDFAbnormal += 1

        return report

    def outputNodeStatus(self, stdout, user, showDetail=False):
        """  
        function :  output the status of node
        input : stdout, user
        output : NA
        """
        global g_clusterInfo
        global g_instanceInfo
        global g_clusterInfoInitialized
        if not g_clusterInfoInitialized:
            ClusterUser.checkUser(user)
            g_clusterInfo = dbClusterInfo()
            g_clusterInfo.initFromStaticConfig(user)
            g_clusterInfoInitialized = True
        dbNode = g_clusterInfo.getDbNodeByName(self.name)
        instName = ""
        # print node information
        print("%-20s: %s" % ("node", str(self.id)), file=stdout)
        print("%-20s: %s" % ("node_name", self.name), file=stdout)
        if (self.isNodeHealthy()):
            print("%-20s: %s\n" % ("node_state",
                                   DbClusterStatus.OM_NODE_STATUS_NORMAL),
                  file=stdout)
        else:
            print("%-20s: %s\n" % ("node_state",
                                   DbClusterStatus.OM_NODE_STATUS_ABNORMAL),
                  file=stdout)

        if (not showDetail):
            return

        # coordinator status
        for inst in self.coordinators:
            # get the instance info
            g_instanceInfo = None
            for instInfo in dbNode.coordinators:
                if instInfo.instanceId == inst.instanceId:
                    g_instanceInfo = instInfo
                    break
            if not g_instanceInfo:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51620"] % "CN")
            # construct the instance name
            instName = "cn_%s" % g_instanceInfo.instanceId
            # print CN instance information
            print("Coordinator", file=stdout)
            print("%-20s: %d" % ("    node", inst.nodeId), file=stdout)
            print("%-20s: %s" % ("    instance_name", instName), file=stdout)
            print("%-20s: %s" % ("    listen_IP", g_instanceInfo.listenIps),
                  file=stdout)
            print("%-20s: %d" % ("    port", g_instanceInfo.port), file=stdout)
            print("%-20s: %s" % ("    data_path", inst.datadir), file=stdout)
            print("%-20s: %s" % ("    instance_state", inst.status),
                  file=stdout)
            print("", file=stdout)

        for inst in self.gtms:
            # get the instance info
            g_instanceInfo = None
            for instInfo in dbNode.gtms:
                if instInfo.instanceId == inst.instanceId:
                    g_instanceInfo = instInfo
                    break
            if not g_instanceInfo:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51620"] % "GTM")
            # construct the instance name
            instName = "gtm_%s" % g_instanceInfo.instanceId
            # print gtm instance information
            print("GTM", file=stdout)
            print("%-20s: %d" % ("    node", inst.nodeId), file=stdout)
            print("%-20s: %s" % ("    instance_name", instName), file=stdout)
            print("%-20s: %s" % ("    listen_IP", g_instanceInfo.listenIps),
                  file=stdout)
            print("%-20s: %d" % ("    port", g_instanceInfo.port), file=stdout)
            print("%-20s: %s" % ("    data_path", inst.datadir),
                  file=stdout)
            print("%-20s: %s" % ("    instance_state", inst.status),
                  file=stdout)
            print("%-20s: %s" % ("    conn_state", inst.connStatus),
                  file=stdout)
            print("%-20s: %s" % ("    reason", inst.reason), file=stdout)
            print("", file=stdout)

        i = 1
        for inst in self.datanodes:
            # get the instance info
            g_instanceInfo = None
            for instInfo in dbNode.datanodes:
                if instInfo.instanceId == inst.instanceId:
                    g_instanceInfo = instInfo
                    break
            if not g_instanceInfo:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51620"] % "DN")
            # construct the instance name
            peerInsts = g_clusterInfo.getPeerInstance(g_instanceInfo)
            instName = \
                ClusterInstanceConfig. \
                    setReplConninfoForSinglePrimaryMultiStandbyCluster(
                    g_instanceInfo, peerInsts, g_clusterInfo)[1]

            # print DB instance information
            print("Datanode%d" % i, file=stdout)
            print("%-20s: %d" % ("    node", inst.nodeId), file=stdout)
            print("%-20s: %s" % ("    instance_name", instName), file=stdout)
            print("%-20s: %s" % ("    listen_IP", g_instanceInfo.listenIps),
                  file=stdout)
            print("%-20s: %s" % ("    HA_IP", g_instanceInfo.haIps),
                  file=stdout)
            print("%-20s: %d" % ("    port", g_instanceInfo.port), file=stdout)
            print("%-20s: %s" % ("    data_path", inst.datadir), file=stdout)
            print("%-20s: %s" % ("    instance_state", inst.status),
                  file=stdout)
            print("%-20s: %s" % ("    HA_state", inst.haStatus), file=stdout)
            print("%-20s: %s" % ("    reason", inst.reason), file=stdout)
            print("", file=stdout)

            i += 1
        # print fenced UDF status
        for inst in self.fencedUDFs:
            print("Fenced UDF", file=stdout)
            print("%-20s: %d" % ("    node", inst.nodeId), file=stdout)
            print("%-20s: %s" % ("    listen_IP", dbNode.backIps[0]),
                  file=stdout)
            print("%-20s: %s" % ("    instance_state", inst.status),
                  file=stdout)


class DbClusterStatus():
    """
    classdocs
    """

    OM_STATUS_FILE = "gs_om_status.dat"
    ###################################################################
    # OM status
    ###################################################################
    OM_STATUS_NORMAL = "Normal"

    ###################################################################
    # node status
    ###################################################################
    OM_NODE_STATUS_NORMAL = "Normal"
    OM_NODE_STATUS_ABNORMAL = "Abnormal"

    ###################################################################
    # cluster status
    ###################################################################
    CLUSTER_STATUS_NORMAL = "Normal"
    CLUSTER_STATUS_ABNORMAL = "Abnormal"
    CLUSTER_STATUS_DEGRADED = "Degraded"
    CLUSTER_STATUS_MAP = {
        "Normal": "Normal",
        "Redistributing": "Redistributing",
        "Repair": "Abnormal",
        "Starting": "Starting",
        "Degraded": "Degraded",
        "Unknown": "Abnormal"
    }
    INSTANCE_STATUS_MAP_CHECK_STATUS = {
        "Normal": "Primary",
        "Unnormal": "Abnormal",
        "Primary": "Primary",
        "Standby": "Standby",
        "Secondary": "Secondary",
        "Pending": "Abnormal",
        "Down": "Down",
        "Unknown": "Abnormal",
        "Offline": "Offline",
        "Main Standby": "Standby",
        "Cascade Standby": "Standby"
    }
    INSTANCE_STATUS_MAP_CHECK_FAILOVER = {
        "Need repair(Disconnected)": "Normal",
        "Need repair": "Normal"
    }
    ###################################################################
    # instance role
    ###################################################################
    INSTANCE_TYPE_GTM = "GTM"
    INSTANCE_TYPE_DATANODE = "Datanode"
    INSTANCE_TYPE_COORDINATOR = "Coordinator"
    INSTANCE_TYPE_CMSERVER = "CMServer"
    INSTANCE_TYPE_FENCED_UDF = "Fenced UDF"
    INSTANCE_TYPE_ETCD = "ETCD"

    ###################################################################
    # instance status
    ###################################################################
    INSTANCE_STATUS_NORMAL = "Normal"
    INSTANCE_STATUS_PRIMARY = "Primary"
    INSTANCE_STATUS_STANDBY = "Standby"
    INSTANCE_STATUS_CASCADE_STANDBY = "Cascade Standby"
    INSTANCE_STATUS_MAIN_STANDBY = "Main Standby"
    INSTANCE_STATUS_ABNORMAL = "Abnormal"
    INSTANCE_STATUS_DOWN = "Down"
    INSTANCE_STATUS_DUMMY = "Secondary"
    INSTANCE_STATUS_DELETED = "Deleted"
    INSTANCE_STATUS_STATElEADER = "StateLeader"
    INSTANCE_STATUS_STATEfOLLOWER = "StateFollower"
    INSTANCE_STATUS_MAP = {
        # When instance run stand-alone,it's 'Normal'
        "Normal": "Primary",
        "Unnormal": "Abnormal",
        "Primary": "Primary",
        "Standby": "Standby",
        "Secondary": "Secondary",
        "Cascade Standby": "Cascade Standby",
        "Main Standby": "Main Standby",
        "Pending": "Abnormal",
        "Down": "Down",
        "Unknown": "Abnormal"
    }

    ###################################################################
    # ha status
    ###################################################################
    HA_STATUS_NORMAL = "Normal"
    HA_STATUS_BUILD = "Building"
    HA_STATUS_ABNORMAL = "Abnormal"
    HA_STATUS_MAP = {
        "Normal": "Normal",
        "Building": "Building",
        "Need repair": "Abnormal",
        "Starting": "Starting",
        "Demoting": "Demoting",
        "Promoting": "Promoting",
        "Waiting": "Abnormal",
        "Unknown": "Abnormal",
        "Catchup": "Normal"
    }

    ###################################################################
    # connection status
    ###################################################################
    CONN_STATUS_NORMAL = "Normal"
    CONN_STATUS_ABNORMAL = "Abnormal"
    CONN_STATUS_MAP = {
        "Connection ok": "Normal",
        "Connection bad": "Abnormal",
        "Connection started": "Abnormal",
        "Connection made": "Abnormal",
        "Connection awaiting response": "Abnormal",
        "Connection authentication ok": "Abnormal",
        "Connection prepare SSL": "Abnormal",
        "Connection needed": "Abnormal",
        "Unknown": "Abnormal"
    }

    ###################################################################
    # data status
    ###################################################################
    DATA_STATUS_Unknown = "Unknown"
    DATA_STATUS_MAP = {
        "Async": "Async",
        "Sync": "Sync",
        "Most available": "Standby Down",
        "Potential": "Potential",
        "Unknown": "Unknown"
    }

    def __init__(self):
        """
        Constructor
        """
        self.dbNodes = []
        self.clusterStatus = ""
        self.redistributing = ""
        self.clusterStatusDetail = ""
        self.__curNode = None
        self.__curInstance = None
        self.balanced = ""

    def __str__(self):
        """
        """
        retStr = "clusterStatus=%s,redistributing=%s,clusterStatusDetail=%s," \
                 "balanced=%s" % \
                 (self.clusterStatus, self.redistributing,
                  self.clusterStatusDetail, self.balanced)

        for dbNode in self.dbNodes:
            retStr += "\n%s" % str(dbNode)

        return retStr

    def getDbNodeStatusById(self, nodeId):
        """  
        function : Get node status by node id
        input : nodeId
        output : dbNode
        """
        for dbNode in self.dbNodes:
            if (dbNode.id == nodeId):
                return dbNode

        return None

    def getInstanceStatusById(self, instId):
        """   
        function : Get instance by its id
        input : instId
        output : dbInst
        """
        for dbNode in self.dbNodes:
            # get DB instance
            instances = dbNode.coordinators + dbNode.gtms + dbNode.datanodes
            # get instance by its id
            for dbInst in instances:
                if (dbInst.instanceId == instId):
                    return dbInst

        return None

    def isAllHealthy(self, cluster_normal_status=None):
        """ 
        function : Check if cluster is healthy
        input : cluster_normal_status
        output : boolean
        """
        if cluster_normal_status is None:
            cluster_normal_status = [DbClusterStatus.CLUSTER_STATUS_NORMAL]

        if self.clusterStatus not in cluster_normal_status:
            return False

        for dbNode in self.dbNodes:
            if (not dbNode.isNodeHealthy()):
                return False

        return True

    def getClusterStatusReport(self):
        """ 
        function : Get the health report of cluster
        input : NA
        output : clusterRep
        """
        clusterRep = StatusReport()
        for dbNode in self.dbNodes:
            nodeRep = dbNode.getNodeStatusReport()
            clusterRep.nodeCount += 1
            clusterRep.cooNormal += nodeRep.cooNormal
            clusterRep.cooAbnormal += nodeRep.cooAbnormal
            clusterRep.gtmPrimary += nodeRep.gtmPrimary
            clusterRep.gtmStandby += nodeRep.gtmStandby
            clusterRep.gtmAbnormal += nodeRep.gtmAbnormal
            clusterRep.gtmDown += nodeRep.gtmDown
            clusterRep.dnPrimary += nodeRep.dnPrimary
            clusterRep.dnStandby += nodeRep.dnStandby
            clusterRep.dnDummy += nodeRep.dnDummy
            clusterRep.dn_cascade_standby += nodeRep.dn_cascade_standby
            clusterRep.dnBuild += nodeRep.dnBuild
            clusterRep.dnAbnormal += nodeRep.dnAbnormal
            clusterRep.dnDown += nodeRep.dnDown
            clusterRep.fencedUDFNormal += nodeRep.fencedUDFNormal
            clusterRep.fencedUDFAbnormal += nodeRep.fencedUDFAbnormal

        return clusterRep

    def getClusterStauts(self):
        """
        function : Get the status of cluster for Healthcheck 
        input : user
        output : statusInfo
        """
        clusterStat = DbClusterStatus.OM_STATUS_NORMAL
        redistributing_state = self.redistributing
        balanced_state = self.balanced
        if (clusterStat == DbClusterStatus.OM_STATUS_NORMAL):
            clusterStat = self.clusterStatus
        statusInfo = "        %s: %s\n" % ("cluster_state".ljust(22),
                                           clusterStat)
        statusInfo += "        %s: %s\n" % ("redistributing".ljust(22),
                                            redistributing_state)
        statusInfo += "        %s: %s\n" % ("balanced".ljust(22),
                                            balanced_state)
        for dbNode in self.dbNodes:
            if (dbNode.isNodeHealthy()):
                statusInfo += "        %s: %s \n" % (
                    dbNode.name.ljust(22),
                    DbClusterStatus.OM_NODE_STATUS_NORMAL)
            else:
                statusInfo += "        %s: %s \n" % (
                    dbNode.name.ljust(22),
                    DbClusterStatus.OM_NODE_STATUS_ABNORMAL)
        return statusInfo

    def init_from_content(self, content, is_expand_scene=False, check_action=None, logger=None):
        """
        Init from content
        """
        content_list = content.split('\n')
        try:
            for line in content_list:
                line = line.strip()
                if line == "":
                    continue
                str_list = line.split(":")
                if len(str_list) != 2:
                    continue
                self.__fillField(str_list[0].strip(), str_list[1].strip(),
                                 is_expand_scene, check_action=check_action)
        except Exception as error:
            if logger:
                logger.debug("Failed parse cluster status with error:%s, "
                             "status content:%s" % (error, content))
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50204"] % "status content" + " Error: \n%s" % str(error))

    def initFromFile(self, filePath, isExpandScene=False, check_action=None):
        """
        function : Init from status file 
        input : filePath
        output : NA
        """
        # check file path
        if (not os.path.exists(filePath)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            "status file" + " Path: %s." % filePath)
        if (not os.path.isfile(filePath)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] %
                            "status file" + " Path: %s." % filePath)

        try:
            with open(filePath, "r") as fp:
                for line in fp.readlines():
                    line = line.strip()
                    if line == "":
                        continue

                    strList = line.split(":")
                    if len(strList) != 2:
                        continue

                    self.__fillField(strList[0].strip(), strList[1].strip(),
                                     isExpandScene, check_action=check_action)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] %
                            "status file" + " Error: \n%s" % str(e))

    def __fillField(self, field, value, isExpandScene, check_action=None):
        """ 
        function : Fill field 
        input : field, value
        output : NA
        """
        if field == "cluster_state":
            status = DbClusterStatus.CLUSTER_STATUS_MAP.get(value)
            self.clusterStatus = DbClusterStatus.CLUSTER_STATUS_ABNORMAL \
                if status is None else status
            self.clusterStatusDetail = value
        elif field == "redistributing":
            self.redistributing = value
        elif field == "balanced":
            self.balanced = value
        elif field == "node":
            if not value.isdigit():
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51633"] % "node id")
            newId = int(value)
            if self.__curNode is None or self.__curNode.id != newId:
                self.__curNode = DbNodeStatus(newId)
                self.dbNodes.append(self.__curNode)
        elif field == "node_name":
            self.__curNode.name = value
        elif field == "instance_id":
            if not value.isdigit():
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51633"] %
                                "instance id")
            self.__curInstance = DbInstanceStatus(self.__curNode.id,
                                                  int(value))
        elif field == "data_path":
            self.__curInstance.datadir = value
        elif field == "type":
            if value == DbClusterStatus.INSTANCE_TYPE_FENCED_UDF:
                self.__curInstance = DbInstanceStatus(self.__curNode.id)
                self.__curNode.fencedUDFs.append(self.__curInstance)
            self.__curInstance.type = value
            if value == DbClusterStatus.INSTANCE_TYPE_GTM:
                self.__curNode.gtms.append(self.__curInstance)
            elif value == DbClusterStatus.INSTANCE_TYPE_DATANODE:
                self.__curNode.datanodes.append(self.__curInstance)
            elif value == DbClusterStatus.INSTANCE_TYPE_COORDINATOR:
                self.__curNode.coordinators.append(self.__curInstance)
            elif value == DbClusterStatus.INSTANCE_TYPE_CMSERVER:
                self.__curNode.cmservers.append(self.__curInstance)
            elif value == DbClusterStatus.INSTANCE_TYPE_ETCD:
                self.__curNode.etcds.append(self.__curInstance)
        elif field == "instance_state":
            if check_action == DefaultValue.TASK_QUERY_STATUS:
                status = DbClusterStatus.INSTANCE_STATUS_MAP_CHECK_STATUS.get(value)
            else:
                status = DbClusterStatus.INSTANCE_STATUS_MAP.get(value)
            self.__curInstance.status = \
                DbClusterStatus.INSTANCE_STATUS_ABNORMAL \
                    if status is None else status
        elif field == "node_ip":
            self.__curInstance.nodeIp = value
        elif field == "state":
            if (value == DbClusterStatus.INSTANCE_STATUS_NORMAL or
                    value == DbClusterStatus.INSTANCE_STATUS_STATElEADER or
                    value == DbClusterStatus.INSTANCE_STATUS_STATEfOLLOWER):
                self.__curInstance.status = value
            elif (value == DbClusterStatus.INSTANCE_STATUS_DELETED):
                global g_deletedCNId
                self.__curInstance.status = \
                    DbClusterStatus.INSTANCE_STATUS_ABNORMAL
                self.__curInstance.detail_status = value
                g_deletedCNId.append(self.__curInstance.instanceId)
            else:
                if (isExpandScene and self.__curInstance.type ==
                        DbClusterStatus.INSTANCE_TYPE_COORDINATOR):
                    self.clusterStatus = \
                        DbClusterStatus.CLUSTER_STATUS_ABNORMAL
                self.__curInstance.status = \
                    DbClusterStatus.INSTANCE_STATUS_ABNORMAL
                self.__curInstance.detail_status = value
                if check_action == StreamingConstants.STREAM_DISTRIBUTE_ACTION:
                    self.__curInstance.status = \
                        DbClusterStatus.INSTANCE_STATUS_MAP_CHECK_FAILOVER.get(value, value)
                    self.__curInstance.detail_status = \
                        DbClusterStatus.INSTANCE_STATUS_MAP_CHECK_FAILOVER.get(value, value)
        elif field == "HA_state":
            haStatus = DbClusterStatus.HA_STATUS_MAP.get(value)
            detail_ha = value
            self.__curInstance.haStatus = DbClusterStatus.HA_STATUS_ABNORMAL \
                if haStatus is None else haStatus
            self.__curInstance.detail_ha = DbClusterStatus.HA_STATUS_ABNORMAL \
                if detail_ha is None else detail_ha
        elif field == "con_state":
            connStatus = DbClusterStatus.CONN_STATUS_MAP.get(value)
            detail_conn = value
            self.__curInstance.connStatus = \
                DbClusterStatus.CONN_STATUS_ABNORMAL \
                    if connStatus is None else connStatus
            self.__curInstance.detail_conn = detail_conn if detail_conn else \
                DbClusterStatus.CONN_STATUS_ABNORMAL
        elif field == "static_connections":
            connStatus = DbClusterStatus.CONN_STATUS_MAP.get(value)
            self.__curInstance.connStatus = \
                DbClusterStatus.CONN_STATUS_ABNORMAL \
                    if connStatus is None else connStatus
        elif field == "sync_state":
            dataStatus = DbClusterStatus.DATA_STATUS_MAP.get(value)
            self.__curInstance.syncStatus = \
                DbClusterStatus.DATA_STATUS_Unknown \
                    if dataStatus is None else dataStatus
        elif field == "reason":
            self.__curInstance.reason = value
            if check_action == StreamingConstants.STREAM_DISTRIBUTE_ACTION and \
                    hasattr(self.__curInstance, "detail_ha") and value == "Disconnected":
                self.__curInstance.detail_ha = \
                    DbClusterStatus.INSTANCE_STATUS_MAP_CHECK_FAILOVER.get("Need repair", value)


