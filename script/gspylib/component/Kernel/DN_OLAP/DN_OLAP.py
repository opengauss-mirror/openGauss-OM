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
import sys
import os
import re

sys.path.append(sys.path[0] + "/../../../../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue, ClusterInstanceConfig
from gspylib.component.Kernel.Kernel import Kernel
from gspylib.component.DSS.dss_comp import Dss, DssInst
from gspylib.common.DbClusterInfo import dbClusterInfo
from base_utils.os.cmd_util import CmdUtil
from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.compress_util import CompressUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.cluster_os.cluster_user import ClusterUser
from base_utils.os.grep_util import GrepUtil
from base_utils.os.user_util import UserUtil
from gspylib.component.DSS.dss_checker import DssConfig


METHOD_TRUST = "trust"
METHOD_SHA = "sha256"
MAX_PARA_NUMBER = 1000
INSTANCE_TYPE_UNDEFINED = -1
MASTER_INSTANCE = 0
STANDBY_INSTANCE = 1
DUMMY_STANDBY_INSTANCE = 2
CASCADE_STANDBY_INSTANCE = 3


class DN_OLAP(Kernel):
    '''
    The class is used to define base component.
    '''

    def __init__(self):
        '''
        Constructor
        '''
        super(DN_OLAP, self).__init__()

    def getDnGUCDict(self):
        """
        function : get init DB install guc parameter
        input : String,String,String,int
        output : String
        """
        tmpDict = {}
        tmpDict["ssl"] = "on"
        tmpDict["ssl_cert_file"] = "'server.crt'"
        tmpDict["ssl_key_file"] = "'server.key'"
        tmpDict["ssl_ca_file"] = "'cacert.pem'"
        return tmpDict

    def copyAndModCertFiles(self):
        """
        function : copy and chage permission cert files
        input : NA
        output : NA
        """
        user = UserUtil.getUserInfo()["name"]
        appPath = ClusterDir.getInstallDir(user)
        caPath = os.path.join(appPath, "share/sslcert/om")
        # cp cert files
        FileUtil.cpFile("%s/server.crt" % caPath, "%s/" %
                      self.instInfo.datadir)
        FileUtil.cpFile("%s/server.key" % caPath, "%s/" %
                      self.instInfo.datadir)
        FileUtil.cpFile("%s/cacert.pem" % caPath, "%s/" %
                      self.instInfo.datadir)
        FileUtil.cpFile("%s/server.key.cipher" % caPath, "%s/" %
                      self.instInfo.datadir)
        FileUtil.cpFile("%s/server.key.rand" % caPath, "%s/" %
                      self.instInfo.datadir)
        # change mode
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.crt" %
                          self.instInfo.datadir)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.key" %
                          self.instInfo.datadir)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, "%s/cacert.pem" %
                          self.instInfo.datadir)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.key.cipher" %
                          self.instInfo.datadir)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, "%s/server.key.rand" %
                          self.instInfo.datadir)

    @Dss.catch_err(exist_so=True)
    def initInstance(self):
        """
        function:
            init DB instance
        input:string:NA
        output:
        """
        if (not os.path.exists(self.instInfo.datadir)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                            ("data directory [%s]" % self.instInfo.datadir))

        nodename = self.getInstanceNodeName()
        # if nodename too long, obtains the first 22 digits
        nodename = nodename[:22]
        if (self.dwsMode):
            image_path = DefaultValue.DWS_IMAGE_PATH
            # decompress package to files
            packageName = "%s/datanode.tar.gz" % image_path
            CompressUtil.decompressFiles(packageName, self.instInfo.datadir)
            # set GUC parameter
            tmpDict = {}
            tmpDict["pgxc_node_name"] = "'%s'" % nodename
            self.setGucConfig(tmpDict)
        else:
            # If xlogdir is set in xmlfile, an independent xlog
            # path will be created.
            if (self.instInfo.xlogdir != ''):
                cmd = "%s/gs_initdb --locale=C -D %s -X %s " \
                      "--nodename=%s %s -C %s" % (
                          self.binPath, self.instInfo.datadir,
                          self.instInfo.xlogdir, nodename,
                          " ".join(self.initParas), self.binPath)
            else:
                cmd = "%s/gs_initdb --locale=C -D %s --nodename=%s %s -C %s" \
                      % \
                      (self.binPath, self.instInfo.datadir, nodename,
                       " ".join(self.initParas), self.binPath)
            self.logger.debug('check DCF mode:%s' % self.paxos_mode)
            if self.paxos_mode:
                cmd += " -c"
            elif self.dss_mode:
                vgname = EnvUtil.getEnv('VGNAME')
                dss_home = EnvUtil.getEnv('DSS_HOME')
                inst_id = DssInst.get_dss_id_from_key(dss_home)
                dss_nodes_list = DssConfig.get_value_b64_handler(
                    'dss_nodes_list', self.dss_config, action='decode')
                cfg_context = DssInst.get_dms_url(dss_nodes_list)

                # when use one private vg for xlog, vgname should get from inst_id=0
                pri_vgname = DssInst.get_private_vgname_by_ini(dss_home, inst_id)
                cmd += " -n --vgname=\"{}\" --enable-dss --dms_url=\"{}\" -I {}" \
                    " --socketpath=\"{}\"".format(
                    "+{},+{}".format(vgname, pri_vgname), cfg_context, inst_id,
                    "UDS:{}/.dss_unix_d_socket".format(dss_home))
                if (self.dorado_cluster_mode != ""):
                    cmd += " --enable-ss-dorado"
            self.logger.debug("Command for initializing database "
                              "node instance: %s" % cmd)
            status, output = CmdUtil.retryGetstatusoutput(
                cmd, retry_time=0 if self.dss_mode else 3)
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51615"] +
                                " Command:%s. Error:\n%s" % (cmd, output))
        # set ssl to DB nodes.
        dnGucParas = self.getDnGUCDict()
        self.setGucConfig(dnGucParas)
        self.copyAndModCertFiles()

    def getInstanceNodeName(self):
        """
        function: Get Instance Node Name
        input : NA
        output: instance node name
        """
        user = UserUtil.getUserInfo()["name"]
        clusterInfo = dbClusterInfo()
        clusterInfo.initFromStaticConfig(user)
        peerInsts = clusterInfo.getPeerInstance(self.instInfo)
        nodename = "dn_%d" % self.instInfo.instanceId
        if len(peerInsts) == 0:
            return nodename
        nodename = ClusterInstanceConfig. \
            setReplConninfoForSinglePrimaryMultiStandbyCluster(
            self.instInfo, peerInsts, clusterInfo)[1]
        return nodename


    def getDNDict(self, user, configItemType=None, peerInsts=None,
                  azNames=None, syncNum=-1, syncNumFirst=""):
        """
        function: Get database node configuration
        input : user, configItemType=None, peerInsts,
                azNames=None, syncNum
        output: NA
        """
        if peerInsts is None:
            peerInsts = []
        if azNames is None:
            azNames = []
        tmp_dn_dict = {}
        if self.instInfo.dcf_data_path != "":
            tmp_dn_dict["dcf_node_id"] = str(int(self.instInfo.instanceId) - 6000)
            tmp_dn_dict["dcf_data_path"] = self.instInfo.datadir + '/dcf_data'
            tmp_dn_dict["dcf_log_path"] = '%s/dcf_log' % ClusterDir.getUserLogDirWithUser(user)
        if EnvUtil.get_rdma_type(user) == "RDMA":
            tmp_dn_dict["ss_interconnect_type"] = '\'RDMA\''
            tmp_dn_dict["ss_ock_log_path"] = "'%s/pg_log/dn_%d'" % (
                ClusterDir.getUserLogDirWithUser(user),
                self.instInfo.instanceId)
            rdma_config = EnvUtil.get_rdma_config(user)
            if rdma_config:
                tmp_dn_dict["ss_rdma_work_config"] = "'{}'".format(rdma_config)
        if "127.0.0.1" in self.instInfo.listenIps:
            tmp_dn_dict["listen_addresses"] = "'%s'" % ",".join(
                self.instInfo.listenIps)
        else:
            tmp_dn_dict["listen_addresses"] = "'localhost,%s'" % ",".join(
                self.instInfo.listenIps)

        tmp_dn_dict["local_bind_address"] = "'%s'" % self.instInfo.listenIps[0]
        tmp_dn_dict["port"] = self.instInfo.port

        if self.dss_mode:
            tmp_dn_dict["comm_sctp_port"] = self.instInfo.port + 100
            tmp_dn_dict["comm_control_port"] = self.instInfo.port + 200

        if configItemType == "ConfigInstance":
            tmp_dn_dict["cstore_buffers"] = "1GB"
            tmp_dn_dict["max_connections"] = "3000"
            tmp_dn_dict["shared_buffers"] = "1GB"
            tmp_dn_dict["work_mem"] = "64MB"
            tmp_dn_dict["maintenance_work_mem"] = "128MB"
            tmp_dn_dict["data_replicate_buffer_size"] = "128MB"
        if (self.clusterType ==
                DefaultValue.CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY or
                self.clusterType == DefaultValue.CLUSTER_TYPE_SINGLE_INST):
            tmp_dn_dict["enable_data_replicate"] = "off"
            tmp_dn_dict["replication_type"] = "1"
            tmp_dn_dict["max_wal_senders"] = "16"
            totalnum = len(peerInsts)
            for inst in peerInsts:
                if inst.instanceType == CASCADE_STANDBY_INSTANCE:
                    totalnum = totalnum - 1
            tmp_dn_dict["application_name"] = "'dn_%s'" % \
                                            self.instInfo.instanceId

            if syncNumFirst != [] and syncNumFirst != '':
                user = UserUtil.getUserInfo()["name"]
                clusterInfo = dbClusterInfo()
                clusterInfo.initFromStaticConfig(user)
                peerInsts = clusterInfo.getPeerInstance(self.instInfo)
                dbNodes = clusterInfo.dbNodes
                dn = dict()
                for dbinfo in dbNodes:
                    datanodes = dbinfo.datanodes
                    for datainfo in datanodes:
                        dn[datainfo.hostname] = datainfo.instanceId
                for sync in dn.keys():
                    if syncNumFirst.count(sync) > 1:
                        self.logger.debug("sync must be only one")
                    else:
                        syncNumFirst = syncNumFirst.replace(sync,'dn_%s' % (dn[sync]))
                tmp_dn_dict["synchronous_standby_names"] = "'%s'" % (syncNumFirst)
            elif len(azNames) == 1 and totalnum > 0:
                if syncNum == -1 and totalnum > 1:
                    num = (totalnum + 1)//2
                    dn_inst_str = ",".join(['dn_{0}'.format(inst.instanceId)
                                            for inst in peerInsts])
                    tmp_dn_dict["synchronous_standby_names"] = \
                        "'ANY %d(%s)'" % (num, dn_inst_str)
                elif syncNum > 0:
                    tmp_dn_dict["synchronous_standby_names"] = \
                        "'ANY %d(%s)'" % (syncNum, azNames[0])
                elif syncNum == 0:
                    tmp_dn_dict["synchronous_standby_names"] = \
                        "'ANY 1(%s)'" % (azNames[0])
            elif len(azNames) == 2 and totalnum in (3, 4):
                tmp_dn_dict["synchronous_standby_names"] = \
                    "'ANY 2(%s,%s)'" % (azNames[0], azNames[1])
            elif len(azNames) == 2 and totalnum in (5, 6, 7):
                tmp_dn_dict["synchronous_standby_names"] = \
                    "'ANY 3(%s,%s)'" % (azNames[0], azNames[1])
            elif len(azNames) == 3 and totalnum in (3, 4):
                tmp_dn_dict["synchronous_standby_names"] = \
                    "'ANY 2(%s,%s,%s)'" % (azNames[0], azNames[1], azNames[2])
            elif len(azNames) == 3 and totalnum in (5, 6, 7):
                tmp_dn_dict["synchronous_standby_names"] = \
                    "'ANY 3(%s,%s,%s)'" % (azNames[0], azNames[1], azNames[2])

        if self.clusterType == DefaultValue.CLUSTER_TYPE_SINGLE:
            tmp_dn_dict["replication_type"] = "2"

        if configItemType != "ChangeIPUtility":
            tmp_dn_dict["log_directory"] = "'%s/pg_log/dn_%d'" % (
                ClusterDir.getUserLogDirWithUser(user),
                self.instInfo.instanceId)
            tmp_dn_dict["audit_directory"] = "'%s/pg_audit/dn_%d'" % (
                ClusterDir.getUserLogDirWithUser(user),
                self.instInfo.instanceId)

        if (len(self.instInfo.ssdDir) != 0 and configItemType !=
                "ChangeIPUtility"):
            tmp_dn_dict["ssd_cache_dir"] = "'%s'" % (self.instInfo.ssdDir)
            tmp_dn_dict["enable_adio_function"] = "on"
            tmp_dn_dict["enable_cstore_ssd_cache"] = "on"
        self.logger.debug("DN parameter value is : {0}".format(tmp_dn_dict))
        return tmp_dn_dict

    def getPrivateGucParamList(self):
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

    def modifyDummpyStandbyConfigItem(self):
        """
        function: Modify the parameter at dummyStandby instance.
                  It only be used by DB instance.
        input : Inst, configFile
        output: NA
        """
        # only modify config item for dummpy standby instance
        if (self.instInfo.instanceType != DefaultValue.DUMMY_STANDBY_INSTANCE):
            return
        tmpDNDict = self.getPrivateGucParamList()
        self.setGucConfig(tmpDNDict)

    def setPrimaryStandyConnInfo(self, peerInsts):
        """
        function: Modify replconninfo for datanode
        input : peerInsts
        output: NA
        """
        connInfo1 = None
        connInfo2 = None
        dummyStandbyInst = None
        nodename = None
        user = UserUtil.getUserInfo()["name"]
        clusterInfo = dbClusterInfo()
        clusterInfo.initFromStaticConfig(user)
        if (self.clusterType ==
                DefaultValue.CLUSTER_TYPE_SINGLE_PRIMARY_MULTI_STANDBY or
                self.clusterType == DefaultValue.CLUSTER_TYPE_SINGLE_INST):
            (connInfo1, nodename) = ClusterInstanceConfig. \
                setReplConninfoForSinglePrimaryMultiStandbyCluster(
                self.instInfo, peerInsts, clusterInfo)
            for i in range(len(connInfo1)):
                connInfo = "replconninfo" + "%d" % (i + 1)
                tmpDict1 = {}
                tmpDict1[connInfo] = "'%s'" % connInfo1[i]
                self.setGucConfig(tmpDict1)
            self.setGucConfig({"available_zone": "'%s'" %
                                                 self.instInfo.azName})
        else:
            (connInfo1, connInfo2, dummyStandbyInst, nodename) = \
                ClusterInstanceConfig.setReplConninfo(self.instInfo,
                                                      peerInsts, clusterInfo)
            connInfo = "replconninfo1"
            tmpDict1 = {}
            tmpDict1[connInfo] = "'%s'" % connInfo1
            self.setGucConfig(tmpDict1)

        if (dummyStandbyInst is not None):
            tmpDict2 = {}
            tmpDict2["replconninfo2"] = "'%s'" % connInfo2
            self.setGucConfig(tmpDict2)

    def configInstance(self, user, dataConfig, peerInsts,
                       configItemType=None, alarm_component=None,
                       azNames=None, gucXml=False):
        """
        peerInsts : peerInsts is empty means that it is a single cluster.
        """
        if azNames is None:
            azNames = []
        syncNum = self.instInfo.syncNum
        syncNumFirst = self.instInfo.syncNumFirst
        tmpDNDict = self.getDNDict(user, configItemType, peerInsts,
                                   azNames, syncNum, syncNumFirst)

        commonDict = self.setCommonItems()
        self.setGucConfig(commonDict)

        self.logger.debug("Check if tmp_guc file exists.")
        tmpGucFile = ""
        tmpGucPath = EnvUtil.getTmpDirFromEnv(user)
        tmpGucFile = "%s/tmp_guc" % tmpGucPath
        if (os.path.exists(tmpGucFile)):
            dynamicDict = {}
            dynamicDict = DefaultValue.dynamicGuc("dn", tmpGucFile,
                                                  gucXml)
            if gucXml:
                dynamicDict["log_line_prefix"] = "'%s'" % \
                                                 dynamicDict["log_line_prefix"]
                dynamicDict["thread_pool_attr"] = "'%s'" % \
                                                  dynamicDict[
                                                      "thread_pool_attr"]
            if (len(dynamicDict) != 0):
                self.logger.debug("set dynamic guc parameters "
                                  "for database node instances.")
                if (self.instInfo.instanceType ==
                        DefaultValue.DUMMY_STANDBY_INSTANCE):
                    self.logger.debug("remove max_process_memory if "
                                      "current datanode is dummy one.")
                    dummydynamicDict = dynamicDict
                    dummydynamicDict.pop("max_process_memory")
                    tmpDNDict.update(dummydynamicDict)
                else:
                    tmpDNDict.update(dynamicDict)
            else:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                                "guc_list.conf")
        tmpDNDict.update(dataConfig)
        tmpDNDict["alarm_component"] = "'%s'" % alarm_component
        self.setGucConfig(tmpDNDict)

        if (len(peerInsts)):
            self.setPrimaryStandyConnInfo(peerInsts)
        else:
            tmpDict1 = {}
            tmpDict1["synchronous_commit"] = "off"
            self.setGucConfig(tmpDict1)

        if syncNum == 0 or (syncNum == -1 and len(peerInsts) == 1):
            tmpDict1 = {}
            tmpDict1["synchronous_commit"] = "off"
            self.setGucConfig(tmpDict1)


        self.modifyDummpyStandbyConfigItem()

    def setPghbaConfig(self, clusterAllIpList, try_reload=False, float_ips=None):
        """
        """
        principal = None
        if DefaultValue.checkKerberos(EnvUtil.getMpprcFile()):

            (status, output) = \
                GrepUtil.getGrepValue("-Er", "^default_realm",
                                     os.path.join(os.path.dirname(
                                         EnvUtil.getMpprcFile()),
                                         DefaultValue.FI_KRB_CONF))
            if status != 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50222"] %
                                "krb5.conf" + "Error:\n%s" % output)
            principal = output.split("=")[1].strip()

        # build ip string list
        # Every 1000 records merged into one
        i = 0
        guc_paras_str = ""
        GUCParasStrList = []
        pg_user = ClusterUser.get_pg_user()
        for ip_address in clusterAllIpList:
            i += 1
            # Set the initial user and initial database access permissions
            if principal is None:
                if ip_address.startswith("floatIp"):
                    guc_paras_str += "-h \"host    all    all    %s/32    %s\" " % \
                                     (float_ips[ip_address], METHOD_SHA)
                else:
                    guc_paras_str += "-h \"host    all    %s    %s/32    %s\" " % \
                                     (pg_user, ip_address, METHOD_TRUST)
                    guc_paras_str += "-h \"host    all    all    %s/32    %s\" " % \
                                     (ip_address, METHOD_SHA)
            else:
                if ip_address.startswith("floatIp"):
                    guc_paras_str += "-h \"host    all    all    %s/32    %s\" " % \
                                     (float_ips[ip_address], METHOD_SHA)
                else:
                    guc_paras_str += "-h \"host    all    %s    %s/32    gss    include_realm=1 " \
                                     "   krb_realm=%s\" " % (pg_user, ip_address, principal)
                    guc_paras_str += "-h \"host    all    all    %s/32    %s\" " % \
                                     (ip_address, METHOD_SHA)
            if (i % MAX_PARA_NUMBER == 0):
                GUCParasStrList.append(guc_paras_str)
                i = 0
                guc_paras_str = ""
        # Used only streaming disaster cluster
        streaming_dn_ips = self.get_streaming_relate_dn_ips(self.instInfo)
        if streaming_dn_ips:
            for dn_ip in streaming_dn_ips:
                guc_paras_str += "-h \"host    all    %s    %s/32    %s\" " \
                               % (pg_user, dn_ip, METHOD_TRUST)
                guc_paras_str += "-h \"host    all    all    %s/32    %s\" " \
                               % (dn_ip, METHOD_SHA)
                ip_segment = '.'.join(dn_ip.split('.')[:2]) + ".0.0/16"
                guc_paras_str += "-h \"host    replication    all    %s    sha256\" " % ip_segment

        if (guc_paras_str != ""):
            GUCParasStrList.append(guc_paras_str)

        for parasStr in GUCParasStrList:
            self.doGUCConfig("set", parasStr, True, try_reload=try_reload)

    """
    Desc: 
        Under the AP branch, we don't need to the 
        uninstall/postcheck for every componet. 
    """

    def upgrade(self):
        pass
