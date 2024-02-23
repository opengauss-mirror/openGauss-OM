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
# Description  : Generate_xml.py is generate xml base on cluster 
#############################################################################
import os
import pwd
import datetime
import subprocess
import copy
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

from base_utils.os.env_util import EnvUtil
from gspylib.common.ErrorCode import ErrorCode


class ClusterKey:
    # cluster label
    CLUSTER_NAME = "clusterName"
    NODENAMES = "nodeNames"
    GAUSS_DB_APP_PATH = "gaussdbAppPath"
    GAUSS_DB_LOG_PATH = "gaussdbLogPath"
    GAUSS_MPP_DB_PATH = "tmpMppdbPath"
    GAUSS_DB_TOOL_PATH = "gaussdbToolPath"
    CORE_PATH = "corePath"
    BAKCIP1S = "backIp1s"

    # ddes
    ENABLE_DSS = "enable_dss"
    DSS_HOME = "dss_home"
    SS_DSS_VG_NAME = "ss_dss_vg_name"
    DSS_VG_INFO = "dss_vg_info"
    VOTING_DISK_PATH = "votingDiskPath"
    SHARE_DISK_DIR = "shareDiskDir"
    DSS_SSL_ENABLE = "dss_ssl_enable"

    # dcf
    ENABLE_DCF = "enable_dcf"
    DCF_CONFIG = "dcf_config"

    # device labes
    # om
    NAME = "name"
    AZNAME = "azName"
    AZPRIORITY = "azPriority"
    BACKIP1 = "backIp1"
    SSHIP1 = "sshIp1"
    DATA_NUM = "dataNum"
    DATA_PORT_BASE = "dataPortBase"
    DATA_NODE1 = "dataNode1"
    DATA_NODE1_SYNCNUM = "dataNode1_syncNum"

    # cm
    CMS_NUM = "cmsNum"
    CM_SERVER_PORT_BASE = "cmServerPortBase"
    CM_SERVER_LISTEN_IP1 = "cmServerListenIp1"
    CM_SERVER_HA_IP1 = "cmServerHaIp1"
    CM_SERVER_LEVEL = "cmServerlevel"
    CM_SERVER_RELATION = "cmServerRelation"
    CM_SERVER_PORT_STANDBY = "cmServerPortStandby"
    CM_DIR = "cmDir"

    # cascadeRole
    CASCADEROLE = "cascadeRole"

    CLUSTER_LABEL = [CLUSTER_NAME, NODENAMES, GAUSS_DB_APP_PATH, GAUSS_DB_LOG_PATH, GAUSS_MPP_DB_PATH,
                     GAUSS_DB_TOOL_PATH, CORE_PATH, BAKCIP1S]

    DSS_LABEL = [ENABLE_DSS, DSS_HOME, SS_DSS_VG_NAME, DSS_VG_INFO, VOTING_DISK_PATH,
                 SHARE_DISK_DIR, DSS_SSL_ENABLE]

    DCF_LABEL = [ENABLE_DCF, DCF_CONFIG]

    DEVICE_LABEL_SN = [NAME, AZNAME, AZPRIORITY, BACKIP1, SSHIP1, DATA_NUM, DATA_PORT_BASE,
                       DATA_NODE1, DATA_NODE1_SYNCNUM, CASCADEROLE]

    CM_LABEL_SN = [CMS_NUM, CM_SERVER_PORT_BASE, CM_SERVER_LISTEN_IP1, CM_SERVER_HA_IP1,
                   CM_SERVER_LEVEL, CM_SERVER_RELATION, CM_SERVER_PORT_STANDBY, CM_DIR]


def check_cluster_node_count(cluster_info):
    node_count = len(cluster_info.dbNodes)
    if node_count < 0 or node_count > 9:
        raise Exception("The cluster supports a maximum of one primary node and eight backup nodes")

class GenerateXml:

    def __init__(self):
        self.tree = None
        self.root = None
        self.cluster_label = ""
        self.device_list_label = ""
        self.device_label = ""
        self.hostip_list = []
        self.hostname_list = []
        self.hostip_str = ""
        self.hostname_str = ""
        self.cm_flag = False

    def create_init_label(self):
        root = ET.Element("ROOT")
        cluster = ET.Element("CLUSTER")
        device_list = ET.Element("DEVICELIST")
        root.append(cluster)
        root.append(device_list)
        self.cluster_label = cluster
        self.device_list_label = device_list
        self.tree = ET.ElementTree(root)
        self.root = self.tree.getroot()

    def update_cluster_node_info(self, cluster_info, new_host_info):
        """
        function: update cluster new node info
        input  : cluster_info new_host_info
        output : NA
        """
        if not new_host_info:
            return
        for hostname, hostip in new_host_info.items():
            new_node = copy.deepcopy(cluster_info.dbNodes[-1])
            new_node.name = hostname
            new_node.backIps[0] = hostip
            new_node.sshIps[0] = hostip
            new_node.datanodes[0].instanceType = '1'
            cluster_info.dbNodes.append(new_node)

            # if has cm, need copy cmservers cmagents
            if self.cm_flag: 
                cm_server = new_node.cmservers[0]
                cm_server.hostname = hostname
                cm_server.listenIps[0] = hostip
                cm_server.haIps[0] = hostip
        
        check_cluster_node_count(cluster_info)

    def do_generate_xml(self, cluster_info, new_host_info=None):
        """
        function: Generate XML based on cluster
        input  : cluster_info new_host_info
        output : NA
        """
        # Add node information to the existing cluster information
        self.update_cluster_node_info(cluster_info, new_host_info)
        # if has cm
        self.has_cm(cluster_info)
        # get cluster info
        cluster_info_dict = self.get_cluster_info(cluster_info)
        # generate xml
        self.create_init_label()
        self.set_cluster_info(cluster_info_dict)
        self.set_device_info(cluster_info_dict)
        # output
        self.output_xml()

    def get_cluster_info(self, cluster_info):
        cluster_info_dict = {}
        # cluster
        self.gen_cluster(cluster_info, cluster_info_dict)
        # ddes
        self.gen_ddes(cluster_info, cluster_info_dict)
        # dcf 
        self.gen_dcf(cluster_info, cluster_info_dict)
        # om
        self.gen_om(cluster_info, cluster_info_dict)
        # cm
        self.gen_cm(cluster_info, cluster_info_dict)
        # cascadeRole
        self.gen_cascade_role(cluster_info, cluster_info_dict)

        cluster_info_dict[ClusterKey.NODENAMES] = self.hostname_str
        cluster_info_dict[ClusterKey.BAKCIP1S] = self.hostip_str

        return cluster_info_dict

    def gen_cluster(self, cluster_info, cluster_info_dict):
        gp_home = EnvUtil.getEnv('GPHOME')
        tmp_path = EnvUtil.getEnv("PGHOST")
        core_path = EnvUtil.getEnv("COREPATH")
        cluster_info_dict[ClusterKey.CLUSTER_NAME] = cluster_info.name
        cluster_info_dict[ClusterKey.GAUSS_DB_APP_PATH] = cluster_info.appPath
        cluster_info_dict[ClusterKey.GAUSS_DB_LOG_PATH] = cluster_info.logPath
        cluster_info_dict[ClusterKey.GAUSS_MPP_DB_PATH] = tmp_path
        cluster_info_dict[ClusterKey.GAUSS_DB_TOOL_PATH] = gp_home
        cluster_info_dict[ClusterKey.CORE_PATH] = core_path

    def gen_ddes(self, cluster_info, cluster_info_dict):
        username = pwd.getpwuid(os.getuid()).pw_name
        dss_home = EnvUtil.get_dss_home(username)
        dss_ssl = EnvUtil.get_dss_ssl_status(username)
        vg_name = EnvUtil.getEnv('VGNAME')
        if not dss_home:
            return

        cm_conf_file = os.path.normpath(os.path.join(dss_home, 'cfg', 'dss_cm_conf.ini'))
        vg_conf_file = os.path.normpath(os.path.join(dss_home, 'cfg', 'dss_vg_conf.ini'))

        voting_disk_path = ""
        share_disk_dir = ""
        if not os.path.exists(cm_conf_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % cm_conf_file)
        with open(cm_conf_file, 'r') as fd:
            lines = fd.readlines()
            voting_disk_path = lines[0].strip()
            share_disk_dir = lines[1].strip()

        dss_vg_info = ""
        if not os.path.exists(vg_conf_file):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % vg_conf_file)
        with open(vg_conf_file, 'r') as fd:
            lines = fd.readlines()
            lines = [line.strip() for line in lines]
            dss_vg_info = ",".join(lines)

        cluster_info_dict[ClusterKey.ENABLE_DSS] = "on"
        cluster_info_dict[ClusterKey.DSS_HOME] = dss_home
        cluster_info_dict[ClusterKey.SS_DSS_VG_NAME] = vg_name
        cluster_info_dict[ClusterKey.DSS_VG_INFO] = dss_vg_info
        cluster_info_dict[ClusterKey.VOTING_DISK_PATH] = voting_disk_path
        cluster_info_dict[ClusterKey.SHARE_DISK_DIR] = share_disk_dir
        cluster_info_dict[ClusterKey.DSS_SSL_ENABLE] = dss_ssl

    def gen_dcf(self, cluster_info, cluster_info_dict):
        if cluster_info.enable_dcf == "on":
            cluster_info_dict[ClusterKey.ENABLE_DCF] = cluster_info.enable_dcf
            cluster_info_dict[ClusterKey.DCF_CONFIG] = cluster_info.dcf_config

    def get_datanodes1_value(self, cluster_info):
        datanode = cluster_info.dbNodes[0].datanodes[0].datadir
        datanode1_list = []
        datanode1_list.append(datanode)
        for node in cluster_info.dbNodes[1:]:
            datanode1_list.append(node.name)
            datanode1_list.append(datanode)
        datanode1 = ",".join(datanode1_list)
        return datanode1

    def gen_om(self, cluster_info, cluster_info_dict):
        hostname_list = []
        hostip_list = []
        datanode1 = self.get_datanodes1_value(cluster_info)
        for node in cluster_info.dbNodes:
            hostname = node.name
            host_ip = node.backIps[0]
            hostname_list.append(hostname)
            hostip_list.append(host_ip)

            instance_type = node.datanodes[0].instanceType
            cluster_info_dict[hostname] = {
                ClusterKey.NAME: hostname,
                ClusterKey.AZNAME: node.azName,
                ClusterKey.AZPRIORITY: str(node.azPriority),
                ClusterKey.BACKIP1: host_ip,
                ClusterKey.SSHIP1: node.sshIps[0],
                "instance_type": str(instance_type)
            }

            if instance_type == 0:
                cluster_info_dict[hostname].update({
                    ClusterKey.DATA_NUM: "1",
                    ClusterKey.DATA_PORT_BASE: str(node.datanodes[0].port),
                    ClusterKey.DATA_NODE1: datanode1,
                    ClusterKey.DATA_NODE1_SYNCNUM: "0"
                })

        self.hostname_list = hostname_list
        self.hostip_list = hostip_list
        self.hostname_str = ",".join(self.hostname_list)
        self.hostip_str = ",".join(self.hostip_list)

    def has_cm(self, cluster_info):
        if cluster_info.cmscount > 0:
            self.cm_flag = True

    def gen_cm(self, cluster_info, cluster_info_dict):
        if self.cm_flag:
            for node in cluster_info.dbNodes:
                hostname = node.name
                port = node.cmservers[0].port
                cm_dir = node.cmDataDir
                instance_type = node.cmservers[0].instanceType
                if instance_type == 0:
                    cluster_info_dict[hostname]['cm'] = {
                        "cm_instance_type": instance_type,
                        ClusterKey.CMS_NUM: "1",
                        ClusterKey.CM_SERVER_PORT_BASE: str(port),
                        ClusterKey.CM_SERVER_LISTEN_IP1: self.hostip_str,
                        ClusterKey.CM_SERVER_HA_IP1: self.hostip_str,
                        ClusterKey.CM_SERVER_LEVEL: "1",
                        ClusterKey.CM_SERVER_RELATION: self.hostname_str,
                        ClusterKey.CM_DIR: cm_dir
                    }
                else:
                    cluster_info_dict[hostname]['cm'] = {
                        "cm_instance_type": instance_type,
                        ClusterKey.CM_SERVER_PORT_STANDBY: str(port),
                        ClusterKey.CM_DIR: cm_dir
                    }

    def gen_cascade_role(self, cluster_info, cluster_info_dict):
        for node in cluster_info.dbNodes:
            hostname = node.name
            cascade_role = node.cascadeRole
            if node.cascadeRole == "on":
                cluster_info_dict[hostname].update({
                    ClusterKey.CASCADEROLE: cascade_role
                })

    def set_dict_key(self, dict_obj, key, value):
        if key in dict_obj.keys():
            dict_obj.update({key: value})
        else:
            dict_obj[key] = value

    def set_cluster_info(self, cluster_info_dict):
        self.set_cluster_common_info(cluster_info_dict, ClusterKey.CLUSTER_LABEL)
        self.set_cluster_common_info(cluster_info_dict, ClusterKey.DSS_LABEL)
        self.set_cluster_common_info(cluster_info_dict, ClusterKey.DCF_LABEL)

    def set_cluster_common_info(self, cluster_info_dict, keys):
        for label in keys:
            if label in cluster_info_dict.keys() and cluster_info_dict.get(label):
                key = label
                value = cluster_info_dict.get(label)
                param = ET.Element("PARAM", name=key, value=value)
                self.cluster_label.append(param)

    def set_device_info(self, cluster_info_dict):
        for hostname in self.hostname_list:
            parent = ET.SubElement(self.device_list_label, "DEVICE", sn=hostname)
            for label in ClusterKey.DEVICE_LABEL_SN:
                if label in cluster_info_dict[hostname].keys() and cluster_info_dict[hostname].get(label):
                    key = label
                    value = cluster_info_dict[hostname].get(label)
                    ET.SubElement(parent, "PARAM", name=key, value=value)
            
            if not self.cm_flag:
                continue
            for label in ClusterKey.CM_LABEL_SN:
                if label in cluster_info_dict[hostname]['cm'].keys() and cluster_info_dict[hostname]['cm'].get(label):
                    key = label
                    value = cluster_info_dict[hostname]['cm'].get(label)
                    ET.SubElement(parent, "PARAM", name=key, value=value)

    def output_xml(self):
        user = pwd.getpwuid(os.getuid()).pw_name
        current_date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        target_xml = "/home/%s/xml_output_%s.xml" % (user, str(current_date))
        # convert ElementTree tag tree to string
        xml_str = ET.tostring(self.root, encoding="UTF-8", method="xml")
        dom = minidom.parseString(xml_str)
        formatted_xml = dom.toprettyxml(encoding="UTF-8")
        with open(target_xml, "wb") as f:
            f.write(formatted_xml)
        xml_tmp_file = "/home/%s/tmp_generate_xml" % user
        cmd = "echo '%s' > '%s'" % (target_xml, xml_tmp_file)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception("Failed to write xml tmp file: %s" % output)
