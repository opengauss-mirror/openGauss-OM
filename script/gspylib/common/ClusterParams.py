# -*- coding:utf-8 -*-
###########################################################################################
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
# -----------------------------------------------------------------------------------------
# Description  : ClusterParams.py is used to define the parameters under the cluster label.
###########################################################################################
import re


class ClusterParams:
    """
    Cluster parameter names constants.
    """

    def __init__(self):
        pass

    CLUSTER_NAME = 'clusterName'
    NODE_NAMES = 'nodeNames'
    GAUSSDB_APP_PATH = 'gaussdbAppPath'
    GAUSSDB_LOG_PATH = 'gaussdbLogPath'
    TMP_MPPDB_PATH = 'tmpMppdbPath'
    GAUSSDB_TOOL_PATH = 'gaussdbToolPath'
    CORE_PATH = 'corePath'
    BACK_IP1S = 'backIp1s'
    ENABLE_DCF = 'enable_dcf'
    DCF_CONFIG = 'dcf_config'
    ENABLE_DSS = 'enable_dss'
    DSS_HOME = 'dss_home'
    SS_DSS_VG_NAME = 'ss_dss_vg_name'
    DSS_VG_INFO = 'dss_vg_info'
    VOTING_DISK_PATH = 'votingDiskPath'
    SHARE_DISK_DIR = 'shareDiskDir'
    DSS_SSL_ENABLE = 'dss_ssl_enable'
    SS_INTERCONNECT_TYPE = 'ss_interconnect_type'
    SS_RDMA_WORK_CONFIG = 'ss_rdma_work_config'
    ENABLE_UWAL = 'enable_uwal'
    UWAL_DISK_SIZE = 'uwal_disk_size'
    UWAL_LOG_PATH = 'uwal_log_path'
    UWAL_RPC_COMPRESSION_SWITCH = 'uwal_rpc_compression_switch'
    UWAL_RPC_FLOWCONTROL_SWITCH = 'uwal_rpc_flowcontrol_switch'
    UWAL_RPC_FLOWCONTROL_VALUE = 'uwal_rpc_flowcontrol_value'
    UWAL_ASYNC_APPEND_SWITCH = 'uwal_async_append_switch'
    UWAL_DEVICES_PATH = 'uwal_devices_path'
    PASSWORD = 'password'
    CLUSTER_TYPE = 'clusterType'

    @staticmethod
    def get_all_param_names():
        return [
            ClusterParams.CLUSTER_NAME,
            ClusterParams.NODE_NAMES,
            ClusterParams.GAUSSDB_APP_PATH,
            ClusterParams.GAUSSDB_LOG_PATH,
            ClusterParams.TMP_MPPDB_PATH,
            ClusterParams.GAUSSDB_TOOL_PATH,
            ClusterParams.CORE_PATH,
            ClusterParams.BACK_IP1S,
            ClusterParams.ENABLE_DCF,
            ClusterParams.DCF_CONFIG,
            ClusterParams.ENABLE_DSS,
            ClusterParams.DSS_HOME,
            ClusterParams.SS_DSS_VG_NAME,
            ClusterParams.DSS_VG_INFO,
            ClusterParams.VOTING_DISK_PATH,
            ClusterParams.SHARE_DISK_DIR,
            ClusterParams.DSS_SSL_ENABLE,
            ClusterParams.SS_INTERCONNECT_TYPE,
            ClusterParams.SS_RDMA_WORK_CONFIG,
            ClusterParams.ENABLE_UWAL,
            ClusterParams.UWAL_DISK_SIZE,
            ClusterParams.UWAL_LOG_PATH,
            ClusterParams.UWAL_RPC_COMPRESSION_SWITCH,
            ClusterParams.UWAL_RPC_FLOWCONTROL_SWITCH,
            ClusterParams.UWAL_RPC_FLOWCONTROL_VALUE,
            ClusterParams.UWAL_ASYNC_APPEND_SWITCH,
            ClusterParams.UWAL_DEVICES_PATH,
            ClusterParams.PASSWORD,
            ClusterParams.CLUSTER_TYPE
        ]

    FLOAT_IP_PATTERN = re.compile(r'\bfloatIp[0-9]+')
