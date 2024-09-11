# -*- coding:utf-8 -*-
###############################################################################################
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
# ---------------------------------------------------------------------------------------------
# Description  : DeviceListParams.py is used to define the parameters under the DeviceList tag.
###############################################################################################
import re


class DeviceListParams:
    """
    DeviceList parameter names and patterns constants.
    """

    def __init__(self):
        pass

    NAME = 'name'
    AZ_NAME = 'azName'
    AZ_PRIORITY = 'azPriority'
    BACK_IP1 = 'backIp1'
    SSH_IP1 = 'sshIp1'
    DATA_NUM = 'dataNum'
    DATA_PORT_BASE = 'dataPortBase'
    DATA_NODE1 = 'dataNode1'
    DATA_NODE1_SYNC_NUM = 'dataNode1_syncNum'
    CMS_NUM = 'cmsNum'
    CM_DIR = 'cmDir'
    CM_SERVER_PORT_BASE = 'cmServerPortBase'
    CM_SERVER_LISTEN_IP1 = 'cmServerListenIp1'
    CM_SERVER_HA_IP1 = 'cmServerHaIp1'
    CM_SERVER_LEVEL = 'cmServerlevel'
    CM_SERVER_LEVEL1 = 'cmServerLevel'
    CM_SERVER_RELATION = 'cmServerRelation'
    CM_SERVER_PORT_STANDBY = 'cmServerPortStandby'
    CASCADE_ROLE = 'cascadeRole'
    DATA_LISTEN_IP1 = 'dataListenIp1'
    DATA_NODE_XLOG_PATH1 = 'dataNodeXlogPath1'
    FLOAT_IP_MAP1 = 'floatIpMap1'
    DATA_PORT_STANDBY = 'dataPortStandby'
    DATA_PORT_DUMMY_STANDBY = 'dataPortDummyStandby'
    LOCAL_STREAM_IP_MAP1 = 'localStreamIpmap1'
    REMOTE_STREAM_IP_MAP1 = 'remoteStreamIpmap1'
    REMOTE_DATA_PORT_BASE = 'remotedataPortBase'

    @staticmethod
    def get_all_param_names():
        return [
            DeviceListParams.NAME,
            DeviceListParams.AZ_NAME,
            DeviceListParams.AZ_PRIORITY,
            DeviceListParams.BACK_IP1,
            DeviceListParams.SSH_IP1,
            DeviceListParams.DATA_NUM,
            DeviceListParams.DATA_PORT_BASE,
            DeviceListParams.DATA_NODE1,
            DeviceListParams.DATA_NODE1_SYNC_NUM,
            DeviceListParams.CMS_NUM,
            DeviceListParams.CM_DIR,
            DeviceListParams.CM_SERVER_PORT_BASE,
            DeviceListParams.CM_SERVER_LISTEN_IP1,
            DeviceListParams.CM_SERVER_HA_IP1,
            DeviceListParams.CM_SERVER_LEVEL,
            DeviceListParams.CM_SERVER_LEVEL1,
            DeviceListParams.CM_SERVER_RELATION,
            DeviceListParams.CM_SERVER_PORT_STANDBY,
            DeviceListParams.CASCADE_ROLE,
            DeviceListParams.DATA_LISTEN_IP1,
            DeviceListParams.DATA_NODE_XLOG_PATH1,
            DeviceListParams.FLOAT_IP_MAP1,
            DeviceListParams.DATA_PORT_STANDBY,
            DeviceListParams.DATA_PORT_DUMMY_STANDBY,
            DeviceListParams.LOCAL_STREAM_IP_MAP1,
            DeviceListParams.REMOTE_STREAM_IP_MAP1,
            DeviceListParams.REMOTE_DATA_PORT_BASE
        ]

    SYNC_NODE_PATTERN = re.compile(r'^syncNode_.*')