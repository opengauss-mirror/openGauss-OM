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
# Description  : streaming_disaster_recovery_failover.py is utility for
# standby cluster failover to primary cluster.


from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from impl.streaming_disaster_recovery.streaming_base import StreamingBase


class StreamingFailoverHandler(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.log("Start streaming disaster failover.")
        self.check_action_and_mode()
        step = self.check_streaming_failover_workable(check_type_step=3, check_status_step=0)
        self.check_is_under_upgrade()
        self.init_cluster_conf()
        try:
            self.streaming_failover_single_inst(step)
            self.update_streaming_info("cluster", "normal")
            self.clean_step_file()
        except Exception as error:
            self.update_streaming_info("cluster", "promote_fail")
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "centralize failover" + "Error:%s" % error)
        finally:
            self.remove_cluster_maintance_file()
        self.clean_streaming_dir()
        self.logger.log("Successfully do streaming disaster recovery failover.")

    def check_streaming_failover_workable(self, check_type_step=0, check_status_step=0):
        """
        Check streaming failover is workable.
        """
        self.logger.debug("Streaming disaster distribute cluster failover...")
        stream_disaster_step = self.query_streaming_step()
        if not DefaultValue.is_disaster_cluster(self.cluster_info) \
                and stream_disaster_step < check_type_step:
            self.logger.debug("The primary dn exist, do nothing except record the result file.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "streaming disaster cluster failover, Because the primary cluster "
                            "does not support failover")
        cluster_normal_status = [DefaultValue.CLUSTER_STATUS_NORMAL,
                                 DefaultValue.CLUSTER_STATUS_DEGRADED]
        if stream_disaster_step < check_status_step:
            self.init_cluster_status()
        self.parse_cluster_status()
        if stream_disaster_step < check_status_step:
            self.check_cluster_status(cluster_normal_status)
        return stream_disaster_step
