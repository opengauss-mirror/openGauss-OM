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
# Description  : dorado_disaster_recovery_failover.py is utility for
# standby cluster failover to primary cluster.


from gspylib.common.Common import DefaultValue
from gspylib.common.ErrorCode import ErrorCode
from impl.dorado_disaster_recovery.ddr_base import DoradoDisasterRecoveryBase
from impl.dorado_disaster_recovery.ddr_constants import DoradoDisasterRecoveryConstants

class DisasterRecoveryFailoverHandler(DoradoDisasterRecoveryBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.log("Start dorado disaster recovery failover.")
        self.check_action_and_mode()
        step = self.check_dorado_failover_workable(check_type_step=3, check_status_step=0)
        self.check_is_under_upgrade()
        self.init_cluster_conf()
        if self.judge_ss_cluster_role() != "disaster_standby":
            self.logger.log("Failover operation for SS dual_cluster only support disaster_standby cluster.")
            return
        self.params.disaster_type = DefaultValue.get_ss_disaster_mode()
        if self.params.disaster_type:
            self.logger.log("Successfully get the para disaster_type: %s." % self.params.disaster_type)
        try:
            self.dorado_failover_single_inst(step, DoradoDisasterRecoveryConstants.ACTION_FAILOVER)
            self.update_dorado_info("cluster", "normal")
            self.clean_step_file()
        except Exception as error:
            self.update_dorado_info("cluster", "promote_fail")
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51632"] % "centralize failover" + "Error:%s" % error)
        self.clean_streaming_dir()
        self.logger.log("Successfully do dorado disaster recovery failover.")

    def check_dorado_failover_workable(self, check_type_step=0, check_status_step=0):
        """
        Check dorado failover is workable.
        """
        self.logger.debug("dorado disaster distribute cluster failover...")
        dorado_disaster_step = self.query_dorado_step()
        if not DefaultValue.is_disaster_cluster(self.cluster_info) \
                and dorado_disaster_step < check_type_step:
            self.logger.debug("The primary dn exist, do nothing except record the result file.")
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51632"] %
                            "dorado disaster cluster failover, Because the primary cluster "
                            "does not support failover")
        cluster_normal_status = [DefaultValue.CLUSTER_STATUS_NORMAL,
                                 DefaultValue.CLUSTER_STATUS_DEGRADED]
        if dorado_disaster_step < check_status_step:
            self.init_cluster_status()
        self.parse_cluster_status()
        if dorado_disaster_step < check_status_step:
            self.check_cluster_status(cluster_normal_status)
        return dorado_disaster_step

