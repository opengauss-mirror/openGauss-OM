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
# Description  : dorado_disaster_recovery_query.py is utility for
# query dorado disaster recovery condition.

import os

from base_utils.security.sensitive_mask import SensitiveMask
from impl.dorado_disaster_recovery.ddr_constants import DoradoDisasterRecoveryConstants
from gspylib.common.Common import ClusterCommand
from impl.dorado_disaster_recovery.ddr_base import DoradoDisasterRecoveryBase


class DoradoQueryHandler(DoradoDisasterRecoveryBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_ddr_cluster_query_value(self, file_name):
        """
        Query infos from files.
        """
        file_path = os.path.realpath(os.path.join(self.dorado_file_dir, file_name))
        if not os.path.isfile(file_path) and file_name in [DoradoDisasterRecoveryConstants.DDR_CLUSTER_STAT]:
            return "normal"
        if not os.path.isfile(file_path):
            return "0%"
        with open(file_path, 'r') as read_file:
            value = read_file.read().strip()
            return value

    def check_archive(self, former_status, cluster_status):
        """
        Check for archive.
        """
        self.logger.log("Start check archive.")
        if former_status.strip() not in ["archive", "archive_fail"]:
            self.logger.debug("Ignore for status:%s" % former_status)
            return
        archive_status = "archive_fail"
        if cluster_status.lower() not in ["normal", "degraded"]:
            self.logger.debug("Cluster status:%s,archive fail." % cluster_status)
            return archive_status
        if self.main_standby_ids or (not self.primary_dn_ids):
            self.logger.debug("Ignore update archive for disaster_standby cluster.")
            return archive_status
        sql_check = "select * from pg_catalog.pg_stat_get_wal_senders();"
        dn_instances = [inst for node in self.cluster_info.dbNodes for inst in node.datanodes
                        if inst.instanceId in self.primary_dn_ids]
        self.logger.debug("Check archive with cmd:%s." % sql_check)
        if dn_instances:
            status, output = ClusterCommand.remoteSQLCommand(
                sql_check, self.user, dn_instances[0].hostname,
                dn_instances[0].port)
            if status == 0 and output and output.strip():
                archive_status = "archive"
                self.logger.debug("Successfully check archive, results:%s." %
                                  SensitiveMask.mask_pwd(output))
                return archive_status
            elif status == 0 and not output.strip():
                self.logger.debug("Check archive fail.")
                return archive_status
            else:
                self.logger.debug("Check archive status:%s, output:%s."
                                  % (status, output))
        self.logger.debug("Check archive result:%s." % archive_status)
        return archive_status

    def check_recovery(self, former_status, cluster_status="normal"):
        """
        Check for recovery.
        """
        self.logger.log("Start check recovery.")
        if former_status.strip() not in ["recovery", "recovery_fail"]:
            self.logger.debug("Ignore for check recovery status:%s" % former_status)
            return
        recovery_status = "recovery_fail"
        if cluster_status.lower() not in ["normal", "degraded"]:
            self.logger.debug("Cluster status:%s,recovery fail." % cluster_status)
            return recovery_status
        if self.primary_dn_ids or (not self.main_standby_ids):
            self.logger.debug("Ignore update recovery for primary cluster.")
            return recovery_status
        return "recovery"

    def run(self):
        self.logger.log(DoradoDisasterRecoveryConstants.TASK_START_MSG % 
                            (self.params.disaster_type, self.params.task))
        cluster_info = self.query_cluster_info()
        if cluster_info:
            self.parse_cluster_status(current_status=cluster_info)
        self.check_is_under_upgrade()
        check_cluster_stat = self.get_ddr_cluster_query_value(
            DoradoDisasterRecoveryConstants.DDR_CLUSTER_STAT)
        archive_status = self.check_archive(check_cluster_stat, self.cluster_status)
        recovery_status = self.check_recovery(check_cluster_stat, self.cluster_status)
        ddr_cluster_stat = archive_status or recovery_status or check_cluster_stat

        ddr_failover_stat = self.get_ddr_cluster_query_value(
            DoradoDisasterRecoveryConstants.DDR_FAILOVER_STAT)
        ddr_switchover_stat = self.get_ddr_cluster_query_value(
            DoradoDisasterRecoveryConstants.DDR_SWITCHOVER_STAT)
        if ddr_cluster_stat != "promote":
            ddr_failover_stat = ""
        if ddr_cluster_stat != "switchover":
            ddr_switchover_stat = ""

        self.logger.debug("Start check max rpo and rto.")
        self.logger.debug("Finished check max rpo and rto.")
        values = dict()
        values["ddr_cluster_stat"] = ddr_cluster_stat
        values["ddr_failover_stat"] = ddr_failover_stat
        values["ddr_switchover_stat"] = ddr_switchover_stat
        self.logger.log(DoradoDisasterRecoveryConstants.TASK_FINISH_MSG % 
                            (self.params.disaster_type, self.params.task) + 
                            "\nresult:\n%s" % values)

