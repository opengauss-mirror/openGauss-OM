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
# Description  : streaming_disaster_recovery_query.py is utility for
# query streaming disaster recovery condition.

import os

from base_utils.security.sensitive_mask import SensitiveMask
from impl.streaming_disaster_recovery.streaming_constants import StreamingConstants
from gspylib.common.Common import ClusterCommand
from impl.streaming_disaster_recovery.streaming_base import StreamingBase


class StreamingQueryHandler(StreamingBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_streaming_cluster_query_value(self, file_name):
        """
        Query infos from files.
        """
        file_path = os.path.realpath(os.path.join(self.streaming_file_dir, file_name))
        if not os.path.isfile(file_path) and file_name in [StreamingConstants.HADR_CLUSTER_STAT]:
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
        sql_check = "select 1 from pg_catalog.pg_stat_get_wal_senders() where sync_state" \
                    "='Async' and peer_role='Standby' and peer_state='Normal';"
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

    def get_max_rpo_rto(self):
        """
        Get max rpo and rto.
        """
        self.logger.log("Start check RPO & RTO.")
        rpo_sql = "SELECT current_rpo FROM dbe_perf.global_streaming_hadr_rto_and_rpo_stat;"
        rto_sql = "SELECT current_rto FROM dbe_perf.global_streaming_hadr_rto_and_rpo_stat;"
        rto_rpo_sql = rpo_sql + rto_sql
        if not self.primary_dn_ids:
            self.logger.debug("Not found primary dn in cluster, cluster status:%s, "
                              "main standby:%s." % (self.cluster_status, self.main_standby_ids))
            return "", ""
        log_info = "Execute sql [%s] on node [%s: %s] with result:%s"
        dn_instances = [inst for node in self.cluster_info.dbNodes for inst in node.datanodes
                        if inst.instanceId in self.primary_dn_ids]
        if dn_instances:
            status, output = ClusterCommand.remoteSQLCommand(
                rto_rpo_sql, self.user, dn_instances[0].hostname, dn_instances[0].port)
            if status == 0 and output:
                try:
                    rets = output.strip().split('\n')
                    length = len(rets) // 2
                    rpo_list = [int(i) for i in rets[:length]]
                    rto_list = [int(j) for j in rets[length:]]
                    max_rpo, max_rto = str(max(rpo_list)), str(max(rto_list))
                except ValueError:
                    return "", ""
                self.logger.debug("Successfully get max rpo:%s, rto:%s, output:%s"
                                  % (max_rpo, max_rto, ','.join(output.split('\n'))))
                return max_rpo, max_rto
            else:
                self.logger.debug(log_info % (rto_rpo_sql, dn_instances[0].hostname,
                                              dn_instances[0].port, ','.join(output.split('\n'))))
        return "", ""

    def run(self):
        self.logger.log("Start streaming disaster query.")
        cluster_info = self.query_cluster_info()
        if cluster_info:
            self.parse_cluster_status(current_status=cluster_info)
        self.check_is_under_upgrade()
        check_cluster_stat = self.get_streaming_cluster_query_value(
            StreamingConstants.HADR_CLUSTER_STAT)
        archive_status = self.check_archive(check_cluster_stat, self.cluster_status)
        recovery_status = self.check_recovery(check_cluster_stat, self.cluster_status)
        hadr_cluster_stat = archive_status or recovery_status or check_cluster_stat

        hadr_failover_stat = self.get_streaming_cluster_query_value(
            StreamingConstants.HADR_FAILOVER_STAT)
        hadr_switchover_stat = self.get_streaming_cluster_query_value(
            StreamingConstants.HADR_SWICHOVER_STAT)
        if hadr_cluster_stat != "promote":
            hadr_failover_stat = ""
        if hadr_cluster_stat != "switchover":
            hadr_switchover_stat = ""

        self.logger.debug("Start check max rpo and rto.")
        max_rpo, max_rto = self.get_max_rpo_rto()
        self.logger.debug("Finished check max rpo and rto.")
        values = dict()
        values["hadr_cluster_stat"] = hadr_cluster_stat
        values["hadr_failover_stat"] = hadr_failover_stat
        values["hadr_switchover_stat"] = hadr_switchover_stat
        values["RPO"] = max_rpo
        values["RTO"] = max_rto
        self.logger.log("Successfully executed streaming disaster "
                        "recovery query, result:\n%s" % values)
