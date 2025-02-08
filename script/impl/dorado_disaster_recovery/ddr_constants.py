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
# Description  : ddr_constants.py is utility for defining constants
# of dorado disaster recovery.
#############################################################################


class DoradoDisasterRecoveryConstants:

    # dorado files
    DDR_LOG_FILE = "gs_ddr.log"
    DDR_FILES_DIR = 'ddr_cabin'
    DDR_CLUSTER_STATUS_TMP_FILE = "cluster_state_tmp"

    DDR_CLUSTER_CONF_RECORD = "cluster_conf_record"

    PROCESS_LOCK_FILE = 'ddr_lock_'
    DDR_CONFIG_XML = "ddr_config.xml"
    GUC_BACKUP_FILE = ".ddr_guc_backup"

    ACTION_START = "start"
    ACTION_SWITCHOVER = "switchover"
    ACTION_FAILOVER = "failover"
    ACTION_ESTABLISH = "establish"

    # dorado query temp file
    DDR_CLUSTER_STAT = ".ddr_cluster_stat"
    DDR_FAILOVER_STAT = ".ddr_failover_stat"
    DDR_SWITCHOVER_STAT = ".ddr_switchover_stat"
    DDR_ESTABLISH_STAT = ".ddr_establish_stat"

    DDR_DISTRIBUTE_ACTION = "distribute_dorado_failover"

    # GUC CHANGE MAP
    GUC_CHANGE_MAP = {}

    # step file of each module
    DDR_STEP_FILES = {
        "start_primary": ".ddr_start_primary.step",
        "start_standby": ".ddr_start_standby.step",
        "stop": ".ddr_stop.step",
        "switchover_primary": ".ddr_switchover_primary.step",
        "switchover_standby": ".ddr_switchover_standby.step",
        "failover": ".ddr_failover.step",
        "query": ".ddr_query.step",
    }
    # task need check process is exist
    TASK_EXIST_CHECK = ["start", "stop", "switchover", "failover"]

    # default values
    MAX_BUILD_TIMEOUT = 1209600
    STANDBY_START_TIMEOUT = 3600 * 24 * 7
    CHECK_PROCESS_WAIT_TIME = 3

    # log remark
    LOG_REMARK = "-" * 80

    START_MSG = "Please ensure that the \"Remote Replication Pairs\" configured correctly "\
            "between the primary cluster and the disaster recovery cluster, "\
            "with Replication Mode in \"Synchronous\" state.\n" \
            "Ready to move on (yes/no)? "
    
    SWITCHOVER_MSG = "Please restore the original \"Remote Replication Pairs\" correctly on "\
            "the storage management interface.\n"\
            "And check and grant appropriate permissions to the corresponding device files.\n"\
            "After completing these steps, start the cluster manually !"

    PRIMARY_MSG = "Please ensure that the \"Remote Replication Pairs\" configured correctly, "\
            "and check the \"Local Resource Role\" is Primary."\
            "Ready to move on (yes/no)? "
    
    STANDBY_MSG = "Please manually switchover the primary and secondary replication relationship "\
            "of the \"Remote Replication Pairs\" in Device Manager, "\
            "and ensure the \"Local Resource Role\" is Secondary."\
            "Ready to move on (yes/no)? "

