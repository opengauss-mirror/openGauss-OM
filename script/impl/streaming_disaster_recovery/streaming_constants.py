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
# Description  : streaming_constants.py is utility for defining constants
# of streaming disaster recovery.
#############################################################################


class StreamingConstants:

    # streaming files
    STREAMING_LOG_FILE = "gs_sdr.log"
    STREAMING_FILES_DIR = 'streaming_cabin'
    STREAMING_CLUSTER_STATUS_TMP_FILE = "cluster_state_tmp"
    WAL_KEEP_SEGMENTS = ".wal_keep_segments_record"
    STREAMING_CLUSTER_CONF_RECORD = "cluster_conf_record"
    GS_SECURE_FILES = "gs_secure_files"
    HADR_KEY_CIPHER = "hadr.key.cipher"
    HADR_KEY_RAND = "hadr.key.rand"
    STREAM_SWITCHOVER_STATE = ".switchover_cluster_state"
    MAX_TERM_RECORD = ".max_term_record"
    PROCESS_LOCK_FILE = 'streaming_lock_'
    STREAMING_CONFIG_XML = "streaming_config.xml"
    GUC_BACKUP_FILE = ".streaming_guc_backup"
    CLUSTER_USER_RECORD = ".cluster_user_record"

    ACTION_START = "start"
    ACTION_SWITCHOVER = "switchover"
    ACTION_FAILOVER = "failover"

    ACTION_ESTABLISH = "establish"

    # streaming query temp file
    HADR_CLUSTER_STAT = ".hadr_cluster_stat"
    HADR_FAILOVER_STAT = ".hadr_failover_stat"
    HADR_SWICHOVER_STAT = ".hadr_switchover_stat"
    HADR_ESTABLISH_STAT = ".hadr_establish_stat"

    STREAM_DISTRIBUTE_ACTION = "distribute_stream_failover"
    SWITCH_ENABLE_READ_ONLY_FILE = ".switch_readonly_stat_file"

    # GUC CHANGE MAP
    GUC_CHANGE_MAP = {"most_available_sync": "on", "synchronous_commit": "on"}

    # params in json file for each module
    STREAMING_JSON_PARAMS = {
        "start": ["localClusterConf", "remoteClusterConf"],
        "stop": ["localClusterConf", "remoteClusterConf"],
        "switchover": [],
        "failover": [],
        "query": []
    }

    # step file of each module
    STREAMING_STEP_FILES = {
        "start_primary": ".streaming_start_primary.step",
        "start_standby": ".streaming_start_standby.step",
        "stop": ".streaming_stop.step",
        "switchover_primary": ".streaming_switchover_primary.step",
        "switchover_standby": ".streaming_switchover_standby.step",
        "failover": ".streaming_failover.step",
        "query": ".streaming_query.step",
    }
    # task need check process is exist
    TASK_EXIST_CHECK = ["start", "stop", "switchover", "failover"]

    # default values
    MAX_WAL_KEEP_SEGMENTS = 16384
    MAX_REPLICATION_NUMS = 8
    MAX_BUILD_TIMEOUT = 1209600
    STANDBY_START_TIMEOUT = 3600 * 24 * 7
    CHECK_PROCESS_WAIT_TIME = 3

    # backup open key
    BACKUP_OPEN = "/%s/CMServer/backup_open"

    # log remark
    LOG_REMARK = "-" * 80
