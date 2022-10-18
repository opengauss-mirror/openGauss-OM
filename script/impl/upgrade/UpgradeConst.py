#-*- coding:utf-8 -*-

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
# Const values
#############################################################################

UPGRADE_TIMEOUT_CLUSTER_START = 600
UPGRADE_TIMEOUT_CLUSTER_STOP = 1800

#because the number is float, so notice the recision
DELTA_NUM = 0.000001
#external action
ACTION_CHOSE_STRATEGY = "chose-strategy"
ACTION_INPLACE_UPGRADE = "inplace-binary-upgrade"
ACTION_UPGRADE_CM = "upgrade-cm"
#grey upgrade
ACTION_SMALL_UPGRADE = "small-binary-upgrade"
ACTION_LARGE_UPGRADE = "large-binary-upgrade"
# ACTION_ONLINE_UPGRADE is used for record online upgrade step,
# not really provide this action outside to user,
# if use ACTION_BINARY_UPGRADE, it will confuse with off-line binary upgrade
ACTION_AUTO_UPGRADE = "auto-upgrade"
ACTION_AUTO_ROLLBACK = "auto-rollback"
ACTION_COMMIT_UPGRADE = "commit-upgrade"

############################################################
# function key
# ---------------------------------------------------------
ACTION_SYNC_CONFIG = "sync_config"
ACTION_RELOAD_CMAGENT = "reload_cmagent"
ACTION_RELOAD_CMSERVER = "reload_cmserver"
ACTION_SWITCH_PROCESS = "switch_little_effect_process"
ACTION_SWITCH_CMSERVER = "switch_server"
ACTION_SWITCH_BIN = "switch_bin"
ACTION_COPY_CERTS = "copy_certs"
ACTION_CLEAN_INSTALL_PATH = "clean_install_path"

ACTION_TOUCH_INIT_FILE = "touch_init_file"
ACTION_CHECK_VERSION = "check_version"

ACTION_BACKUP_CONFIG = "backup_config"
ACTION_RESTORE_CONFIG = "restore_config"
ACTION_INPLACE_BACKUP = "inplace_backup"
ACTION_INPLACE_RESTORE = "inplace_restore"
ACTION_CHECK_GUC = "check_guc"
ACTION_BACKUP_HOTPATCH = "backup_hotpatch"
ACTION_ROLLBACK_HOTPATCH = "rollback_hotpatch"
ACTION_UPGRADE_SQL_FOLDER = "prepare_upgrade_sql_folder"
ACTION_BACKUP_OLD_CLUSTER_DB_AND_REL = "backup_old_cluster_db_and_rel"
ACTION_UPDATE_CATALOG = "update_catalog"
ACTION_BACKUP_OLD_CLUSTER_CATALOG_PHYSICAL_FILES = \
    "backup_old_cluster_catalog_physical_files"
ACTION_RESTORE_OLD_CLUSTER_CATALOG_PHYSICAL_FILES = \
    "restore_old_cluster_catalog_physical_files"
ACTION_CLEAN_OLD_CLUSTER_CATALOG_PHYSICAL_FILES = \
    "clean_old_cluster_catalog_physical_files"
ACTION_REPLACE_PG_PROC_FILES = "replace_pg_proc_files"
ACTION_CREATE_PG_PROC_MAPPING_FILE = "create_pg_proc_mapping_file"
ACTION_CREATE_NEW_CSV_FILE = "create_new_csv_file"
ACTION_RESTORE_DYNAMIC_CONFIG_FILE = "restore_dynamic_config_file"
ACTION_GREY_SYNC_GUC = "grey_sync_guc"
ACTION_GREY_UPGRADE_CONFIG_SYNC = "grey_upgrade_config_sync"
ACTION_SWITCH_DN = "switch_dn"
ACTION_GET_LSN_INFO = "get_lsn_info"
ACTION_GREY_RESTORE_CONFIG = "grey_restore_config"
ACTION_GREY_RESTORE_GUC = "grey_restore_guc"
ACTION_CLEAN_CONF_BAK_OLD = "clean_conf_bak_old"
ACTION_SET_GUC_VALUE = "setGucValue"
ACTION_CLEAN_CM = "clean_cm_inst"
ACTION_RESTORE_GLOBAL_RELMAP_FILE = "restore_global_relmap_file"
ACTION_CLEAN_TMP_GLOBAL_RELMAP_FILE = "clean_tmp_global_relmap_file"
ACTION_BACKUP_GLOBAL_RELMAP_FILE = "backup_global_relmap_file"

OPTION_PRECHECK = "before"
OPTION_POSTCHECK = "after"
INPLACE_UPGRADE_STEP_FILE = "upgrade_step.dat"
GREY_UPGRADE_STEP_FILE = "upgrade_step.csv"
CLUSTER_CNSCONF_FILE = "cluster_cnconf.json"
TMP_DYNAMIC_DN_INFO = "upgrade_gauss_dn_status.dat"
GET_LSN_SQL_FILE = "get_lsn_sql"
INPLACE_UPGRADE_FLAG_FILE = "inplace_upgrade_flag"
POSTGRESQL_CONF_BAK_OLD = "postgresql.conf.bak.old"

#step flag
BINARY_UPGRADE_NO_NEED_ROLLBACK = -2
INVALID_UPRADE_STEP = -1
# binary upgrade step
BINARY_UPGRADE_STEP_INIT_STATUS = 0
BINARY_UPGRADE_STEP_STOP_NODE = 2
BINARY_UPGRADE_STEP_BACKUP_VERSION = 3
BINARY_UPGRADE_STEP_UPGRADE_APP = 4
BINARY_UPGRADE_STEP_START_NODE = 5
BINARY_UPGRADE_STEP_PRE_COMMIT = 6

# upgrade CM component
ACTION_UPGRADE_PREPARE_UPGRADE_CM = "prepare_upgrade_cm"
ACTION_UPGRADE_CM_UPGRADE_BINARY = "upgrade_cm"
ACTION_UPGRADE_CM_ROLLBACK = "rollback_cm"

UPGRADE_BACKUP_DIR = "upgrade_cm_backup_dir"
UPGRADE_CM_DECOMPRESS_DIR = "cm_decompress_package"
UPGRADE_TMP_BACKUP_DIR = "ready_backup_cm"
UPGRADE_BACKUP_TAR_NAME = "upgrade_cm_backup.tar.gz"
UPGRADE_BINARY_LIST_FILE_NAME = "upgrade_binary_list"

# dual cluster stage
class DualClusterStage:
    """
    Dual cluster stage upgrade marking
    """
    def __init__(self):
        pass

    (STEP_UPGRADE_END,
     STEP_UPGRADE_UNFINISHED,
     STEP_UPGRADE_FINISH,
     STEP_UPGRADE_COMMIT,
     ) = list(range(0, 4))

    def __str__(self):
        pass


# grey upgrade
class GreyUpgradeStep:
    def __init__(self):
        pass

    (STEP_INIT_STATUS,
     STEP_UPDATE_CATALOG,
     STEP_SWITCH_NEW_BIN,
     STEP_UPGRADE_PROCESS,
     STEP_UPDATE_POST_CATALOG,
     STEP_PRE_COMMIT,
     STEP_BEGIN_COMMIT
     ) = range(0, 7)


BACKUP_DIR_LIST_BASE = ['global', 'pg_clog', 'pg_csnlog']
BACKUP_DIR_LIST_64BIT_XID = ['pg_multixact', 'pg_replslot', 'pg_notify',
                             'pg_subtrans', 'pg_twophase']
VALUE_OFF = ["off", "false", "0", "no"]
VALUE_ON = ["on", "true", "1", "yes"]
DN_GUC = ["upgrade_mode", "enable_stream_replication"]

CMS_GUC = ["backup_open", "install_type"]
CMA_GUC = ["upgrade_from"]

FIRST_GREY_UPGRADE_NUM = 92

UPGRADE_UNSET_NUM = 0

INST_TYPE_MAP = {-1: "undefined", 0: "cmserver", 4: "datanode", 5: "cmagent"}

CMSERVER_GUC_DEFAULT = {"enable_transaction_read_only": "on",
                        "coordinator_heartbeat_timeout": "1800",
                        "instance_failover_delay_timeout": 0,
                        "cmserver_ha_heartbeat_timeout": 8}
CMSERVER_GUC_CLOSE = {"enable_transaction_read_only": "off",
                      "coordinator_heartbeat_timeout": "0",
                      "instance_failover_delay_timeout": 40,
                      "cmserver_ha_heartbeat_timeout": 20}
CMSERVER_GUC_DEFAULT_HA = {"enable_transaction_read_only": "on",
                           "instance_failover_delay_timeout": 0,
                           "cmserver_ha_heartbeat_timeout": 8}
CMSERVER_GUC_CLOSE_HA = {"enable_transaction_read_only": "off",
                         "instance_failover_delay_timeout": 40,
                         "cmserver_ha_heartbeat_timeout": 20}
CMSERVER_GUC_GREYUPGRADE_DEFAULT = {"enable_transaction_read_only": "on"}
CMSERVER_GUC_GREYUPGRADE_CLOSE = {"enable_transaction_read_only": "off"}
# Script name
GS_UPGRADECTL = "gs_upgradectl"
# table schema and table name
UPGRADE_SCHEMA = "on_upgrade_69954349032535120"
RECORD_NODE_STEP = "record_node_step"
READ_STEP_FROM_FILE_FLAG = "read_step_from_file_flag"
RECORD_UPGRADE_DIR = "record_app_directory"
XLOG_BACKUP_INFO = "xlog_backup_info.json"
OLD = "old"
NEW = "new"
# upgrade sql sha file and sql file
UPGRADE_SQL_SHA = "upgrade_sql.sha256"
UPGRADE_SQL_FILE = "upgrade_sql.tar.gz"

ON_INPLACE_UPGRADE = "IsInplaceUpgrade"
MAX_APP_SIZE = 2000
UPGRADE_VERSION_64bit_xid = 91.208
ENABLE_STREAM_REPLICATION_VERSION = "92.149"
ENABLE_STREAM_REPLICATION_NAME = "enable_stream_replication"
RELMAP_4K_VERSION = "92.420"

# streaming cluster
GS_SECURE_FILES = "gs_secure_files"
UPGRADE_PHASE_INFO = "upgrade_phase_info"
HARD_KEY_CIPHER = "hadr.key.cipher"
HARD_KEY_RAND = "hadr.key.rand"
DISASTER_RECOVERY_GUC = "backup_open"
INSTALL_TYPE_GUC = "install_type"
REMOTE_INFO_GUC = {
    "dual-standby-streamDR": "replconninfo",
    "dual-primary-streamDR": "replconninfo"
}
LENGTH_STORAGE_INFO_LEN = 4
ACTION_CLEAN_GS_SECURE_FILES = "clean_gs_secure_files"
