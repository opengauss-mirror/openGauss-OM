
class ClusterConstants:
    TOOL_PATH_ENV = "GPHOME"

    # default GPHOME
    CLUSTER_TOOL_PATH = "/opt/huawei/wisequery"
    # gauss log dir
    GAUSSDB_DIR = "/var/log/gaussdb"
    # gs
    GS_VIRTULIP_LOG_PATH = "/var/log/gs_virtualip"
    # env file
    HOME_USER_BASHRC = "/home/%s/.bashrc"
    ETC_PROFILE = "/etc/profile"
    BASHRC = "~/.bashrc"

    DEV_NULL = "/dev/null"
    TOP_DIR_FILE = "/etc/topDirPath.dat"

    # env parameter
    ENV_CLUSTERCONFIG = "CLUSTERCONFIGFILE"

    # action log file name
    DEFAULT_LOG_FILE = "gaussdb.log"
    LOCAL_LOG_FILE = "gs_local.log"
    PREINSTALL_LOG_FILE = "gs_preinstall.log"
    DEPLOY_LOG_FILE = "gs_install.log"
    REPLACE_LOG_FILE = "gs_replace.log"
    UNINSTALL_LOG_FILE = "gs_uninstall.log"
    OM_LOG_FILE = "gs_om.log"
    UPGRADE_LOG_FILE = "gs_upgradectl.log"
    CONTRACTION_LOG_FILE = "gs_shrink.log"
    DILATAION_LOG_FILE = "gs_expand.log"
    UNPREINSTALL_LOG_FILE = "gs_postuninstall.log"
    GS_CHECKPERF_LOG_FILE = "gs_checkperf.log"
    GS_BACKUP_LOG_FILE = "gs_backup.log"
    GS_COLLECTOR_LOG_FILE = "gs_collector.log"
    GS_COLLECTOR_CONFIG_FILE = "./gspylib/etc/conf/gs_collector.json"
    GS_COLLECTOR_CONFIG_FILE_CENTRALIZED = "./gspylib/etc/conf/centralized/gs_collector.json"
    LCCTL_LOG_FILE = "gs_lcctl.log"
    RESIZE_LOG_FILE = "gs_resize.log"
    HOTPATCH_LOG_FILE = "gs_hotpatch.log"

