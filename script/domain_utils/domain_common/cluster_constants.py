
class ClusterConstants:
    TOOL_PATH_ENV = "GPHOME"


    # default GPHOME
    CLUSTER_TOOL_PATH = "/opt/huawei/wisequery"
    # gauss log dir
    GAUSSDB_DIR = "/var/log/gaussdb"
    # dss home
    DSS_ROOT_HOME = "/opt/huawei/dss_root_home"
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
    GS_CHECKOS_LOG_FILE = "gs_checkos.log"
    GS_CHECKSE_LOG_FILE = "gs_checkse.log"
    GS_PREUPGRADECHK_LOG_FILE = "gs_preupgradechk.log"

    MPPRC_WHITE_LIST = ["ELK_CONFIG_DIR", "ELK_SYSTEM_TABLESPACE","MPPDB_ENV_SEPARATE_PATH", "GPHOME", "PATH",
            "LD_LIBRARY_PATH", "PYTHONPATH", "GAUSS_WARNING_TYPE", "GAUSSHOME", "HOST_IP", "SSH_AGENT_PID", "SSH_AUTH_SOCK",
            "S3_CLIENT_CRT_FILE", "GAUSS_VERSION", "PGHOST", "GS_CLUSTER_NAME", "GAUSSLOG",
            "GAUSS_ENV", "KRB5_CONFIG", "PGKRBSRVNAME", "KRBHOSTNAME", "ETCD_UNSUPPORTED_ARCH", "UNPACKPATH",
            "PGDATA", "COREPATH", "PGDATABASE", "PGPORT", "IP_TYPE", "LC_ALL", "PYTHONIOENCODING",
            "KRB_HOME", "KRB5_KDC_PROFILE", "KRB5RCACHETYPE", "MPPDB_KRB5_FILE_PATH",
            "ENABLE_DSS", "DSS_HOME", "DSS_SSL", "VGNAME", "DSS_MAINTAIN", "ENABLE_HUGEBIN", "RDMA_TYPE", "RDMA_CONFIG",
            "AGENTPATH", "AGENTLOGPATH", "WHITELIST_ENV", "OPENSSL_CONF"
        ]