import os

from gspylib.common.GaussLog import GaussLog


class XmlConstant:
    IS_CHINESE = False
    IS_CM = False
    IS_DDES = False
    IS_PRI_STANDBY = False
    PRI_STANDBY_COUNT = 3
    PRI_STANDBY_IP = {}
    HOSTNAME_LISTS = []
    IP_LISTS = []
    DDES_INFO = {}
    OPENGAUSS_INSTALL_DIR = ""
    TARGET_XML = ""
    RESOURCE_DATA = None
    TRIES = 4

    DSS_PARA_INFO = ['enable_dss', 'dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name',
                     'dss_ssl_enable']
    UPDATE_DSS_PARA_INFO = ['dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name']
    CM_PARA_INFO = ['cmDir', 'cmsNum', 'cmServerPortBase', 'cmServerPortStandby', 'cmServerListenIp1',
                    'cmServerHaIp1', 'cmServerlevel', 'cmServerRelation']
    HOST_NODE_INFO = ['node1_hostname', 'node2_hostname', 'node3_hostname',
                      'node4_hostname', 'node5_hostname', 'node6_hostname',
                      'node7_hostname', 'node8_hostname', 'node9_hostname']

    DATABASE_PORT = ""
    CM_SERVER_PORT = ""
    SSH_PORTS = []

    DEFAULT_DATABASE_PORT = "15000"
    DEFAULT_CM_SERVER_PORT = "15400"

    KEEP_FILES = ['cluster_tmp.xml', 'resource_en.json', 'resource_zh.json', 'xml_template.py', '__init__.py',
                  'xml_constant,py', "xml_status.py"]

    DEFAULT_SSH_PORT = "22"

    DATABASE_INSTALL_DIR = "/opt/openGauss/install"

    DSS_HOME_DIR = "/opt/openGauss/install/dss_home"

    DSS_VG_NAME_DIR = "data"

    DSS_VG_INFO_DIR = "data:/dev/sdb,p0:/dev/sdc,p1:/dev/sdd"

    VOTING_DIR = "/dev/sde"

    SHAREDISK_DIR = "/dev/sdf"

    @staticmethod
    def get_current_dir():
        return os.path.dirname(os.path.realpath(__file__))

    @staticmethod
    def select_option(valid_str, invalid_str):
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                GaussLog.printMessage(">> " + str(i) + ") " + valid_str)
            else:
                GaussLog.printMessage("   " + str(i) + ") " + invalid_str)

        GaussLog.printMessage("-------------------------------")
