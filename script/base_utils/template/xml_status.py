import os
import sys
import socket
import subprocess

from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue
from base_utils.os.net_util import NetUtil
from base_utils.template.xml_constant import XmlConstant


def check_illegal_character(user_put):
    for rac in DefaultValue.PATH_CHECK_LIST:
        flag = user_put.find(rac)
        if flag >= 0:
            GaussLog.printMessage("%s %s" % (user_put, XmlConstant.RESOURCE_DATA.get('invalid_character')))
            return False
    return True


def check_port(port, action='', database_port=''):
    if not str(port).isdigit():
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_num'))
        return False
    if int(port) > 65535 or int(port) < 1024:
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_port'))
        return False

    if action == 'cm':
        if port == database_port:
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('cm_port_repeat'))
            return False
        if int(port) in range(int(database_port), int(database_port) + 11):
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('cm_port_beyond'))
            return False
    return True


def check_database_dir(database_dir):
    # check illegal character
    if not check_illegal_character(database_dir):
        return False

    # check isabs path
    if not os.path.isabs(database_dir):
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_abs_dir'))
        return False

    # check path exists
    if os.path.exists(database_dir):
        files = os.listdir(database_dir)
        if len(files) != 0:
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_database_dir'))
            return False

        # check permission
        if not os.access(database_dir, os.R_OK | os.W_OK):
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('not_permission'), database_dir)
            return False
    return True


def check_ip_hostname_valid(ip, hostname):
    if not NetUtil.isIpValid(ip):
        GaussLog.printMessage("%s %s" % (ip, XmlConstant.RESOURCE_DATA.get('invalid_ip')))
        return False
    if not check_illegal_character(ip):
        return False
    if not check_illegal_character(hostname):
        return False
    return True


def check_ip_node_count():
    if len(XmlConstant.PRI_STANDBY_IP.keys()) != XmlConstant.PRI_STANDBY_COUNT:
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('ip_hostname_not_match'))
        return False
    return True


def get_ip_hostname(user_input):
    pri_standby_ip = {}
    ip_lists = []
    hostname_lists = []
    ip_hostname = user_input.split(";")
    # ip_hostname remove empty elements
    ip_hostname = [tmp for tmp in ip_hostname if tmp]
    if (len(ip_hostname) != XmlConstant.PRI_STANDBY_COUNT):
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('ip_hostname_not_match'))
        return False
    for tmp in ip_hostname:
        if len(tmp.strip().split()) != 2:
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('ip_hostname_not_match'))
            return False
        ip = str(tmp.strip().split()[0])
        hostname = str(tmp.strip().split()[1])
        if not check_ip_hostname_valid(ip, hostname):
            return False
        pri_standby_ip[ip] = hostname
        ip_lists.append(ip)
        hostname_lists.append(hostname)

    XmlConstant.PRI_STANDBY_IP = pri_standby_ip
    XmlConstant.IP_LISTS = ip_lists
    XmlConstant.HOSTNAME_LISTS = hostname_lists
    if not check_ip_node_count():
        return False
    return True


class TemplateStatus:

    def work(self):
        pass


def check_xml_isabs(xml_dir):
    if os.path.isabs(xml_dir):
        target_xml = xml_dir
    else:
        target_xml = os.path.normpath(os.path.join(XmlConstant.get_current_dir(), xml_dir))
    return target_xml


def check_xml_file_permission(target_xml):
    if os.path.exists(target_xml):
        if not os.path.isfile(target_xml):
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_xml_dir'))
            return False

        # check permission
        if not os.access(target_xml, os.R_OK | os.W_OK):
            GaussLog.printMessage("%s %s" % (XmlConstant.RESOURCE_DATA.get('not_permission'), target_xml))
            return False
    else:
        (tmp_dir, top_dir_name) = os.path.split(target_xml)
        cmd = "mkdir -p %s" % tmp_dir
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            GaussLog.printMessage("%s %s" % (XmlConstant.RESOURCE_DATA.get('mkdir_dir_failed'), tmp_dir))
            return False
    return True


def check_xml_dir_repeat(target_xml):
    cur_dir = XmlConstant.get_current_dir()
    files = []
    for tmp in XmlConstant.KEEP_FILES:
        file = os.path.normpath(os.path.join(cur_dir, tmp))
        files.append(file)
    if target_xml in files:
        GaussLog.printMessage("%s %s" % (XmlConstant.RESOURCE_DATA.get('invalid_xml_path'), target_xml))
        return False
    return True


def check_input_xml_info(xml_dir):
    # check illegal
    if not check_illegal_character(xml_dir):
        return False
    # get xml file's abs dir
    XmlConstant.TARGET_XML = check_xml_isabs(xml_dir)
    if not check_xml_file_permission(XmlConstant.TARGET_XML):
        return False
    if not check_xml_dir_repeat(XmlConstant.TARGET_XML):
        return False
    return True


class XmlStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            # 用户输入back回退到上个流程
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_xml_path')).strip()
            if user_input.lower() in ('back', 'b'):
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('not_back'))
                return XmlStatus()
            if not user_input:
                tmp_dir = os.path.join(XmlConstant.get_current_dir(), 'cluster.xml')
                if os.path.exists(tmp_dir):
                    os.remove(tmp_dir)
                XmlConstant.TARGET_XML = tmp_dir
                return DatabaseInstallStatus()
            if not check_input_xml_info(user_input):
                continue
            XmlConstant.TARGET_XML = user_input
            return DatabaseInstallStatus()


class DatabaseInstallStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_database_path')).strip()
            if user_input.lower() in ('back', 'b'):
                return XmlStatus()
            if not user_input:
                XmlConstant.OPENGAUSS_INSTALL_DIR = XmlConstant.DATABASE_INSTALL_DIR
                return DataPortStatus()
            if not check_database_dir(user_input):
                continue
            XmlConstant.OPENGAUSS_INSTALL_DIR = user_input
            return DataPortStatus()


class DataPortStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_database_port')).strip()
            if user_input.lower() in ('back', 'b'):
                return DatabaseInstallStatus()
            if not user_input:
                return PriStandbyStatus()
            if not check_port(user_input):
                continue
            XmlConstant.DATABASE_PORT = user_input
            return PriStandbyStatus()


class PriStandbyStatus(TemplateStatus):

    def work(self):
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('choose_pri_standby'))
        XmlConstant.select_option(XmlConstant.RESOURCE_DATA.get('deploy_pri_standby'),
                                  XmlConstant.RESOURCE_DATA.get('deploy_single'))

        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_pri_standby')).strip()
            if user_input.lower() in ('back', 'b'):
                return DataPortStatus()
            if not user_input:
                XmlConstant.IS_PRI_STANDBY = True
                return DdesStatus()
            if not user_input.isdigit():
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_num'))
                continue
            if user_input == "1":
                XmlConstant.IS_PRI_STANDBY = True
                return DdesStatus()
            elif user_input == "2":
                XmlConstant.IS_PRI_STANDBY = False
                return PriStandbyCountStatus()
            else:
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_character'))
                continue


class DdesStatus(TemplateStatus):

    def work(self):
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('choose_ddes'))
        XmlConstant.select_option(XmlConstant.RESOURCE_DATA.get('not_deploy'), XmlConstant.RESOURCE_DATA.get('deploy'))

        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_ddes')).strip()
            if user_input.lower() in ('back', 'b'):
                return PriStandbyStatus()
            if not user_input:
                XmlConstant.IS_DDES = False
                return CmStatus()
            if not user_input.isdigit():
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_num'))
                continue
            if user_input == "1":
                XmlConstant.IS_DDES = False
                return CmStatus()
            elif user_input == "2":
                XmlConstant.IS_DDES = True
                XmlConstant.IS_CM = True
                return DdesDssHomeStatus()
            else:
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_character'))
                continue


class DdesDssHomeStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('intput_dss_home')).strip()
            if user_input.lower() in ('back', 'b'):
                return DdesStatus()
            if not user_input:
                XmlConstant.DDES_INFO['dss_home'] = XmlConstant.DSS_HOME_DIR
                return DdesDssVgNameStatus()
            if not check_database_dir(user_input):
                continue
            XmlConstant.DDES_INFO['dss_home'] = user_input
            return DdesDssVgNameStatus()


class DdesDssVgNameStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('intput_ss_dss_vg_name')).strip()
            if user_input.lower() in ('back', 'b'):
                return DdesDssHomeStatus()
            if not user_input:
                XmlConstant.DDES_INFO['ss_dss_vg_name'] = XmlConstant.DSS_VG_NAME_DIR
                return DdesDssVgInfoStatus()
            XmlConstant.DDES_INFO['ss_dss_vg_name'] = user_input
            return DdesDssVgInfoStatus()


class DdesDssVgInfoStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_dss_vg_info')).strip()
            if user_input.lower() in ('back', 'b'):
                return DdesDssVgNameStatus()
            if not user_input:
                XmlConstant.DDES_INFO['dss_vg_info'] = XmlConstant.DSS_VG_INFO_DIR
                return DdesVotingStatus()
            XmlConstant.DDES_INFO['dss_vg_info'] = user_input
            return DdesVotingStatus()


class DdesVotingStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_voting_disk_path')).strip()
            if user_input.lower() in ('back', 'b'):
                return DdesDssVgInfoStatus()
            if not user_input:
                XmlConstant.DDES_INFO['votingDiskPath'] = XmlConstant.VOTING_DIR
                return DdesShareDiskStatus()
            XmlConstant.DDES_INFO['votingDiskPath'] = user_input
            return DdesShareDiskStatus()


class DdesShareDiskStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_share_disk_dir')).strip()
            if user_input.lower() in ('back', 'b'):
                return DdesVotingStatus()
            if not user_input:
                XmlConstant.DDES_INFO['shareDiskDir'] = XmlConstant.SHAREDISK_DIR
                return CmServerPortStatus()
            XmlConstant.DDES_INFO['shareDiskDir'] = user_input
            return CmServerPortStatus()


class CmStatus(TemplateStatus):

    def work(self):
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('choose_cm'))
        XmlConstant.select_option(XmlConstant.RESOURCE_DATA.get('deploy'), XmlConstant.RESOURCE_DATA.get('not_deploy'))

        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_cm')).strip()
            if user_input.lower() in ('back', 'b'):
                if XmlConstant.IS_DDES:
                    return DdesShareDiskStatus()
                else:
                    return DdesStatus()
            if not user_input:
                XmlConstant.IS_CM = True
                return CmServerPortStatus()
            if not user_input.isdigit():
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_num'))
                continue
            if user_input == "1":
                XmlConstant.IS_CM = True
                return CmServerPortStatus()
            elif user_input == "2":
                XmlConstant.IS_CM = False
                return PriStandbyCountStatus()
            else:
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_character'))
                continue


class CmServerPortStatus(TemplateStatus):

    def work(self):
        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('cm_port')).strip()
            if user_input.lower() in ('back', 'b'):
                if XmlConstant.IS_DDES:
                    return DdesShareDiskStatus()
                return CmStatus()
            if not user_input:
                if not check_port(XmlConstant.CM_SERVER_PORT, 'cm', XmlConstant.DATABASE_PORT):
                    continue
                return PriStandbyCountStatus()
            if not check_port(user_input, 'cm', XmlConstant.DATABASE_PORT):
                continue
            XmlConstant.CM_SERVER_PORT = user_input
            return PriStandbyCountStatus()


class PriStandbyCountStatus(TemplateStatus):

    def work(self):
        if not XmlConstant.IS_PRI_STANDBY:
            XmlConstant.PRI_STANDBY_COUNT = 1
            return PriStandbyIpStatus()

        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('max_nodes')).strip()
            if user_input.lower() in ('back', 'b'):
                if XmlConstant.IS_DDES:
                    return CmServerPortStatus()
                elif XmlConstant.IS_CM:
                    return CmServerPortStatus()
                else:
                    return PriStandbyStatus()
            if not user_input:
                XmlConstant.PRI_STANDBY_COUNT = 3
                return PriStandbyIpStatus()
            if not user_input.isdigit():
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_num'))
                continue
            if 2 <= int(user_input) <= 9:
                XmlConstant.PRI_STANDBY_COUNT = int(user_input)
                return PriStandbyIpStatus()

            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_character'))
            continue


def get_localhost_name():
    return socket.gethostname()


def get_localhost_ip():
    return socket.gethostbyname(get_localhost_name())


class PriStandbyIpStatus(TemplateStatus):

    def work(self):
        ip_lists = []
        hostname_lists = []
        if not XmlConstant.IS_PRI_STANDBY:
            hostname_lists.append(get_localhost_name())
            ip_lists.append(get_localhost_ip())
            XmlConstant.IP_LISTS = ip_lists
            XmlConstant.HOSTNAME_LISTS = hostname_lists
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('finish'))
            return

        for i in range(XmlConstant.TRIES):
            if i == 3:
                sys.exit(0)
            user_input = input(XmlConstant.RESOURCE_DATA.get('input_ip_hostname')).strip()
            if user_input.lower() in ('back', 'b'):
                return PriStandbyCountStatus()
            if not user_input:
                GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('ip_hostname_empty'))
                continue
            if not get_ip_hostname(user_input):
                continue
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('finish'))
            return
