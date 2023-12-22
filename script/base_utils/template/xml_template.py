#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
# Description  : xml_template is generate XML template file
#############################################################################

import os
import re
import sys
import subprocess
import json
import socket
import xml.etree.ElementTree as ET

from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue
from base_utils.os.net_util import NetUtil

DSS_PARA_INFO = ['enable_dss', 'dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name',
                 'dss_ssl_enable']
UPDATE_DSS_PARA_INFO = ['dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir']
CM_PARA_INFO = ['cmDir', 'cmsNum', 'cmServerPortBase', 'cmServerPortStandby', 'cmServerListenIp1',
                'cmServerHaIp1', 'cmServerlevel', 'cmServerRelation']
HOST_NODE_INFO = ['node1_hostname', 'node2_hostname', 'node3_hostname', 
                  'node4_hostname', 'node5_hostname', 'node6_hostname', 
                  'node7_hostname', 'node8_hostname', 'node9_hostname']

DATABASE_PORT = "15000"
CM_SERVER_PORT = "15400"

KEEP_FILES = ['cluster_tmp.xml', 'resource_en.json', 'resource_zh.json', 'xml_template.py', '__init__.py']


def get_current_dir():
    return os.path.dirname(os.path.realpath(__file__))

class GenerateTemplate:

    def __init__(self):
        """
        function: constructor
        """
        self.is_chinese = False
        self.is_cm = False
        self.is_ddes = False
        self.is_pri_standby = False
        self.pri_standby_count = 3
        self.pri_standby_ip = {}
        self.hostname_lists = []
        self.ip_dict = {}
        self.ip_lists = []
        self.ddes_info = {}
        self.tries = 4
        self.database_port = ""
        self.cm_server_port = ""
        self.opengauss_install_dir = ""
        self.target_xml = ""
        self.tree = ET.ElementTree()
        self.root = None
        self.xml_file_path = ""
        self.logger = None
        self.logfile = ""
        self.dss_home = ""
        self.cm_info = {}
        self.cluster_info = {}

    def check_illegal_character(self, user_put):
        for rac in DefaultValue.PATH_CHECK_LIST:
            flag = user_put.find(rac)
            if flag >= 0:
                self.logger.log("%s %s" % (user_put, resource_data.get('invalid_path')))
                return False
        return True

    def check_xml_file(self, xml_dir):
        # check illegal
        if not self.check_illegal_character(xml_dir):
            return False
        if os.path.isabs(xml_dir):
            self.target_xml = xml_dir
        else:
            self.target_xml = os.path.normpath(os.path.join(get_current_dir(), xml_dir))

        if os.path.exists(self.target_xml):
            if not os.path.isfile(self.target_xml):
                self.logger.log(resource_data.get('invalid_xml_dir'))
                return False

            # check permission
            if not os.access(self.target_xml, os.R_OK | os.W_OK):
                self.logger.log("%s %s" % (resource_data.get('not_permission'), xml_dir))
                return False
        else:
            (tmp_dir, top_dir_name) = os.path.split(self.target_xml)
            cmd = "mkdir -p %s" % tmp_dir
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.log("%s %s" % (resource_data.get('mkdir_dir_failed'), tmp_dir))
                return False
        return True

    def check_xml_dir_repeat(self):
        cur_dir = get_current_dir()
        files = []
        for tmp in KEEP_FILES:
            file = os.path.normpath(os.path.join(cur_dir, tmp))
            files.append(file)
        if self.target_xml in files:
            self.logger.log("%s %s" % (resource_data.get('invalid_xml_path'), self.target_xml))
            return False
        else:
            return True

    def check_input_xml_info(self):
        user_input = input(resource_data.get('input_xml_path')).strip()
        if not user_input:
            tmp_dir = os.path.join(get_current_dir(), 'cluster.xml')
            if os.path.exists(tmp_dir):
                os.remove(tmp_dir)
            self.target_xml = tmp_dir
            return True
        if not self.check_xml_file(user_input):
            return False
        if not self.check_xml_dir_repeat():
            return False
        return True
        
    def check_database_dir(self, database_dir):
        # check illegal character
        if not self.check_illegal_character(database_dir):
            return False
        
        # check isabs path
        if not os.path.isabs(database_dir):
            self.logger.log(resource_data.get('invalid_abs_dir'))
            return False

        # check path exists
        if os.path.exists(database_dir):
            files = os.listdir(database_dir)
            if len(files) != 0:
                self.logger.log(resource_data.get('invalid_database_dir'))
                return False

            # check permission
            if not os.access(database_dir, os.R_OK | os.W_OK):
                self.logger.log("%s %s" % (resource_data.get('not_permission'), database_dir))
                return False
        return True
    
    def check_input_database_install_dir(self):
        user_input = input(resource_data.get('input_database_path')).strip()
        if not user_input:
            self.opengauss_install_dir = "/opt/openGauss/install"
            return True
        elif not self.check_database_dir(user_input):
            return False
        else:
            self.opengauss_install_dir = user_input
            return True
    
    def check_input_database_port(self):
        user_input = input(resource_data.get('input_database_port')).strip()
        if not user_input:
            self.database_port = DATABASE_PORT
            return True
        elif not self.check_port(user_input):
            return False
        else:
            self.database_port = user_input
            return True

    def check_port(self, port, action=''):
        if not str(port).isdigit():
            self.logger.log(resource_data.get('invalid_num'))
            return False
        if int(port) > 65535 or int(port) < 0:
            self.logger.log(resource_data.get('invalid_port'))
            return False

        if action == 'cm':
            if port == self.database_port:
                self.logger.log(resource_data.get('cm_port_repeat'))
                return False
        return True

    def check_dss_home(self):
        user_input = input(resource_data.get('intput_dss_home')).strip()
        if not user_input:
            self.ddes_info['dss_home'] = "/opt/openGauss/install/dss_home"
            return True
        elif not self.check_database_dir(user_input):
            return False
        else:
            self.ddes_info['dss_home'] = user_input
            return True

    def check_dss_vg_info(self):
        user_input = input(resource_data.get('input_dss_vg_info')).strip()
        if not user_input:
            self.ddes_info['dss_vg_info'] = "data:/dev/sdb,p0:/dev/sdc,p1:/dev/sdd"
            return True
        else:
            self.ddes_info['dss_vg_info'] = user_input
            return True

    def check_voting_disk_path(self):
        user_input = input(resource_data.get('input_voting_disk_path')).strip()
        if not user_input:
            self.ddes_info['votingDiskPath'] = "/dev/sde"
            return True
        else:
            self.ddes_info['votingDiskPath'] = user_input
            return True

    def check_share_disk_dir(self):
        user_input = input(resource_data.get('input_share_disk_dir')).strip()
        if not user_input:
            self.ddes_info['shareDiskDir'] = "/dev/sdf"
            return True
        else:
            self.ddes_info['shareDiskDir'] = user_input
            return True

    def check_input_cm_server_port(self):
        user_input = input(resource_data.get('cm_port')).strip()
        if not user_input:
            self.cm_server_port = DATABASE_PORT
            return True
        elif not self.check_port(user_input, 'cm'):
            return False
        else:
            self.cm_server_port = user_input
            return True

    def check_ip_node_count(self):
        if len(self.pri_standby_ip.keys()) != self.pri_standby_count:
            self.logger.log(resource_data.get('ip_hostname_not_match'))
            return False
        return True

    def get_ip_hostname(self, user_input):
        self.pri_standby_ip = {}
        self.ip_lists = []
        self.hostname_lists = []
        ip_hostname = user_input.split(";")
        for tmp in ip_hostname:
            if tmp:
                if len(tmp.strip().split()) != 2:
                    self.logger.log(resource_data.get('ip_hostname_not_match'))
                    return False
                ip = str(tmp.strip().split()[0])
                hostname = str(tmp.strip().split()[1])
                if not self.check_ip_hostname_valid(ip, hostname):
                    return False
                self.pri_standby_ip[ip] = hostname
                self.ip_lists.append(ip)
                self.hostname_lists.append(hostname)

        if not self.check_ip_node_count():
            return False
        return True

    def check_ip_hostname_valid(self, ip, hostname):
        if not NetUtil.isIpValid(ip):
            self.logger.log("%s %s" % (ip, resource_data.get('invalid_ip')))
            return False
        if not self.check_illegal_character(ip):
            return False
        if not self.check_illegal_character(hostname):
            return False
        return True

    @staticmethod
    def get_localhost_name():
        return socket.gethostname()

    @staticmethod
    def get_localhost_ip():
        return socket.gethostbyname(GenerateTemplate.get_localhost_name())

    def check_input_pri_standby_count(self):
        if not self.is_pri_standby:
            self.pri_standby_count = 1
            return True
        user_input = input(resource_data.get('max_nodes')).strip()
        if not user_input:
            self.pri_standby_count = 3
            return True
        elif not user_input.isdigit():
            self.logger.log(resource_data.get('invalid_num'))
            return False
        elif 2 <= int(user_input) <= 9:
            self.pri_standby_count = int(user_input)
            return True
        else:
            self.logger.log(resource_data.get('invalid_character'))
            return False

    def check_input_pri_standby_ip(self):
        self.ip_lists = []
        self.hostname_lists = []
        if not self.is_pri_standby:
            self.ip_lists.append(GenerateTemplate.get_localhost_ip())
            self.hostname_lists.append(GenerateTemplate.get_localhost_name())
            return True
        user_input = input(resource_data.get('input_ip_hostname')).strip()
        if not user_input:
            self.logger.log(resource_data.get('ip_hostname_empty'))
            return False
        if not self.get_ip_hostname(user_input):
            return False
        return True

    def check_input_chinese(self):
        user_input = input(resource_data.get('input_chinese')).strip()
        if not user_input:
            self.is_chinese = True
            return True
        if user_input == "1":
            self.is_chinese = True
            return True
        elif user_input == "2":
            self.is_chinese = False
            return True
        else:
            self.logger.log(resource_data.get('invalid_character'))
            return False

    def with_chinese(self):
        self.logger.log(resource_data.get('navigation'))
        self.select_option(resource_data.get('chinese'), resource_data.get('english'))
        self.check_common(self.check_input_chinese)

    def user_input_select_common(self, action='', promp=''):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            user_input = input(promp).strip()
            if not user_input:
                self.is_pri_standby = True
                self.is_cm = True
                self.is_ddes = False
                break
            if not user_input.isdigit():
                self.logger.log(resource_data.get('invalid_num'))
                continue
            if user_input == "1":
                if action == "ddes":
                    self.is_ddes = False
                elif action == "cm":
                    self.is_cm = True
                elif action == "pri_standby":
                    self.is_pri_standby = True
                break
            elif user_input == "2":
                if action == "ddes":
                    self.is_ddes = True
                    self.is_cm = True
                elif action == "cm":
                    self.is_cm = False
                elif action == "pri_standby":
                    self.is_pri_standby = False
                break
            else:
                self.logger.log(resource_data.get('invalid_character'))

    def select_option(self, valid_str, invalid_str):
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                self.logger.log(">> " + str(i) + ") " + valid_str)
            else:
                self.logger.log("   " + str(i) + ") " + invalid_str)
                
        self.logger.log("-------------------------------")

    def check_common(self, check):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if not check():
                continue
            else:
                break

    def with_xml_file(self):
        self.check_common(self.check_input_xml_info)

    def with_database_install_dir(self):
        self.check_common(self.check_input_database_install_dir)

    def with_database_port(self):
        self.check_common(self.check_input_database_port)

    def with_pri_standby(self):
        self.logger.log(resource_data.get('choose_pri_standby'))
        self.select_option(resource_data.get('deploy_pri_standby'), resource_data.get('deploy_single'))
        self.user_input_select_common('pri_standby', resource_data.get('input_pri_standby'))

    def with_pri_standby_count(self):
        self.check_common(self.check_input_pri_standby_count)

    def with_pri_standby_ip(self):
        self.check_common(self.check_input_pri_standby_ip)

    def with_ddes(self):
        self.logger.log(resource_data.get('choose_ddes'))
        self.select_option(resource_data.get('not_deploy'), resource_data.get('deploy'))
        self.user_input_select_common('ddes', resource_data.get('input_ddes'))

    def with_dss_home(self):
        self.check_common(self.check_dss_home)

    def with_dss_vg_info(self):
        self.check_common(self.check_dss_vg_info)

    def with_voting_disk_path(self):
        self.check_common(self.check_voting_disk_path)

    def with_share_disk_dir(self):
        self.check_common(self.check_share_disk_dir)

    def with_cm(self):
        self.logger.log(resource_data.get('choose_cm'))
        self.select_option(resource_data.get('deploy'), resource_data.get('not_deploy'))
        self.user_input_select_common('cm', resource_data.get('input_cm'))

    def with_cm_server_port(self):
        self.check_common(self.check_input_cm_server_port)
            
    def load_xml(self):
        try:
            # xml default path is ./cluster_tmp.xml 
            tmp_xml_dir = "./cluster_tmp.xml"
            xml_dir = os.path.normpath(os.path.join(get_current_dir(), tmp_xml_dir))
            self.tree = ET.parse(xml_dir)
            self.root = self.tree.getroot()
            self.xml_file_path = xml_dir
        except Exception as e:
            raise Exception("xml file parsing failed: ", e)

    def delete_xml_node(self):
        if 9 >= self.pri_standby_count > 0:
            new_node_list = HOST_NODE_INFO[self.pri_standby_count:]
            for child in self.root[1].findall('DEVICE'):
                if child.get('sn') in new_node_list:
                    self.root[1].remove(child)

    def delete_xml_ddes(self):
        if self.is_ddes:
            return
        # 删除资源池化相关参数 {'enable_dss', 'dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name'}
        for child in self.root[0].findall('PARAM'):
            if child.attrib['name'] in DSS_PARA_INFO:
                self.root[0].remove(child)

    def delete_xml_cm(self):
        if self.is_cm:
            return
        # 删除CM相关参数,cmDir cmsNum cmServerPortBase cmServerListenIp1 cmServerlevel cmServerRelation
        for i in range(0, len(self.root[1])):
            for child in self.root[1][i].findall('PARAM'):
                if child.attrib['name'] in CM_PARA_INFO:
                    self.root[1][i].remove(child)

    def update_cluster_label_nodename_info(self):
        for child in self.root[0]:
            if child.attrib['name'] == "nodeNames":
                child.attrib['value'] = ",".join(self.hostname_lists)
            if child.attrib['name'] == "backIp1s":
                child.attrib["value"] = ",".join(self.ip_lists)

    def update_database_install_dir(self):
        for child in self.root[0]:
            if child.get('name') == "gaussdbAppPath":
                child.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'app'))
            elif child.get('name') == "gaussdbLogPath":
                child.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'log'))
            elif child.get('name') == "tmpMppdbPath":
                child.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'tmp'))
            elif child.get('name') == "gaussdbToolPath":
                child.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'tool'))
            elif child.get('name') == "corePath":
                child.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'corefile'))

    def update_cluster_label_common_info(self):
        self.update_cluster_label_nodename_info()
        self.update_database_install_dir()

    def update_database_port(self):
        for i in range(len(self.root[1])):
            for child in self.root[1][i]:
                if child.attrib['name'] == 'dataPortBase':
                    child.attrib['value'] = self.database_port

    def update_node_ip_hostname_info(self):
        datanode1_value = ""
        datanode1 = os.path.normpath(os.path.join(self.opengauss_install_dir, "data/dn1"))
        if not self.is_pri_standby:
            datanode1_value = datanode1
        else:
            for i in range(len(self.hostname_lists)):
                if i == 0:
                    datanode1_value = datanode1 + ","
                elif i == len(self.hostname_lists) - 1:
                    datanode1_value += self.hostname_lists[i] + "," + datanode1
                else:
                    datanode1_value += self.hostname_lists[i] + "," + datanode1 + ","

        for i in range(len(self.root[1])):
            for ele in self.root[1][i]:
                if ele.attrib['name'] == "name":
                    ele.attrib['value'] = self.hostname_lists[i]
                if ele.attrib['name'] == "backIp1":
                    ele.attrib['value'] = self.ip_lists[i]
                if ele.attrib['name'] == "sshIp1":
                    ele.attrib['value'] = self.ip_lists[i]
                if ele.attrib['name'] == "dataNode1":
                    ele.attrib['value'] = datanode1_value

    def update_device_label_info(self):
        # update database port
        self.update_database_port()
        # update node ip
        self.update_node_ip_hostname_info()

    def update_ddes_info(self):
        if not self.is_ddes:
            return
        # 更新的信息:dss_vg_info  votingDiskPath  shareDiskDir
        for child in self.root[0].findall('PARAM'):
            if child.attrib['name'] in UPDATE_DSS_PARA_INFO:
                child.attrib['value'] = self.ddes_info.get(child.attrib['name'])

    def update_cm_info(self):
        if not self.is_cm:
            return
        # 更新cm的话  第一个device 更新 cmServerPortBase cmServerListenIp1 cmServerHaIp1 cmServerRelation cmDir
        for child in self.root[1]:
            for ele in child:
                if ele.attrib['name'] == "cmServerPortBase":
                    ele.attrib['value'] = self.cm_server_port
                if ele.attrib['name'] == "cmServerPortStandby":
                    ele.attrib['value'] = self.cm_server_port
                if ele.attrib['name'] == "cmServerListenIp1":
                    ele.attrib['value'] = ",".join(self.ip_lists)
                if ele.attrib['name'] == "cmServerHaIp1":
                    ele.attrib["value"] = ",".join(self.ip_lists)
                if ele.attrib['name'] == "cmServerRelation":
                    ele.attrib['value'] = ",".join(self.hostname_lists)
                if ele.attrib['name'] == "cmDir":
                    ele.attrib['value'] = os.path.normpath(os.path.join(self.opengauss_install_dir, 'data', 'cmserver'))

    def update_xml_all_info(self):
        # 更新用户输入的所有值
        # 1.update cluster label common info
        self.update_cluster_label_common_info()
        # 2.update device label common info
        self.update_device_label_info()
        # 3.update ddes info
        self.update_ddes_info()
        # 4.update cm info
        self.update_cm_info()

    def generate_new_xml_file(self):
        if os.path.exists(self.target_xml):
            os.remove(self.target_xml)
        ET.ElementTree(self.root).write(self.target_xml)

    def display_xml_info(self):
        if not os.path.exists(self.target_xml):
            raise Exception("new xml file not found!")
        self.logger.log("%s   %s" % (resource_data.get('target_xml_dir'), self.target_xml))
        self.logger.log(resource_data.get('target_xml_content'))
        # use cat 
        cmd = "cat %s" % self.target_xml
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0:
            self.logger.log(output)

    def get_locale(self):
        cmd = "echo $LANG"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0:
            if output:
                if "CN" in output:
                    self.is_chinese = True
                else:
                    self.is_chinese = False
            else:
                self.logger.exitWithError("Executing %s failed. output is empty." % cmd)
        else:
            self.logger.exitWithError("Executing %s failed. Error: %s" % (cmd, output))

    def init_globals(self):
        if self.logfile == "":
            if os.getuid() == 0:
                self.logfile = "/tmp/root/xml_template.log"
            else:
                self.logfile = "/tmp/xml_template.log"
        self.logger = GaussLog(self.logfile, "xml_template")

    def confim_xml(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            user_input = input(resource_data.get('confirm_xml')).strip()
            
            if user_input.lower() in ('y', 'yes'):
                return
            else:
                self.logger.log(resource_data.get('invalid_confirm_xml'))

    def delete_log(self):
        if os.getuid() == 0:
            cmd = "rm -rf /tmp/root/xml_template*.log"
        else:
            cmd = "rm -rf /tmp/xml_template*.log"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            self.logger.error("delete /tmp/xml_template*.log failed! Error: %s" % output) 

    def load_json_file(self):
        global resource_data
        if self.is_chinese:
            resource = "resource_zh.json"
        else:
            resource = "resource_en.json"
        with open(os.path.join(get_current_dir(), resource), 'r') as f:
            resource_data = json.load(f)

    def input_user_info(self):
        self.with_xml_file()
        self.with_database_install_dir()
        self.with_database_port()
        self.with_pri_standby()
        if self.is_pri_standby:
            self.with_ddes()
            if self.is_ddes:
                self.with_dss_home()
                self.with_dss_vg_info()
                self.with_voting_disk_path()
                self.with_share_disk_dir()
            else:
                self.with_cm()
            if self.is_cm:
                self.with_cm_server_port()
                self.with_pri_standby_count()
                self.with_pri_standby_ip()
            else:
                self.with_pri_standby_count()
                self.with_pri_standby_ip()
        else:
            self.with_pri_standby_count()
            self.with_pri_standby_ip()

    def run(self):
        global DATABASE_PORT
        global CM_SERVER_PORT

        # init globals
        self.init_globals()
        # get loacle
        self.get_locale()
        # load json file
        self.load_json_file()
        # navigation for englist or chinese
        self.with_chinese()
        # load json file
        self.load_json_file()
        # input user info
        self.input_user_info()
        # load xml
        self.load_xml()
        # delete xml excess node count
        self.delete_xml_node()
        # delete xml ddes info
        self.delete_xml_ddes()
        # delete xml cm info
        self.delete_xml_cm()
        # update xml all info
        self.update_xml_all_info()
        # generate a new xml file
        self.generate_new_xml_file()
        # display xml info
        self.display_xml_info()
        # delete log
        self.delete_log()
        # confim xml content
        self.confim_xml()

