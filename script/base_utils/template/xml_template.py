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
import sys
import subprocess
import json
import xml.etree.ElementTree as ET

from gspylib.common.GaussLog import GaussLog
from base_utils.template.xml_status import XmlStatus
from base_utils.template.xml_constant import XmlConstant


def load_json_file():
    if XmlConstant.IS_CHINESE:
        resource = "resource_zh.json"
    else:
        resource = "resource_en.json"
    with open(os.path.join(XmlConstant.get_current_dir(), resource), 'r') as f:
        XmlConstant.RESOURCE_DATA = json.load(f)


def get_locale():
    cmd = "echo $LANG"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status == 0:
        if output:
            if "CN" in output:
                XmlConstant.IS_CHINESE = True
            else:
                XmlConstant.IS_CHINESE = False
        else:
            GaussLog.exitWithError("Executing %s failed. output is empty." % cmd)
    else:
        GaussLog.exitWithError("Executing %s failed. Error: %s" % (cmd, output))


def check_input_chinese():
    user_input = input(XmlConstant.RESOURCE_DATA.get('input_chinese')).strip()
    if not user_input:
        XmlConstant.IS_CHINESE = True
        return True
    if user_input == "1":
        XmlConstant.IS_CHINESE = True
        return True
    elif user_input == "2":
        XmlConstant.IS_CHINESE = False
        return True
    else:
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_character'))
        return False


def input_user_info():
    current_state = XmlStatus()
    while True:
        current_state = current_state.work()
        if current_state is None:
            break


def check_common(check):
    for i in range(XmlConstant.TRIES):
        if i == 3:
            sys.exit(0)
        if not check():
            continue
        else:
            break


def with_chinese():
    GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('navigation'))
    XmlConstant.select_option(XmlConstant.RESOURCE_DATA.get('chinese'), XmlConstant.RESOURCE_DATA.get('english'))
    check_common(check_input_chinese)

def confirm_xml():
    for i in range(XmlConstant.TRIES):
        if i == 3:
            sys.exit(0)
        user_input = input(XmlConstant.RESOURCE_DATA.get('confirm_xml')).strip()

        if user_input.lower() in ('y', 'yes'):
            return
        else:
            GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('invalid_confirm_xml'))


class GenerateTemplate:

    def __init__(self):
        """
        function: constructor
        """
        self.tree = ET.ElementTree()
        self.root = None
        self.xml_file_path = ""
        self.target_xml = ""

    def load_xml(self):
        try:
            # xml default path is ./cluster_tmp.xml 
            tmp_xml_dir = "./cluster_tmp.xml"
            xml_dir = os.path.normpath(os.path.join(XmlConstant.get_current_dir(), tmp_xml_dir))
            self.tree = ET.parse(xml_dir)
            self.root = self.tree.getroot()
            self.xml_file_path = xml_dir
        except Exception as e:
            raise Exception("xml file parsing failed: ", e)

    def delete_xml_node(self):
        if 9 >= XmlConstant.PRI_STANDBY_COUNT > 0:
            new_node_list = XmlConstant.HOST_NODE_INFO[XmlConstant.PRI_STANDBY_COUNT:]
            for child in self.root[1].findall('DEVICE'):
                if child.get('sn') in new_node_list:
                    self.root[1].remove(child)

    def delete_xml_ddes(self):
        if XmlConstant.IS_DDES:
            return
        # remove dss info: {'enable_dss', 'dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name'}
        for child in self.root[0].findall('PARAM'):
            if child.attrib['name'] in XmlConstant.DSS_PARA_INFO:
                self.root[0].remove(child)

    def delete_xml_cm(self):
        if XmlConstant.IS_CM:
            return
        # remove cm info: ['cmDir', 'cmsNum', 'cmServerPortBase', 'cmServerPortStandby', 'cmServerListenIp1',
        #                     'cmServerHaIp1', 'cmServerlevel', 'cmServerRelation']
        for i in range(0, len(self.root[1])):
            for child in self.root[1][i].findall('PARAM'):
                if child.attrib['name'] in XmlConstant.CM_PARA_INFO:
                    self.root[1][i].remove(child)

    def update_cluster_label_nodename_info(self):
        for child in self.root[0]:
            if child.attrib['name'] == "nodeNames":
                child.attrib['value'] = ",".join(XmlConstant.HOSTNAME_LISTS)
            if child.attrib['name'] == "backIp1s":
                child.attrib["value"] = ",".join(XmlConstant.IP_LISTS)

    def update_database_install_dir(self):
        for child in self.root[0]:
            if child.get('name') == "gaussdbAppPath":
                child.attrib['value'] = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'app'))
            elif child.get('name') == "gaussdbLogPath":
                child.attrib['value'] = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'log'))
            elif child.get('name') == "tmpMppdbPath":
                child.attrib['value'] = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'tmp'))
            elif child.get('name') == "gaussdbToolPath":
                child.attrib['value'] = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'tool'))
            elif child.get('name') == "corePath":
                child.attrib['value'] = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'corefile'))

    def update_cluster_label_common_info(self):
        self.update_cluster_label_nodename_info()
        self.update_database_install_dir()

    def update_database_port(self):
        for i in range(len(self.root[1])):
            for child in self.root[1][i]:
                if child.attrib['name'] == 'dataPortBase':
                    child.attrib['value'] = XmlConstant.DATABASE_PORT

    def update_node_ip_hostname_info(self):
        datanode1 = os.path.normpath(os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, "data/dn1"))
        if not XmlConstant.IS_PRI_STANDBY:
            datanode1_value = datanode1
        else:
            datanode1_list = []
            datanode1_list.append(datanode1)
            for hostname in XmlConstant.HOSTNAME_LISTS[1:]:
                datanode1_list.append(hostname)
                datanode1_list.append(datanode1)
            datanode1_value = ",".join(datanode1_list)

        for i in range(len(self.root[1])):
            for ele in self.root[1][i]:
                if ele.attrib['name'] == "name":
                    ele.attrib['value'] = XmlConstant.HOSTNAME_LISTS[i]
                if ele.attrib['name'] == "backIp1":
                    ele.attrib['value'] = XmlConstant.IP_LISTS[i]
                if ele.attrib['name'] == "sshIp1":
                    ele.attrib['value'] = XmlConstant.IP_LISTS[i]
                if ele.attrib['name'] == "dataNode1":
                    ele.attrib['value'] = datanode1_value

    def update_device_label_info(self):
        # update database port
        self.update_database_port()
        # update node ip
        self.update_node_ip_hostname_info()

    def update_ddes_info(self):
        if not XmlConstant.IS_DDES:
            return
        # update ddes info
        for child in self.root[0].findall('PARAM'):
            if child.attrib['name'] in XmlConstant.UPDATE_DSS_PARA_INFO:
                child.attrib['value'] = XmlConstant.DDES_INFO.get(child.attrib['name'])

    def update_cm_info(self):
        if not XmlConstant.IS_CM:
            return
        # update cm: update cmServerPortBase cmServerListenIp1 cmServerHaIp1 cmServerRelation cmDir
        for child in self.root[1]:
            for ele in child:
                if ele.attrib['name'] == "cmServerPortBase":
                    ele.attrib['value'] = XmlConstant.CM_SERVER_PORT
                if ele.attrib['name'] == "cmServerPortStandby":
                    ele.attrib['value'] = XmlConstant.CM_SERVER_PORT
                if ele.attrib['name'] == "cmServerListenIp1":
                    ele.attrib['value'] = ",".join(XmlConstant.IP_LISTS)
                if ele.attrib['name'] == "cmServerHaIp1":
                    ele.attrib["value"] = ",".join(XmlConstant.IP_LISTS)
                if ele.attrib['name'] == "cmServerRelation":
                    ele.attrib['value'] = ",".join(XmlConstant.HOSTNAME_LISTS)
                if ele.attrib['name'] == "cmDir":
                    ele.attrib['value'] = os.path.normpath(
                        os.path.join(XmlConstant.OPENGAUSS_INSTALL_DIR, 'data', 'cmserver'))

    def update_xml_all_info(self):
        # update all info
        # 1.update cluster label common info
        self.update_cluster_label_common_info()
        # 2.update device label common info
        self.update_device_label_info()
        # 3.update ddes info
        self.update_ddes_info()
        # 4.update cm info
        self.update_cm_info()

    def generate_new_xml_file(self):
        self.target_xml = XmlConstant.TARGET_XML
        if os.path.exists(self.target_xml):
            os.remove(self.target_xml)
        ET.ElementTree(self.root).write(self.target_xml)

    def display_xml_info(self):
        if not os.path.exists(self.target_xml):
            raise Exception("new xml file not found!")
        GaussLog.printMessage("%s   %s" % (XmlConstant.RESOURCE_DATA.get('target_xml_dir'), self.target_xml))
        GaussLog.printMessage(XmlConstant.RESOURCE_DATA.get('target_xml_content'))
        # use cat
        cmd = "cat %s" % self.target_xml
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0:
            GaussLog.printMessage(output)

    def run(self):
        # get locale
        get_locale()
        # load json file
        load_json_file()
        # navigation for english or chinese
        with_chinese()
        # load json file
        load_json_file()
        # input user info
        input_user_info()
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
        # confirm xml content
        confirm_xml()
