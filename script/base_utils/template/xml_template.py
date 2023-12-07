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
import xml.etree.ElementTree as ET

from gspylib.common.GaussLog import GaussLog
from gspylib.common.Common import DefaultValue

DSS_PARA_INFO = ['enable_dss', 'dss_home', 'dss_vg_info', 'votingDiskPath', 'shareDiskDir', 'ss_dss_vg_name',
                 'dss_ssl_enable']
UPDATE_DSS_PARA_INFO = ['dss_vg_info', 'votingDiskPath', 'shareDiskDir']
CM_PARA_INFO = ['cmDir', 'cmsNum', 'cmServerPortBase', 'cmServerPortStandby', 'cmServerListenIp1',
                'cmServerHaIp1', 'cmServerlevel', 'cmServerRelation']
HOST_NODE_INFO = ['node1_hostname', 'node2_hostname', 'node3_hostname', 
                  'node4_hostname', 'node5_hostname', 'node6_hostname', 
                  'node7_hostname', 'node8_hostname', 'node9_hostname']


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
        self.tries = 3
        self.database_port = ""
        self.cm_server_port = ""
        self.opengauss_install_dir = ""
        self.target_xml = ""
        self.tree = ET.ElementTree()
        self.root = None
        self.xml_file_path = ""
        self.logger = None
        self.logfile = ""

    def check_isdigit(self, user_input):
        if not str(user_input).strip().isdigit():
            if self.is_chinese:
                self.logger.log("输入字符必须是数字!")
            else:
                self.logger.log("The input character must be a number!")
            return False
        return True

    def check_path(self, dir_path):
        one_path = dir_path.strip()

        # 1.dir path illegal characters
        for rac in DefaultValue.PATH_CHECK_LIST:
            flag = one_path.find(rac)
            if flag >= 0:
                self.logger.log("There are illegal characters in the path")
                return False
        # 2.dir must be abs path
        if not os.path.abspath(one_path):
            self.logger.log("%s path nust be abs path" % one_path)
            return False
        # 3.if dir exits, delete it
        if os.path.exists(one_path):
            cmd = "rm -rf %s" % one_path
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.log("The user does not have permission for %s" % one_path)
                return False
        else:
            # 4.if not dir exits, create it and delete it
            cmd = "mkdir -p %s; rm -rf %s" % (one_path, one_path)
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                self.logger.log("The user does not have permission for %s" % one_path)
                return False
        return True

    def with_chinese(self):
        self.logger.log("请选择是英文还是中文导航一键式生成xml文件?")
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                print(">> " + str(i) + ") " + "中文")
            else:
                print("   " + str(i) + ") " + "英文")

        self.logger.log("-------------------------------")
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            user_input = input("请输入1/2进行选择,默认选项为1)中文: ")
            if not user_input.strip():
                self.is_chinese = True
                break
            if not self.check_isdigit(user_input):
                continue
            if user_input.strip() == "1":
                self.is_chinese = True
                break
            elif user_input.strip() == "2":
                self.is_chinese = False
                break
            else:
                self.logger.log("输入字符不合法!")

    def with_xml_file(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入xml的路径和文件名(默认:./cluster.xml):  ")
            else:
                user_input = input(
                    "Please enter the path and file name of the XML file(default:./cluster.xml):  ")
            if not user_input.strip():
                cur_dir = os.path.dirname(os.path.realpath(__file__))
                tmp_dir = os.path.join(cur_dir, 'cluster.xml')
                if os.path.exists(tmp_dir):
                    os.removedirs(tmp_dir)
                self.target_xml = tmp_dir
                break
            # 校验路径是否合法，判断，路径如果存在，是否有权限；不存在，看能否创建文件
            if not self.check_path(user_input):
                continue
            else:
                self.target_xml = user_input.strip()
                break

    def with_database_install_dir(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入数据库安装目录(默认:/opt/openGauss/install):  ")
            else:
                user_input = input(
                    "Please enter the database installation directory(default:/opt/openGauss/install):  ")
            # 校验路径是否合法，判断，路径如果存在，是否有权限；不存在，看能否创建文件
            if not user_input.strip():
                self.opengauss_install_dir = "/opt/openGauss/install"
                break
            if not self.check_path(user_input):
                continue
            else:
                self.opengauss_install_dir = user_input.strip()
                break

    def with_database_port(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入数据库端口(默认:15000):  ")
            else:
                user_input = input("Please enter the database port(default:15000):  ")
            if not user_input.strip():
                self.database_port = "15000"
                break
            if not self.check_isdigit(user_input):
                continue
            else:
                self.database_port = user_input.strip()
                break

    def with_ddes(self):
        if self.is_chinese:
            self.logger.log("请选择是否部署资源池化?(如果配置了资源池化,默认配置cm)")
        else:
            self.logger.log("Please choose whether to deploy resource pooling? (If configured, cm must be configured)")
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                if self.is_chinese:
                    print(">> " + str(i) + ") " + "不部署")
                else:
                    print(">> " + str(i) + ") " + "Do not deploy")
            else:
                if self.is_chinese:
                    print("   " + str(i) + ") " + "部署")
                else:
                    print("   " + str(i) + ") " + "Deploy")

        self.logger.log("-------------------------------")
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入 1/2 进行选择，默认选项是 1)不部署 ")
            else:
                user_input = input("Please enter 1/2 for selection, the default option is 1) Do not deploy ")
            if not user_input.lower().strip():
                self.is_ddes = False
                break
            # 校验输入的是否合法，必须是数字，如果不是，提示
            if not self.check_isdigit(user_input):
                continue
            if user_input.lower() == '1':
                self.is_ddes = False
                break
            elif user_input.lower() == '2':
                self.is_ddes = True
                self.is_cm = True
                break
            else:
                if self.is_chinese:
                    self.logger.log("输入的字符不合法!")
                else:
                    self.logger.log("The input character is invalid!")

    def with_cm_server_port(self):
        if not self.is_cm:
            return
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入cmserver端口(默认:15400):  ")
            else:
                user_input = input("Please enter the cmserver port(default:15400):  ")
            if not user_input.strip():
                self.cm_server_port = "15400"
                break
            # 校验是否是数字，不是,提示
            if not self.check_isdigit(user_input):
                continue
            else:
                self.cm_server_port = user_input.strip()
                break

    def with_dss_vg_info(self):
        if self.is_chinese:
            self.logger.log("请输入资源池化相关路径信息，友情提示：请检查资源池化各节点间的磁盘映射信息。")
        else:
            self.logger.log(
                "Please enter the path information related to resource pooling. Friendly reminder: \
                Please check the disk mapping information between nodes in resource pooling")
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            user_input = input("请输入'dss_vg_info'的路径信息(默认是:data:/dev/sdb,p0:/dev/sdc,p1:/dev/sdd) ")
            # 校验路径是否合法
            if not user_input.strip():
                self.ddes_info['dss_vg_info'] = "data:/dev/sdb,p0:/dev/sdc,p1:/dev/sdd"
                break
            else:
                self.ddes_info['dss_vg_info'] = user_input.strip()
                break

    def with_voting_disk_path(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入'votingDiskPath'的路径信息(默认是:/dev/sde) ")
            else:
                user_input = input("Please enter the path information for 'votingDiskPath'(default:/dev/sde) ")
            # 校验路径是否合法
            if not user_input.strip():
                self.ddes_info['votingDiskPath'] = "/dev/sde"
                break
            else:
                self.ddes_info['votingDiskPath'] = user_input.strip()
                break

    def with_share_disk_dir(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入'shareDiskDir'的路径信息(默认是:/dev/sdf) ")
            else:
                user_input = input("Please enter the path information for 'shareDiskDir'(default:/dev/sdf) ")
            # 校验路径是否合法
            if not user_input.strip():
                self.ddes_info['shareDiskDir'] = "/dev/sdf"
                break
            else:
                self.ddes_info['shareDiskDir'] = user_input.strip()
                break

    def with_pri_standby(self):
        if self.is_chinese:
            self.logger.log("请选择是否主备部署?")
        else:
            self.logger.log("Please choose whether to deploy as primary standby or single?")
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                if self.is_chinese:
                    print(">> " + str(i) + ") " + "主备部署")
                else:
                    print(">> " + str(i) + ") " + "Primary and standby deployment")
            else:
                if self.is_chinese:
                    print("   " + str(i) + ") " + "单机部署")
                else:
                    print("   " + str(i) + ") " + "single deployment")
        self.logger.log("-------------------------------")
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入 1/2 进行选择，默认选项是 1)主备部署 ")
            else:
                user_input = input(
                    "Please enter 1/2 for selection, the default option is 1) primary and standby deployment ")
            if not user_input.strip():
                self.is_pri_standby = True
                break
            if not self.check_isdigit(user_input):
                continue
            if user_input.strip() == '1':
                self.is_pri_standby = True
                break
            elif user_input.strip() == '2':
                self.is_pri_standby = False
                self.pri_standby_count = 1
                break
            else:
                if self.is_chinese:
                    self.logger.log("输入的字符不合法!")
                else:
                    self.logger.log("The input character is invalid!")

    def with_cm(self):
        if self.is_chinese:
            self.logger.log("请选择是否部署CM?")
        else:
            self.logger.log("Please choose whether to deploy CM?")
        selected_option = 1
        for i in range(1, 3):
            if i == selected_option:
                if self.is_chinese:
                    print(">> " + str(i) + ") " + "部署cm")
                else:
                    print(">> " + str(i) + ") " + "Deploy cm")
            else:
                if self.is_chinese:
                    print("   " + str(i) + ") " + "不部署cm")
                else:
                    print("   " + str(i) + ") " + "Do not deploy cm")

        self.logger.log("-------------------------------")
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入 1/2 进行选择，默认选项是 1)部署 ")
            else:
                user_input = input("Please enter 1/2 for selection, the default option is 1) Deployment ")
            if not user_input.strip():
                self.is_cm = True
                break
            if not self.check_isdigit(user_input):
                continue
            if user_input.strip() == "1":
                self.is_cm = True
                break
            elif user_input.strip() == "2":
                self.is_cm = False
                break
            else:
                if self.is_chinese:
                    self.logger.log("输入的字符不合法!")
                else:
                    self.logger.log("The input character is invalid!")

    def with_pri_standby_count(self):
        if not self.is_pri_standby:
            return
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入节点数量,最多支持一主八备,即9个节点(默认是一主两备,3个节点)  ")
            else:
                user_input = input("Please enter the number of nodes, supporting a maximum of one primary and eight backup, which is 9 nodes \
                (default is one primary and two backup, with 3 nodes)  ")
            if not user_input.strip():
                self.pri_standby_count = 3
                break
            # 校验输入的字符必须是数字
            if not self.check_isdigit(user_input):
                continue
            if 2 <= int(user_input.strip()) <= 9:
                self.pri_standby_count = int(user_input.strip())
                break
            else:
                if self.is_chinese:
                    self.logger.log("输入的字符不合法")
                else:
                    self.logger.log("The input character is invalid!")

    def check_ip_node_count(self):
        if len(self.pri_standby_ip.keys()) != self.pri_standby_count:
            if self.is_chinese:
                self.logger.log("输入节点数量和节点ip,hostname不匹配!")
                return False
            else:
                self.logger.log("The number of input nodes and node IP do not match the host name!")
                return False
        return True

    def check_ip_tmp(self, ip_address):
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if not re.match(regex, ip_address):
            if self.is_chinese:
                self.logger.log("无效的ip!")
            else:
                self.logger.log("Invaild ipaddress!")
            return False
        return True

    def get_ip_hostname(self, user_input):
        self.pri_standby_ip = {}
        self.ip_lists = []
        self.hostname_lists = []
        ip_hostname = user_input.strip().split(";")
        for tmp in ip_hostname:
            ip = tmp.split(" ")[0]
            hostname = tmp.split(" ")[1]
            if not self.check_ip_tmp(ip):
                return False
            self.pri_standby_ip[ip] = hostname
            self.ip_lists.append(ip)
            self.hostname_lists.append(hostname)
        return True

    def with_pri_standby_ip(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请输入主机节点IP和节点名称(如:192.168.0.1 hostname1) ")
            else:
                user_input = input("Please enter the host node IP and node name(如:192.168.0.1 hostname1) ")
            if not user_input.strip():
                if self.is_chinese:
                    self.logger.log("输入的ip和hostname不能为空")
                else:
                    self.logger.log("The input IP and host name cannot be empty")
            else:
                if not self.get_ip_hostname(user_input.strip()):
                    continue
                else:
                    # 校验ip数量是否一样
                    if self.check_ip_node_count():
                        break
            
    def load_xml(self):
        try:
            # xml default path is ./cluster_tmp.xml 
            tmp_xml_dir = "./cluster_tmp.xml"
            current_dir = os.path.dirname(os.path.realpath(__file__))
            xml_dir = os.path.normpath(os.path.join(current_dir, tmp_xml_dir))
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
        # 判断xml文件是否存在，存在 读取；不存在 报错
        if not os.path.exists(self.target_xml):
            raise Exception("new xml file not found!")
        self.logger.log("The generated XML path and file name are:  " + self.target_xml)
        self.logger.log("The content is:")
        # use cat 
        cmd = "cat %s" % self.target_xml
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0:
            self.logger.log(output) 

    def init_globals(self):
        if self.logfile == "":
            self.logfile = "/tmp/xml_template.log"
        self.logger = GaussLog(self.logfile, "xml_template")

    def confim_xml(self):
        for i in range(self.tries):
            if i == 3:
                sys.exit(0)
            if self.is_chinese:
                user_input = input("请确认xml的内容是否正确,正确输入yes;如需修改xml内容请自行修改,然后输入yes确认  ")
            else:
                user_input = input("Please confirm if the content of the XML is correct and input yes correctly;\
                     If you need to modify the XML content, please modify it yourself and then enter yes to confirm  ")
            
            if user_input.strip().lower() == 'y' or user_input.strip().lower() == 'yes':
                return
            else:
                self.logger.log("Only you can be entered y or yes")
                continue


    def run(self):
        self.init_globals()
        self.with_chinese()
        self.with_xml_file()
        self.with_database_install_dir()
        self.with_database_port()
        self.with_pri_standby()
        if self.is_pri_standby:
            self.with_ddes()
            if self.is_ddes:
                self.with_cm_server_port()
                self.with_dss_vg_info()
                self.with_voting_disk_path()
                self.with_share_disk_dir()
                self.with_pri_standby_count()
                self.with_pri_standby_ip()
            else:
                self.with_cm()
            if self.is_cm:
                self.with_cm_server_port()
                self.with_pri_standby_count()
                self.with_pri_standby_ip()
        else:
            self.with_pri_standby_count()
            self.with_pri_standby_ip()

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
        # confim xml content
        self.confim_xml()
