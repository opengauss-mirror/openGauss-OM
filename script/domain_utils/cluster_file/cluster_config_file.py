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
# Description  : cluster_config_file.py is a utility to do something for cluster config file.
#############################################################################

import os
import re
import xml.etree.cElementTree as ETree

from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.GaussLog import GaussLog
from base_utils.security.security_checker import SecurityChecker
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ClusterConfigFile:
    """
    utility to do something for cluster config file.
    """

    @staticmethod
    def getOneClusterConfigItem(item_name, xml):
        """
        function: get the OM log path
        input : NA
        output: NA
        """
        # set env paramter CLUSTERCONFIGFILE
        os.putenv(ClusterConstants.ENV_CLUSTERCONFIG, xml)
        # read one cluster configuration item "cluster"
        (ret_status, ret_value) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(xml), item_name, "cluster")
        if ret_status == 0:
            return os.path.normpath(ret_value)
        elif ret_status == 2:
            return ""
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"]
                            % "the cluster configuration item file"
                            + " Error: \n%s." % ret_status)

    @staticmethod
    def initParserXMLFile(xml_file_path):
        """
        function : Init parser xml file
        input : String
        output : Object
        """
        try:
            # check xml for security requirements
            ClusterConfigFile.checkXMLFile(xml_file_path)
            dom_tree = ETree.parse(xml_file_path)
            root_node = dom_tree.getroot()
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51236"] + " Error: \n%s." % str(e))
        return root_node

    @staticmethod
    def checkXMLFile(xml_file):
        """
        function : check XML contain DTDs
        input : String
        output : NA
        """
        # Check xml for security requirements
        # if it have "<!DOCTYPE" or it have "<!ENTITY",
        # exit and print "File have security risks."
        try:
            with open(xml_file, "r", encoding='utf-8') as fb:
                lines = fb.readlines()
            for line in lines:
                if re.findall("<!DOCTYPE", line) or re.findall("<!ENTITY", line):
                    raise Exception("File have security risks.")
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def readOneClusterConfigItem(root_node, para_name, input_element_name,
                                 nodeName=""):
        """
        function : Read one cluster configuration item
        input : Object,String,String
        output : String,String
        """
        # if read node level config item, should input node name
        if input_element_name.upper() == 'node'.upper() and nodeName == "":
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51201"] + \
                            " Need node name for node configuration level.")

        element_name = input_element_name.upper()
        return_value = ""
        return_status = 2

        if element_name == 'cluster'.upper():
            if not root_node.findall('CLUSTER'):
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"] % element_name)
            element = root_node.findall('CLUSTER')[0]
            nodeArray = element.findall('PARAM')
            (return_status, return_value) = ClusterConfigFile.findParamInCluster(para_name,
                                                                                 nodeArray)
        elif element_name == 'node'.upper():
            element_name = 'DEVICELIST'
            if not root_node.findall('DEVICELIST'):
                raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"] % element_name)
            device_array = root_node.findall('DEVICELIST')[0]
            device_node = device_array.findall('DEVICE')
            (return_status, return_value) = ClusterConfigFile.findParamByName(nodeName, para_name,
                                                                              device_node)
        else:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"] % element_name)

        return (return_status, return_value)

    @staticmethod
    def findParamByName(node_name, para_name, device_node):
        """
        function : Find parameter by name
        input : String,String,Object
        output : String,String
        """
        return_value = ""
        return_status = 2
        for dev in device_node:
            param_list = dev.findall('PARAM')
            for param in param_list:
                thisname = param.attrib['name']
                if thisname == 'name':
                    value = param.attrib['value']
                    if node_name == value:
                        for param in param_list:
                            name = param.attrib['name']
                            if name == para_name:
                                return_status = 0
                                return_value = str(param.attrib['value'].strip())
                                if ((name.find("Dir") > 0 or name.find(
                                        "dataNode") == 0) and return_value != ""):
                                    return_value = os.path.normpath(return_value)
        return return_status, return_value

    @staticmethod
    def findParamInCluster(para_name, node_array):
        """
        function : Find parameter in cluster
        input : String,[]
        output : String,String
        """
        return_value = ""
        return_status = 2
        for node in node_array:
            name = node.attrib['name']
            if name == para_name:
                return_status = 0
                return_value = str(node.attrib['value'])
                break
        return return_status, return_value

    @staticmethod
    def setDefaultXmlFile(xml_file):
        """
        function : Set the default xml file
        input : String
        output : NA
        """
        if not os.path.exists(xml_file):
            raise Exception(
                ErrorCode.GAUSS_502["GAUSS_50201"] % "XML configuration")

        os.putenv(ClusterConstants.ENV_CLUSTERCONFIG, xml_file)

    @staticmethod
    def readClusterLogPath(xml_file):
        """
        function : Read log path from xml file
        input : String
        output : NA
        """
        ClusterConfigFile.setDefaultXmlFile(xml_file)
        # read log path from xml file
        (ret_status, ret_value) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(xml_file), "gaussdbLogPath", "cluster")
        if ret_status == 0:
            tmppath = os.path.normpath(ret_value)
            SecurityChecker.check_injection_char(tmppath)
            return tmppath
        elif ret_status == 2:
            return ClusterConstants.GAUSSDB_DIR
        else:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"] %
                            "gaussdbLogPath" + " Error: \n%s" % ret_value)

    @staticmethod
    def readClusterAppPath(xml_file):
        """
        function : Read the cluster's application path from xml file
        input : String
        output : String
        """
        ClusterConfigFile.setDefaultXmlFile(xml_file)
        # read the cluster's application path from xml file
        (ret_status, ret_value) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(xml_file), "gaussdbAppPath", "cluster")
        if ret_status != 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51200"]
                            % "gaussdbAppPath" + " Error: \n%s" % ret_value)

        app_path = os.path.normpath(ret_value)
        SecurityChecker.check_injection_char(app_path)
        return app_path

    @staticmethod
    def readClusterTmpMppdbPath(user, xml_file):
        """
        function : Read temporary mppdb path from xml file
        input : String,String
        output : String
        """
        ClusterConfigFile.setDefaultXmlFile(xml_file)
        # read temporary mppdb path from xml file
        (ret_status, ret_value) = ClusterConfigFile.readOneClusterConfigItem(
            ClusterConfigFile.initParserXMLFile(xml_file), "tmpMppdbPath", "cluster")
        if ret_status != 0:
            (ret_tool_path_status, ret_tool_path_value) = \
                ClusterConfigFile.readOneClusterConfigItem(
                ClusterConfigFile.initParserXMLFile(xml_file), "gaussdbToolPath", "cluster")
            if ret_tool_path_status != 0:
                ret_tool_path_value = ClusterConstants.CLUSTER_TOOL_PATH
            ret_value = os.path.join(ret_tool_path_value, "%s_mppdb" % user)

        tmp_path = os.path.normpath(ret_value)
        SecurityChecker.check_injection_char(tmp_path)
        return tmp_path

    @staticmethod
    def checkConfigFile(xml_file):
        """
        Check XML file path
        """
        if xml_file == "":
            GaussLog.exitWithError(ErrorCode.GAUSS_500["GAUSS_50001"] % 'X' + ".")
        if not os.path.exists(xml_file):
            GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50201"] % xml_file)
        if not os.path.isabs(xml_file):
            GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50213"] % "configuration file")
