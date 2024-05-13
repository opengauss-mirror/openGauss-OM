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
# Description  : gsnetwork.py is a utility to do something for
#               network information.
#############################################################################
import subprocess
import sys
import _thread as thread
import re
import psutil

sys.path.append(sys.path[0] + "/../../")

from gspylib.os.gsplatform import g_Platform
from gspylib.threads.parallelTool import parallelTool

g_failedAddressList = []
g_lock = thread.allocate_lock()

"""
Requirements:
"""


class networkInfo():
    """
    Class: networkinfo
    """

    def __init__(self):
        """
        constructor
        """
        self.NICNum = ""
        self.ipAddress = ""
        self.networkMask = ""
        self.MTUValue = ""

        self.TXValue = ""
        self.RXValue = ""
        self.networkSpeed = ""
        self.networkConfigFile = ""
        self.networkBondModeInfo = ""
        self.hostName = ""

    def __str__(self):
        """
        function: str
        """
        return "NICNum=%s,ipAddress=%s,networkMask=%s,MTUValue=%s," \
               "TXValue=%s," \
               "RXValue=%s,networkSpeed=%s,networkConfigFile=%s," \
               "networkBondModeInfo=\"%s\"" % \
               (self.NICNum, self.ipAddress, self.networkMask, self.MTUValue,
                self.TXValue, self.RXValue, self.networkSpeed,
                self.networkConfigFile,
                self.networkBondModeInfo)


class Network():
    """
    function: Init the Network options
    """
    NET_IPV6 = "ipv6"
    NET_IPV4 = "ipv4"

    def __init__(self):
        pass

    def isIpValid(self, ip_address):
        """
        function : check if the input ip address is valid
        input : String
        output : bool
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def executePingCmd(self, ipAddress):
        """
        function : Send the network command of ping.
        input : String
        output : NA
        """
        pingCmd = g_Platform.getPingCmd(ipAddress, "5", "1")
        cmd = "%s | %s ttl | %s -l" % (pingCmd, g_Platform.getGrepCmd(),
                                       g_Platform.getWcCmd())
        (status, output) = subprocess.getstatusoutput(cmd)
        if (str(output) == '0' or status != 0):
            g_lock.acquire()
            g_failedAddressList.append(ipAddress)
            g_lock.release()

    def checkIpAddressList(self, ipAddressList):
        """
        function : Check the connection status of network.
        input : []
        output : []
        """
        global g_failedAddressList
        g_failedAddressList = []
        parallelTool.parallelExecute(self.executePingCmd, ipAddressList)
        return g_failedAddressList

    def getAllNetworkIp(self,ip_type=NET_IPV4):
        """
        function: get All network ip
        """
        if ip_type == "":
            raise ValueError("This is the host name,not an ip.")
        networkInfoList = []
        mappingList = g_Platform.getIpAddressAndNICList(ip_type)
        for onelist in mappingList:
            data = networkInfo()
            # NIC number
            data.NICNum = onelist[0]
            # ip address
            data.ipAddress = onelist[1]
            networkInfoList.append(data)
        return networkInfoList

    def getNetworkMTUValueByNICNum(self, networkCardNum):
        """
        function: get Network MTU Value By NICNum
        """
        return psutil.net_if_stats()[networkCardNum].mtu

    def getAllNetworkInfo(self,ip_type=NET_IPV4):
        """
        function: get all network info
        """
        if ip_type == "":
            raise ValueError("This is the host name,not an ip.")
        networkInfoList = []
        mappingList = g_Platform.getIpAddressAndNICList(ip_type)
        for oneList in mappingList:
            data = networkInfo()
            # NIC number
            data.NICNum = oneList[0]
            # ip address
            data.ipAddress = oneList[1]

            # host name
            try:
                data.hostName = g_Platform.getHostNameByIPAddr(
                    data.ipAddress)
            except Exception:
                data.hostName = ""

            # network mask
            try:
                data.networkMask = g_Platform.getNetworkMaskByNICNum(
                    data.NICNum,ip_type)
            except Exception:
                data.networkMask = ""

            # MTU value
            try:
                data.MTUValue = self.getNetworkMTUValueByNICNum(
                    data.NICNum)
            except Exception:
                data.MTUValue = ""

            # TX value
            try:
                data.TXValue = g_Platform.getNetworkRXTXValueByNICNum(
                    data.NICNum, 'tx')
            except Exception:
                data.TXValue = ""

            # RX value
            try:
                data.RXValue = g_Platform.getNetworkRXTXValueByNICNum(
                    data.NICNum, 'rx')
            except Exception:
                data.RXValue = ""

            # network speed
            try:
                data.networkSpeed = g_Platform.getNetworkSpeedByNICNum(
                    data.NICNum)
            except Exception:
                data.networkSpeed = ""

            # network config file
            try:
                data.networkConfigFile = \
                    g_Platform.getNetworkConfigFileByNICNum(data.NICNum)
            except Exception:
                data.networkConfigFile = ""

            # network bond mode info
            try:
                data.networkBondModeInfo = g_Platform.getNetworkBondModeInfo(
                    data.networkConfigFile, data.NICNum)
            except Exception:
                data.networkBondModeInfo = ""

            networkInfoList.append(data)
        return networkInfoList

    def checkNetworkInterruptByNIC(self, networkCardNum):
        """
        function: check Network Interrupt By NIC
        """
        return g_Platform.checkNetworkInterruptByNIC(networkCardNum)


g_network = Network()
