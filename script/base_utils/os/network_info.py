# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2020 Huawei Technologies Co.,Ltd.
# Portions Copyright (c) 2007 Agendaless Consulting and Contributors.
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
# Description  : network_info.py is utility for network.
#############################################################################


class NetworkInfo(object):
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
