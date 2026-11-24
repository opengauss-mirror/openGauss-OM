# Copyright (c) 2020 Huawei Technologies Co., Ltd.
# openGauss-OM is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


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
