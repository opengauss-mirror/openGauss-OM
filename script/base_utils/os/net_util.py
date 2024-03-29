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
# ----------------------------------------------------------------------------
# Description  : net_util.py is a utility to do something for network information.
#############################################################################
import os
import re
import socket
import subprocess
import sys
import _thread
import time

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.network_info import NetworkInfo
from base_utils.security.security_checker import SecurityChecker
from gspylib.threads.parallelTool import parallelTool
from os_platform.UserPlatform import g_Platform

localDirPath = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, localDirPath + "/../../../lib/netifaces/")
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6
sys.path.insert(0, localDirPath + "/../../../lib")
try:
    import psutil
except ImportError as e:
    if not bool(os.listdir(localDirPath + "/../../../lib")):
        raise
    # mv psutil mode .so file by python version
    pythonVer = str(sys.version_info[0]) + '.' + str(sys.version_info[1])
    psutilLinux = os.path.join(localDirPath,
                               "./../../../lib/psutil/_psutil_linux.so")
    psutilPosix = os.path.join(localDirPath,
                               "./../../../lib/psutil/_psutil_posix.so")
    psutilLinuxBak = "%s_%s" % (psutilLinux, pythonVer)
    psutilPosixBak = "%s_%s" % (psutilPosix, pythonVer)

    glo_cmd = "rm -rf '%s' && cp -r '%s' '%s' " % (psutilLinux,
                                                   psutilLinuxBak,
                                                   psutilLinux)
    glo_cmd += " && rm -rf '%s' && cp -r '%s' '%s' " % (psutilPosix,
                                                        psutilPosixBak,
                                                        psutilPosix)
    psutilFlag = True
    for psutilnum in range(3):
        (status_mvPsutil, output_mvPsutil) = subprocess.getstatusoutput(
            glo_cmd)
        if status_mvPsutil != 0:
            psutilFlag = False
            time.sleep(1)
        else:
            psutilFlag = True
            break
    if not psutilFlag:
        print("Failed to execute cmd: %s. Error:\n%s" % (glo_cmd,
                                                         output_mvPsutil))
        sys.exit(1)
    # del error import and reload psutil
    del sys.modules['psutil._common']
    del sys.modules['psutil._psposix']
    import psutil



g_failed_address_list = []
g_lock = _thread.allocate_lock()


class NetUtil(object):
    """net util"""

    @staticmethod
    def GetHostIpOrName():
        """
        function: Obtaining the local IP address
        input: NA
        output: NA
        """
        env_dist = os.environ
        if "HOST_IP" not in list(env_dist.keys()):
            return NetUtil.getHostName()
        host_ip = env_dist.get("HOST_IP")
        if host_ip is not None and NetUtil.isIpValid(host_ip):
            return host_ip
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
        except Exception as e:
            raise e
        return host_ip

    @staticmethod
    def getHostName():
        """
        function : Get host name
        input : NA
        output: string
        """
        host_cmd = CmdUtil.findCmdInPath("hostname")
        (status, output) = subprocess.getstatusoutput(host_cmd)
        # if cmd failed, then exit
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % "host name"
                            + "The cmd is %s" % host_cmd)
        return output

    @staticmethod
    def isIpValid(ip_address):
        """
        function : check if the input ip address is valid
        input : String
        output : bool
        """
        Valid = re.match(r"^(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|"
                         r"[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9]["
                         r"0-9]"
                         r"|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9]"
                         r"[0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|"
                         r"[1-9][0-9]|[0-9])$", ip_address)
        return Valid and Valid.group() == ip_address

    @staticmethod
    def executePingCmd(ip_address):
        """
        function : Send the network command of ping.
        input : String
        output : NA
        """
        ping_cmd = CmdUtil.getPingCmd(ip_address, "5", "1")
        cmd = "%s | %s ttl | %s -l" % (ping_cmd, CmdUtil.getGrepCmd(),
                                       CmdUtil.getWcCmd())
        (status, output) = subprocess.getstatusoutput(cmd)
        if str(output) == '0' or status != 0:
            g_lock.acquire()
            g_failed_address_list.append(ip_address)
            g_lock.release()

    @staticmethod
    def checkIpAddressList(ip_address_list):
        """
        function : Check the connection status of network.
        input : []
        output : []
        """
        global g_failed_address_list
        g_failed_address_list = []
        parallelTool.parallelExecute(NetUtil.executePingCmd, ip_address_list)
        return g_failed_address_list

    @staticmethod
    def getAllNetworkIp():
        """
        function: get All network ip
        """
        network_info_list = []
        mapping_list = NetUtil.getIpAddressAndNICList()
        for onelist in mapping_list:
            data = NetworkInfo()
            # NIC number
            data.NICNum = onelist[0]
            # ip address
            data.ipAddress = onelist[1]
            network_info_list.append(data)
        return network_info_list

    @staticmethod
    def getIpAddressAndNICList(ip_type="ipv4"):
        """
        function: get ip address and nicList
        input:  ip_type
        output: []
        """
        return list(NetUtil.getIpAddressAndNIC(ip_type))

    @staticmethod
    def getIpAddressAndNIC(ip_type="ipv4"):
        """
        function: get ip address and nic
        input:  ip_type
        output: NA
        """
        if ip_type == "ipv4":
            key = AF_INET
        else:
            key = AF_INET6

        for iface in interfaces():
            if key in ifaddresses(iface):
                ip_address = ifaddresses(iface)[key][0]['addr']
                yield (iface, ip_address)

    @staticmethod
    def getHostNameByIPAddr(ip_address):
        """
        function: get host name by ip addr
        input:  ip_address
        output: str
        """
        return socket.gethostbyaddr(ip_address)[0]

    @staticmethod
    def getNetworkBondModeByBondConfigFile(bonding_conf_file):
        """
        function: get Network Bond Mode By Bond ConfigFile
        input:  bonding_conf_file
        output: str
        """
        # Check the bond mode
        cmd = "%s -w '\<Bonding Mode\>' %s | %s  -F ':' '{print $NF}'" % (
            CmdUtil.getGrepCmd(), bonding_conf_file, CmdUtil.getAwkCmd())
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)
        return "BondMode %s" % output.strip()

    @staticmethod
    def getNetworkBondModeInfo(network_conf_file, network_card_num):
        """
        function: get Network Bond Mode Info
        input: network_conf_file, network_card_num
        output: str
        """
        # Get the bond profile
        if not os.path.isfile(network_conf_file):
            return "BondMode Null"

        bonding_conf_file = "/proc/net/bonding/%s" % (network_card_num)
        cmd = "%s -i 'BONDING_OPTS\|BONDING_MODULE_OPTS' %s" % (
            CmdUtil.getGrepCmd(), network_conf_file)
        output = subprocess.getstatusoutput(cmd)[1]
        # Analysis results
        if output.strip() != "":
            if (output.find("mode") > 0) and os.path.exists(bonding_conf_file):
                bond_info = NetUtil.getNetworkBondModeByBondConfigFile(
                    bonding_conf_file)
            else:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                                " Error: \n%s " % output)
        elif os.path.exists(bonding_conf_file):
            bond_info = NetUtil.getNetworkBondModeByBondConfigFile(bonding_conf_file)
            bond_info += "\nNo 'BONDING_OPTS' or \
            'BONDING_MODULE_OPTS' in bond config file[%s]." % network_conf_file
        else:
            bond_info = "BondMode Null"
        return bond_info

    @staticmethod
    def getNetworkMaskByNICNum(network_card_num, ip_type="ipv4"):
        """
        function: get Network Mask By NICNum
        input:  network_card_num, ip_type
        output: str
        """
        if ip_type == "ipv4":
            return ifaddresses(network_card_num)[AF_INET][0]["netmask"]
        else:
            return ifaddresses(network_card_num)[AF_INET6][0]["netmask"]

    @staticmethod
    def getNetworkRXTXValueByNICNum(network_card_num, value_type):
        """
        function: get Network RXTX Value By NICNum
        input:  network_card_num, value_type
        output: int
        """
        cmd = "%s -g %s | %s '%s:' | %s -n 1" % (CmdUtil.getEthtoolCmd(),
                                                 network_card_num,
                                                 CmdUtil.getGrepCmd(),
                                                 value_type.upper(),
                                                 CmdUtil.getTailCmd())
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)
        value = output.split(':')[-1].split(' ')[0].strip()
        if not str(value).isdigit():
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)
        return int(value)

    @staticmethod
    def getNetworkSpeedByNICNum(network_card_num):
        """
        function: get Network Speed By NICNum
        input:  network_card_num
        output: int
        """
        key_word = "Speed: "
        speed_unit = "Mb/s"
        cmd = "%s %s | grep '%s'" % (CmdUtil.getEthtoolCmd(),
                                     network_card_num, key_word)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or output == "":
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)
        if len(output.split('\n')) >= 1:
            for line in output.split('\n'):
                if line.find(key_word) >= 0 and line.find(speed_unit) >= 0:
                    return int(line.split(':')[-1].strip()[:-4])
        return 0

    @staticmethod
    def getNetworkConfigFileByNICNum(network_card_num):
        """
        function: get linux network config file
        input:  network_conf_path, network_card_num
        output: str
        """
        network_conf_path = g_Platform.getNetWorkConfPath()
        network_conf_file = "%sifcfg-%s" % (network_conf_path, network_card_num)
        # Network configuration file does not exist
        if not os.path.exists(network_conf_file):
            cmd = "%s %s -iname 'ifcfg-*-%s' -print" % (CmdUtil.getFindCmd(),
                                                        network_conf_file,
                                                        network_card_num)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0 or output.strip() == ""
                    or len(output.split('\n')) != 1):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] %
                                network_conf_file + "The cmd is %s" % cmd)
            network_conf_file = output.strip()
        return network_conf_file

    @staticmethod
    def getAllNetworkInfo():
        """
        function: get all network info
        """
        network_info_list = []
        mapping_list = NetUtil.getIpAddressAndNICList()
        for one_list in mapping_list:
            data = NetworkInfo()
            # NIC number
            data.NICNum = one_list[0]
            # ip address
            data.ipAddress = one_list[1]

            # host name
            try:
                data.hostName = NetUtil.getHostNameByIPAddr(
                    data.ipAddress)
            except Exception:
                data.hostName = ""

            # network mask
            try:
                data.networkMask = NetUtil.getNetworkMaskByNICNum(
                    data.NICNum)
            except Exception:
                data.networkMask = ""

            # MTU value
            try:
                data.MTUValue = psutil.net_if_stats()[data.NICNum].mtu
            except Exception:
                data.MTUValue = ""

            # TX value
            try:
                data.TXValue = NetUtil.getNetworkRXTXValueByNICNum(
                    data.NICNum, 'tx')
            except Exception:
                data.TXValue = ""

            # RX value
            try:
                data.RXValue = NetUtil.getNetworkRXTXValueByNICNum(
                    data.NICNum, 'rx')
            except Exception:
                data.RXValue = ""

            # network speed
            try:
                data.networkSpeed = NetUtil.getNetworkSpeedByNICNum(
                    data.NICNum)
            except Exception:
                data.networkSpeed = ""

            # network config file
            try:
                data.networkConfigFile = \
                    NetUtil.getNetworkConfigFileByNICNum(data.NICNum)
            except Exception:
                data.networkConfigFile = ""

            # network bond mode info
            try:
                data.networkBondModeInfo = NetUtil.getNetworkBondModeInfo(
                    data.networkConfigFile, data.NICNum)
            except Exception:
                data.networkBondModeInfo = ""

            network_info_list.append(data)
        return network_info_list

    @staticmethod
    def getLocalIp():
        """
        function: Obtaining the local IP address
        input: NA
        output: str
        """
        try:
            env_dist = os.environ
            if "HOST_IP" not in list(env_dist.keys()):
                host_name = NetUtil.getHostName()
                return host_name
            host_ip = env_dist.get("HOST_IP")
            if host_ip is not None:
                if NetUtil.isIpValid(host_ip):
                    return host_ip
            host_ip = socket.gethostbyname(socket.gethostname())
        except Exception as e:
            raise Exception(str(e))
        return host_ip

    @staticmethod
    def checkBondMode(bonding_conf_file, is_check_os=True):
        """
        function : Check Bond mode
        input  : String, bool
        output : List
        """
        net_name_list = []

        SecurityChecker.check_injection_char(bonding_conf_file)

        cmd = "grep -w 'Bonding Mode' %s | awk  -F ':' '{print $NF}'" % bonding_conf_file
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or output.strip() == "":
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50611"] + " Error: \n%s" % output)
        if is_check_os:
            print("BondMode %s" % output.strip())
        cmd = "grep -w 'Slave Interface' %s | awk  -F ':' '{print $NF}'" % bonding_conf_file
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50611"] + " Error: \n%s" % output)
        for networkname in output.split('\n'):
            net_name_list.append(networkname.strip())
        return net_name_list

    @staticmethod
    def getNetWorkBondFlag(network_card_num):
        """
         function: Check if the network interface card number is bondCard by psutil module
         input: network interface card number
         output: FLAG, netcardList
         """
        try:
            flag = False
            nic_addr = ""
            netcard_list = []
            net_work_info = psutil.net_if_addrs()
            for snic in net_work_info[network_card_num]:
                if snic.family == 17:
                    nic_addr = snic.address
            if nic_addr == "":
                return flag, netcard_list
            for net_num in list(net_work_info.keys()):
                if net_num == network_card_num:
                    continue
                for net_info in net_work_info[net_num]:
                    if net_info.address == nic_addr:
                        netcard_list.append(net_num)
            if len(netcard_list) >= 2:
                flag = True
                for net_num in netcard_list:
                    cmd = "ip link | grep '%s'" % net_num
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if status != 0:
                        raise Exception((ErrorCode.GAUSS_514["GAUSS_51400"] %
                                         cmd) + "\nError: %s" % output)
                    if str(output).find("master %s" % network_card_num) == -1:
                        flag = False
                        netcard_list = []
                        break
            return flag, netcard_list
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] % (
                        "if the netcardNum[%s] is bondCard" % network_card_num)
                            + " Error: \n%s" % str(e))

    @staticmethod
    def getNICNum(ip_address):
        """
        function: Obtain network interface card number by psutil module
        input: ip_address
        output: netWorkNum
        """
        try:
            net_work_num = ""
            net_work_info = psutil.net_if_addrs()
            for nic_num in list(net_work_info.keys()):
                net_info = net_work_info[nic_num][0]
                if net_info.address == ip_address:
                    net_work_num = nic_num
                    break
            if net_work_num == "":
                raise Exception(ErrorCode.GAUSS_506["GAUSS_50604"] % ip_address)
            return net_work_num
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50604"] % ip_address +
                            " Error: \n%s" % str(excep))

    @staticmethod
    def getIpAddressList():
        """
        Get IP address list
        """
        # Obtain all Ips by psutil module
        try:
            ip_address_list = []
            net_work_info = psutil.net_if_addrs()
            for per_num in net_work_info.keys():
                net_info = net_work_info[per_num][0]
                if len(net_info.address.split('.')) == 4:
                    ip_address_list.append(net_info.address)
            if len(ip_address_list) == 0:
                raise Exception(ErrorCode.GAUSS_506["GAUSS_50616"])
            return ip_address_list
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_506["GAUSS_50616"] +
                            " Error: \n%s" % str(excep))

    @staticmethod
    def getNetworkConfiguredFile(ip):
        """
        function: get network configuration file for RHEL
        input: ip
        output: networkFile
        """
        pattern = re.compile("ifcfg-.*:.*")
        network_file = ""
        # network scripts file for RHEL
        REDHAT_NETWORK_PATH = "/etc/sysconfig/network-scripts"
        try:
            for filename in os.listdir(REDHAT_NETWORK_PATH):
                result = pattern.match(filename)
                if result is None:
                    continue
                paramfile = "%s/%s" % (REDHAT_NETWORK_PATH,
                                       filename)
                with open(paramfile, "r") as fp:
                    file_info = fp.readlines()
                # The current opened file is generated while configing
                # virtual IP,
                # there are 3 lines in file, and the second line is IPADDR=IP
                if len(file_info) == 3 and \
                        file_info[1].find("IPADDR=%s" % ip) >= 0:
                    network_file += "%s " % paramfile
            return network_file
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            "network configuration file" +
                            " Error: \n%s " % str(e))
