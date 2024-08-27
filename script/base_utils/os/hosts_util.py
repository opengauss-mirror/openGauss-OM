import os
import re

from base_utils.os.file_util import FileUtil

class HostsUtil:

    @staticmethod
    def hostname_to_ip(hostname):
        """
        function: get ip from hostname
        input: hostname
        output: ip
        """
        ip_str = ""
        hosts_file = FileUtil.get_hosts_file()
        contents = FileUtil.read_hosts_file(hosts_file)
        for ip, name in contents.items():
            if name == hostname:
                ip_str = ip
                return ip_str
        if ip_str == "":
            raise Exception("hostname %s not found in hosts file %s" % (hostname, hosts_file))

    @staticmethod 
    def hostname_list_to_ip_list(host_list):
        if not host_list:
            return []
        hosts_file = FileUtil.get_hosts_file()
        if not os.path.isfile(hosts_file):
            raise Exception("hosts file is not exist")
        # key:value name:ip
        contents = FileUtil.read_hosts_file(hosts_file)
        ip_list = []
        for hostname in host_list:
            for ip, name in contents.items():
                if hostname == name:
                    ip_list.append(ip)
        return ip_list

    @staticmethod
    def ip_to_hostname(host_ip):
        if not host_ip:
            return ""
        if host_ip[:1] == '[' and host_ip[-1:] == ']':
            host_ip = host_ip.strip('[]')

        hosts_file = FileUtil.get_hosts_file()
        if not os.path.isfile(hosts_file):
            raise Exception("hosts file is not exist")
        contents = FileUtil.read_hosts_file(hosts_file)
        name = ""
        for ip, hostname in contents.items():
            if host_ip == ip:
                name = hostname
        if name == "":
            raise Exception("ip to hostname failed,ip is %s" % host_ip)
        return name
    
    