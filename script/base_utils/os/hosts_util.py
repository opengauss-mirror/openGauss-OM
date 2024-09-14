import os
import _thread
import ipaddress
import socket

from base_utils.os.file_util import FileUtil
from gspylib.common.ErrorCode import ErrorCode

class HostsUtil:

    @staticmethod
    def get_ip_by_hostname_from_etc_hosts(hostname):
        """
        function: get hostname from /etc/hosts
        input: ip
        output: hostname
        """
        try:
            host_ip = socket.gethostbyname(hostname)
            if host_ip == "127.0.0.1":
                return ""
        except Exception as e:
            host_ip = ""
        return host_ip
    
    @staticmethod
    def get_hostname_by_ip_from_etc_hosts(ip):
        """
        function: get hostname from /etc/hosts
        input: ip
        output: ip
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname == "localhost":
                return ""
        except Exception as e:
            hostname = ""
        return hostname

    @staticmethod
    def hostname_to_ip(hostname):
        """
        function: get ip from hostname
        input: hostname
        output: ip
        """
        # get ip from /etc/hosts
        host_ip = HostsUtil.get_ip_by_hostname_from_etc_hosts(hostname)
        if host_ip:
            return host_ip
        
        # get ip from custom hosts file
        ip_str = ""
        hosts_file = FileUtil.get_hosts_file()
        contents = HostsUtil.read_hosts_file(hosts_file)
        for ip, name in contents.items():
            if name == hostname:
                ip_str = ip
                return ip_str
        # if not found ip, return hostname
        if ip_str == "":
            return hostname

    @staticmethod 
    def hostname_list_to_ip_list(hostname_list):
        if not hostname_list:
            return []
        # get ip from /etc/hosts
        ip_list = []
        for hostname in hostname_list:
            host_ip = HostsUtil.hostname_to_ip(hostname)
            if host_ip:
                ip_list.append(host_ip)
        if len(ip_list) == len(hostname_list):
            return ip_list

        ip_list = []
        # get ip from custom hosts file
        hosts_file = FileUtil.get_hosts_file()
        if not os.path.isfile(hosts_file):
            raise Exception("hosts file is not exist")
        # key:value name:ip
        contents = HostsUtil.read_hosts_file(hosts_file)
        for hostname in hostname_list:
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

        # get hostname from /etc/hosts
        hostname = HostsUtil.get_hostname_by_ip_from_etc_hosts(host_ip)
        if hostname:
            return hostname

        hosts_file = FileUtil.get_hosts_file()
        if not os.path.isfile(hosts_file):
            raise Exception("hosts file is not exist")
        contents = HostsUtil.read_hosts_file(hosts_file)
        name = ""
        for ip, hostname in contents.items():
            if host_ip == ip:
                name = hostname
                return name
        if name == "":
            return host_ip
        
    @staticmethod
    def read_hosts_file(path, mode='r'):
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        
        content = {}
        with open(path, mode) as f:
            for line in f.readlines():
                if len(line.strip().split()) != 2:
                    raise Exception("Error: %s format error" % path)
                ip = line.strip().split()[0]
                hostname = line.strip().split()[1]
                content[ip] = hostname
        return content
    
    @staticmethod
    def write_hosts_file(path, content=None, mode='w'):
        lock = _thread.allocate_lock()
        if content is None:
            content = {}
        # check if not exists.
        if not os.path.exists(path):
            FileUtil.createFileInSafeMode(path)
        # check if is a file.
        if os.path.exists(path) and not os.path.isfile(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % path)
        # if no context, return
        if not content:
            return False
        
        try:
            with open(path, mode) as f:
                lock.acquire()
                for ip_xml, hostname in content.items():
                    # Use the compressed format of the IP.
                    ip = ipaddress.ip_address(ip_xml).compressed
                    f.write("%s %s" % (ip, hostname) + os.linesep)
                # write context.
                f.flush()
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % path +
                            "Error:\n%s" % str(excep))
        finally:
            lock.release()
        return True
    