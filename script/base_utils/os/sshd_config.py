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
# Description  : sshd config file operation.
#############################################################################

import subprocess
import os

from gspylib.common.ErrorCode import ErrorCode


def get_ssh_config_path():
    ssh_config = os.path.expanduser("~/.ssh/config")
    if os.path.exists(ssh_config):
        return ssh_config
    return ""

def read_ssh_config(ssh_config):
    with open(ssh_config, 'r') as file:
        return file.read()

def find_port_for_host(content, host):
    host_blocks = content.split('Host ')
    for block in host_blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue
        current_host = lines[0].strip()
        if current_host == host:
            return extract_port_from_lines(lines[1:])
    return ""

def extract_port_from_lines(lines):
    for line in lines:
        line = line.strip()
        if line.startswith('Port '):
            return int(line.split(' ', 1)[1].strip())
    return ""

class SshdConfig:
    """
    sshd config file operation
    """
    DEFAULT_SSH_PORT = 22

    def __init__(self):
        pass

    @staticmethod
    def setKeyValueInSshd(key, value):
        """
        function: Set a (key, value) pair into /etc/ssh/sshd_config,
        before "Match" section.
                "Match" section in sshd_config should always places in the end.
                Attention: you need to remove the old (key, value)
                from sshd_config manually.
        input:
            key: the configuration name of sshd_config
            value: the configuration value(Only single line string
            permitted here).
        output:
            void
        """
        sshd_config = '/etc/ssh/sshd_config'
        cmd = "grep -E '^\<Match\>' %s" % sshd_config
        (status, output) = subprocess.getstatusoutput(cmd)

        if status == 0:
            cmd = "sed -i '/^\<Match\>.*/i %s %s' %s" % (key, value,
                                                         sshd_config)
        else:
            if output is not None and len(output.strip()) != 0:
                raise Exception(ErrorCode.GAUSS_503["GAUSS_50321"] %
                                "Match section" + "Command: %s, Error: %s" %
                                (cmd, output))
            cmd = "echo '' >> %s ; echo '%s %s' >> %s" % (sshd_config,
                                                          key, value,
                                                          sshd_config)

        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception((ErrorCode.GAUSS_503["GAUSS_50320"] % (key, value)) + ("Command: %s, Error: %s" % (cmd, output)))

    @staticmethod
    def get_ssh_port_for_host(host):
        """
        function : Get the cluster's node ssh port from config.
        input : NA
        output : NA
        """
        ssh_config = get_ssh_config_path()
        if not ssh_config:
            return ""
        content = read_ssh_config(ssh_config)
        return find_port_for_host(content, host)

    @staticmethod
    def get_ssh_ports_for_hosts(hosts):
        """
        function : Get the cluster's node ssh port from config file.
        input : NA
        output : NA
        """
        ssh_ports_map = {}
        for host in hosts:
            ssh_port = SshdConfig.get_ssh_port_for_host(host)
            ssh_ports_map[host] = ssh_port if ssh_port else SshdConfig.DEFAULT_SSH_PORT
        return ssh_ports_map
