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
# Description  : gs_upgradechk is a utility to check meta data in gaussdb after upgrade.
#############################################################################
"""
快速安装openGauss的bz2
"""

import os
import sys
import time

sys.path.append(sys.path[0] + '/../..')
from upgrade_checker.utils.version import is_support_version
from upgrade_checker.utils.command import Shell
from upgrade_checker.utils.exception import ShellExecException

class OGController(object):

    @staticmethod
    def is_support_package(pkg):
        # openGauss server：openGauss-Server-7.0.0-RC2-openEuler20.03-x86_64.tar.gz
        parts = os.path.basename(pkg).split('-')

        if len(parts) < 5 or parts[0] != 'openGauss' or parts[1] != 'Server':
            return False, '非openGauss server压缩安装包：' + pkg
        
        if not is_support_version(parts[2]):
            return False, '工具不支持的OG版本：' + parts[1]
        
        return True, ''
     
    def __init__(self, package):
        self.package = package
        
        self.gausshome = ''
        self.version = ''
        self.dn = ''
        self.port = ''
        
    def _generate_env(self):
        env = {
            'GAUSSHOME': self.gausshome,
            'PATH': '{0}/bin:{1}'.format(self.gausshome, os.getenv('PATH')),
            'LD_LIBRARY_PATH': '{0}/lib:{1}'.format(self.gausshome, os.getenv('LD_LIBRARY_PATH'))
        }
        
        env_text = ''
        for name, val in env.items():
            os.environ[name] = val
            env_text += 'export {0}={1}\n'.format(name, val)
        
        env_file = '{0}/env.source'.format(self.gausshome)
        with open(env_file, 'w') as f:
            f.write(env_text)
            print('生成环境变量', env_file)
        
        return env, env_file
        
    def install(self):
        pkg_path = os.path.dirname(self.package)
        pkg_name = os.path.basename(self.package)
        self.version = pkg_name.split('-')[1]
        self.gausshome = pkg_path + '/' + self.version
        
        if os.access(self.gausshome, os.F_OK):
            self.dn = self.gausshome + '/dn'
            try:
                self.stop()
            except ShellExecException as e:
                pass

            try:
                self.uninstall()
            except ShellExecException as e:
                pass
        
        os.mkdir(self.gausshome, 0o700)
        
        cmd = 'tar -jxf {0} -C {1}'.format(self.package, self.gausshome)
        Shell.run(cmd, print_desc='解压安装包', check=True)
        
        return self._generate_env()
        
    def initdb(self):
        self.dn = self.gausshome + '/dn'
        cmd = "gs_initdb -D {0} -w Test@123 --nodename='sgnode' >/dev/null 2>&1 ".format(self.dn)
        Shell.run(cmd, print_desc='初始化数据库', check=True)
    
    def guc(self, setting):
        cmd = 'gs_guc reload -D {0} -c "{1}" >/dev/null 2>&1'.format(self.dn, setting)
        Shell.run(cmd, print_desc='设置GUC参数')
    
    def start(self):
        cmd = "gs_ctl start -D {0} >/dev/null 2>&1".format(self.dn)
        Shell.run(cmd, print_desc='启动数据库', check=True)
        
    def stop(self):
        cmd = "gs_ctl stop -D {0} >/dev/null 2>&1 ".format(self.dn)
        Shell.run(cmd, print_desc='关闭数据库', check=True)
        
    def uninstall(self):
        cmd = "rm {0} {1} -fr".format(self.dn, self.gausshome)
        Shell.run(cmd, print_desc='卸载数据库', check=True)
        
if __name__ == "__main__":
    og = OGController('/data/pkg/openGauss-Server-7.0.0-RC2-openEuler20.03-x86_64.tar.bz2')
    og.install()
    og.initdb()
    og.start(16666)
