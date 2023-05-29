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
批量生成基准校验地图

用法：
    1、下载openGauss bz2安装包，保存至任意位置，可放多个包。
            - 举例 /data/pkg/openGauss-5.0.0-openEuler-64bit.tar.gz
                   /data/pkg/openGauss-5.1.0-openEuler-64bit.tar.gz
            
    2、执行本脚本： python StandardVmapGen.py path port [ no-clean ]
            - path: 安装包所在路径：/data/pkg
            - port: 为提供临时安装运行openGauss所用，如 16666
            - no-clean: 不清理临时安装环境，此时port会+5以间隔
    
    基准vmap会自动生成到安装包所在路径。
"""

import os
import sys
import time

sys.path.append(sys.path[0] + '/../..')
from upgrade_checker.utils.version import UPGRADE_CHECKER_VERSION
from upgrade_checker.utils.param import Param
from upgrade_checker.project import ExportProj
from upgrade_checker.rules.vmap import VerifyMap
from upgrade_checker.dev.og_controller import OGController


class FakeParam(Param):
    """
    运行一个导出操作所需要的参数
    """
    def __init__(self, port):
        fake_root = sys.path[0] + '/..'
        super(FakeParam, self).__init__(fake_root, ['', 'export', '-p', str(port)])


class FakeExportProj(ExportProj):
    """
    导出工程，将导出位置、文件名称进行修改，改成我们想要的位置和名称格式
    """
    def __init__(self, port, og_version, export_dir):
        super(FakeExportProj, self).__init__(FakeParam(port))
        self.export_dir = export_dir
        standard_vmap_name = VerifyMap.standard_name(UPGRADE_CHECKER_VERSION, og_version)
        self.vmap = '{0}/{1}'.format(self.export_dir, standard_vmap_name)


class VmapGen(object):
    """
    Vmap生成器。批量安装openGauss包，并生成vmap
    """
    def __init__(self, package_path, port, clean):
        """
        :param package_path: 存放了openGauss bz2安装包的路径
        :param port: 用于临时安装运行openGauss的端口
        :param clean: 清理临时安装环境
        """
        self.package_path = package_path
        self.port = port
        self.clean = clean
        
    def run(self):
        files = os.listdir(self.package_path)
        vmaps = []
        for f in files:
            pkg = self.package_path + '/' + f
            support, msg = OGController.is_support_package(pkg)
            if not support:
                print('\n[跳过文件或文件夹]:', msg)
                continue
            
            print('\n[开始执行第{}个任务]'.format(len(vmaps) + 1))
            og = OGController(pkg)
            og.install()
            og.initdb()
            og.guc('port = {0}'.format(self.port))
            og.guc('enable_wdr_snapshot = on')
            og.start()
            time.sleep(2)
            
            proj = FakeExportProj(self.port, og.version, self.package_path)
            proj.init()
            proj.run()
            vmap = proj.close()
            vmaps.append(vmap)
            
            if self.clean:
                og.stop()
                og.uninstall()
            else:
                self.port += 5

            print('第{0}个任务执行完成，输出vmap: {1}'.format(len(vmaps), vmap))
        
        print('\n批量共生成{0}个vmap'.format(len(vmaps)))
        print('\n'.join(vmaps))
        
        
if __name__ == '__main__':
    argv_pkg_path = sys.argv[1]
    argv_port = int(sys.argv[2])
    argv_clean = False if len(sys.argv) > 3 and sys.argv[3].lower() == 'no-clean' else True
    VmapGen(argv_pkg_path, argv_port, argv_clean).run()

