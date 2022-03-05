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
# Description  : os version info.
#############################################################################

import os
import re

from os_platform.common import _supported_dists


class LinuxDistro(object):
    """
    replace expired func linux_distribution
    """
    @staticmethod
    def _parse_release_file(num1_line):
        """
        Default to empty 'version' and 'id' strings.  Both defaults are used
        when 'num1_line' is empty.  'id' defaults to empty when an id can not
        be deduced.
        """
        version = ''
        id_num = ''

        # Parse the first line
        _hw_publish_version = re.compile(r'(.+)'
                                          ' release '
                                          '([\d.]+)'
                                          '[^(]*(?:\((.+)\))?')
        implication = _hw_publish_version.match(num1_line)
        if implication is not None:
            # LSB format: "distro release x.x (codename)"
            return tuple(implication.groups())

        # Pre-LSB format: "distro x.x (codename)"
        _publish_version = re.compile(r'([^0-9]+)'
                                      '(?: release )?'
                                      '([\d.]+)'
                                      '[^(]*(?:\((.+)\))?')
        implication = _publish_version.match(num1_line)
        if implication is not None:
            return tuple(implication.groups())

        line = num1_line.strip().split()
        if line:
            version = line[0]
            if len(line) > 1:
                id_num = line[1]
        return '', version, id_num

    @staticmethod
    def linux_distribution(distname='', version='', idNum='',
                           supported_dists=_supported_dists,
                           full_distribution_name=0):
        """
        Tries to determine the name of the Linux OS distribution name.

            The function first looks for a distribution release file in
            /etc and then reverts to _dist_try_harder() in case no
            suitable files are found.

            supported_dists may be given to define the set of Linux
            distributions to look for. It defaults to a list of currently
            supported Linux distributions identified by their release file
            name.

            If full_distribution_name is true (default), the full
            distribution read from the OS is returned. Otherwise the short
            name taken from supported_dists is used.

            Returns a tuple (distname,version,id) which default to the
            args given as parameters.

        """
        try:
            etc_dir = os.listdir('/etc')
        except os.error:
            # Probably not a Unix system
            return distname, version, idNum
        etc_dir.sort()
        gFile = None
        _release_filename = re.compile(r'(\w+)[-_](release|version)')
        for file in etc_dir:
            if os.path.islink('/etc/' + file):
                continue
            m = _release_filename.match(file)
            if m is not None:
                _distname, dummy = m.groups()
                if _distname in supported_dists:
                    gFile = file
                    distname = _distname
                    break

        # Read the first line
        if gFile is None:
            return distname, version, idNum
        with open('/etc/' + gFile, 'r') as f:
            firstline = f.readline()
        _distname, _version, _id = LinuxDistro._parse_release_file(firstline)

        if _distname and full_distribution_name:
            distname = _distname
        if _version:
            version = _version
        if _id:
            idNum = _id
        return distname, version, idNum
