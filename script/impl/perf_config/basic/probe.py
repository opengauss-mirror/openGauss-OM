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
# Description  : probe.py setup a base class model for organizing information
#############################################################################


from impl.perf_config.basic.project import Project


class ProbeNotebook(object):
    """
    A notepad, an organization pattern of key-value pairs,
    used to record some information at any time.
    """
    def __init__(self):
        self._notebook = {}

    def read(self, title):
        return self._notebook.get(title)

    def write(self, title, content):
        self._notebook[title] = content

    def delete(self, title):
        if self._notebook.get(title) is None:
            return
        return self._notebook.pop(title)


class Probe(object):
    """
    This is a base class for any probes.
    It's essentially a collection of information. A class of information is
    stored or an interface for obtaining information.

    There is also a built-in notebook, which is convenient to record something
     at any time.
    """
    def __init__(self, probe_name=''):
        """
        :param probe_name:
        """
        Project.log('Probe init <Class {0}> {1}'.format(self.__class__.__name__, probe_name))
        self.probe_name = probe_name
        self.notebook = ProbeNotebook()

    def detect(self):
        """
        detect some perf information
        :return:
        """
        assert False, 'Subclass must override this function.'

    def refresh(self):
        self.detect()


class ProbeGroup(Probe):
    """
    Similar to TunerGroup, this is a component that manages probe groups.
    """
    def __init__(self, probe_name=''):
        super(ProbeGroup, self).__init__(probe_name)
        self._sub_probe_groups = []

    def add(self, sub_probe):
        """

        :param sub_probe:
        :return:
        """
        self._sub_probe_groups.append(sub_probe)
        return sub_probe

    def detect(self):
        """
        detect performance information for subset
        :return:
        """
        for sub in self._sub_probe_groups:
            sub.detect()

    def refresh(self):
        self.detect()
