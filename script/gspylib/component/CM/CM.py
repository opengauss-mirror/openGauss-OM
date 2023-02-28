# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
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
#############################################################################
try:
    import sys

    sys.path.append(sys.path[0] + "/../../../")
    from gspylib.component.BaseComponent import BaseComponent
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class CM(BaseComponent):
    '''
    The class is used to define cluster manager component.
    '''

    def __init__(self):
        '''
        Constructor
        '''
        super(CM, self).__init__()
        self.timeout = 300
        self.level = 2


class CmResAttr():

    def __init__(self, script, res_type='DN'):
        self.resources_type = res_type
        self.script = script
        self.check_interval = 1
        self.time_out = 120
        self.restart_times = 5
        self.restart_delay = 1
        self.restart_period = 1

    def __str__(self):
        return str(vars(self)).replace(":", '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"')


class DssInstAttr():

    def __init__(self, node_id, dss_id, dss_home):
        self.node_id = node_id
        self.res_instance_id = dss_id
        self.res_args = dss_home

    def __str__(self):
        return str(vars(self)).replace(":", '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"').replace(';', ' ')


class VipResAttr():
    """
    VIP resource attribute
    """
    def __init__(self, float_ip):
        self.resources_type = "VIP"
        self.float_ip = float_ip

    def __str__(self):
        return str(vars(self)).replace(':', '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"').replace(';', ' ')


class VipInstAttr():
    """
    VIP instance attribute
    """
    def __init__(self, base_ip):
        self.base_ip = base_ip

    def __str__(self):
        return str(vars(self)).replace(':', '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"').replace(';', ' ')


class VipAddInst():
    """
    VIP add instance attribute
    """
    def __init__(self, res_instance_id, node_id):
        self.node_id = node_id
        self.res_instance_id = res_instance_id

    def __str__(self):
        return str(vars(self)).replace(':', '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"').replace(';', ' ')


class VipDelInst():
    """
    VIP del instance attribute
    """
    def __init__(self, res_instance_id):
        self.res_instance_id = res_instance_id

    def __str__(self):
        return str(vars(self)).replace(':', '=').replace('\'', '').replace(
            ' ', '').replace('{', '"').replace('}', '"').replace(';', ' ')


class CmResCtrlCmd():

    def __init__(self, action='add', name='', attr=''):
        self.action = action
        self.attr_name = name
        self.attr = attr

    def __str__(self):
        cmd = ''
        if self.action == 'add':
            cmd = 'cm_ctl res --add --res_name {} --res_attr={}'.format(
                  self.attr_name, self.attr)
        elif self.action == 'edit':
            cmd = 'cm_ctl res --edit --res_name {} --add_inst={}'.format(
                  self.attr_name, self.attr)
        return cmd


class VipCmResCtrlCmd():
    """
    VipCmResCtrlCmd
    """
    def __init__(self, action, name, inst="", attr=""):
        self.action = action
        self.name = name
        self.inst = inst
        self.attr = attr

    def __str__(self):
        cmd = ""
        if self.action == "add_res":
            cmd = "cm_ctl res --add --res_name=\"%s\" --res_attr=%s" % \
                  (self.name, self.attr)
        elif self.action == "del_res":
            cmd = "cm_ctl res --del --res_name=\"%s\"" % self.name
        elif self.action == "add_inst":
            cmd = "cm_ctl res --edit --res_name=\"%s\" --add_inst=%s --inst_attr=%s" % \
                  (self.name, self.inst, self.attr)
        elif self.action == "del_inst":
            cmd = "cm_ctl res --edit --res_name=\"%s\" --del_inst=%s" % \
                  (self.name, self.inst)
        return cmd
