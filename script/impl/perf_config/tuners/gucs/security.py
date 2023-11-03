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
# Description  : gs_perfconfg is a utility to optimize system and database configure about openGauss
#############################################################################

from impl.perf_config.basic.project import Project
from impl.perf_config.basic.tuner import Tuner, TunerGroup
from impl.perf_config.basic.guc import GucMap, GUCTuneGroup
from impl.perf_config.probes.business import BsScenario


class SecurityGUC(GUCTuneGroup):
    def __init__(self):
        super(SecurityGUC, self).__init__()
        # connect and timeout
        self.authentication_timeout = self.bind('authentication_timeout')
        self.auth_iteration_count = self.bind('auth_iteration_count')
        self.session_authorization = self.bind('session_authorization')
        self.session_timeout = self.bind('session_timeout')
        self.idle_in_transaction_session_timeout = self.bind('idle_in_transaction_session_timeout')
        # ssl
        self.ssl = self.bind('ssl')
        self.require_ssl = self.bind('require_ssl')
        self.ssl_ciphers = self.bind('ssl_ciphers')
        self.ssl_renegotiation_limit = self.bind('ssl_renegotiation_limit')
        self.ssl_cert_file = self.bind('ssl_cert_file')
        self.ssl_key_file = self.bind('ssl_key_file')
        self.ssl_ca_file = self.bind('ssl_ca_file')
        self.ssl_crl_file = self.bind('ssl_crl_file')
        # krb
        self.krb_server_keyfile = self.bind('krb_server_keyfile')
        self.krb_srvname = self.bind('krb_srvname')
        self.krb_caseins_users = self.bind('krb_caseins_users')
        # password
        self.password_policy = self.bind('password_policy')
        self.password_reuse_time = self.bind('password_reuse_time')
        self.password_reuse_max = self.bind('password_reuse_max')
        self.password_lock_time = self.bind('password_lock_time')
        self.password_encryption_type = self.bind('password_encryption_type')
        self.password_min_length = self.bind('password_min_length')
        self.password_max_length = self.bind('password_max_length')
        self.password_min_uppercase = self.bind('password_min_uppercase')
        self.password_min_lowercase = self.bind('password_min_lowercase')
        self.password_min_digital = self.bind('password_min_digital')
        self.password_min_special = self.bind('password_min_special')
        self.password_effect_time = self.bind('password_effect_time')
        self.password_notify_time = self.bind('password_notify_time')
        self.modify_initial_password = self.bind('modify_initial_password')
        # config
        self.failed_login_attempts = self.bind('failed_login_attempts')
        self.elastic_search_ip_addr = self.bind('elastic_search_ip_addr')
        self.enable_security_policy = self.bind('enable_security_policy')
        self.use_elastic_search = self.bind('use_elastic_search')
        self.is_sysadmin = self.bind('is_sysadmin')
        self.enable_tde = self.bind('enable_tde')
        self.tde_cmk_id = self.bind('tde_cmk_id')
        self.block_encryption_mode = self.bind('block_encryption_mode')
        self.enableSeparationOfDuty = self.bind('enableSeparationOfDuty')
        self.enable_nonsysadmin_execute_direct = self.bind('enable_nonsysadmin_execute_direct')
        self.enable_access_server_directory = self.bind('enable_access_server_directory')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.ssl.turn_off()
            self.enable_security_policy.turn_off()
            self.use_elastic_search.turn_off()
            self.enable_tde.turn_off()
            self.enableSeparationOfDuty.turn_off()


class AuditGUC(GUCTuneGroup):
    def __init__(self):
        super(AuditGUC, self).__init__()
        self.audit_enabled = self.bind('audit_enabled')
        self.audit_directory = self.bind('audit_directory')
        self.audit_data_format = self.bind('audit_data_format')
        self.audit_rotation_interval = self.bind('audit_rotation_interval')
        self.audit_rotation_size = self.bind('audit_rotation_size')
        self.audit_resource_policy = self.bind('audit_resource_policy')
        self.audit_file_remain_time = self.bind('audit_file_remain_time')
        self.audit_space_limit = self.bind('audit_space_limit')
        self.audit_file_remain_threshold = self.bind('audit_file_remain_threshold')
        self.audit_thread_num = self.bind('audit_thread_num')

        self.audit_login_logout = self.bind('audit_login_logout')
        self.audit_database_process = self.bind('audit_database_process')
        self.audit_user_locked = self.bind('audit_user_locked')
        self.audit_user_violation = self.bind('audit_user_violation')
        self.audit_grant_revoke = self.bind('audit_grant_revoke')
        self.full_audit_users = self.bind('full_audit_users')
        self.no_audit_client = self.bind('no_audit_client')

        self.audit_system_object = self.bind('audit_system_object')
        self.audit_dml_state = self.bind('audit_dml_state')
        self.audit_dml_state_select = self.bind('audit_dml_state_select')
        self.audit_function_exec = self.bind('audit_function_exec')
        self.audit_system_function_exec = self.bind('audit_system_function_exec')
        self.audit_copy_exec = self.bind('audit_copy_exec')
        self.audit_set_parameter = self.bind('audit_set_parameter')
        self.audit_xid_info = self.bind('audit_xid_info')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.audit_enabled.turn_off()


