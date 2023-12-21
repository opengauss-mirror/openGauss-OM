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

from impl.perf_config.basic.guc import GucMap, GUCTuneGroup


class StmtBehaviorGUC(GUCTuneGroup):
    def __init__(self):
        super(StmtBehaviorGUC, self).__init__()
        self.search_path = self.bind('search_path')
        self.current_schema = self.bind('current_schema')
        self.default_tablespace = self.bind('default_tablespace')
        self.temp_tablespaces = self.bind('temp_tablespaces')
        self.check_function_bodies = self.bind('check_function_bodies')
        self.session_replication_role = self.bind('session_replication_role')
        self.statement_timeout = self.bind('statement_timeout')
        self.bytea_output = self.bind('bytea_output')
        self.xmlbinary = self.bind('xmlbinary')
        self.xmloption = self.bind('xmloption')
        self.max_compile_functions = self.bind('max_compile_functions')
        self.gin_pending_list_limit = self.bind('gin_pending_list_limit')

    def calculate(self):
        pass


class VersionCompatibilityGUC(GUCTuneGroup):
    def __init__(self):
        super(VersionCompatibilityGUC, self).__init__()
        self.array_nulls = self.bind('array_nulls')
        self.backslash_quote = self.bind('backslash_quote')
        self.escape_string_warning = self.bind('escape_string_warning')
        self.lo_compat_privileges = self.bind('lo_compat_privileges')
        self.quote_all_identifiers = self.bind('quote_all_identifiers')
        self.sql_inheritance = self.bind('sql_inheritance')
        self.standard_conforming_strings = self.bind('standard_conforming_strings')
        self.synchronize_seqscans = self.bind('synchronize_seqscans')
        self.enable_beta_features = self.bind('enable_beta_features')
        self.default_with_oids = self.bind('default_with_oids')

    def calculate(self):
        self.enable_beta_features.turn_on()


class EnvCompatibilityGUC(GUCTuneGroup):
    def __init__(self):
        super(EnvCompatibilityGUC, self).__init__()
        self.convert_string_to_digit = self.bind('convert_string_to_digit')
        self.nls_timestamp_format = self.bind('nls_timestamp_format')
        self.group_concat_max_len = self.bind('group_concat_max_len')
        self.max_function_args = self.bind('max_function_args')
        self.transform_null_equals = self.bind('transform_null_equals')
        self.support_extended_features = self.bind('support_extended_features')
        self.sql_compatibility = self.bind('sql_compatibility')
        self.b_format_behavior_compat_options = self.bind('b_format_behavior_compat_options')
        self.enable_set_variable_b_format = self.bind('enable_set_variable_b_format')
        self.behavior_compat_options = self.bind('behavior_compat_options')
        self.plsql_compile_check_options = self.bind('plsql_compile_check_options')
        self.td_compatible_truncation = self.bind('td_compatible_truncation')
        self.uppercase_attribute_name = self.bind('uppercase_attribute_name')
        self.lastval_supported = self.bind('lastval_supported')
        self.character_set_connection = self.bind('character_set_connection')
        self.collation_connection = self.bind('collation_connection')

    def calculate(self):
        pass

