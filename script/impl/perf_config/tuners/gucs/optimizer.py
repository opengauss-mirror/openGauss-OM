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


class OptNodeCostGUC(GUCTuneGroup):
    def __init__(self):
        super(OptNodeCostGUC, self).__init__()
        self.enable_broadcast = self.bind('enable_broadcast')
        self.enable_material = self.bind('enable_material')
        self.enable_sort = self.bind('enable_sort')

        self.enable_bitmapscan = self.bind('enable_bitmapscan')
        self.enable_indexscan = self.bind('enable_indexscan')
        self.enable_indexonlyscan = self.bind('enable_indexonlyscan')
        self.enable_seqscan = self.bind('enable_seqscan')
        self.enable_tidscan = self.bind('enable_tidscan')
        self.force_bitmapand = self.bind('force_bitmapand')
        self.cost_weight_index = self.bind('cost_weight_index')
        self.effective_cache_size = self.bind('effective_cache_size')

        self.enable_hashagg = self.bind('enable_hashagg')
        self.enable_sortgroup_agg = self.bind('enable_sortgroup_agg')
        self.enable_sonic_hashagg = self.bind('enable_sonic_hashagg')

        self.enable_hashjoin = self.bind('enable_hashjoin')
        self.enable_mergejoin = self.bind('enable_mergejoin')
        self.enable_nestloop = self.bind('enable_nestloop')
        self.enable_index_nestloop = self.bind('enable_index_nestloop')
        self.enable_inner_unique_opt = self.bind('enable_inner_unique_opt')
        self.enable_change_hjcost = self.bind('enable_change_hjcost')
        self.enable_sonic_hashjoin = self.bind('enable_sonic_hashjoin')
        self.enable_sonic_optspill = self.bind('enable_sonic_optspill')

        self.enable_vector_engine = self.bind('enable_vector_engine')
        self.enable_vector_targetlist = self.bind('enable_vector_targetlist')
        self.enable_force_vector_engine = self.bind('enable_force_vector_engine')
        self.try_vector_engine_strategy = self.bind('try_vector_engine_strategy')

        self.seq_page_cost = self.bind('seq_page_cost')
        self.random_page_cost = self.bind('random_page_cost')
        self.cpu_tuple_cost = self.bind('cpu_tuple_cost')
        self.cpu_index_tuple_cost = self.bind('cpu_index_tuple_cost')
        self.cpu_operator_cost = self.bind('cpu_operator_cost')
        self.allocate_mem_cost = self.bind('allocate_mem_cost')

        self.var_eq_const_selectivity = self.bind('var_eq_const_selectivity')
        self.cost_param = self.bind('cost_param')

        self.enable_functional_dependency = self.bind('enable_functional_dependency')
        self.default_statistics_target = self.bind('default_statistics_target')
        self.constraint_exclusion = self.bind('constraint_exclusion')

        self.cursor_tuple_fraction = self.bind('cursor_tuple_fraction')
        self.default_limit_rows = self.bind('default_limit_rows')
        self.enable_extrapolation_stats = self.bind('enable_extrapolation_stats')

    def calculate(self):
        pass


class OptRewriteGUC(GUCTuneGroup):
    def __init__(self):
        super(OptRewriteGUC, self).__init__()
        self.qrw_inlist2join_optmode = self.bind('qrw_inlist2join_optmode')
        self.rewrite_rule = self.bind('rewrite_rule')
        self.from_collapse_limit = self.bind('from_collapse_limit')
        self.join_collapse_limit = self.bind('join_collapse_limit')

    def calculate(self):
        pass


class OptPartTableGUC(GUCTuneGroup):
    def __init__(self):
        super(OptPartTableGUC, self).__init__()
        self.enable_valuepartition_pruning = self.bind('enable_valuepartition_pruning')
        self.partition_page_estimation = self.bind('partition_page_estimation')
        self.partition_iterator_elimination = self.bind('partition_iterator_elimination')
        self.enable_partitionwise = self.bind('enable_partitionwise')

    def calculate(self):
        pass


class OptGeqoGUC(GUCTuneGroup):
    def __init__(self):
        super(OptGeqoGUC, self).__init__()
        self.geqo = self.bind('geqo')
        self.geqo_threshold = self.bind('geqo_threshold')
        self.geqo_effort = self.bind('geqo_effort')
        self.geqo_pool_size = self.bind('geqo_pool_size')
        self.geqo_generations = self.bind('geqo_generations')
        self.geqo_selection_bias = self.bind('geqo_selection_bias')
        self.geqo_seed = self.bind('geqo_seed')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.TP_PERFORMANCE:
            self.geqo.turn_off()


class OptCodeGenGUC(GUCTuneGroup):
    def __init__(self):
        super(OptCodeGenGUC, self).__init__()
        self.enable_codegen = self.bind('enable_codegen')
        self.codegen_strategy = self.bind('codegen_strategy')
        self.enable_codegen_print = self.bind('enable_codegen_print')
        self.codegen_cost_threshold = self.bind('codegen_cost_threshold')

    def calculate(self):
        self.enable_codegen.turn_off()


class OptBypassGUC(GUCTuneGroup):
    def __init__(self):
        super(OptBypassGUC, self).__init__()
        self.enable_opfusion = self.bind('enable_opfusion')
        self.enable_partition_opfusion = self.bind('enable_partition_opfusion')
        self.opfusion_debug_mode = self.bind('opfusion_debug_mode')

    def calculate(self):
        self.enable_opfusion.turn_on()
        self.enable_partition_opfusion.turn_on()


class OptExplainGUC(GUCTuneGroup):
    def __init__(self):
        super(OptExplainGUC, self).__init__()
        self.explain_perf_mode = self.bind('explain_perf_mode')
        self.explain_dna_file = self.bind('explain_dna_file')
        self.enable_hypo_index = self.bind('enable_hypo_index')
        self.enable_auto_explain = self.bind('enable_auto_explain')
        self.auto_explain_level = self.bind('auto_explain_level')
        self.show_fdw_remote_plan = self.bind('show_fdw_remote_plan')

    def calculate(self):
        pass


class OptSmpGUC(GUCTuneGroup):
    def __init__(self):
        super(OptSmpGUC, self).__init__()
        self.query_dop = self.bind('query_dop')
        self.enable_seqscan_dopcost = self.bind('enable_seqscan_dopcost')

    def calculate(self):
        infos = Project.getGlobalPerfProbe()
        if infos.business.scenario == BsScenario.AP:
            self.query_dop.set('4')


class OptNgrmGUC(GUCTuneGroup):
    def __init__(self):
        super(OptNgrmGUC, self).__init__()
        self.ngram_gram_size = self.bind('ngram_gram_size')
        self.ngram_grapsymbol_ignore = self.bind('ngram_grapsymbol_ignore')
        self.ngram_punctuation_ignore = self.bind('ngram_punctuation_ignore')

    def calculate(self):
        pass


class OptPbeGUC(GUCTuneGroup):
    def __init__(self):
        super(OptPbeGUC, self).__init__()
        self.enable_pbe_optimization = self.bind('enable_pbe_optimization')
        self.plan_cache_mode = self.bind('plan_cache_mode')

    def calculate(self):
        pass


class OptGlobalPlanCacheGUC(GUCTuneGroup):
    def __init__(self):
        super(OptGlobalPlanCacheGUC, self).__init__()
        self.enable_global_plancache = self.bind('enable_global_plancache')
        self.gpc_clean_timeout = self.bind('gpc_clean_timeout')

    def calculate(self):
        pass


class OptOtherGUC(GUCTuneGroup):
    def __init__(self):
        super(OptOtherGUC, self).__init__()
        self.enable_startwith_debug = self.bind('enable_startwith_debug')

        self.analysis_options = self.bind('analysis_options')
        self.plan_mode_seed = self.bind('plan_mode_seed')

        self.enable_global_stats = self.bind('enable_global_stats')

        self.sql_beta_feature = self.bind('sql_beta_feature')

        self.enable_bloom_filter = self.bind('enable_bloom_filter')

        self.autoanalyze = self.bind('autoanalyze')
        self.enable_analyze_check = self.bind('enable_analyze_check')

        self.skew_option = self.bind('skew_option')
        self.enable_expr_fusion = self.bind('enable_expr_fusion')
        self.enable_indexscan_optimization = self.bind('enable_indexscan_optimization')
        self.enable_default_index_deduplication = self.bind('enable_default_index_deduplication')

        # some option
        self.hashagg_table_size = self.bind('hashagg_table_size')
        self.check_implicit_conversions = self.bind('check_implicit_conversions')
        self.max_recursive_times = self.bind('max_recursive_times')

        self.enable_absolute_tablespace = self.bind('enable_absolute_tablespace')
        self.enable_kill_query = self.bind('enable_kill_query')
        self.enforce_a_behavior = self.bind('enforce_a_behavior')

    def calculate(self):
        self.sql_beta_feature.set('partition_opfusion')
