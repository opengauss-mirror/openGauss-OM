#!/bin/bash

# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# openGauss-OM is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# user
export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=on'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=off'
python3 gs_perfconfig tune --apply
# x x n

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=0'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=1'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=true'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=false'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=xxx'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=ON'
python3 gs_perfconfig tune --apply
# x x y a