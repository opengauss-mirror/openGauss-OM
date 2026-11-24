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

# ok
python3 gs_perfconfig help
python3 gs_perfconfig --help
python3 gs_perfconfig -h
python3 gs_perfconfig -?

python3 gs_perfconfig Help
python3 gs_perfconfig --hElp
python3 gs_perfconfig -H
python3 gs_perfconfig -?

# falied
python3 gs_perfconfig xxx
python3 gs_perfconfig --xxx
python3 gs_perfconfig -x
python3 gs_perfconfig -.


# will ignode other param
python3 gs_perfconfig help ddd
python3 gs_perfconfig --help fd
python3 gs_perfconfig -h da
python3 gs_perfconfig -? das