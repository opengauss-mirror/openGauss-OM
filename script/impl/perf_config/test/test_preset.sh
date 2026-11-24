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

export GAUSSHOME=''
export GAUSSLOG=''
export PGDATA=''


# ok
python3 gs_perfconfig preset
python3 gs_perfconfig preset help
python3 gs_perfconfig preset --help
python3 gs_perfconfig preset -h
python3 gs_perfconfig preset -?
python3 gs_perfconfig preset HELP
python3 gs_perfconfig preset --Help
python3 gs_perfconfig preset -H
python3 gs_perfconfig preset -?
python3 gs_perfconfig preset default


# failed
python3 gs_perfconfig preSet
python3 gs_perfconfig preSet help
python3 gs_perfconfig preSet --help
python3 gs_perfconfig preSet -h
python3 gs_perfconfig preSet -?
python3 gs_perfconfig preSet HELP
python3 gs_perfconfig preSet --Help
python3 gs_perfconfig preSet -H
python3 gs_perfconfig preSet -?
python3 gs_perfconfig preset Default   # failed


# ok
cp ../preset/default.json ../preset/xx1.json
python3 gs_perfconfig preset
python3 gs_perfconfig preset xx1

# xx1 = default
cp ../preset/kunpeng-4P-tpcc.json $GAUSSLOG/om/perf_config/preset/xx1.json
python3 gs_perfconfig preset
python3 gs_perfconfig preset xx1

# ok
cp ../preset/kunpeng-4P-tpcc.json $GAUSSLOG/om/perf_config/preset/xx2.json
python3 gs_perfconfig preset
python3 gs_perfconfig preset xx2


cp data/test-preset* $GAUSSLOG/om/perf_config/preset/
python3 gs_perfconfig preset
python3 gs_perfconfig preset test-preset-wrong-format
python3 gs_perfconfig preset test-preset-wrong-format2
python3 gs_perfconfig preset test-preset-wrong-param
python3 gs_perfconfig preset test-preset-wrong-val
python3 gs_perfconfig preset test-preset-wrong-val32
python3 gs_perfconfig preset test-preset-wrong-val

