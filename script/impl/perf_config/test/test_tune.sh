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
vim /home/carrot/test.source   # GAUSSHOME  GAUSSLOG PGDATA.  gs_om env

# root
python3 gs_perfconfig tune
python3 gs_perfconfig tune -t os,guc,os
python3 gs_perfconfig tune -t all
python3 gs_perfconfig tune -t os,guc,os --apply
python3 gs_perfconfig tune -t all --apply
python3 gs_perfconfig tune -t os,guc,os --apply -y
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source -y
python3 gs_perfconfig tune --apply
python3 gs_perfconfig tune --apply --env /home/carrot/test.source


# user
python3 gs_perfconfig tune
python3 gs_perfconfig tune -t os
python3 gs_perfconfig tune -t os,guc,os
python3 gs_perfconfig tune -t all
python3 gs_perfconfig tune -t os,guc,os --apply
python3 gs_perfconfig tune -t all --apply
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source
python3 gs_perfconfig tune --apply -y
python3 gs_perfconfig tune --apply --env /home/carrot/test.source -y


# mix
# root
python3 gs_perfconfig tune
# user
python3 gs_perfconfig tune -t os
# root
python3 gs_perfconfig tune -t os,guc,os
# user
python3 gs_perfconfig tune -t all
# root
python3 gs_perfconfig tune -t os,guc,os --apply
# user
python3 gs_perfconfig tune -t all --apply
# root
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source -y
# user
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source -y
# root
python3 gs_perfconfig tune --apply -y
# user
python3 gs_perfconfig tune --apply --env /home/carrot/test.source -y



