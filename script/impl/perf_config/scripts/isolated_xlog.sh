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

action=$1
xlog_old=$2
xlog_new=$3


function isolated
{
  mv $xlog_old $xlog_new  # mv not change owner and mod
  ln -s $xlog_new $xlog_old
}

function recover
{
  rm $xlog_old
  mv $xlog_new $xlog_old   # mv not change owner and mod
}

if [ "$action" = "isolated" ]; then
    isolated
elif [ "$action" = "recover" ]; then
    recover
else
    echo 'unknown action', $action
    exit 1
fi