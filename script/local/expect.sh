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

read -r secret
expect_content="$1"
passwd=$secret
cmd="$2"
func_remote_execute_cmd()
{
    echo "Access Method"
    echo "cmd:$cmd"
    expect -c "
    spawn $cmd;
    expect {
            \"$expect_content\"
            {send $passwd\n; exp_continue}
            \"$expect_content\"
            {send $passwd\n}  }
        expect eof
        catch wait result;
        exit [lindex \$result 3]"
}
func_remote_execute_cmd
