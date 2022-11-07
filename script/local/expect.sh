#!/bin/bash
#############################################################################
# Copyright (c): 2021-2025, Huawei Tech. Co., Ltd.
# FileName     : expect
# Version      : V1.0.0
# Date         : 2020-01-13
#############################################################################

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
