#!/bin/bash
#############################################################################
# Copyright (c): 2021-2025, Huawei Tech. Co., Ltd.
# FileName     : ssh-agent
# Version      : V1.0.0
# Date         : 2020-01-13
#############################################################################

read -r secret
id_rsa_path="$1"
passwd=$secret
cmd="ssh-add ${id_rsa_path}"
func_remote_execute_cmd()
{
set timeout 5
echo "Access Method"
echo "ssh-agent command:$cmd"
expect << EOF
spawn $cmd
expect {
    "Enter passphrase for *" {send $passwd\n}
    }
expect {
    "Bad passphrase*" {puts \"failure\";exit 2}
    eof {puts \"success:eof\"\n }
    }
catch wait result
puts \$result
exit [lindex \$result 3]
EOF
}
func_remote_execute_cmd
