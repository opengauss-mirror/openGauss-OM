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
