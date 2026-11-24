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
encrypt_type="$1"
passwd=$secret
cmd1="$2"
cmd2="$3"

func_sshkeygen_cmd()
{
cmd="unset LD_LIBRARY_PATH; ssh-keygen -t ed25519 -N \"$passwd\" -f ~/.ssh/id_om < /dev/null && chmod 600 ${cmd1} ${cmd2}"
eval $cmd
}

if [ "-$encrypt_type" = "-sshkeygen" ];then
echo "Generating mutual trust files"
func_sshkeygen_cmd
fi
