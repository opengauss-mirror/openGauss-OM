#!/bin/bash
#############################################################################
# Copyright (c): 2021-2025, Huawei Tech. Co., Ltd.
# FileName     : sshexkey_encrypt_tool.sh
# Version      : V1.0.0
# Date         : 2022-02-13
#############################################################################

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
