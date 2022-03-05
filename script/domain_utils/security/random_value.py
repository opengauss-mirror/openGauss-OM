# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#############################################################################
from gspylib.common.ErrorCode import ErrorCode
from base_utils.executor.cmd_executor import CmdExecutor


class RandomValue:
    """manage random value."""
    # random passwd len
    RANDOM_PASSWD_LEN = 12

    @staticmethod
    def getRandStr():
        """
        function: get random passwd
        input: NA
        output: passwd
        """
        uppercmd = 'openssl rand -base64 12 | tr "[0-9][a-z]" "[A-Z]" | tr -d [/+=] |cut -c 1-3'
        lowercmd = 'openssl rand -base64 12 | tr "[0-9][A-Z]" "[a-z]" | tr -d [/+=] |cut -c 1-4'
        numcmd = 'openssl rand -base64 12 | md5sum | tr "[a-z]" "[0-9]" |cut -c 1-3'
        strcmd = 'openssl rand -base64 48 | tr "[0-9][a-z][A-Z]" "[~@_#*]" | tr -d [/+=] ' \
                 '|cut -c 1-1'

        _, upperoutput, _ = CmdExecutor.execCommandWithSubprocess(uppercmd)
        _, loweroutput, _ = CmdExecutor.execCommandWithSubprocess(lowercmd)
        _, numoutput, _ = CmdExecutor.execCommandWithSubprocess(numcmd)
        _, stroutput, _ = CmdExecutor.execCommandWithSubprocess(strcmd)
        ranpwd = 'G' + upperoutput.strip() + loweroutput.strip() + \
                 numoutput.strip() + stroutput.strip()
        if len(ranpwd) == RandomValue.RANDOM_PASSWD_LEN:
            return ranpwd
        ranpwd = "G"
        cmd_tuple = (uppercmd, lowercmd, numcmd, strcmd)
        out_tuple = (upperoutput.strip(), loweroutput.strip(),
                     numoutput.strip(), stroutput.strip())
        str_len = (3, 4, 3, 1)
        for i in range(4):
            if len(out_tuple[i]) != str_len[i]:
                count = 0
                while True:
                    count += 1
                    _, output, _ = CmdExecutor.execCommandWithSubprocess(cmd_tuple[i])
                    if len(output.strip()) == str_len[i]:
                        ranpwd += output.strip()
                        break
                    if count > 100:
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51402"] + cmd_tuple[i])
            else:
                ranpwd += out_tuple[i].strip()
        return ranpwd
