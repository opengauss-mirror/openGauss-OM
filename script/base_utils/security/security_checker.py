# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c): 2012-2019, Huawei Tech. Co., Ltd.
# FileName     : security_checker.py
# Version      : Gauss300
# Date         : 2021-06-30
# Description  : security_checker.py check security conditions
#############################################################################

from gspylib.common.ErrorCode import ErrorCode


class SecurityChecker(object):
    """check security conditions"""
    INJECTION_CHAR_LIST = ["|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}", "(", ")",
                           "[", "]", "~", "*", "?", " ", "!", "\n"]

    @staticmethod
    def check_injection_char(check_value):
        """
        function: check suspicious injection value
        input : check_value
        output: NA
        """
        if not check_value.strip():
            return
        if any(rac in check_value for rac in SecurityChecker.INJECTION_CHAR_LIST):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % check_value +
                            " There are illegal characters.")
