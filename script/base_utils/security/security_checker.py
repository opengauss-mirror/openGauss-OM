# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c): 2012-2019, Huawei Tech. Co., Ltd.
# FileName     : security_checker.py
# Version      : Gauss300
# Date         : 2021-06-30
# Description  : security_checker.py check security conditions
#############################################################################
import re
from gspylib.common.ErrorCode import ErrorCode


class ValidationError(Exception):
    """
    validation base error
    """
    def __init__(self, error_info):
        super().__init__(self)
        self.error_info = error_info

    def __str__(self):
        return self.error_info


class SecurityChecker(object):
    """check security conditions"""
    INJECTION_CHAR_LIST = ["|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}", "(", ")",
                           "[", "]", "~", "*", "?", " ", "!", "\n"]
    PWD_VALIDATION_PATTERN = r'^[A-Za-z0-9~!@#%^*\-_=+?,]+$'
    IP_PATTERN = r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'

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

    @staticmethod
    def check_is_string(description, value):
        """
        Check is string
        """
        if not isinstance(value, str):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022'] % (description, 'string'))

    @staticmethod
    def check_max_length(description, value, max_length):
        """
        Check max length
        """
        if len(value) > max_length:
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50023"] % (description, max_length))

    @staticmethod
    def check_db_injection(description, value):
        """
        Check db injection
        """
        for rac in SecurityChecker.INJECTION_CHAR_LIST:
            if value.find(rac) > 0:
                raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50025'] % (rac, description))

    @staticmethod
    def check_password(description, value):
        if not re.match(SecurityChecker.PWD_VALIDATION_PATTERN, value):
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50024"] % description)

    @staticmethod
    def check_db_user(description, value):
        SecurityChecker.check_is_string(description, value)
        SecurityChecker.check_max_length(description, value, 256)
        SecurityChecker.check_db_injection(description, value)

    @staticmethod
    def check_db_password(description, value):
        SecurityChecker.check_is_string(description, value)
        SecurityChecker.check_max_length(description, value, 256)
        SecurityChecker.check_password(description, value)

    @staticmethod
    def check_is_digit(description, value):
        if isinstance(value, int):
            return
        elif isinstance(value, str):
            if not value.isdigit():
                raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022']
                                      % (description, 'integer'))
        else:
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022']
                                  % (description, 'int or string'))

    @staticmethod
    def check_is_list(description, value):
        if not isinstance(value, list):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022'] % (description, 'list'))

    @staticmethod
    def check_is_dict(description, value):
        if not isinstance(value, dict):
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022'] % (description, 'dict'))

    @staticmethod
    def check_ip_valid(description, value):
        SecurityChecker.check_is_string(description, value)
        if not re.match(SecurityChecker.IP_PATTERN, value):
            raise ValidationError(ErrorCode.GAUSS_500["GAUSS_50024"] % description)

    @staticmethod
    def check_port_valid(description, value, max_value=65535, des2=''):
        SecurityChecker.check_is_digit(description, value)
        value = int(value) if not isinstance(value, int) else value
        if value > max_value or value < 0:
            raise ValidationError(ErrorCode.GAUSS_500['GAUSS_50022'] %
                                  (description, 'between 0 and {}{}'.format(
                                      str(max_value), des2)))
