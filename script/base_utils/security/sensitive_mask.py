# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c): 2012-2019, Huawei Tech. Co., Ltd.
# FileName     : sensitive_mask.py
# Version      : Gauss300
# Date         : 2021-06-30
# Description  : sensitive_mask.py is utility to mask sensitive message
#############################################################################

import re


class SensitiveMask(object):
    """ Mask sensitive message
    """
    @classmethod
    def mask_sensitive_para(cls, msg):
        """ mask gs tools Sensitive param """
        mask_items = {
            "gsql": ["--with-key", "-k"],
            "gs_encrypt": ["--key-base64", "--key", "-B", "-k"],
            "gs_guc encrypt": ["-K"],
            "gs_guc generate": ["-S"],
            "gs_dump": ["--rolepassword", "--with-key"],
            "gs_dumpall": ["--rolepassword", "--with-key"],
            "gs_restore": ["--with-key", "--rolepassword"],
            "gs_ctl": ["-P"],
            "gs_redis": ["-A"],
            "gs_initdb": ["--pwprompt", "--pwpasswd"],
            "gs_roach": ["--obs-sk"],
            "InitInstance": ["--pwpasswd"]
        }
        for t_key, t_value in mask_items.items():
            if t_key in msg or all(tk in msg for tk in t_key.split()):
                pattern = re.compile("|".join([r"(?<=%s)[ =]+[^ ]*[ ]*" % i for i in t_value]))
                msg = pattern.sub(lambda m: " *** ", msg)
        return msg

    @classmethod
    def mask_pwd(cls, msg):
        """mask pwd in msg"""
        replace_reg = re.compile(r' -W[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' -W *** ', str(msg))
        replace_reg = re.compile(r' -w[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' -w *** ', str(msg))
        replace_reg = re.compile(r' --password[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' --password *** ', str(msg))
        replace_reg = re.compile(r' --pwd[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' --pwd *** ', str(msg))
        replace_reg = re.compile(r' --root-passwd[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' --root-passwd *** ', str(msg))
        replace_reg = re.compile(r' -P[ ]*[^ ]+[ ]*')
        msg = replace_reg.sub(' -P *** ', str(msg))

        msg = cls.mask_sensitive_para(msg)
        replace_reg = re.compile(r'echo[ ]+[^ ]+[ ]*\|')
        msg = replace_reg.sub('echo *** |', str(msg))
        return msg
