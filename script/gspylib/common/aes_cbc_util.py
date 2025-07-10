# -*- coding:utf-8 -*-

"""
# Copyright (c): 2012-2020, Huawei Tech. Co., Ltd.
# FileName     : base_command.py
# Version      : GaussDB Kernel V500R001
# Date         : 2020-09-08
# Description  : base_command
"""

import os
import ctypes
import hashlib
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except Exception as err:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % err)

os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"

class AesCbcUtil(object):
    """
    aes  cbc tool
    """
    @staticmethod
    def get_old_version_path(path):
        """ Compatible old version path
            egg1: compatible 'encrypt'
                 old: /home/xxx/key_0
                 new: /home/xxx/cipher/key_0
            egg2: compatible 'gs_guc encrypt'
                old: /home/xxx/
                new: /home/xxx/cipher/
        """
        dirname, basename = os.path.split(path.rstrip("/"))
        if basename in ["cipher", "rand"]:
            return dirname
        dirname, _ = os.path.split(dirname)
        path = os.path.join(dirname, basename)
        return path

    @staticmethod
    def aes_cbc_decrypt_with_path(cipher_path, rand_path, key_name="client"):
        """
        aes cbc decrypt for one path
        """
        if not os.path.isdir(cipher_path):
            cipher_path = AesCbcUtil.get_old_version_path(cipher_path)
            rand_path = AesCbcUtil.get_old_version_path(rand_path)
        with open(os.path.join(cipher_path, '%s.key.cipher' % key_name), 'rb') as cipher_file:
            cipher_txt = cipher_file.read()

        with open(os.path.join(rand_path, '%s.key.rand' % key_name), 'rb') as rand_file:
            rand_txt = rand_file.read()

        if cipher_txt is None or cipher_txt == "":
            return None
        server_vector_cipher_vector = cipher_txt[16 + 1:16 + 1 + 16]
        # pre shared key rand
        server_key_rand = rand_txt[:16]
        # worker key
        server_decrypt_key = hashlib.pbkdf2_hmac('sha256', server_key_rand,
                                                 server_vector_cipher_vector, 10000,
                                                 16)
        enc = AesCbcUtil.aes_cbc_decrypt(cipher_txt, server_decrypt_key)
        return enc

    @staticmethod
    def aes_cbc_decrypt(content, key):
        """
        aes cbc decrypt for content and key
        """
        AesCbcUtil.check_content_key(content, key)
        if isinstance(key, str):
            key = bytes(key)
        iv_len = 16
        # pre shared key iv
        iv_value = content[16 + 1 + 16 + 1:16 + 1 + 16 + 1 + 16]
        # pre shared key  enctryt
        enc_content = content[:iv_len]

        try:
            backend = default_backend()
        except Exception as imp_clib_err:
            # from 3.1.0 version. we build openssl with SSLv3_method.
            # if not find SSLv3_method, then use ours.
            local_path = os.path.dirname(os.path.realpath(__file__))
            clib_path = os.path.realpath(os.path.join(local_path, "../clib"))
            ssl_path = os.path.join(clib_path, 'libssl.so.3')
            crypto_path = os.path.join(clib_path, 'libcrypto.so.3')
            if os.path.isfile(crypto_path):
                ctypes.CDLL(crypto_path, mode=ctypes.RTLD_GLOBAL)
            if os.path.isfile(ssl_path):
                ctypes.CDLL(ssl_path, mode=ctypes.RTLD_GLOBAL)

            backend = default_backend()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_value), backend=backend)
        decrypter = cipher.decryptor()
        dec_content = decrypter.update(enc_content) + decrypter.finalize()
        server_decipher_key = dec_content.rstrip(b'\x00')[:-1].decode()
        return server_decipher_key

    @staticmethod
    def check_content_key(content, key):
        """
        check ase cbc content and key
        """
        if not isinstance(content, bytes):
            raise Exception("content's type must be bytes.")

        if not isinstance(key, (bytes, str)):
            raise Exception("bytes's type must be in (bytes, str).")

        iv_len = 16
        if not len(content) >= (iv_len + 16):
            raise Exception("content's len must >= (iv_len + 16).")

    @staticmethod
    def aes_cbc_decrypt_with_multi(cipher_root, rand_root, key_name="server"):
        """
        decrypt message with multi depth
        """
        num = 0
        decrypt_str = ""
        if not os.path.isdir(cipher_root):
            cipher_root = os.path.dirname(cipher_root.rstrip("/"))
            rand_root = os.path.dirname(rand_root.rstrip("/"))
        while True:
            cipher_path = os.path.join(cipher_root, "key_%s" % num)
            rand_path = os.path.join(rand_root, "key_%s" % num)
            part = AesCbcUtil.aes_cbc_decrypt_with_path(cipher_path, rand_path, key_name)
            if part is None:
                break
            elif len(part) < 15:
                decrypt_str += part
                break
            else:
                decrypt_str += part

            num = num + 1
        if decrypt_str == "":
            return None
        return decrypt_str

    @staticmethod
    def format_path(root_path):
        """format decrypt_with_multi or decrypt_with_path"""
        return os.path.join(root_path, "cipher"), os.path.join(root_path, "rand")
