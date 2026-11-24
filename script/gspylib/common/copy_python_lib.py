# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# openGauss-OM is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import os
import sys
import subprocess


def copy_lib():
    current_path = os.path.dirname(os.path.abspath(__file__))
    bcrypt_lib = os.path.join(current_path, "../../../lib/bcrypt/_bcrypt.abi3.so")
    if os.path.exists(bcrypt_lib):
        return
    source = os.path.join(current_path, '../../../lib/bcrypt/lib3.' + \
                          str(sys.version_info[1]), '_bcrypt.abi3.so')
    dest = os.path.join(current_path, '../../../lib/bcrypt/')
    cmd = f"cp {source} {dest}"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception("cp file failed.\nError:%s\nThe cmd is: %s\n" %
                        (output, cmd))

    source = os.path.join(current_path, '../../../lib/_cffi_backend_3.' + \
                          str(sys.version_info[1]), '_cffi_backend.so')
    dest = os.path.join(current_path, '../../../lib/')
    cmd = f"cp {source} {dest}"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception("cp file failed.\nError:%s\nThe cmd is: %s\n" %
                        (output, cmd))

    source = os.path.join(current_path, '../../../lib/cryptography/hazmat/bindings/lib3.' + \
                          str(sys.version_info[1]), '*.so')
    dest = os.path.join(current_path, '../../../lib/cryptography/hazmat/bindings/')
    cmd = f"cp {source} {dest}"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception("cp file failed.\nError:%s\nThe cmd is: %s\n" %
                        (output, cmd))

    source = os.path.join(current_path, '../../../lib/nacl/lib3.' + \
                          str(sys.version_info[1]), '_sodium.abi3.so')
    dest = os.path.join(current_path, '../../../lib/nacl/')
    cmd = f"cp {source} {dest}"
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        raise Exception("cp file failed.\nError:%s\nThe cmd is: %s\n" %
                        (output, cmd))


if __name__ == "__main__":
    copy_lib()