import os
import sys
import subprocess


def copy_lib():
    current_path = os.path.dirname(os.path.abspath(__file__))
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
