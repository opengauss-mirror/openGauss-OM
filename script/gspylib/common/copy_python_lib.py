import os
import sys
import subprocess

def copy_lib():
    pyverson = str(sys.version_info[1])
    if pyverson not in ['7','11']:
        print("Not support python version: %s" % sys.version)
        return
    current_path = os.path.dirname(os.path.abspath(__file__))
    libdir = os.path.join(current_path, '../../../lib')
    newlibdir = os.path.join(current_path, '../../../lib_py' + pyverson)
    if os.path.exists(newlibdir):
        cmd = f"rm -rf {libdir}"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("remove lib dir failed.\nError:%s\nThe cmd is: %s\n" %
                          (output, cmd))
        cmd = f"mv {newlibdir} {libdir}"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("mv lib dir failed.\nError:%s\nThe cmd is: %s\n" %
                          (output, cmd))

if __name__ == "__main__":
    copy_lib()