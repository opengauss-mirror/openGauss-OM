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
# ----------------------------------------------------------------------------
# Description  :
#############################################################################


import os
import subprocess
import sys
import psutil
import math
sys.path.append(sys.path[0] + "/../../")
from base_utils.os.cmd_util import CmdUtil
from gspylib.common.ErrorCode import ErrorCode


class DiskUtil(object):
    """
    function: Init the DiskUsage options
    """
    MTAB_FILE = "/etc/mtab"

    @staticmethod
    def getMountInfo(all_info=False):
        """
        get mount disk information: device mountpoint fstype opts
        input: bool (physical devices and all others)
        output: list
        """
        return psutil.disk_partitions(all_info)

    @staticmethod
    def getUsageSize(directory):
        """
        get directory or file real size. Unit is byte
        """
        cmd = ""
        try:
            cmd = "%s -l -R %s | %s ^- | %s '{t+=$5;} END {print t}'" % (
                CmdUtil.getListCmd(), directory, CmdUtil.getGrepCmd(),
                CmdUtil.getAwkCmd())
            (status, output) = subprocess.getstatusoutput(cmd)
            if status == 0:
                return output.split('\t')[0].strip()
            else:
                raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd
                                + " Error: \n%s" % str(output))
        except Exception:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)

    # Mtab always keeps the partition information already mounted in the
    # current system.
    # For programs like fdisk and df,
    # you must read the mtab file to get the partition mounting status in
    # the current system.
    @staticmethod
    def getMountPathByDataDir(data_dir):
        """
        function : Get the disk by the file path
          input  : datadir   the file path
          output : device    disk
        """
        device = ""
        mount_disk = {}
        if not os.path.exists(data_dir):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50228"] % data_dir)
        try:
            datadir = os.path.realpath(data_dir)
            with open(DiskUtil.MTAB_FILE, "r") as fp:
                for line in fp.readlines():
                    if line.startswith('none'):
                        continue
                    i_fields = line.split()
                    if len(i_fields) < 3:
                        continue
                    i_device = i_fields[0].strip()
                    i_mountpoint = i_fields[1].strip()
                    mount_disk[i_mountpoint] = [i_device, i_mountpoint]

            mountList = list(mount_disk.keys())
            mountList.sort(reverse=True)
            for mount in mountList:
                i_mountpoint = mount_disk[mount][1]
                if i_mountpoint == '/':
                    i_mount_dirlst = ['']
                else:
                    i_mount_dirlst = i_mountpoint.split('/')
                data_dirlst = datadir.split('/')
                if len(i_mount_dirlst) > len(data_dirlst):
                    continue
                if i_mount_dirlst == data_dirlst[:len(i_mount_dirlst)]:
                    device = mount_disk[mount][0]
                    break

        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] %
                            " disk mount." + "Error: %s" % str(excep))
        return device

    # Mtab always keeps the partition information already mounted in the
    # current system.
    # For programs like fdisk and df,
    # you must read the mtab file to get the partition mounting status in
    # the current system.
    @staticmethod
    def getMountPathAvailSize(device, sizeUnit='MB'):
        """
        function : Get the disk size by the file path
          input  : device    the file path
                 : sizeUnit  byte, GB, MB, KB
          output : total     disk size
        """
        total = 0
        if not os.path.exists(device):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50228"] % device)
        try:
            dev_info = os.statvfs(device)
            if sizeUnit == 'GB':
                total = dev_info.f_bavail * dev_info.f_frsize // (
                        1024 * 1024 * 1024)
            elif sizeUnit == 'MB':
                total = dev_info.f_bavail * dev_info.f_frsize // (1024 * 1024)
            elif sizeUnit == 'KB':
                total = dev_info.f_bavail * dev_info.f_frsize // 1024
            else:
                total = dev_info.f_bavail * dev_info.f_frsize
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] % " disk size."
                            + "Error: %s" % str(excep))
        return total

    # Mtab always keeps the partition information already mounted in the
    # current system.
    # For programs like fdisk and df,
    # you must read the mtab file to get the partition mounting status in
    # the current system.
    @staticmethod
    def getDiskSpaceUsage(path):
        """
        function : Get the disk usage by the file path
                method of calculation:
                    Total capacity (KB)=f_bsize*f_blocks/1024 [1k-blocks]
                    Usage (KB)= f_bsize*(f_blocks-f_bfree)/1024 [Used]
                    Valid capacity (KB) = f_bsize*f_bavail/1024 [Available]
                    Usage (%) = Usage/(Usage + Valid capacity) *100 [Use%]
          input  : path      the file path
          output : percent
        """
        percent = 0
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50228"] % path)
        try:
            dev_info = os.statvfs(path)
            used = dev_info.f_blocks - dev_info.f_bfree
            valueable = dev_info.f_bavail + used
            percent = math.ceil((float(used) / valueable) * 100)
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] % " disk space."
                            + "Error: %s" % str(excep))
        return float(percent)

    @staticmethod
    def getDiskSpaceForShrink(path, delta):
        """
        function : Get the disk usage by the file path for Shrink
          input  : path      the file path and deltasize
          output : percent
        """
        percent = 0
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50228"] % path)
        try:
            dev_info = os.statvfs(path)
            used = (dev_info.f_blocks - dev_info.f_bfree) * dev_info.f_bsize
            valueable = dev_info.f_bavail * dev_info.f_bsize + used + delta
            percent = math.ceil((float(used) / valueable) * 100)
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] % " disk space."
                            + "Error: %s" % str(excep))
        return float(percent)

    @staticmethod
    def getDiskInodeUsage(Path):
        """
        function : Get the inode by the file path
        input  : Path     the file path
        output : percent
        """
        percent = 0
        if not os.path.exists(Path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50228"] % Path)
        try:
            dev_info = os.statvfs(Path)
            used = dev_info.f_files - dev_info.f_ffree
            valueable = dev_info.f_favail + used
            percent = math.ceil((float(used) / valueable) * 100)
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] % " disk Inode."
                            + "Error: %s" % str(excep))
        return float(percent)

    @staticmethod
    def getDiskMountType(device):
        """
        function : Get the mount type by device
        input  : device   eg:/dev/pts
        output : fstype   device type
        """
        fstype = ""
        try:
            with open(DiskUtil.MTAB_FILE, "r") as fp:
                for line in fp.readlines():
                    if line.startswith('#'):
                        continue
                    i_fields = line.split()
                    if len(i_fields) < 3:
                        continue
                    i_device = i_fields[0].strip()
                    i_fstype = i_fields[2].strip()
                    if i_device == device:
                        fstype = i_fstype
                        break
        except Exception as excep:
            raise Exception(ErrorCode.GAUSS_530["GAUSS_53011"] %
                            " disk mount type." + "Error: %s" % str(excep))
        return fstype

    @staticmethod
    def getDevices():
        """
        functino: get device
        input: NA
        output: NA
        """
        cmd = "fdisk -l 2>/dev/null | grep \"Disk /dev/\" | " \
              "grep -Ev \"/dev/mapper/|loop\" | awk '{ print $2 }' | " \
              "awk -F'/' '{ print $NF }' | sed s/:$//g"
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd + " Error: \n%s" % output)
        return output.split('\n')

    @staticmethod
    def get_scsi_dev_id(dev_name):
        cmd = '/lib/udev/scsi_id -g -u {}'.format(dev_name)
        sts, out = CmdUtil.getstatusoutput_by_fast_popen(cmd)
        if sts not in [0]:
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50422"] %
                            str(out).strip())
        return out.strip()

    @staticmethod
    def active_udev():
        cmd = 'udevadm control --reload-rules; '
        cmd += 'udevadm trigger --type=devices --action=change; '
        cmd += 'udevadm trigger --type=devices --action=add; '
        cmd += 'udevadm trigger; '

        sts, out = CmdUtil.getstatusoutput_by_fast_popen(cmd)
        if sts not in [0]:
            raise Exception(ErrorCode.GAUSS_504["GAUSS_50423"] %
                            str(out).strip())
