# -*- coding:utf-8 -*-
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

import sys
import os

localDirPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(sys.path[0] + "/../../")
from base_utils.os.cmd_util import CmdUtil


class fileManage():
    """
    Class to handle OS file operations
    """
    SHELL_CMD_DICT = {
        "deleteFile": "(if [ -f '%s' ];"
                      "then rm -f '%s';fi)",
        "deleteLibFile": "cd %s && ls | grep -E '%s'|"
                         "xargs rm -f",
        "cleanDir": "(if [ -d '%s' ];then rm -rf "
                    "'%s'/* && cd '%s' && ls -A | "
                    "xargs rm -rf ; fi)",
        "execShellFile": "sh %s",
        "getFullPathForShellCmd": "which %s",
        "deleteDir": "(if [ -d '%s' ];then rm "
                     "-rf '%s';fi)",
        "deleteLib": "(if [ -e '%s' ];then rm "
                     "-rf '%s';fi)",
        "createDir": "(if [ ! -d '%s' ]; "
                     "then mkdir -p '%s' -m %s;fi)",
        "createFile": "touch '%s' && chmod %s '%s'",
        "deleteBatchFiles": "rm -f %s*",
        "compressTarFile": "cd '%s' && tar -cf "
                           "'%s' %s && chmod %s '%s'",
        "decompressTarFile": "cd '%s' && tar -xf '%s' ",
        "copyFile": " cp -rf %s %s ",
        "sshCmd": "pssh -s -H %s 'source %s;%s'",
        "renameFile": "(if [ -f '%s' ];then mv '%s' "
                      "'%s';fi)",
        "cleanFile": "if [ -f %s ]; then echo '' > "
                     "%s; fi",
        "exeRemoteShellCMD": "pssh -s -H %s 'source %s;%s'",
        "exeRemoteShellCMD1": "pssh -s -H %s \"%s\"",
        "userExeRemoteShellCmd": "su - %s -c \"pssh -s -H %s "
                                 "'%s'\"",
        "checkUserPermission": "su - %s -c \"cd '%s'\"",
        "getFileTime": "echo $[`date +%%s`-`stat -c "
                       "%%Y %s`]",
        "scpFileToRemote": "pscp -H '%s' '%s' '%s'",
        "scpFileFromRemote": "pssh -s -H '%s' \"pscp -H "
                             "'%s' '%s' '%s' \"",
        "findfiles": "cd %s && find . "
                     "-type l -print",
        "copyFile1": "(if [ -f '%s' ];then cp "
                     "'%s' '%s';fi)",
        "copyFile2": "(if [ -f '%s' ] && [ ! -f "
                     "'%s' ];then cp '%s' '%s';fi)",
        "copyRemoteFile": "(if [ -d '%s' ];then pssh "
                          "-s -H '%s' \"pscp -H '%s' "
                          "'%s' '%s' \";fi)",
        "cleanDir1": "(if [ -d '%s' ]; then cd "
                     "'%s' && rm -rf '%s' && "
                     "rm -rf '%s' && cd -; fi)",
        "cleanDir2": "(if [ -d '%s' ]; then "
                     "rm -rf '%s'/* && cd '%s' && "
                     "ls -A | xargs rm -rf && "
                     "cd -; fi)",
        "cleanDir3": "rm -rf '%s'/* && cd '%s' && "
                     "ls -A | xargs rm -rf && "
                     "cd - ",
        "cleanDir4": "rm -rf %s/*",
        "checkNodeConnection": "ping %s -i 1 -c 3 |grep ttl |"
                               "wc -l",
        "overWriteFile": "echo '%s' > '%s'",
        "physicMemory": "cat /proc/meminfo | "
                        "grep MemTotal",
        "findFile": "(if [ -d '%s' ]; then "
                    "find '%s' -type f;fi)",
        "unzipForce": "unzip -o '%s' -d '%s'",
        "killAll": CmdUtil.findCmdInPath("killall") + " %s",
        "sleep": "sleep %s",
        "softLink": "ln -s '%s' '%s'",
        "findwithcd": "cd %s && find ./ -name %s",
        "installRpm": "rpm -ivh --nofiledigest %s "
                      "--nodeps --force --prefix=%s",
        "changeMode": "chmod %s %s",
        "checkPassword": "export LC_ALL=C; "
                         "chage -l %s | "
                         "grep -i %s"
    }

    def __init__(self):
        """
        constructor
        """
        pass

    def checkClusterPath(self, path_name):
        """
        Check the path
        :param path_name:
        :return:
        """
        if not path_name:
            return False

        a_ascii = ord('a')
        z_ascii = ord('z')
        A_ascii = ord('A')
        Z_ascii = ord('Z')
        num0_ascii = ord('0')
        num9_ascii = ord('9')
        blank_ascii = ord(' ')
        sep1_ascii = ord('/')
        sep2_ascii = ord('_')
        sep3_ascii = ord('-')
        sep4_ascii = ord(':')
        sep5_ascii = ord('.')
        sep6_ascii = ord(',')
        for path_char in path_name:
            char_check = ord(path_char)
            if (not (a_ascii <= char_check <= z_ascii or A_ascii <=
                     char_check <= Z_ascii or
                     num0_ascii <= char_check <= num9_ascii or
                     char_check == blank_ascii or
                     char_check == sep1_ascii or
                     char_check == sep2_ascii or
                     char_check == sep3_ascii or
                     char_check == sep4_ascii or
                     char_check == sep5_ascii or
                     char_check == sep6_ascii)):
                return False
        return True

g_file = fileManage()
