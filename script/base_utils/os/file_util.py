# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2020 Huawei Technologies Co.,Ltd.
# Portions Copyright (c) 2007 Agendaless Consulting and Contributors.
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
# Description  : file_util.py for file utility.
#############################################################################
import os
import _thread
import shutil
import stat
import subprocess
import pwd
import grp
import json
from subprocess import PIPE

from base_utils.common.constantsbase import ConstantsBase
from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.user_util import UserUtil
from base_utils.common.fast_popen import FastPopen
from base_utils.security.sensitive_mask import SensitiveMask


class FileUtil(object):
    """file utility"""

    @staticmethod
    def cleanTmpFile(path, file_handler=None):
        """
        function : close and remove temporary file
        input : String,file
        output : NA
        """
        if file_handler:
            file_handler.close()
        if os.path.exists(path):
            os.remove(path)

    @staticmethod
    def createFileInSafeMode(file_path, mode=stat.S_IWUSR | stat.S_IRUSR):
        """
        Call this method before open(file_path) functions,
        if it may create a new file.
        This method guarantees a 0o600 file is created
        instead of an arbitrary one.
        """
        if os.path.exists(file_path):
            return
        try:
            os.mknod(file_path, mode)
        except IOError as error:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50206"] % file_path +
                            " Error:\n%s." % str(error))

    @staticmethod
    def get_permission_value(file_path):
        """
        function : Obtaining Permissions on a File or Directory
        input : String
        output : String
        """
        if not os.path.exists(file_path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % file_path)
        try:
            value = oct(os.stat(file_path).st_mode)[-3:]
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            ("permission with %s" % file_path) + " Error:\n%s" % str(e))
        return value

    @staticmethod
    def check_file_permission(filename,
                              check_read_permission=False,
                              check_write_permission=False,
                              check_execute_permission=False):
        """
        Function : check file: 1.exist 2. isfile 3. permission
        Note     : 1.You must check that the file exist and is a file.
                   2.You can choose whether to check the file's
                   permission:readable/writable/executable.
        input : filename, isread, iswrite, isexecute
        output : True
        """
        if not os.path.exists(filename):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50236"] % filename)
        if not os.path.isfile(filename):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % filename)
        if check_read_permission:
            if not os.access(filename, os.R_OK):
                raise Exception(ErrorCode.GAUSS_501["GAUSS_50100"] % (
                    filename, "the user") +
                                " Error:\n%s: Permission denied." % filename)
        if check_write_permission:
            if not os.access(filename, os.W_OK):
                raise Exception(ErrorCode.GAUSS_501["GAUSS_50102"] % (
                    filename, "the user") +
                                " Error:\n%s: Permission denied." % filename)
        if check_execute_permission:
            if not os.access(filename, os.X_OK):
                raise Exception(ErrorCode.GAUSS_501[
                                    "GAUSS_50101"] % (filename, "the user") +
                                " Error:\n%s: Permission denied." % filename)
        return True

    @staticmethod
    def createFile(path, overwrite=True, mode=None):
        """
        function: create file and set the permission
        input:
            path: the file path.
            overwrite: if file already exists and this parameter is true,
            we can overwrtie it.
            mode: Specify file permissions, type is int and start with 0.
            ex: 0700
        output:
            return true or false.
        """
        try:
            if overwrite:
                cmd = CmdUtil.getCreateFileCmd(path)
                if mode:
                    cmd += "; %s" % CmdUtil.getChmodCmd(str(mode), path)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(output + " The cmd is %s" % cmd)
            else:
                # create file by python API
                if mode:
                    os.mknod(path, mode)
                else:
                    os.mknod(path)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50206"] % path +
                            " Error:\n%s" % str(e))
        return True

    @staticmethod
    def removeFile(path, cmd_type="shell"):
        """
        function: remove a file
        input: the path of file(include file name)
        output: return true or false
        """
        if cmd_type in ["python", "python3"]:
            # no file need remove.
            if not os.path.exists(path):
                return True
            # check if is a file.
            if not os.path.isfile(path):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % path)
            try:
                # remove file.
                os.remove(path)
            except Exception:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] % path)
        else:
            # Support* for fuzzy matching
            if "*" in path:
                path = FileUtil.withAsteriskPath(path)
                cmd = CmdUtil.getRemoveCmd('file') + path
            else:
                cmd = CmdUtil.getRemoveCmd('file') + "'" + path + "'"
            (status, output) = subprocess.getstatusoutput(cmd)
            if status != 0:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] % path
                                + " Error:\n%s" % output
                                + " The cmd is %s" % cmd)
        return True

    @staticmethod
    def moveFile(src, dest, overwrite=True):
        """
        function: move a file
        input:
            src: the dir of file
            dest: the dir which want to move
        output:
            return true or false
        """
        # check if can overwrite
        if os.path.exists(dest) and not overwrite:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50102"] % (
                "parameter overwrite", dest))
        try:
            if overwrite:
                cmd = CmdUtil.getMoveFileCmd(src, dest)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(output + "The cmd is %s" % cmd)
            else:
                # move file
                shutil.move(src, dest)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50232"] % (src, dest) +
                            " Error:\n%s" % str(e))

        return True

    @staticmethod
    def is_in_file_with_context(file_path,
                                call_back_name=lambda _: True,
                                call_back_context=lambda _: True):
        '''
        Easy to match strings in files
        '''
        if call_back_name(file_path):
            with open(file_path, 'r') as fr_any:
                if call_back_context(fr_any.read()):
                    return True
        return False

    @staticmethod
    def readFile(filename, keyword="", rows=0):
        """
        function: read the content of a file
        input:
            filename: the name and path of the file
            keyword: read line include keyword
            rows: the row number, which want to read
            offset: keep the parameter, but do nothing
        output:list
        """
        list_key = []
        str_rows = ""
        all_lines = []
        # check if file exists.
        if not os.path.exists(filename):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % filename)
        try:
            with open(filename, 'rb') as fp:
                for line in fp:
                    all_lines.append(line.decode("utf-8"))
        except Exception:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % filename)
        # get keyword lines
        if keyword != "":
            for line in all_lines:
                flag = line.find(keyword)
                if flag >= 0:
                    list_key.append(line)
        # get content of row
        if rows:
            if not str(rows).isdigit():
                raise Exception
            if rows > 0:
                row_num = rows - 1
            else:
                row_num = rows
            try:
                if row_num < (len(all_lines)):
                    str_rows = all_lines[row_num]
            except Exception:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50204"] % (
                        "the %s line of the file [%s]" % (rows, filename)))
        # check which needs return
        if keyword != "" and rows != 0:
            return [str_rows]
        if keyword != "" and rows == 0:
            return list_key
        if keyword == "" and rows != 0:
            return [str_rows]
        if keyword == "" and rows == 0:
            return all_lines

    @staticmethod
    def writeFile(path, context=None, mode="a+"):
        """
        function: write content in a file
        input:
            path: the name and path of the file
            context: the content, which want to write
            mode: the write mode
        output:
        """
        lock = _thread.allocate_lock()
        if context is None:
            context = []
        # check if not exists.
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        # check if is a file.
        if os.path.exists(path) and not os.path.isfile(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % path)
        # if no context, return
        if not context:
            return False
        FileUtil.createFileInSafeMode(path)
        with open(path, mode) as fp:
            fp.writelines(line + os.linesep for line in context)
            lock.acquire()
            try:
                # write context.
                fp.flush()
            except Exception as excep:
                lock.release()
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % path +
                                "Error:\n%s" % str(excep))
            lock.release()
        return True

    @staticmethod
    def write_update_file(file_path, content, authority, is_json=True):
        """
        Write or update file, create if not exist.
        """
        with os.fdopen(os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                               authority), "w") as fp_write:
            if is_json:
                json.dump(content, fp_write)
            else:
                fp_write.write(content)

    @staticmethod
    def write_add_file(file_path, content, authority):
        """
        Write or add content in file, create if not exist.
        """

        if not os.path.isfile(file_path):
            FileUtil.createFileInSafeMode(file_path, mode=authority)
        FileUtil.writeFile(file_path, [content])

    @staticmethod
    def write_custom_context(file_path, content, authority, p_mode="w"):
        '''
        Write file in overwrite mode
        '''

        if not os.path.isfile(file_path):
            FileUtil.createFileInSafeMode(file_path, mode=authority)
        FileUtil.writeFile(file_path, content, p_mode)

    @staticmethod
    def withAsteriskPath(path):
        """
        function: deal with the path with *
        input: the path to deal with
        output: cmd
        """
        path_dir_list = os.path.realpath(path).split(os.path.sep)[1:]
        path = "'"
        for dir_name in path_dir_list:
            if "*" in dir_name:
                dir_path = "'" + os.path.sep + dir_name + "'"
            else:
                dir_path = os.path.sep + dir_name
            path += dir_path
        if path[-1] == "'":
            path = path[:-1]
        else:
            path += "'"
        return path

    @staticmethod
    def changeMode(mode, path, recursive=False, cmd_type="shell",
                   retry_flag=False, retry_time=15, waite_time=1):
        """
        function: change permission of file
        input:
            cmd_type: user shell or python
            mode:permission value, Type is int and start with 0. ex: 0700
            path:file path
            recursive: recursive or not
        output:
        """
        # do with shell command.
        if cmd_type == "shell":
            if "*" in path:
                path = FileUtil.withAsteriskPath(path)
            else:
                path = "'" + path + "'"
            cmd = CmdUtil.getChmodCmd(str(mode), path, recursive)
            if retry_flag:
                CmdUtil.retryGetstatusoutput(cmd, retry_time, waite_time)
            else:
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(ErrorCode.GAUSS_501[
                                    "GAUSS_50107"] % path +
                                    " Error:\n%s." % output +
                                    "The cmd is %s" % cmd)
        # do with python API. If the name has special characters.
        else:
            os.chmod(path, mode)
        return True

    @staticmethod
    def change_caps(cap_mode, path):
        '''
        Add the read and write permissions of some root users.
        '''

        cmd = 'export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin; '
        cmd = cmd + 'setcap {}+ep {}'.format(cap_mode, path)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50107"] % path +
                            " Error:\n%s." % output + "The cmd is %s" % cmd)

    @staticmethod
    def get_caps(path):
        '''
        Get the permissions of some root users.
        '''
        cmd = 'export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin; '
        cmd = cmd + f'getcap {path}'
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50112"] % path +
                            " Error:\n%s." % output + "The cmd is %s" % cmd)
        return output.strip()


    @staticmethod
    def changeOwner(user, path, recursive=False, cmd_type="shell",
                    retry_flag=False, retry_time=15, waite_time=1, link=False):
        """
        function: change the owner of file
        input: cmd_type, user, path, recursive
        output: return true
        """
        try:
            # get uid and gid by username.
            try:
                userInfo = pwd.getpwnam(user)
            except KeyError:
                userInfo = pwd.getpwnam(user)
            group = grp.getgrgid(userInfo.pw_gid).gr_name
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50308"] +
                            " Error:\n%s" % str(e))
        try:
            # do with shell command.
            if cmd_type == "shell":
                if "*" in path:
                    path = FileUtil.withAsteriskPath(path)
                else:
                    path = "'" + path + "'"
                cmd = CmdUtil.getChownCmd(user, group, path, recursive)
                if link:
                    cmd = cmd + " -h"
                if retry_flag:
                    CmdUtil.retryGetstatusoutput(cmd, retry_time, waite_time)
                else:
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if status != 0:
                        raise Exception(output + " The cmd is %s" % cmd)
            # do with python API. If the name has special characters.
            else:
                os.chown(path, userInfo.pw_uid, userInfo.pw_gid)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_501["GAUSS_50106"] % path +
                            " Error:\n%s." % str(e))
        return True

    @staticmethod
    def modifyFileOwner(user, currentfile):
        """
        function : Modify the file's owner
        input : String,String
        output : String
        """
        # only root user can run this function
        if os.getuid() == 0:
            UserUtil.getGroupByUser(user)
            if os.path.exists(currentfile):
                FileUtil.changeOwner(user, currentfile)

    @staticmethod
    def modifyFileOwnerFromGPHOME(currentfile):
        """
        function : Modify the file's owner to the GPHOME's user
        input : String,String
        output : String
        """
        gphome = EnvUtil.getEnv("GPHOME")
        if not gphome:
            raise Exception(ErrorCode.GAUSS_518["GAUSS_51802"] % "GPHOME")
        (user, group) = UserUtil.getPathOwner(gphome)
        if user == "" or group == "":
            raise Exception(ErrorCode.GAUSS_503["GAUSS_50308"])
        FileUtil.modifyFileOwner(user, currentfile)

    @staticmethod
    def createDirectory(path, overwrite=True, mode=None):
        """
        function: create a directory
        input: path, overwrite
        output: true
        """
        try:
            if os.path.exists(path) and not overwrite:
                raise Exception(ErrorCode.GAUSS_501["GAUSS_50102"] % (
                    "parameter overwrite", path))
            if overwrite:
                cmd = CmdUtil.getMakeDirCmd(path, overwrite)
                if mode:
                    cmd += "; %s" % CmdUtil.getChmodCmd(str(mode), path)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(output + " The cmd is %s" % cmd)
            if not overwrite:
                if mode:
                    os.mkdir(path, mode)
                else:
                    os.mkdir(path)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50208"] % path +
                            " Error:\n%s" % str(e))
        return True

    @staticmethod
    def cleanDirectoryContent(path):
        """
        function: clean the content in a directory,
        but do not remove directory.
        input:path
        output:true
        """
        prefix_cmd = "cd %s && ls | xargs -n 100000" % path
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        cmd = "%s %s && %s '%s'/.[^.]*" % (prefix_cmd, CmdUtil.getRemoveCmd(
            "directory"), CmdUtil.getRemoveCmd("directory"), path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50209"] % (
                    "content in the directory %s " % path) +
                    " Error:\n%s." % output + "The cmd is %s" % cmd)
        return True

    @staticmethod
    def cleanFileContext(path):
        """
        function: clean file context
        input: path, file path
        """
        real_path = os.path.realpath(path)
        if os.path.exists(real_path) and os.path.getsize(real_path) > 0:
            with open(real_path, 'r+') as fp_file:
                fp_file.seek(0)
                fp_file.truncate()
                fp_file.flush()

    @staticmethod
    def removeDirectory(path):
        """
        function: remove the content in a directory
        input:path
        output:true
        """
        if "*" in path:
            path = FileUtil.withAsteriskPath(path)
            cmd = "%s %s" % (CmdUtil.getRemoveCmd("directory"), path)
        else:
            cmd = "%s '%s'" % (CmdUtil.getRemoveCmd("directory"), path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50209"] % path +
                            " Error:\n%s." % output + "The cmd is %s" % cmd)
        return True

    @staticmethod
    def getDirectoryList(path, keywords="", recursive=False):
        """
        function:give the list of file in the directory
        input:path, keywords, recursive
        output:list
        """
        list_dir = []
        try:
            if keywords == "":
                if recursive:
                    cmd = "%s -R '%s'" % (CmdUtil.getListCmd(), path)
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if status != 0:
                        raise Exception(output + "\nThe cmd is %s" % cmd)
                    list_dir = output.split('\n')
                else:
                    list_dir = os.listdir(path)
            else:
                if recursive:
                    cmd = "%s -R '%s' |%s -E '%s'" % (
                        CmdUtil.getListCmd(), path,
                        CmdUtil.getGrepCmd(), keywords)
                else:
                    cmd = "%s '%s' |%s -E '%s'" % (
                        CmdUtil.getListCmd(), path,
                        CmdUtil.getGrepCmd(), keywords)
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0 and output != "":
                    raise Exception(output + "\nThe cmd is %s" % cmd)
                else:
                    list_dir = output.split('\n')
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % (
                    "the list of %s" % path) + " Error:\n%s" % str(e))
        while '' in list_dir:
            list_dir.remove('')
        return list_dir

    @staticmethod
    def cpFile(src, dest, cmd_type="shell", skip_check=False):
        """
        function: copy a file
        input:src, dest, cmd_type
        output:true
        """
        if skip_check:
            if not os.path.exists(src):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % src)
            if not os.path.exists(os.path.dirname(dest)):
                raise Exception(ErrorCode.GAUSS_502[
                                    "GAUSS_50201"] % os.path.dirname(dest))
        try:
            if cmd_type != "shell":
                shutil.copy(src, dest)
            else:
                cmd = CmdUtil.getCopyCmd(src, dest, "directory")
                (status, output) = subprocess.getstatusoutput(cmd)
                if status != 0:
                    raise Exception(output + "\nThe cmd is %s" % cmd)
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50214"] % src +
                            " Error:\n%s" % str(e))
        return True

    @staticmethod
    def findFile(path, keyword, choice='name'):
        """
        function:find a file by name or size or user
        input:path, keyword, choice, type
        output:NA
        """
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)
        cmd = "%s '%s' -%s %s " % (CmdUtil.getFindCmd(), path,
                                   choice, keyword)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % (
                    "the files of path %s" % path) + " Error:\n%s" % output
                            + "\nThe cmd is %s" % cmd)
        list_file = output.split('\n')
        while '' in list_file:
            list_file.remove('')
        return list_file

    @staticmethod
    def replaceFileLineContent(old_line, new_line, path):
        """
        function: replace the line in a file to a new line
        input:
        old_line : Need to replace content
        new_line : Replaced content
        path
        output:NA
        """
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)

        cmd = CmdUtil.getReplaceFileLineContentCmd(old_line, new_line, path)
        proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid, close_fds=True)
        stdout, stderr = proc.communicate()
        output = stdout + stderr
        status = proc.returncode
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50223"] % path +
                            " Error:\n%s" % SensitiveMask.mask_pwd(output) +
                            "\nThe cmd is %s" % SensitiveMask.mask_pwd(cmd))

    @staticmethod
    def checkIsInDirectory(file_name, directory_list):
        """
        function : Check if the file is in directory_list.
        input : String,[]
        output : []
        """
        is_exist = False
        for one_path in directory_list:
            dir_name = os.path.normpath(file_name)
            is_exist = False

            while dir_name != "/":
                if dir_name == one_path:
                    is_exist = True
                    break
                dir_name = os.path.dirname(dir_name)

            if is_exist:
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50229"] % (
                    file_name, one_path))
        return is_exist

    @staticmethod
    def checkDirWriteable(dir_path):
        """
        function : Check if target directory is writeable for execute user.
        input : String,String
        output : boolean
        """
        # if we can touch a tmp file under the path, it is true;
        return os.access(dir_path, os.W_OK)

    @staticmethod
    def getFileSHA256(filename):
        """
        function : Get the ssh file by SHA256
        input : String
        output : String
        """
        if not os.path.exists(filename):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % filename)
        if not os.path.isfile(filename):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % filename)

        strSHA256 = ""
        cmd = CmdUtil.getFileSHA256Cmd(filename)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            return strSHA256
        strSHA256 = output.strip()

        return strSHA256

    @staticmethod
    def getDirSize(path, unit=""):
        """
        function : Get the directory or file size
        input : String, String
        output : String
        """
        sizeInfo = ""
        cmd = CmdUtil.getDirSizeCmd(path, unit)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            return sizeInfo
        return output.split()[0]

    @staticmethod
    def getFilesType(given_path):
        """
        function : get the file and subdirectory type of the given path
        input : String
        output : String
        """
        if not os.path.exists(given_path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % given_path)
        # obtain the file type
        tmp_file = "/tmp/fileList_%d" % os.getpid()
        cmd = "%s '%s' ! -iname '.*' | %s file -F '::' > %s 2>/dev/null" % (
            CmdUtil.getFindCmd(), given_path,
            CmdUtil.getXargsCmd(), tmp_file)
        subprocess.getstatusoutput(cmd)
        # Return code is not equal to zero when file a non-existent
        # file in SLES SP4
        # But it is equal to zero in SLES SP1/SP2/SP3 and
        # RHEL 6.4/6.5/6.6 platform, skip check status and output
        res_dict = {}
        try:
            with open(tmp_file, 'r') as fp:
                file_name_type_list = fp.readlines()
            os.remove(tmp_file)
            for one_item in file_name_type_list:
                res = one_item.split("::")
                if len(res) != 2:
                    continue
                else:
                    res_dict[res[0]] = res[1]
            return res_dict
        except Exception as excep:
            if os.path.exists(tmp_file):
                FileUtil.removeFile(tmp_file)
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50221"] +
                            " Error: \n%s" % str(excep))

    @staticmethod
    def deleteLine(file_path, line_info):
        """
        function : delete a line in file match with re
        input : file_path ,line_info
        output : NA
        """
        cmd = CmdUtil.getSedCmd()
        cmd += " -i '/%s/d' %s" % (line_info, file_path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % file_path +
                            " Error:\n%s" % output + "\nThe cmd is %s" % cmd)

    @staticmethod
    def deleteLineByRowNum(file_path, line_num):
        """
        function : delete line in a file by row num
        input : file_path ,line_info
        output : NA
        """
        cmd = CmdUtil.getSedCmd()
        cmd += " -i '%sd' %s" % (line_num, file_path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"] % file_path +
                            " Error:\n%s" % output + "\nThe cmd is %s" % cmd)

    @staticmethod
    def rename(old_file_path, new_file_path):
        """
        function : rename a file name to new name
        input : old_file_path, new_file_path
        output : NA
        """
        cmd = CmdUtil.getMoveCmd(old_file_path, new_file_path)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50218"] % old_file_path +
                            " Error:\n%s" % output + "\nThe cmd is %s" % cmd)

    @staticmethod
    def checkLink(file_path):
        """
        function:check if file is a link
        input: file_path
        output:NA
        """
        if os.path.exists(file_path):
            if os.path.islink(file_path):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50210"] % file_path)

    @staticmethod
    def getTopPathNotExist(top_dir_path):
        """
        function : Get the top path if exist
        input : String
        output : String
        """
        tmp_dir = top_dir_path
        while True:
            # find the top path to be created
            (tmp_dir, top_dir_name) = os.path.split(tmp_dir)
            if os.path.exists(tmp_dir) or top_dir_name == "":
                tmp_dir = os.path.join(tmp_dir, top_dir_name)
                break
        return tmp_dir

    @staticmethod
    def getfileUser(path):
        """
        function: get the info(username group) of a file
        input:path
        output:list of info
        """
        if not os.path.exists(path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % path)

        user = pwd.getpwuid(os.stat(path).st_uid).pw_name
        group = grp.getgrgid(os.stat(path).st_gid).gr_name
        return user, group

    @staticmethod
    def judgePathUser(temp_path):
        """
        function: judge the owner of path if exist
        input: temp_path
        output: True/False
        """
        try:
            pwd.getpwuid(os.stat(temp_path).st_uid).pw_name
            return True
        except Exception as e:
            # if the user is not exist
            if str(e).find("uid not found") >= 0:
                return False
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            ("the owner of %s" % temp_path) +
                            " Error: \n%s" % str(e))

    @staticmethod
    def checkPathandChangeOwner(one_path, user, permission):
        """
        function: Get the owner of each layer path , if the user does not
                  exist and change owner
        input: onePath---the specified path; user---the user of cluster;
               group---the group of cluster
        output: the owner of path
        precondiftion: the path exists
        """
        pathlist = []
        if not os.path.exists(one_path):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % one_path)

        owner_path = one_path
        while True:
            # obtain the each top path
            (owner_path, dirName) = os.path.split(owner_path)
            if os.path.exists(owner_path) and dirName != "":
                pathlist.append(os.path.join(owner_path, dirName))
            else:
                break

        for temp_path in pathlist:
            # the user does not exist
            if not FileUtil.judgePathUser(temp_path):
                FileUtil.changeMode(permission, temp_path)
                FileUtil.changeOwner(user, temp_path)

    @staticmethod
    def getchangeDirModeCmd(user_dir):
        """
        function : change directory permission
        input : user_dir
        output: NA
        """
        # Use "find -exec" to mask special characters
        cmd_dir = "find '%s' -type d -exec chmod '%s' {} \;" % (
            user_dir, ConstantsBase.KEY_DIRECTORY_MODE)
        (status, diroutput) = subprocess.getstatusoutput(cmd_dir)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % user_dir +
                            " Error: \n%s" % diroutput)

    @staticmethod
    def getchangeFileModeCmd(user_dir):
        """
        function : change log file permission
        input : user_dir
        output: NA
        """
        # Use "find -exec" to mask special characters
        cmd_file = "find '%s' -type f -name '*.log' -exec chmod '%s' {} \;" \
                   % (user_dir, ConstantsBase.KEY_FILE_MODE)
        (status, file_output) = subprocess.getstatusoutput(cmd_file)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % "log file" +
                            " Directory:%s." % user_dir + " Error: \n%s" % file_output)

    @staticmethod
    def checkFileExists(file):
        """
        function : change file exists
        input : file name
        output: NA
        """
        return os.path.exists(file)
