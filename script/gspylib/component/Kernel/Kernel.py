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
#############################################################################
import sys
import os
import subprocess
import re
import pwd
import json

sys.path.append(sys.path[0] + "/../../../")
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.GaussLog import GaussLog
from gspylib.component.BaseComponent import BaseComponent
from gspylib.common.Common import DefaultValue
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.security.security_checker import SecurityChecker
from domain_utils.cluster_os.cluster_user import ClusterUser
from base_utils.os.net_util import NetUtil

MAX_PARA_NUMBER = 1000


class Kernel(BaseComponent):
    '''
    The class is used to define base component.
    '''

    def __init__(self):
        """
        """
        super(Kernel, self).__init__()
        # init paramter schemaCoordinatorFile,
        # schemaJobFile and schemaDatanodeFile
        tmpDir = EnvUtil.getTmpDirFromEnv()
        self.schemaCoordinatorFile = "%s/%s" % (
            tmpDir, DefaultValue.SCHEMA_COORDINATOR)
        self.coordinatorJobDataFile = "%s/%s" % (
            tmpDir, DefaultValue.COORDINATOR_JOB_DATA)
        self.schemaDatanodeFile = "%s/%s" % (tmpDir,
                                             DefaultValue.SCHEMA_DATANODE)
        self.dumpTableFile = "%s/%s" % (tmpDir,
                                        DefaultValue.DUMP_TABLES_DATANODE)
        self.dumpOutputFile = "%s/%s" % (tmpDir,
                                         DefaultValue.DUMP_Output_DATANODE)
        self.coordinatorStatisticsDataFile = "%s/%s" % (
            tmpDir, DefaultValue.COORDINATOR_STAT_DATA)

    """
    Desc: 
        start/stop/query single instance 
    """

    def start(self, time_out=DefaultValue.TIMEOUT_CLUSTER_START,
              security_mode="off", cluster_number=None, is_dss_mode=False):
        """
        """
        if cluster_number:
            cmd = "%s/gs_ctl start -o '-u %s' -D %s " % (
                self.binPath, int(float(cluster_number) * 1000),
                self.instInfo.datadir)
        else:
            cmd = "%s/gs_ctl start -D %s " % (
                self.binPath, self.instInfo.datadir)
        if not is_dss_mode and self.instInfo.instanceType == DefaultValue.MASTER_INSTANCE:
            if len(self.instInfo.peerInstanceInfos) > 0:
                cmd += "-M primary"
        elif not is_dss_mode and self.instInfo.instanceType == DefaultValue.CASCADE_STANDBY:
            cmd += "-M cascade_standby"
        elif not is_dss_mode and self.instInfo.instanceType == DefaultValue.STANDBY_INSTANCE:
            cmd += "-M standby"
        if time_out is not None:
            cmd += " -t %s" % time_out
        if security_mode == "on":
            cmd += " -o \'--securitymode\'"
        configFile = "%s/postgresql.conf" % self.instInfo.datadir
        output = FileUtil.readFile(configFile, "logging_collector")
        value = None
        for line in output:
            line = line.split('#')[0].strip()
            if line.find('logging_collector') >= 0 and line.find('=') > 0:
                value = line.split('=')[1].strip()
                break
        if value == "off":
            cmd += " >/dev/null 2>&1"
        self.logger.debug("start cmd = %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0 or re.search("start failed", output):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51607"] % "instance"
                            + " Error: Please check the gs_ctl log for "
                              "failure details." + "\n" + output)
        if value == "off":
            output = "[BACKEND] WARNING: The parameter logging_collector is " \
                     "set to off. The log will not be recorded to file. " \
                     "Please check any error manually."
        self.logger.log(output)

    def stop(self, stopMode="", time_out=300):
        """
        """
        cmd = "%s/gs_ctl stop -D %s " % (
            self.binPath, self.instInfo.datadir)
        if not self.isPidFileExist():
            cmd += " -m immediate"
        else:
            # check stop mode
            if stopMode != "":
                cmd += " -m %s" % stopMode
        cmd += " -t %s" % time_out
        self.logger.debug("stop cmd = %s" % cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51610"] %
                            "instance" + " Error: \n%s." % output)
        if output.find("No such process") > 0:
            cmd = "ps c -eo pid,euid,cmd | grep gaussdb | grep -v grep | " \
                  "awk '{if($2 == curuid && $1!=\"-n\") " \
                  "print \"/proc/\"$1\"/cwd\"}' curuid=`id -u`|" \
                  " xargs ls -l |awk '{if ($NF==\"%s\") print $(NF-2)}' | " \
                  "awk -F/ '{print $3 }'" % (self.instInfo.datadir)
            (status, rightpid) = subprocess.getstatusoutput(cmd)
            if rightpid and rightpid.find("Permission denied") > -1:
                self.logger.debug("stop success with query process %s" % output)
                return
            if rightpid or status != 0:
                GaussLog.exitWithError(output)

    def isPidFileExist(self):
        pidFile = "%s/postmaster.pid" % self.instInfo.datadir
        return os.path.isfile(pidFile)

    def build(self, buidMode="full", standByBuildTimeout=300):
        """
        """
        ping_tool = CmdUtil.get_ping_tool()
        cmd = "%s/gs_ctl build -D %s -M standby -b %s -r %d " % (
            self.binPath, self.instInfo.datadir, buidMode, standByBuildTimeout)
        (status, output) = subprocess.getstatusoutput(cmd)
        self.logger.debug("cmd is %s; output: %s" % (cmd, output))
        if (status != 0):
            hostname_cmd = "cat /etc/hosts | grep -i '#Gauss OM IP Hosts Mapping' | awk '{print $2}' | grep -v 'localhost'"
            (status, result) = subprocess.getstatusoutput(hostname_cmd)
            self.logger.debug("cmd is %s; output: %s" % (hostname_cmd, result))
            if status != 0:
                raise Exception("cat /etc/hosts failed! cmd: %s; Error: %s " % (hostname_cmd, result))
            host_list = result.splitlines()
            for host in host_list:
                ping_cmd = f"{ping_tool} {host} -c 5"
                (status, result) = subprocess.getstatusoutput(ping_cmd)
                self.logger.debug("cmd is %s; output: %s" % (ping_cmd, result))
                if status != 0:
                    raise Exception(f"{ping_tool} {host} failed! {output}")
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)

    def build_cascade(self, buidMode="full", standByBuildTimeout=300):
        """
        """
        cmd = "%s/gs_ctl build -D %s -M cascade_standby -b %s -r %d " % (
            self.binPath, self.instInfo.datadir, buidMode, standByBuildTimeout)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd +
                            " Error: \n%s " % output)

    """
    Desc: 
        Under the AP branch, the installation package of each 
        component is not distinguished. 
        After checking, unzip the public installation package and 
        complete the installation. 
    """

    def install(self, nodeName="", dbInitParams=""):
        """
        """
        pass

    def getInstanceTblspcDirs(self, nodeName=""):
        """
        function: Get instance dirs 
        input : NA
        output: NA
        """
        tbsDirList = []

        if (not os.path.exists("%s/pg_tblspc" % self.instInfo.datadir)):
            self.logger.debug("%s/pg_tblspc does not exists." %
                              self.instInfo.datadir)
            return tbsDirList

        fileList = os.listdir("%s/pg_tblspc" % self.instInfo.datadir)
        if (len(fileList)):
            for filename in fileList:
                if (os.path.islink("%s/pg_tblspc/%s" % (self.instInfo.datadir,
                                                        filename))):
                    linkDir = os.readlink("%s/pg_tblspc/%s" % (
                        self.instInfo.datadir, filename))
                    if (os.path.isdir(linkDir)):
                        tblspcDir = "%s/%s_%s" % (
                            linkDir, DefaultValue.TABLESPACE_VERSION_DIRECTORY,
                            nodeName)
                        self.logger.debug("Table space directories is %s." %
                                          tblspcDir)
                        tbsDirList.append(tblspcDir)
                    else:
                        self.logger.debug(
                            "%s is not link directory." % linkDir)
                else:
                    self.logger.debug("%s is not a link file." % filename)
        else:
            self.logger.debug("%s/pg_tblspc is empty." % self.instInfo.datadir)

        return tbsDirList

    def getLockFiles(self):
        """
        function: Get lock files 
        input : NA
        output: NA
        """
        fileList = []
        # the static file must be exists
        tmpDir = os.path.realpath(EnvUtil.getTmpDirFromEnv())

        pgsql = ".s.PGSQL.%d" % self.instInfo.port
        pgsqlLock = ".s.PGSQL.%d.lock" % self.instInfo.port
        fileList.append(os.path.join(tmpDir, pgsql))
        fileList.append(os.path.join(tmpDir, pgsqlLock))
        return fileList

    def removeSocketFile(self, fileName):
        """
        """
        FileUtil.removeFile(fileName, "shell")

    def removeTbsDir(self, tbsDir):
        """
        """
        FileUtil.removeDirectory(tbsDir)

    def cleanDir(self, instDir):
        """
        function: Clean the dirs
        input : instDir
        output: NA
        """
        if (not os.path.exists(instDir)):
            return

        dataDir = []
        dataDir = os.listdir(instDir)
        if (os.getuid() == 0):
            pglDir = '%s/pg_location' % instDir
            isPglDirEmpty = False
            if (os.path.exists(pglDir) and len(os.listdir(pglDir)) == 0):
                isPglDirEmpty = True
            if (len(dataDir) == 0 or isPglDirEmpty):
                FileUtil.cleanDirectoryContent(instDir)
        else:
            for info in dataDir:
                if (str(info) == "pg_location"):
                    resultMount = []
                    resultDir = []
                    pglDir = '%s/pg_location' % instDir

                    # delete all files in the mount point
                    cmd = "%s | %s '%s' | %s '{printf $3}'" % \
                          (CmdUtil.getMountCmd(), CmdUtil.getGrepCmd(),
                           pglDir, CmdUtil.getAwkCmd())
                    (status, outputMount) = subprocess.getstatusoutput(cmd)
                    if (status != 0):
                        raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] %
                                        instDir + " Error:\n%s." %
                                        str(outputMount) +
                                        "The cmd is %s" % cmd)
                    else:
                        if (len(outputMount) > 0):
                            resultMount = str(outputMount).split()
                            for infoMount in resultMount:
                                FileUtil.cleanDirectoryContent(infoMount)
                        else:
                            FileUtil.cleanDirectoryContent(instDir)
                            continue

                    # delete file in the pg_location directory
                    if (not os.path.exists(pglDir)):
                        continue
                    cmd = "cd '%s'" % pglDir
                    (status, output) = subprocess.getstatusoutput(cmd)
                    if (status != 0):
                        raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                                        cmd + " Error: \n%s " % output)

                    outputFile = FileUtil.findFile(".", "f", "type")
                    if (len(outputFile) > 0):
                        for infoFile in outputFile:
                            tmpinfoFile = pglDir + infoFile[1:]
                            for infoMount in resultMount:
                                if (tmpinfoFile.find(infoMount) < 0 and
                                        infoMount.find(tmpinfoFile) < 0):
                                    realFile = "'%s/%s'" % (pglDir, infoFile)
                                    FileUtil.removeFile(realFile, "shell")

                    # delete directory in the pg_location directory
                    cmd = "if [ -d '%s' ]; then cd '%s' && find -type d; fi" \
                          % \
                          (pglDir, pglDir)
                    (status, outputDir) = subprocess.getstatusoutput(cmd)
                    if (status != 0):
                        raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] %
                                        instDir + " Error:\n%s." %
                                        str(outputDir) + "The cmd is %s" % cmd)
                    else:
                        resultDir = FileUtil.findFile(".", "d", "type")
                        resultDir.remove(".")
                        if (len(resultDir) > 0):
                            for infoDir in resultDir:
                                tmpinfoDir = pglDir + infoDir[1:]
                                for infoMount in resultMount:
                                    if (tmpinfoDir.find(infoMount) < 0 and
                                            infoMount.find(tmpinfoDir) < 0):
                                        realPath = "'%s/%s'" % (
                                        pglDir, infoDir)
                                        FileUtil.removeDirectory(realPath)

            ignores = [
                'pg_location', 'cfg', 'log', 'dss_inst.ini', 'dss_vg_conf.ini',
                'nodedata.cfg', '.', '..'
            ]
            extra_cmd = '! -name'.join([' \'{}\' '.format(ig) for ig in ignores])

            cmd = "if [ -d '%s' ];then cd '%s' && find . ! -name %s -print0" \
                  " |xargs -r -0 -n100 rm -rf; fi "   % (instDir, instDir, extra_cmd)
            (status, output) = subprocess.getstatusoutput(cmd)
            if (status != 0):
                raise Exception(ErrorCode.GAUSS_502["GAUSS_50207"] %
                                instDir + " Error:\n%s." % str(output) +
                                "The cmd is %s" % cmd)

    def uninstall(self, instNodeName):
        """
        function: Clean node instances.
                  1.get the data dirs, tablespaces, soketfiles
                  2.use theard delete the dirs or files
        input : instNodeName
        output: NA
        """
        self.logger.log("Cleaning instance.")

        # tablespace data directory
        tbsDirList = self.getInstanceTblspcDirs(instNodeName)

        # sockete file
        socketFiles = self.getLockFiles()

        # clean tablespace dir
        if (len(tbsDirList) != 0):
            try:
                self.logger.debug("Deleting instances tablespace directories.")
                for tbsDir in tbsDirList:
                    if DefaultValue.non_root_owner(tbsDir):
                        self.removeTbsDir(tbsDir)
            except Exception as e:
                raise Exception(str(e))
            self.logger.log("Successfully cleaned instance tablespace.")

        if (len(self.instInfo.datadir) != 0):
            try:
                self.logger.debug("Deleting instances directories.")
                if DefaultValue.non_root_owner(self.instInfo.datadir):
                    self.cleanDir(self.instInfo.datadir)
            except Exception as e:
                raise Exception(str(e))
            self.logger.log("Successfully cleaned instances.")

        if (len(self.instInfo.xlogdir) != 0):
            try:
                self.logger.debug("Deleting instances xlog directories.")
                if DefaultValue.non_root_owner(self.instInfo.xlogdir):
                    self.cleanDir(self.instInfo.xlogdir)
            except Exception as e:
                raise Exception(str(e))
            self.logger.log("Successfully cleaned instances.")

        if (len(socketFiles) != 0):
            try:
                self.logger.debug("Deleting socket files.")
                for socketFile in socketFiles:
                    if DefaultValue.non_root_owner(socketFile):
                        self.removeSocketFile(socketFile)
            except Exception as e:
                raise Exception(str(e))
            self.logger.log("Successfully cleaned socket files.")

    def setCommonItems(self):
        """
        function: set common items
        input : tmpDir
        output: tempCommonDict
        """
        tempCommonDict = {}
        tmpDir = EnvUtil.getTmpDirFromEnv()
        tempCommonDict["unix_socket_directory"] = "'%s'" % tmpDir
        tempCommonDict["unix_socket_permissions"] = "0700"
        tempCommonDict["log_file_mode"] = "0600"
        tempCommonDict["enable_nestloop"] = "off"
        tempCommonDict["enable_mergejoin"] = "off"
        tempCommonDict["explain_perf_mode"] = "pretty"
        tempCommonDict["log_line_prefix"] = "'%m %c %d %p %a %x %n %e '"
        tempCommonDict["modify_initial_password"] = "true"

        return tempCommonDict

    def doGUCConfig(self, action, GUCParasStr, isHab=False, try_reload=False):
        """
        """
        # check instance data directory
        if (self.instInfo.datadir == "" or not os.path.exists(
                self.instInfo.datadir)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] %
                            ("data directory of the instance[%s]" %
                             str(self.instInfo)))

        if (GUCParasStr == ""):
            return

        # check conf file
        if (isHab == True):
            configFile = "%s/pg_hba.conf" % self.instInfo.datadir
        else:
            configFile = "%s/postgresql.conf" % self.instInfo.datadir
        if (not os.path.exists(configFile)):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % configFile)

        if try_reload:
            cmd_reload = "%s/gs_guc %s -D %s %s " % (self.binPath, 'reload',
                                                     self.instInfo.datadir, GUCParasStr)
            status, output = CmdUtil.retryGetstatusoutput(cmd_reload, 3, 3)
            if status != 0:
                self.logger.log("Failed to reload guc params with commander:[%s]" % cmd_reload)
            else:
                self.logger.log("Successfully to reload guc params with commander:[%s]"
                                % cmd_reload)
                return
        cmd = "%s/gs_guc %s -D %s %s " % (self.binPath, action,
                                          self.instInfo.datadir, GUCParasStr)
        self.logger.debug("gs_guc command is: {0}".format(cmd))
        (status, output) = CmdUtil.retryGetstatusoutput(cmd, 3, 3)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50007"] % "GUC" +
                            " Command: %s. Error:\n%s" % (cmd, output))

    def setGucConfig(self, paraDict=None, setMode='set'):
        """
        """
        i = 0
        guc_paras_str = ""
        guc_paras_str_list = []
        if paraDict is None:
            paraDict = {}
        for paras in paraDict:
            i += 1
            value = str(paraDict[paras])
            if (paras.startswith('dcf') and paras.endswith(('path', 'config'))):
                value = "'%s'" % value
            guc_paras_str += " -c \"%s=%s\" " % (paras, value)
            if (i % MAX_PARA_NUMBER == 0):
                guc_paras_str_list.append(guc_paras_str)
                i = 0
                guc_paras_str = ""
        if guc_paras_str != "":
            guc_paras_str_list.append(guc_paras_str)

        for parasStr in guc_paras_str_list:
            self.doGUCConfig(setMode, parasStr, False)

    def get_streaming_relate_dn_ips(self, instance):
        """
        function: Streaming disaster cluster, obtain the IP address of the DN
        with the same shards.
        input: NA
        :return: Cn ip
        """
        self.logger.debug("Start parse cluster_conf_record.")
        pg_host = EnvUtil.getEnv("PGHOST")
        config_param_file = os.path.realpath(
            os.path.join(pg_host, "streaming_cabin", "cluster_conf_record"))
        if not os.path.isfile(config_param_file):
            self.logger.debug("Not found streaming cluster config file.")
            return []

        with open(config_param_file, "r") as fp_read:
            param_dict = json.load(fp_read)
        dn_ip_list = []
        remote_cluster_conf = param_dict.get("remoteClusterConf")
        shards = remote_cluster_conf.get('shards')
        for shard in shards:
            for node_info in shard:
                shard_num = node_info.get("shardNum", '1')
                node_ip = node_info.get("dataIp")
                SecurityChecker.check_ip_valid("check ip from cluster_conf_record", node_ip)
                if not all([shard_num, node_ip]):
                    raise Exception(ErrorCode.GAUSS_516['GAUSS_51632']
                                    % "obtain remote conf from cluster_conf_record")
                if str(shard_num) == str(instance.mirrorId):
                    dn_ip_list.append(node_ip)
        self.logger.debug("Got streaming cluster pg_hba ips %s." % dn_ip_list)
        return dn_ip_list

    def removeIpInfoOnPghbaConfig(self, ipAddressList):
        """
        """
        i = 0
        GUCParasStr = ""
        GUCParasStrList = []
        pg_user = ClusterUser.get_pg_user()
        for ipAddress in ipAddressList:
            i += 1
            submask_length = NetUtil.get_submask_len(ipAddress)
            GUCParasStr += " -h \"host    all    all    %s/%s\"" % (ipAddress, submask_length)
            GUCParasStr += " -h \"host    all    %s    %s/%s\"" % (pg_user, ipAddress, submask_length)
            if i * 2 % MAX_PARA_NUMBER == 0:
                GUCParasStrList.append(GUCParasStr)
                i = 0
                GUCParasStr = ""
        if (GUCParasStr != ""):
            GUCParasStrList.append(GUCParasStr)

        for parasStr in GUCParasStrList:
            self.doGUCConfig("set", parasStr, True)
