# -*- coding:utf-8 -*-
# coding: UTF-8
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

import subprocess
import os
import time
import json
from functools import cmp_to_key

from gspylib.common.Common import ClusterCommand, DefaultValue
from gspylib.common.OMCommand import OMCommand
from gspylib.common.ErrorCode import ErrorCode
from gspylib.threads.parallelTool import parallelTool
from impl.checkperf.CheckperfImpl import CheckperfImpl
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from domain_utils.sql_handler.sql_executor import SqlExecutor
from base_utils.os.net_util import NetUtil
from base_utils.os.cmd_util import CmdUtil

# Database size inspection interval
DB_SIZE_CHECK_INTERVAL = 21600


class CheckperfImplOLAP(CheckperfImpl):
    """
    checkperf with OLAP
    """

    def __init__(self):
        """
        function: constructor
        """
        CheckperfImpl.__init__(self)
        self.recordColumn = {}
        self.recordPrevStat = {}
        self.sessionCpuColumn = []
        self.sessionMemoryColumn = []
        self.sessionIOColumn = []
        # Functional options
        self.ACTION_INSTALL_PMK = "install_pmk"
        self.ACTION_COLLECT_STAT = "collect_stat"
        self.ACTION_DISPLAY_STAT = "display_stat"
        self.ACTION_ASYN_COLLECT = "asyn_collect"
        self.DWS_mode = False

    def getNormalDatanodes(self):
        """
        function: get normal primary datanodes.
        input : NA
        output: instlist
        """
        clusterStatus = OMCommand.getClusterStatus()
        if clusterStatus is None:
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51600"])

        normalDNList = []
        for dbNode in self.clusterInfo.dbNodes:
            for dnInst in dbNode.datanodes:
                instStatus = clusterStatus.getInstanceStatusById(
                    dnInst.instanceId)
                if (instStatus is not None and
                        instStatus.isInstanceHealthy() and
                        instStatus.status in ["Primary"]):
                    normalDNList.append(dnInst)

        if (len(normalDNList) == 0):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51601"] % "DN" +
                            " There is no normal primary datanode.")

        # the cluster must be non-read-only status
        (status, output) = DefaultValue.checkTransactionReadonly(
            self.opts.user, self.clusterInfo, normalDNList)
        if (status != 0):
            raise Exception(
                ErrorCode.GAUSS_516["GAUSS_51602"] + "Error: \n%s" \
                % output + \
                "\nPlease ensure the database is not read only mode.")

        return normalDNList

    def checkClusterStatus(self):
        """
        function: Check cluster status,
         should be normal, no redistributing,and degrade(CN deleted only)
        input : NA
        output: None
        """
        self.logger.debug("Checking cluster status.")

        cmd = ClusterCommand.getQueryStatusCmd("", "", False)
        (status, output) = subprocess.getstatusoutput(cmd)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51600"]
                            + "\nCommand:\n  %s\nOutput:\n  %s"
                            % (cmd, str(output)))

        cluster_state = None
        redistributing = None
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("cluster_state"):
                cluster_state = \
                    line.split(":")[1].strip() \
                        if len(line.split(":")) == 2 else None
                continue
            if line.startswith("redistributing"):
                redistributing = \
                    line.split(":")[1].strip() \
                        if len(line.split(":")) == 2 else None
                continue

        # cluster status should be Normal or Degraded
        if cluster_state != "Normal" and cluster_state != "Degraded":
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51602"])

        # redistributing should be No
        if (redistributing != "No"):
            raise Exception(ErrorCode.GAUSS_516["GAUSS_51602"] + \
                            "\nPlease ensure the cluster is not in "
                            "redistributing.")

    def collectPMKData(
            self, pmk_curr_collect_start_time,
            pmk_last_collect_start_time, last_snapshot_id, port, host_name_list):
        """
        function: collect PMK data
        input  : pmk_curr_collect_start_time,
            pmk_last_collect_start_time, last_snapshot_id, port
        output : NA
        """
        cmd = ""
        failedNodes = []
        if (self.opts.mpprcFile != ""):
            cmd += "source %s;" % self.opts.mpprcFile
        cmd += \
            "%s -t %s -p %s -u %s -c %s -l %s" \
            % (OMCommand.getLocalScript("UTIL_GAUSS_STAT"),
               self.ACTION_COLLECT_STAT,
               self.clusterInfo.appPath,
               self.opts.user,
               str(port),
               self.opts.localLog)
        if (self.DWS_mode):
            cmd += " --dws-mode"
        if pmk_curr_collect_start_time != "":
            cmd += " --curr-time='%s'" % pmk_curr_collect_start_time
        if pmk_last_collect_start_time != "":
            cmd += " --last-time='%s'" % pmk_last_collect_start_time
        if last_snapshot_id != "":
            cmd += " --snapshot-id=%s" % last_snapshot_id

        cmd += " --flag-num=%d" % os.getpid()

        cmd += " --master-host=%s" % NetUtil.GetHostIpOrName()

        self.logger.debug("Command for executing %s on all hosts" % cmd)
        if (os.getuid() == 0):
            cmd = """su - %s -c \\\"%s\\\" """ % (self.opts.user, cmd)
        (status, output) = self.sshTool.getSshStatusOutput(cmd, host_name_list)
        for node in status.keys():
            if (status[node] == DefaultValue.SUCCESS):
                pass
            else:
                failedNodes.append(node)

        if (len(failedNodes) != 0):
            self.logger.debug(
                "Failed to collect statistics on (%s). Output: \n%s." \
                % (failedNodes, output))
            raise Exception(output)
        else:
            self.logger.debug(
                "Successfully collected statistics on all hosts.")

    def getMetaData(self, hostName, host, port):
        """
        function: get meta data of PMK(curr_collect_start_time,
        last_collect_start_time, last_snapshot_id)
        input : hostName, port
        output: NA
        """
        self.logger.debug("Getting PMK meta data.")
        try:
            local_host = NetUtil.GetHostIpOrName()
            status = 7
            result = None
            error_output = ""
            querySql = "SELECT l_pmk_curr_collect_start_time, " \
                       "l_pmk_last_collect_start_time, l_last_snapshot_id " \
                       "FROM pmk.get_meta_data();"
            if (self.DWS_mode):
                if (hostName == local_host):
                    # execute sql
                    (status, result, error_output) = \
                        SqlExecutor.excuteSqlOnLocalhost(port, querySql)
                else:
                    # Gets the current time
                    currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                    pid = os.getpid()
                    outputfile = \
                        "metadata_%s_%s_%s.json" \
                        % (hostName, pid, currentTime)
                    # Get the temporary directory from PGHOST
                    tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                    filepath = os.path.join(tmpDir, outputfile)
                    # execute SQL on remote host
                    ClusterCommand.executeSQLOnRemoteHost(
                        host, port, querySql, filepath)
                    # get sql result from outputfile
                    (status, result, error_output) = \
                        SqlExecutor.getSQLResult(host, outputfile)

                if (status != 2 or error_output != ""):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] \
                                    % querySql + " Error: \n%s" \
                                    % str(error_output))
                self.logger.debug("output: %s" % result)
                if (len(result) == 0):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] \
                                    % querySql + " Return record is null")

                recordList = result[0]

                if (recordList[0] != ''):
                    recordList[0] = (recordList[0]).strip()
                if (recordList[1] != ''):
                    recordList[1] = (recordList[1]).strip()
                if (recordList[2] != ''):
                    recordList[2] = (recordList[2]).strip()

                self.logger.debug("Successfully got PMK meta data.")
                return recordList[0], recordList[1], recordList[2]
            else:
                (status, output) = ClusterCommand.remoteSQLCommand(
                    querySql, self.opts.user,
                    host, port, False, DefaultValue.DEFAULT_DB_NAME)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"]
                                    % querySql + " Error: \n%s" % str(output))
                self.logger.debug("output: %s" % output)
                if (output == ""):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"]
                                    % querySql + " Return record is null")
                recordList = output.split('|')

                if (recordList[0] != ''):
                    recordList[0] = (recordList[0]).strip()
                if (recordList[1] != ''):
                    recordList[1] = (recordList[1]).strip()
                if (recordList[2] != ''):
                    recordList[2] = (recordList[2]).strip()

                self.logger.debug("Successfully got PMK meta data.")
                return recordList[0], recordList[1], recordList[2]
        except Exception as e:
            raise Exception(str(e))

    def deleteExpiredSnapShots(self, hostName, host, port):
        """
        function: delete expired snapshots records
        input : hostName, port
        output: NA
        """
        self.logger.debug("Deleting expired snapshots records.")
        try:
            local_host = NetUtil.GetHostIpOrName()
            # execute sql
            querySql = "SELECT * FROM pmk.delete_expired_snapshots();"
            if (self.DWS_mode):
                if (hostName == local_host):
                    (status, result, error_output) = \
                        SqlExecutor.excuteSqlOnLocalhost(port, querySql)
                else:
                    # Gets the current time
                    currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                    pid = os.getpid()
                    outputfile = \
                        "deleteSnapshots_%s_%s_%s.json" \
                        % (hostName, pid, currentTime)
                    # Create a temporary file
                    tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                    filepath = os.path.join(tmpDir, outputfile)
                    # execute SQL on remote host
                    ClusterCommand.executeSQLOnRemoteHost( \
                        host, port, querySql, filepath)
                    # get sql result from outputfile
                    (status, result, error_output) = \
                        SqlExecutor.getSQLResult(host, outputfile)
                if (status != 2):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] \
                                    % querySql \
                                    + " Error: \n%s" % str(error_output))
                self.logger.debug(
                    "Successfully deleted expired snapshots records.")
            else:
                # execute sql
                querySql = "SELECT * FROM pmk.delete_expired_snapshots();"
                (status, output) = ClusterCommand.remoteSQLCommand(
                    querySql, self.opts.user,
                    host, port, False, DefaultValue.DEFAULT_DB_NAME)
                if (status != 0):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] \
                                    % querySql \
                                    + " Error: \n%s" % str(output))
                self.logger.debug(
                    "Successfully deleted expired snapshots records.")
        except Exception as e:
            raise Exception(str(e))

    def parseSingleHostNodeStat(self, filePath):
        """
        function: parse node stat of single host
        input : filePath
        output: NA
        """
        self.logger.debug(
            "Parsing node stat of single host into the file[%s]." \
            % filePath)
        try:
            # read file
            nodtStat = FileUtil.readFile(filePath)
            # parse node stat
            for line in nodtStat:
                line = line.strip()
                recordItem = line.split("::::")
                if (len(recordItem) != 2):
                    continue
                column = (recordItem[1]).split('|')
                recordNode = (recordItem[0]).strip()
                self.recordColumn[recordNode] = column
            self.logger.debug(
                "Successfully parsed node stat of single " \
                "host into the file[%s]." % filePath)
        except Exception as e:
            raise Exception(str(e))

    def parseSessionCpuStat(self, filePath):
        """
        function: parse session cpu stat of single host
        input : filePath
        output: NA
        """
        self.logger.debug(
            "Parsing session cpu stat of single host into the file[%s]." \
            % filePath)
        try:
            # read file
            cpuStat = FileUtil.readFile(filePath)
            # parse session cpu stat
            for line in cpuStat:
                line = line.strip()
                column = line.split('|')
                self.sessionCpuColumn.append(column)
            self.logger.debug(
                "Successfully parsed session cpu " \
                "stat of single host into the file[%s]." % filePath)
        except Exception as e:
            raise Exception(str(e))

    def parseSessionMemoryStat(self, filePath):
        """
        function: parse session memory of single host
        input : filePath
        output: NA
        """
        self.logger.debug(
            "Parsing session memory stat of single host into the file[%s]." \
            % filePath)
        try:
            # read file
            MemoryStat = FileUtil.readFile(filePath)
            for line in MemoryStat:
                line = line.strip()
                column = line.split('|')
                self.sessionMemoryColumn.append(column)
            self.logger.debug(
                "Successfully parsed session memory stat of " \
                "single host into the file[%s]." % filePath)
        except Exception as e:
            raise Exception(str(e))

    def parseSessionIOStat(self, filePath):
        """
        function: parse session IO stat of single host
        input : filePath
        output: NA
        """
        self.logger.debug(
            "Parsing session IO stat of single host into the file[%s]." \
            % filePath)
        try:
            IOStat = FileUtil.readFile(filePath)
            for line in IOStat:
                line = line.strip()
                column = line.split('|')
                self.sessionIOColumn.append(column)
            self.logger.debug(
                "Successfully parsed session IO stat \
                of single host into the file[%s]." % filePath)
        except Exception as e:
            raise Exception(str(e))

    def getAllHostsNodeStat(self):
        """
        function: get node stat of all hosts
        input : NA
        output: NA
        """
        self.logger.debug("Getting node stat of all hosts.")
        resultFiles = []
        instCounts = 0
        try:
            # Get the cluster's node names
            hostNames = self.clusterInfo.getClusterNodeNames()
            # traversing host name
            for hostName in hostNames:
                node = self.clusterInfo.getDbNodeByName(hostName)
                node_ip = node.sshIps[0]
                recordTempFile = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "recordTempFile_%d_%s" % (os.getpid(), hostName))
                # check if recordTempFile exists
                if (os.path.exists(recordTempFile)):
                    # append recordTempFile to resultFiles
                    resultFiles.append(recordTempFile)
                else:
                    if (self.clusterInfo.isSingleInstCluster()):
                        continue
                    if (hostName != NetUtil.getHostName()):
                        scpcmd = "pssh -s -H %s 'pscp -H %s %s %s' " \
                                 % (node_ip, NetUtil.getHostName(),
                                    recordTempFile, recordTempFile)
                        (status, output) = subprocess.getstatusoutput(scpcmd)
                        if (status != 0):
                            self.logger.debug(
                                "Lost file [%s] in current node " \
                                " path [%s],the file is " \
                                "delivered from node [%s]" \
                                "by command 'scp';Error:\n%s" % \
                                (recordTempFile,
                                 EnvUtil.getTmpDirFromEnv(
                                     self.opts.user),
                                 hostName, output))
                        else:
                            resultFiles.append(recordTempFile)
                    else:
                        self.logger.debug(
                            "Lost local file [%s] in current " \
                            "node path [%s]" % \
                            (recordTempFile,
                             EnvUtil.getTmpDirFromEnv(self.opts.user)))
            # check if number matches
            if (len(resultFiles) == 0):
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50219"] \
                    % "the node stat files of all hosts")
            # concurrent execution
            parallelTool.parallelExecute(
                self.parseSingleHostNodeStat, resultFiles)

            # traverse node item
            for nodeItem in self.clusterInfo.dbNodes:
                instCounts += nodeItem.dataNum

            # judge if number of pgxc_node records is equal to
            # the number of data instances(cn and master dn)
            if (instCounts != len(self.recordColumn)):
                raise Exception(
                    ErrorCode.GAUSS_516["GAUSS_51637"] \
                    % ("number of pgxc_node records[%d]" % \
                       (len(self.recordColumn)),
                       "the number of data instances(cn and master dn)[%d]" \
                       % instCounts))

            # traverse file
            for tempFile in resultFiles:
                FileUtil.removeFile(tempFile)

            self.logger.debug("Successfully got node stat of all hosts.")
        except Exception as e:
            # traverse file
            for tempFile in resultFiles:
                # close and remove temporary file
                FileUtil.removeFile(tempFile)
            raise Exception(str(e))

    def getAllSessionCpuStat(self):
        """
        function: get cpu stat of all sessions
        input : NA
        output: NA
        """
        self.logger.debug("Getting cpu stat of all sessions.")
        resultFiles = []
        hostNames = []
        try:
            # get host names
            hostNames = self.clusterInfo.getClusterNodeNames()
            # traverse host names
            for hostName in hostNames:
                # get session Cpu Temp File
                sessionCpuTempFile = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionCpuTempFile_%d_%s" \
                    % (os.getpid(), hostName))
                # check if session Cpu Temp File exists
                if (os.path.exists(sessionCpuTempFile)):
                    # append session Cpu Temp File to result Files
                    resultFiles.append(sessionCpuTempFile)

            if (len(resultFiles) == 0):
                self.logger.debug("There are no sessions.")
                return

            # Concurrent execution
            self.logger.debug("resultFiles: %s" % resultFiles)
            parallelTool.parallelExecute(
                self.parseSessionCpuStat, resultFiles)

            self.logger.debug("self.sessionCpuColumn: \n")
            # traverse record
            for record in self.sessionCpuColumn:
                self.logger.debug("%s" % record)

            # traverse temp File
            for tempFile in resultFiles:
                # clean temp File
                FileUtil.removeFile(tempFile)

            self.logger.debug("Successfully got cpu stat of all sessions.")
        except Exception as e:
            # traverse temp File
            for tempFile in resultFiles:
                # clean temp File
                FileUtil.removeFile(tempFile)
            raise Exception(str(e))

    def getAllSessionMemoryStat(self):
        """
        function: get memory stat of all sessions
        input : NA
        output: NA
        """
        self.logger.debug("Getting memory stat of all sessions.")
        resultFiles = []
        hostNames = []
        try:
            # get host names
            hostNames = self.clusterInfo.getClusterNodeNames()
            # traverse host names
            for hostName in hostNames:
                sessionMemTempFile = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionMemTempFile_%d_%s" \
                    % (os.getpid(), hostName))
                # check if session Mem Temp File exists
                if (os.path.exists(sessionMemTempFile)):
                    # append session Mem Temp File to resultFiles
                    resultFiles.append(sessionMemTempFile)

            # judge if sessions
            if (len(resultFiles) == 0):
                self.logger.debug("There are no sessions.")
                return

            # Concurrent execution
            self.logger.debug("resultFiles: %s" % resultFiles)
            parallelTool.parallelExecute(
                self.parseSessionMemoryStat, resultFiles)
            self.logger.debug("self.sessionMemoryColumn: \n")
            # traverse record
            for record in self.sessionMemoryColumn:
                self.logger.debug("%s" % record)

            # traverse temp File
            for tempFile in resultFiles:
                FileUtil.removeFile(tempFile)

            self.logger.debug("Successfully got memory stat of all sessions.")
        except Exception as e:
            # traverse temp File
            for tempFile in resultFiles:
                # remove temporary file
                FileUtil.removeFile(tempFile)
            raise Exception(str(e))

    def getAllSessionIOStat(self):
        """
        function: get IO stat of all sessions
        input : NA
        output: NA
        """
        self.logger.debug("Getting IO stat of all sessions.")
        resultFiles = []
        hostNames = []
        try:
            # get host names
            hostNames = self.clusterInfo.getClusterNodeNames()
            # traverse host names
            for hostName in hostNames:
                sessionIOTempFile = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionIOTempFile_%d_%s" % (os.getpid(), hostName))
                # if session IO Temp File exists
                if (os.path.exists(sessionIOTempFile)):
                    # append session IO Temp File to resultFiles
                    resultFiles.append(sessionIOTempFile)

            # judge if sessions
            if (len(resultFiles) == 0):
                self.logger.debug("There are no sessions.")
                return

            # Concurrent execution
            self.logger.debug("resultFiles: %s" % resultFiles)
            parallelTool.parallelExecute(self.parseSessionIOStat, resultFiles)
            self.logger.debug("self.sessionIOColumn: \n")
            # traverse record
            for record in self.sessionIOColumn:
                self.logger.debug("%s" % record)

            # traverse temp File
            for tempFile in resultFiles:
                # close and remove temporary file
                FileUtil.removeFile(tempFile)

            self.logger.debug("Successfully got IO stat of all sessions.")
        except Exception as e:
            # traverse temp File
            for tempFile in resultFiles:
                # close and remove temporary file
                FileUtil.removeFile(tempFile)
            raise Exception(str(e))

    def getAllHostsPrevNodeStat(self, hostName, host, port, snapshotId):
        """
        function: get prev node stat of all hosts
        input : hostName, port, snapshotId
        output: NA
        """
        self.logger.debug("Getting prev node stat of all hosts.")
        dataNum = 0
        cooNum = 0
        try:
            for nodeItem in self.clusterInfo.dbNodes:
                dataNum += nodeItem.dataNum
                cooNum += nodeItem.cooNum
            if (self.DWS_mode):
                if (snapshotId != ""):
                    # query CN sql
                    querySql = ""
                    querySql += "SELECT node_name, " \
                                "COALESCE(pns.physical_reads, 0), " \
                                "COALESCE(pns.physical_writes, 0), "
                    querySql += "COALESCE(pns.read_time, 0), " \
                                "COALESCE(pns.write_time, 0), " \
                                "COALESCE(pns.xact_commit, 0), "
                    querySql += "COALESCE(pns.xact_rollback, 0), " \
                                "COALESCE(pns.checkpoints_timed, 0), " \
                                "COALESCE(pns.checkpoints_req, 0), "
                    querySql += "COALESCE(pns.checkpoint_write_time, 0)," \
                                "COALESCE(pns.blocks_read, 0)," \
                                "COALESCE(pns.blocks_hit, 0), "
                    querySql += "COALESCE(pns.busy_time, 0)," \
                                "COALESCE(pns.idle_time, 0), " \
                                "COALESCE(pns.iowait_time, 0), "
                    querySql += "COALESCE(pns.db_cpu_time, 0)FROM " \
                                "pmk.pmk_snapshot_coordinator_stat pns "
                    querySql += "WHERE pns.snapshot_id = %s" % snapshotId
                    local_host = NetUtil.GetHostIpOrName()

                    if (local_host == hostName):
                        (status, result, error_output) = \
                            SqlExecutor.excuteSqlOnLocalhost(port, querySql)
                    else:
                        # Gets the current time
                        currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                        pid = os.getpid()
                        outputfile = "nodestat_%s_%s_%s.json" \
                                     % (hostName, pid, currentTime)
                        tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                        filepath = os.path.join(tmpDir, outputfile)
                        # execute SQL on remote host
                        ClusterCommand.executeSQLOnRemoteHost(
                            host, port, querySql, filepath, snapshotId)
                        (status, result, error_output) = \
                            SqlExecutor.getSQLResult(host, outputfile)
                    if (status != 2):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Error: \n%s" % str(error_output))
                    self.logger.debug("output: %s" % result)
                    if (len(result) == 0):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Return record is null")

                    prevStatList = result
                    for i in range(len(prevStatList)):
                        prevStat = "|".join(prevStatList[i])
                        column = (prevStat).split('|')
                        recordName = (column[0]).strip()
                        self.recordPrevStat[recordName] = column

                    # query DN sql
                    querySql = ""
                    querySql += "SELECT node_name, " \
                                "COALESCE(pns.physical_reads, 0), " \
                                "COALESCE(pns.physical_writes, 0), "
                    querySql += "COALESCE(pns.read_time, 0), " \
                                "COALESCE(pns.write_time, 0), " \
                                "COALESCE(pns.xact_commit, 0), "
                    querySql += "COALESCE(pns.xact_rollback, 0)," \
                                "COALESCE(pns.checkpoints_timed, 0), " \
                                "COALESCE(pns.checkpoints_req, 0), "
                    querySql += "COALESCE(pns.checkpoint_write_time, 0), " \
                                "COALESCE(pns.blocks_read, 0), " \
                                "COALESCE(pns.blocks_hit, 0), "
                    querySql += "COALESCE(pns.busy_time, 0)," \
                                "COALESCE(pns.idle_time, 0), " \
                                "COALESCE(pns.iowait_time, 0), "
                    querySql += "COALESCE(pns.db_cpu_time, 0) " \
                                "FROM pmk.pmk_snapshot_datanode_stat pns "
                    querySql += "WHERE pns.snapshot_id = %s" % snapshotId
                    if (local_host == hostName):
                        (status, result, error_output) = \
                            SqlExecutor.excuteSqlOnLocalhost(port, querySql)
                    else:
                        # Gets the current time
                        currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                        pid = os.getpid()
                        outputfile = "nodestat_%s_%s_%s.json" \
                                     % (hostName, pid, currentTime)
                        tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                        filepath = os.path.join(tmpDir, outputfile)
                        ClusterCommand.executeSQLOnRemoteHost(
                            host, port, querySql, filepath, snapshotId)
                        (status, result, error_output) = \
                            SqlExecutor.getSQLResult(host, outputfile)
                    if (status != 2):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Error: \n%s" % str(error_output))
                    self.logger.debug("output: %s" % result)
                    if (len(result) == 0):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Return record is null")

                    prevStatList = result
                    for i in range(len(prevStatList)):
                        prevStat = "|".join(prevStatList[i])
                        column = (prevStat).split('|')
                        recordName = (column[0]).strip()
                        self.recordPrevStat[recordName] = column

                    # handle the scrnario expand or add-cn or delete-cn
                    for nodeName in self.recordColumn.keys():
                        if (self.recordPrevStat.__contains__(nodeName)):
                            pass
                        else:
                            tempPrevRecord = ['0', '0', '0', '0',
                                              '0', '0', '0', '0', '0',
                                              '0', '0', '0', '0', '0', '0']
                            prevRecord = []
                            prevRecord.append(nodeName)
                            prevRecord.extend(tempPrevRecord)
                            self.recordPrevStat[nodeName] = prevRecord
                    self.logger.debug("The pgxc nodes have been changed.")
                else:
                    tempPrevRecord = ['0', '0', '0', '0', '0', '0',
                                      '0', '0', '0', '0', '0', '0',
                                      '0', '0', '0']
                    for nodeName in self.recordColumn.keys():
                        prevRecord = []
                        prevRecord.append(nodeName)
                        prevRecord.extend(tempPrevRecord)
                        self.recordPrevStat[nodeName] = prevRecord

                self.logger.debug("Successfully got prev \
                node stat of all hosts.")
            else:
                if (snapshotId != ""):
                    if (not self.clusterInfo.isSingleInstCluster()):
                        # query CN sql
                        querySql = ""
                        querySql += "SELECT node_name, " \
                                    "COALESCE(pns.physical_reads, 0), " \
                                    "COALESCE(pns.physical_writes, 0), "
                        querySql += "COALESCE(pns.read_time, 0)," \
                                    " COALESCE(pns.write_time, 0)," \
                                    "COALESCE(pns.xact_commit, 0), "
                        querySql += "COALESCE(pns.xact_rollback, 0), " \
                                    " COALESCE(pns.checkpoints_timed, 0), " \
                                    " COALESCE(pns.checkpoints_req, 0), "
                        querySql += "COALESCE(pns.checkpoint_write_time, 0)," \
                                    " COALESCE(pns.blocks_read, 0), " \
                                    "COALESCE(pns.blocks_hit, 0), "
                        querySql += "COALESCE(pns.busy_time, 0)," \
                                    "COALESCE(pns.idle_time, 0), " \
                                    "COALESCE(pns.iowait_time, 0), "
                        querySql += "COALESCE(pns.db_cpu_time, 0)FROM " \
                                    "pmk.pmk_snapshot_coordinator_stat pns "
                        querySql += "WHERE pns.snapshot_id = %s" % snapshotId

                        (status, output) = ClusterCommand.remoteSQLCommand(
                            querySql, self.opts.user,
                            hostName, port, False,
                            DefaultValue.DEFAULT_DB_NAME)
                        if (status != 0):
                            raise Exception(
                                ErrorCode.GAUSS_513["GAUSS_51300"] \
                                % querySql + " Error: \n%s" % str(output))
                        self.logger.debug("output: %s" % output)
                        if (output == ""):
                            raise Exception(
                                ErrorCode.GAUSS_513["GAUSS_51300"] \
                                % querySql + " Return record is null")

                        prevStatList = output.split('\n')
                        for prevStat in prevStatList:
                            prevStat = prevStat.strip()
                            column = (prevStat).split('|')
                            recordName = (column[0]).strip()
                            self.recordPrevStat[recordName] = column

                    # query DN sql
                    querySql = ""
                    querySql += "SELECT node_name, " \
                                "COALESCE(pns.physical_reads, 0), " \
                                "COALESCE(pns.physical_writes, 0), "
                    querySql += "COALESCE(pns.read_time, 0)," \
                                "COALESCE(pns.write_time, 0), " \
                                "COALESCE(pns.xact_commit, 0), "
                    querySql += "COALESCE(pns.xact_rollback, 0), " \
                                "COALESCE(pns.checkpoints_timed, 0), " \
                                "COALESCE(pns.checkpoints_req, 0), "
                    querySql += "COALESCE(pns.checkpoint_write_time, 0), " \
                                "COALESCE(pns.blocks_read, 0), " \
                                "COALESCE(pns.blocks_hit, 0), "
                    querySql += "COALESCE(pns.busy_time, 0)," \
                                "COALESCE(pns.idle_time, 0), " \
                                "COALESCE(pns.iowait_time, 0), "
                    querySql += "COALESCE(pns.db_cpu_time, 0) " \
                                "FROM pmk.pmk_snapshot_datanode_stat pns "
                    querySql += "WHERE pns.snapshot_id = %s" % snapshotId

                    # Execute sql command on remote host
                    (status, output) = ClusterCommand.remoteSQLCommand(
                        querySql, self.opts.user,
                        hostName, port, False, DefaultValue.DEFAULT_DB_NAME)
                    if (status != 0):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Error: \n%s" % str(output))
                    self.logger.debug("output: %s" % output)
                    if (output == ""):
                        raise Exception(
                            ErrorCode.GAUSS_513["GAUSS_51300"] \
                            % querySql + " Return record is null")

                    prevStatList = output.split('\n')
                    for prevStat in prevStatList:
                        prevStat = prevStat.strip()
                        column = (prevStat).split('|')
                        recordName = (column[0]).strip()
                        self.recordPrevStat[recordName] = column

                    # handle the scrnario expand or add-cn or delete-cn
                    for nodeName in self.recordColumn.keys():
                        if (self.recordPrevStat.__contains__(nodeName)):
                            pass
                        else:
                            tempPrevRecord = ['0', '0', '0', '0',
                                              '0', '0', '0', '0', '0',
                                              '0', '0', '0', '0', '0', '0']
                            prevRecord = []
                            prevRecord.append(nodeName)
                            prevRecord.extend(tempPrevRecord)
                            self.recordPrevStat[nodeName] = prevRecord
                    self.logger.debug("The pgxc nodes have been changed.")
                else:
                    tempPrevRecord = ['0', '0', '0', '0', '0', '0',
                                      '0', '0', '0', '0', '0', '0', '0',
                                      '0', '0']
                    for nodeName in self.recordColumn.keys():
                        prevRecord = []
                        prevRecord.append(nodeName)
                        prevRecord.extend(tempPrevRecord)
                        self.recordPrevStat[nodeName] = prevRecord
                self.logger.debug(
                    "Successfully got prev node stat of all hosts.")
        except Exception as e:
            raise Exception(str(e))

    def handleNodeStat(self):
        """
        function: handle the node stat of all hosts
        input : NA
        output: NA
        """
        self.logger.debug("Handling the node stat of all hosts.")
        try:

            for record in self.recordColumn.keys():
                columnNow = self.recordColumn[record]
                recordName = (columnNow[1]).strip()
                columnPrev = self.recordPrevStat[recordName]
                # value 1
                tempValue1 = int(
                    float(columnNow[6])) - int(float(columnPrev[1]))
                if (tempValue1 < 0):
                    tempValue1 = 0
                (self.recordColumn[record])[6] = str(tempValue1)

                # value 2
                tempValue2 = int(
                    float(columnNow[8])) - int(float(columnPrev[2]))
                if (tempValue2 < 0):
                    tempValue2 = 0
                (self.recordColumn[record])[8] = str(tempValue2)

                # value 3
                tempValue3 = int(
                    float(columnNow[10])) - int(float(columnPrev[3]))
                if (tempValue3 < 0):
                    tempValue3 = 0
                (self.recordColumn[record])[10] = str(tempValue3)

                # value 4
                tempValue4 = int(
                    float(columnNow[12])) - int(float(columnPrev[4]))
                if (tempValue4 < 0):
                    tempValue4 = 0
                (self.recordColumn[record])[12] = str(tempValue4)

                # value 5
                tempValue5 = int(
                    float(columnNow[18])) - int(float(columnPrev[5]))
                if (tempValue5 < 0):
                    tempValue5 = 0
                (self.recordColumn[record])[18] = str(tempValue5)

                # value 6
                tempValue6 = int(
                    float(columnNow[20])) - int(float(columnPrev[6]))
                if (tempValue6 < 0):
                    tempValue6 = 0
                (self.recordColumn[record])[20] = str(tempValue6)

                # value 7
                tempValue7 = int(
                    float(columnNow[22])) - int(float(columnPrev[7]))
                if (tempValue7 < 0):
                    tempValue7 = 0
                (self.recordColumn[record])[22] = str(tempValue7)

                # value 8
                tempValue8 = int(
                    float(columnNow[24])) - int(float(columnPrev[8]))
                if (tempValue8 < 0):
                    tempValue8 = 0
                (self.recordColumn[record])[24] = str(tempValue8)

                # value 9
                tempValue9 = int(
                    float(columnNow[26])) - int(float(columnPrev[9]))
                if (tempValue9 < 0):
                    tempValue9 = 0
                (self.recordColumn[record])[26] = str(tempValue9)

                # value 10
                tempValue10 = int(
                    float(columnNow[33])) - int(float(columnPrev[10]))
                if (tempValue10 < 0):
                    tempValue10 = 0
                (self.recordColumn[record])[33] = str(tempValue10)

                # value 11
                tempValue11 = int(
                    float(columnNow[35])) - int(float(columnPrev[11]))
                if (tempValue11 < 0):
                    tempValue11 = 0
                (self.recordColumn[record])[35] = str(tempValue11)

                # value 12
                tempValue12 = int(
                    float(columnNow[42])) - int(float(columnPrev[12]))
                if (tempValue12 < 0):
                    tempValue12 = 0
                (self.recordColumn[record])[42] = str(tempValue12)

                # value 13
                tempValue13 = int(
                    float(columnNow[44])) - int(float(columnPrev[13]))
                if (tempValue13 < 0):
                    tempValue13 = 0
                (self.recordColumn[record])[44] = str(tempValue13)

                # value 14
                tempValue14 = int(
                    float(columnNow[46])) - int(float(columnPrev[14]))
                if (tempValue14 < 0):
                    tempValue14 = 0
                (self.recordColumn[record])[46] = str(tempValue14)

                # value 15
                tempValue15 = int(
                    float(columnNow[48])) - int(float(columnPrev[15]))
                if (tempValue15 < 0):
                    tempValue15 = 0
                (self.recordColumn[record])[48] = str(tempValue15)
            self.logger.debug(
                "Successfully handled the node stat of all hosts.")
        except Exception as e:
            raise Exception(str(e))

    def handleSessionCpuStat(self, hostname, host):
        """
        function: handle session cpu stat of all hosts
        input : hostname
        output: NA
        """
        self.logger.debug("Handling session cpu stat of all hosts.")
        tempList = []
        sessionCpuTempResult = ""
        try:
            if (len(self.sessionCpuColumn) > 0):
                for record in self.sessionCpuColumn:
                    if (len(record) == 1):
                        continue
                    tempTuple = tuple(record)
                    tempList.append(tempTuple)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[0] > y[0]) - (x[0] < y[0]))),
                              reverse=False)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[5] > y[5]) - (x[5] < y[5]))),
                              reverse=True)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[3] > y[3]) - (x[3] < y[3]))),
                              reverse=True)
                self.logger.debug("tempList: %s" % tempList)

                sessionCpuTempResult = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionCpuTempResult_%d_%s" \
                    % (os.getpid(),
                       NetUtil.GetHostIpOrName()))
                # clean the temp file first
                FileUtil.createFile(sessionCpuTempResult)

                strCmd = ""
                for index in range(0, min(10, len(self.sessionCpuColumn))):
                    strCmd += "%s|%s|%s|%s|%s|%s\n" % \
                              ((tempList[index])[0], (tempList[index])[1],
                               (tempList[index])[2], (tempList[index])[3],
                               (tempList[index])[4], (tempList[index])[5])

                FileUtil.writeFile(sessionCpuTempResult, [strCmd])
                if (hostname != NetUtil.GetHostIpOrName()):
                    self.sshTool.scpFiles(
                        sessionCpuTempResult,
                        EnvUtil.getTmpDirFromEnv(self.opts.user) \
                        + "/", [host])

                    FileUtil.removeFile(sessionCpuTempResult)
            else:
                self.logger.debug("There are no session cpu statistics.")
            self.logger.debug(
                "Successfully handled session cpu stat of all hosts.")
        except Exception as e:
            # close and remove temporary file
            FileUtil.removeFile(sessionCpuTempResult)
            raise Exception(str(e))

    def handleSessionMemoryStat(self, hostname, host):
        """
        function: handle session memory stat of all hosts
        input : hostname
        output: NA
        """
        self.logger.debug("Handling session memory stat of all hosts.")
        tempList = []
        sessionMemTempResult = ""
        try:
            if (len(self.sessionMemoryColumn) > 0):
                for record in self.sessionMemoryColumn:
                    if (len(record) == 1):
                        continue
                    tempTuple = tuple(record)
                    tempList.append(tempTuple)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[0] > y[0]) - (x[0] < y[0]))),
                              reverse=False)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[4] > y[4]) - (x[4] < y[4]))),
                              reverse=True)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[3] > y[3]) - (x[3] < y[3]))),
                              reverse=True)
                self.logger.debug("tempList: %s" % tempList)

                # get session Mem Temp Result
                sessionMemTempResult = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionMemTempResult_%d_%s" \
                    % (os.getpid(), NetUtil.GetHostIpOrName()))
                # clean the temp file first
                FileUtil.createFile(sessionMemTempResult)

                strCmd = ""
                for index in range(0, min(10, len(self.sessionMemoryColumn))):
                    strCmd += "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" % \
                              ((tempList[index])[0], (tempList[index])[1],
                               (tempList[index])[2], (tempList[index])[3],
                               (tempList[index])[4], (tempList[index])[5],
                               (tempList[index])[6], (tempList[index])[7],
                               (tempList[index])[8], (tempList[index])[9])

                FileUtil.writeFile(sessionMemTempResult, [strCmd])
                if (hostname != NetUtil.GetHostIpOrName()):
                    self.sshTool.scpFiles(
                        sessionMemTempResult,
                        EnvUtil.getTmpDirFromEnv(self.opts.user) \
                        + "/", [host])

                    FileUtil.removeFile(sessionMemTempResult)
            else:
                self.logger.debug("There are no session memory statistics.")
            self.logger.debug(
                "Successfully handled session memory stat of all hosts.")
        except Exception as e:
            # close and remove temporary file
            FileUtil.removeFile(sessionMemTempResult)
            raise Exception(str(e))

    def handleSessionIOStat(self, hostname, host):
        """
        function: handle session IO stat of all hosts
        input : hostname
        output: NA
        """
        self.logger.debug("Handling session IO stat of all hosts.")
        tempList = []
        sessionIOTempResult = ""
        try:
            if (len(self.sessionIOColumn) > 0):
                for record in self.sessionIOColumn:
                    if (len(record) == 1):
                        continue
                    tempTuple = tuple(record)
                    tempList.append(tempTuple)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[0] > y[0]) - (x[0] < y[0]))),
                              reverse=False)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[4] > y[4]) - (x[4] < y[4]))),
                              reverse=True)
                tempList.sort(key=cmp_to_key(
                    lambda x, y: ((x[3] > y[3]) - (x[3] < y[3]))),
                              reverse=True)
                self.logger.debug("tempList: %s" % tempList)

                sessionIOTempResult = os.path.join(
                    EnvUtil.getTmpDirFromEnv(self.opts.user),
                    "sessionIOTempResult_%d_%s" \
                    % (os.getpid(), NetUtil.GetHostIpOrName()))
                # clean the temp file first
                FileUtil.createFile(sessionIOTempResult)

                strCmd = ""
                for index in range(0, min(10, len(self.sessionIOColumn))):
                    strCmd += "%s|%s|%s|%s|%s\n" % ((tempList[index])[0],
                                                    (tempList[index])[1],
                                                    (tempList[index])[2],
                                                    (tempList[index])[3],
                                                    (tempList[index])[4])

                FileUtil.writeFile(sessionIOTempResult, [strCmd])
                if (hostname != NetUtil.GetHostIpOrName()):
                    self.sshTool.scpFiles(
                        sessionIOTempResult,
                        EnvUtil.getTmpDirFromEnv(self.opts.user) \
                        + "/", [host])

                    # close and remove temporary file
                    FileUtil.removeFile(sessionIOTempResult)
            else:
                self.logger.debug("There are no session IO statistics.")
            self.logger.debug(
                "Successfully handled session IO stat of all hosts.")
        except Exception as e:

            # close and remove temporary file
            FileUtil.removeFile(sessionIOTempResult)
            raise Exception(str(e))

    def launchAsynCollection(self, host, port):
        """
        function: launch asyn collection for database size
        input : host, port
        output: NA
        """
        self.logger.debug("Collecting database size.")
        executingNodes = []
        querycmd = "ps -ef |grep '%s' | grep '%s' | grep -v grep" \
                   % (OMCommand.getLocalScript("UTIL_GAUSS_STAT"),
                      self.ACTION_ASYN_COLLECT)
        self.logger.debug(
            "Command for Querying Collecting database size: %s." \
            % querycmd)
        status = self.sshTool.getSshStatusOutput(querycmd)[0]
        outputMap = self.sshTool.parseSshOutput(self.sshTool.hostNames)
        for node in status.keys():
            if (outputMap[node].find(self.ACTION_ASYN_COLLECT) >= 0):
                executingNodes.append(node)

        # judge failed nodes
        if (len(executingNodes)):
            self.logger.debug(
                "Asyn Collection database size is in progress on nodes[%s]." \
                % ' '.join(executingNodes))
            return

        # Skip asyn collects database size when interval is less than 6 hours
        if (os.path.isfile(self.opts.databaseSizeFile)):
            # Get the last modified time of the file
            statinfo = os.stat(self.opts.databaseSizeFile)
            lastChangeTime = statinfo.st_mtime
            localTime = time.time()
            # Query time interval 6 hours
            if (int(localTime) - int(lastChangeTime) < DB_SIZE_CHECK_INTERVAL):
                self.logger.debug(
                    "Asyn collects database size within 6 hours.")
                return

        # launch asyn collection for database size
        cmd = "pssh -s -H %s \'" % (str(host))

        if (self.opts.mpprcFile != ""):
            cmd += "source %s;" % self.opts.mpprcFile
        cmd += "%s -t %s -p %s -u %s -c %s -l %s " \
               % (OMCommand.getLocalScript("UTIL_GAUSS_STAT"),
                  self.ACTION_ASYN_COLLECT,
                  self.clusterInfo.appPath,
                  self.opts.user,
                  str(port),
                  self.opts.localLog)
        cmd += "\' > /dev/null 2>&1 & "
        if (os.getuid() == 0):
            cmd = """su - %s -c "%s" """ % (self.opts.user, cmd)

        self.logger.debug(
            "Launch asyn collection command for executing %s on (%s:%s)" \
            % (cmd, str(host), str(port)))
        status = subprocess.getstatusoutput(cmd)[0]
        if status == 0:
            self.logger.debug("Successfully launch asyn collection.")
        else:
            self.logger.debug("Failed to launch asyn collection.")

    def getPreviousDbSize(self):
        """
        function: get previous database size
        input : NA
        output: NA
        """
        if (not os.path.isfile(self.opts.databaseSizeFile)):
            self.logger.debug(
                "The database size file [%s] does not exists."
                % self.opts.databaseSizeFile)
            return

        lines = FileUtil.readFile(self.opts.databaseSizeFile)

        if (len(lines) == 0):
            self.logger.debug(
                "The database size file [%s] is empty." \
                % self.opts.databaseSizeFile)
            return

        for line in lines:
            if (line.find("total_database_size:") >= 0):
                self.opts.databaseSize = int(
                    line.strip().split(":")[1].strip())
                break

        self.logger.debug(
            "The total database size is [%s]." \
            % str(self.opts.databaseSize))

    def insertNodeStat(self, hostName, host, port, currTime, lastTime, snapshotId):
        """
        function: insert the node stat of all hosts into the cluster
        input : hostname, port, currTime, lastTime, snapshotId
        output: NA
        """
        self.logger.debug(
            "Inserting the node stat of all hosts into the cluster.")
        insertSql = ""
        currTimeTemp = ""
        lastTimeTemp = ""
        snapshotIdTempNum = 0
        snapshotIdTempStr = ""
        try:
            if (currTime == ""):
                currTimeTemp = "NULL"
            else:
                currTimeTemp = "'%s'" % currTime

            if (lastTime == ""):
                lastTimeTemp = "NULL"
            else:
                lastTimeTemp = "'%s'" % lastTime

            if (snapshotId == ""):
                snapshotIdTempStr = "NULL"
            else:
                snapshotIdTempNum = int(snapshotId)

            if (snapshotIdTempNum == 0 or snapshotIdTempNum == 2147483647):
                snapshotIdTempNum = 1
            else:
                snapshotIdTempNum += 1

            snapshotIdTempStr = str(snapshotIdTempNum)
            dnInst = None
            for dbNode in self.clusterInfo.dbNodes:
                # find a dn instance
                if len(dbNode.datanodes) > 0:
                    dntmpInst = dbNode.datanodes[0]
                    if dntmpInst.hostname == hostName:
                        dnInst = dntmpInst
                        break

            for record in self.recordColumn.keys():
                column = self.recordColumn[record]
                insertSql += "INSERT INTO pmk.pmk_snapshot_datanode_stat" \
                             " VALUES("
                insertSql += "%s, '%s', '%s', '%s', %s," % (
                    column[0], column[1], column[2], column[3], column[4])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[5], column[6], column[7], column[8], column[9])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[10], column[11], column[12], column[13], column[14])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[15], column[16], column[17], column[18], column[19])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[20], column[21], column[22], column[23], column[24])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[25], column[26], column[27], column[28], column[29])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[30], column[31], column[32], column[33], column[34])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[35], column[36], column[37], column[38], column[39])
                insertSql += "%s, %s, %s, %s, %s," % (
                    column[40], column[41], column[42], column[43], column[44])
                insertSql += "%s, %s, %s, %s);\n" % (
                    column[45], column[46], column[47], column[48])

            if (insertSql != ""):
                startSql = "START TRANSACTION;"
                commitSql = "COMMIT;"
                tempSql = "INSERT INTO pmk.pmk_snapshot VALUES (%s, %s, %s, " \
                          "current_timestamp);\n" % (snapshotIdTempStr,
                                                     currTimeTemp,
                                                     lastTimeTemp)
                updateSql = "UPDATE pmk.pmk_meta_data SET last_snapshot_id" \
                            " = %s, last_snapshot_collect_time = %s; " % \
                            (snapshotIdTempStr, currTimeTemp)
                # execute the insert sql
                local_host = NetUtil.GetHostIpOrName()
                if self.DWS_mode:
                    if local_host == hostName:
                        (status, result,
                         error_output1) = SqlExecutor.excuteSqlOnLocalhost(
                            port, tempSql)
                        (status, result,
                         error_output2) = SqlExecutor.excuteSqlOnLocalhost(
                            port, insertSql)
                        (status, result,
                         error_output3) = SqlExecutor.excuteSqlOnLocalhost(
                            port, updateSql)
                    else:
                        currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                        pid = os.getpid()
                        outputfile = "metadata_%s_%s_%s.json" % (
                            hostName, pid, currentTime)
                        tmpDir = EnvUtil.getTmpDirFromEnv()
                        filepath = os.path.join(tmpDir, outputfile)
                        ClusterCommand.executeSQLOnRemoteHost(dnInst.listenIps[0],
                                                              dnInst.port,
                                                              tempSql,
                                                              filepath)
                        (status, result,
                         error_output1) = SqlExecutor.getSQLResult(
                            dnInst.listenIps[0], outputfile)
                        ClusterCommand.executeSQLOnRemoteHost(dnInst.listenIps[0],
                                                              dnInst.port,
                                                              insertSql,
                                                              filepath)
                        (status, result,
                         error_output2) = SqlExecutor.getSQLResult(
                            dnInst.listenIps[0], outputfile)
                        ClusterCommand.executeSQLOnRemoteHost(dnInst.listenIps[0],
                                                              dnInst.port,
                                                              updateSql,
                                                              filepath)
                        (status, result,
                         error_output3) = SqlExecutor.getSQLResult(
                            dnInst.listenIps[0], outputfile)
                    if error_output1 != "":
                        self.logger.debug(
                            "Failed to execute SQL: %s" % startSql
                            + "\nError: \n%s" % str(error_output1))
                        raise Exception(ErrorCode.GAUSS_530["GAUSS_53012"]
                                        + "\nError: \n%s\n" \
                                        % str(error_output1)
                                        + "Please check the log for detail.")
                    if error_output2 != "":
                        self.logger.debug(
                            "Failed to execute SQL: %s" % insertSql
                            + "\nError: \n%s" % str(error_output2))
                        raise Exception(ErrorCode.GAUSS_530["GAUSS_53012"]
                                        + "\nError: \n%s\n" \
                                        % str(error_output2)
                                        + "Please check the log for detail.")
                    if error_output3 != "":
                        self.logger.debug(
                            "Failed to execute SQL: %s" % insertSql
                            + "\nError: \n%s" % str(error_output3))
                        raise Exception(ErrorCode.GAUSS_530["GAUSS_53012"]
                                        + "\nError: \n%s\n" \
                                        % str(error_output3)
                                        + "Please check the log for detail.")
                else:
                    sql = startSql + tempSql + insertSql \
                          + updateSql + commitSql
                    (status, output) = ClusterCommand.remoteSQLCommand(
                        sql, self.opts.user,
                        host, port, False, DefaultValue.DEFAULT_DB_NAME)
                    if status != 0:
                        self.logger.debug(
                            "Failed to execute SQL: %s" % sql
                            + "\nError: \n%s" % str(output))
                        raise Exception(ErrorCode.GAUSS_530[
                                            "GAUSS_53012"]
                                        + "\nError: \n%s\n" % str(output)
                                        + "Please check the log for detail.")
            else:
                raise Exception(
                    ErrorCode.GAUSS_502["GAUSS_50203"] % ("sql statement"))

            self.logger.debug(
                "Successfully inserted the node "
                "stat of all host into the cluster.")
        except Exception as e:
            raise Exception(str(e))

    def getDWSMode(self):
        """
        function: get collect pmk infromation mode
        input : NA
        output: NA
        """
        # get security mode
        security_mode_value = DefaultValue.getSecurityMode()
        if (security_mode_value == "on"):
            self.DWS_mode = True

    def installPMKSchema(self, host, port):
        """
        function: install PMK schema
        input  : NA
        output : NA
        """
        try:
            # install pmk schema
            cmd = "%s -t %s -p %s -u %s -c %s -l %s" % (
                OMCommand.getLocalScript("UTIL_GAUSS_STAT"),
                self.ACTION_INSTALL_PMK,
                self.clusterInfo.appPath,
                self.opts.user,
                str(port),
                self.opts.localLog)
            if (self.opts.mpprcFile != ""):
                cmd = "source %s; %s" % (self.opts.mpprcFile, cmd)

            if (host != NetUtil.getLocalIp()):
                cmd = "pssh -s -H %s \'%s\'" % (str(host), cmd)

            if (os.getuid() == 0):
                cmd = """su - %s -c "%s" """ % (self.opts.user, cmd)
            self.logger.debug(
                "Install pmk schema command for executing %s on (%s:%s)" % (
                    cmd, str(host), str(port)))
            self.logger.debug("Command for installing pmk : %s." % cmd)

            (status, output) = subprocess.getstatusoutput(cmd)
            if (status == 0):
                self.logger.debug("Successfully install pmk schema.")
            else:
                self.logger.debug("Failed to install pmk schema.")
                raise Exception(output)
        except Exception as e:
            raise Exception(str(e))

    def dropPMKSchema(self, host, port):
        """
        function: drop PMK schema
        input  : host, port
        output : NA
        """
        try:
            querySql = "DROP SCHEMA IF EXISTS pmk CASCADE;"
            local_host = NetUtil.getLocalIp()
            if (self.DWS_mode):
                if (host == local_host):
                    (status, result,
                     error_output) = SqlExecutor.excuteSqlOnLocalhost(
                        port, querySql)
                else:
                    currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                    pid = os.getpid()
                    outputfile = "droppmk_%s_%s_%s.json" \
                                 % (host, pid, currentTime)
                    tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                    filepath = os.path.join(tmpDir, outputfile)
                    ClusterCommand.executeSQLOnRemoteHost(
                        host, port, querySql, filepath)
                    (status, result, error_output) = \
                        SqlExecutor.getSQLResult(host, outputfile)
                if (status != 2):
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] % querySql \
                        + " Error: \n%s" % str(error_output))
            else:
                (status, output) = ClusterCommand.remoteSQLCommand(
                    querySql, self.opts.user,
                    host, port,
                    False, DefaultValue.DEFAULT_DB_NAME)
                if (status != 0):
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] % querySql \
                        + " Error: \n%s" % str(output))
        except Exception as e:
            raise Exception(str(e))

    def checkPMKMetaData(self, host, port):
        """
        function: check PMK meta data
        input  : host, port
        output : NA
        """
        # check pmk_meta_data
        try:
            querySql = "SELECT * FROM pmk.pmk_meta_data " \
                       "WHERE last_snapshot_collect_time >= " \
                       "date_trunc('second', current_timestamp);"
            local_host = NetUtil.getLocalIp()
            if (self.DWS_mode):
                if (host == local_host):
                    (status, result, error_output) = \
                        SqlExecutor.excuteSqlOnLocalhost(port, querySql)
                else:
                    currentTime = time.strftime("%Y-%m-%d_%H:%M:%S")
                    pid = os.getpid()
                    outputfile = "checkPMK%s_%s_%s.json" \
                                 % (host, pid, currentTime)
                    tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
                    filepath = os.path.join(tmpDir, outputfile)
                    ClusterCommand.executeSQLOnRemoteHost(
                        host, port, querySql, filepath)
                    (status, result, error_output) = \
                        SqlExecutor.getSQLResult(host, outputfile)
                if (status != 2):
                    raise Exception(ErrorCode.GAUSS_513["GAUSS_51300"] \
                                    % querySql + " Error: \n%s" \
                                    % str(error_output))
            else:
                (status, output) = ClusterCommand.remoteSQLCommand(
                    querySql, self.opts.user,
                    host, port, False, DefaultValue.DEFAULT_DB_NAME)
                if (status != 0):
                    raise Exception(
                        ErrorCode.GAUSS_513["GAUSS_51300"] \
                        % querySql \
                        + " Error: \n%s" \
                        % str(output))
                if (output != ""):
                    self.logger.debug(
                        "ERROR: There is a change in system time \
                        of Gauss MPPDB host." + \
                        " PMK does not support the scenarios\
                         related to system time change." + \
                        " The value of table \
                        pmk.pmk_meta_data is \"%s\"." % output)
                    # recreate pmk schema
                    self.dropPMKSchema(host, port)
                    # install pmk schema
                    self.installPMKSchema(host, port)
        except Exception as e:
            raise Exception(str(e))

    def cleanTempFiles(self):
        """
        function: clean temp files
        """
        recordTempFilePattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'recordTempFile_*_*')
        FileUtil.removeFile(recordTempFilePattern)

        sessionCpuTempFilePattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionCpuTempFile_*_*')
        FileUtil.removeFile(sessionCpuTempFilePattern)

        sessionMemTempFilePattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionMemTempFile_*_*')
        FileUtil.removeFile(sessionMemTempFilePattern)

        sessionIOTempFilePattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionIOTempFile_*_*')
        FileUtil.removeFile(sessionIOTempFilePattern)

        sessionCpuTempResultPattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionCpuTempResult_*_*')
        FileUtil.removeFile(sessionCpuTempResultPattern)

        sessionMemTempResultPattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionMemTempResult_*_*')
        FileUtil.removeFile(sessionMemTempResultPattern)

        sessionIOTempResultPattern = os.path.join(
            EnvUtil.getTmpDirFromEnv(self.opts.user),
            'sessionIOTempResult_*_*')
        FileUtil.removeFile(sessionIOTempResultPattern)

    def get_paxos_replication_info(self, dn_ip, inst_dir):
        """
        get Paxos replication info
        input : primary dnDataDir
        output: status and dcf_replication_info information
        """
        self.logger.debug("starting query dn instance dcf_replication_info.")
        query_info = []
        cmd = "pssh -H %s \"source %s && gs_ctl query -D %s | grep 'Paxos replication info' -A " \
              "10 | grep 'dcf_replication_info'| awk '{print $NF}'\"" % (dn_ip,
                                                                         self.opts.mpprcFile,
                                                                         inst_dir)
        self.logger.debug("dcf gs_ctl query cmd: %s" % cmd)
        (query_status, query_output) = CmdUtil.retryGetstatusoutput(cmd)
        self.logger.debug("Query dn dcf_replication_info result: status=%d, "
                                                 "output: %s." % (query_status, query_output))
        if query_status == 0:
            left = query_output.find("{")
            right = query_output.rfind("}")
            paxos_str = query_output[left:right + 1]
            if paxos_str:
                query_info = json.loads(paxos_str)["nodes"]
        elif query_status == 1:
            self.logger.error("Instance %s is unknown." % inst_dir)
        else:
            self.logger.error("Failed to query dn %s instance paxos replication info. "
                                      "Error: \n%s." % (inst_dir, query_output))
        self.logger.debug("Successfully query dn instance dcf_replication_info: %s." %
                                  query_info)
        return query_status, query_info

    def get_paxos_role(self, dn_ip, inst_dir):
        """
        get new node role
        """
        self.logger.debug("Starting to get paxos role ip.")
        paxos_role = []
        try:
            status, info = self.get_paxos_replication_info(dn_ip, inst_dir)
            if status != 0:
                self.logger.error("Failed to obtain %s node information." % inst_dir)
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51636"] % inst_dir)
            for paxos_info in info:
                if paxos_info["role"].upper() == "LOGGER":
                    paxos_role.append(paxos_info["ip"])
            self.logger.debug("Successfully to get paxos role ip. node role ip:%s" %
                                      paxos_role)
            return paxos_role
        except Exception as error:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50219"] % "role" + "Error:\n%s" % str(error))

    def check_enable_dcf(self, dn_ip, inst_dir):
        """
        function: Checking the enable_dcf on or off
        input: NA
        output: NA
        """
        cmd = "pssh -H %s 'source %s && grep \"^enable_dcf.*on\" %s/postgresql.conf'" %\
              (dn_ip, self.opts.mpprcFile, inst_dir)
        self.logger.debug("cmd for check dcf: %s." % cmd)
        (status, output) = CmdUtil.retryGetstatusoutput(cmd)
        if status != 0:
            self.logger.debug("Dcf is off, status is %d, output is %s" % (status, output))
            return False
        else:
            self.logger.debug("Dcf is on.")
            return True

    def CheckPMKPerf(self, outputInfo):
        """
        function: check the performance about PMK tool
        input : outputInfo
        output: NA
        """
        self.logger.debug("Checking PMK performance.")
        tmpFiles = []
        try:
            # clean all the temp files before start
            # collect the performance data
            self.cleanTempFiles()

            # Check whether pmk can be done
            self.checkClusterStatus()

            nodeNames = self.clusterInfo.getClusterNodeNames()
            node_ips = self.clusterInfo.getClusterSshIps()[0]
            tmpDir = EnvUtil.getTmpDirFromEnv(self.opts.user)
            pid = os.getpid()
            for nodeName in nodeNames:
                tmpFiles.append(os.path.join(tmpDir, "recordTempFile_%d_%s" % (
                    pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionCpuTempFile_%d_%s" % (
                                                 pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionMemTempFile_%d_%s" % (
                                                 pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionIOTempFile_%d_%s" % (
                                                 pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionCpuTempResult_%d_%s" % (
                                                 pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionMemTempResult_%d_%s" % (
                                                 pid, nodeName)))
                tmpFiles.append(os.path.join(tmpDir,
                                             "sessionIOTempResult_%d_%s" % (
                                                 pid, nodeName)))

            # get security_mode value from cm_agent conf
            self.getDWSMode()

            normalDNs = self.getNormalDatanodes()
            hostname = normalDNs[0].hostname
            host = normalDNs[0].listenIps[0]
            data_dir = normalDNs[0].datadir
            port = normalDNs[0].port
            dn_ip = NetUtil.getLocalIp()
            if self.check_enable_dcf(dn_ip, data_dir):
                paxos_logger_role_ip = self.get_paxos_role(dn_ip, data_dir)
                self.logger.debug("the paxos logger role ip is %s" % paxos_logger_role_ip)
                if len(paxos_logger_role_ip) != 0:
                    for logger_ip in paxos_logger_role_ip:
                        logger_hostname = self.clusterInfo.getNodeNameByBackIp(logger_ip)
                        nodeNames.remove(logger_hostname)
                        node_ips.remove(logger_ip)
            # install pmk schema
            self.installPMKSchema(dn_ip, port)

            # check pmk_meta_data
            self.checkPMKMetaData(dn_ip, port)

            # get pmk meta data
            (pmk_curr_collect_start_time,
             pmk_last_collect_start_time, last_snapshot_id) = \
                self.getMetaData(hostname, host, port)
            self.deleteExpiredSnapShots(hostname, host, port)
            # collect pmk stat
            self.collectPMKData(pmk_curr_collect_start_time,
                                pmk_last_collect_start_time,
                                last_snapshot_id, port, node_ips)

            # launch asynchronous collection
            self.launchAsynCollection(host, port)

            # get database size from previous collection
            self.getPreviousDbSize()

            if (not self.DWS_mode):
                # get cpu stat of all sessions
                self.getAllSessionCpuStat()
                # get IO stat of all sessions
                self.getAllSessionIOStat()
                # get memory stat of all sessions
                self.getAllSessionMemoryStat()
                # handle session cpu stat of all hosts
                self.handleSessionCpuStat(str(hostname), host)
                # Handle session IO stat of all hosts
                self.handleSessionIOStat(str(hostname), host)
                # handle session memory stat of all hosts
                self.handleSessionMemoryStat(str(hostname), host)

            # get node stat of all hosts
            self.getAllHostsNodeStat()
            # get prev node stat of all hosts
            self.getAllHostsPrevNodeStat(hostname, host, port, last_snapshot_id)
            # handle the node stat of all hosts
            self.handleNodeStat()
            # insert the node stat of all hosts into the cluster
            self.insertNodeStat(hostname, host, port,
                                 pmk_curr_collect_start_time,
                                 pmk_last_collect_start_time, last_snapshot_id)

            # display pmk stat
            showDetail = ""
            if (self.opts.show_detail):
                showDetail = "-d"

            cmd = "%s -t %s -p %s -u %s -c %s %s -l %s" \
                  % (OMCommand.getLocalScript("UTIL_GAUSS_STAT"),
                     self.ACTION_DISPLAY_STAT,
                     self.clusterInfo.appPath,
                     self.opts.user,
                     str(port),
                     showDetail,
                     self.opts.localLog)
            if (self.opts.mpprcFile != ""):
                cmd = "source %s; %s" % (self.opts.mpprcFile, cmd)

            if (self.DWS_mode):
                cmd += " --dws-mode"

            cmd += " --flag-num=%d" % os.getpid()

            cmd += " --master-host=%s" % NetUtil.GetHostIpOrName()

            cmd += " --database-size=%s" % str(self.opts.databaseSize)

            if (str(hostname) != NetUtil.GetHostIpOrName()):
                cmd = "pssh -s -H %s \'%s\'" % (str(host), cmd)

            if (os.getuid() == 0):
                cmd = """su - %s -c "%s" """ % (self.opts.user, cmd)

            self.logger.debug(
                "Display pmk stat command for executing %s on (%s:%s)" % \
                (cmd, str(hostname), str(port)))

            (status, output) = subprocess.getstatusoutput(cmd)
            if (status == 0):
                print("%s\n" % output, end="", file=outputInfo)
                self.logger.debug("Successfully display pmk stat.")
            else:
                self.logger.debug("Failed to display pmk stat.")
                raise Exception(output)

            self.logger.debug("Operation succeeded: PMK performance check.")
        except Exception as e:
            for tmpFile in tmpFiles:
                FileUtil.removeFile(tmpFile)
            raise Exception(str(e))

    def CheckSSDPerf(self, outputInfo):
        """
        function: check the performance about SSD
        input : outputInfo
        output: NA
        """
        self.logger.debug("Checking SSD performance.")
        # print SSD performance statistics information to output file
        print(
            "SSD performance statistics information:",
            end="", file=outputInfo)
        try:
            # check SSD
            cmd = "%s -t SSDPerfCheck -U %s -l %s" \
                  % (OMCommand.getLocalScript("LOCAL_PERFORMANCE_CHECK"),
                     self.opts.user, self.opts.localLog)
            gp_path = os.path.join(
                DefaultValue.ROOT_SCRIPTS_PATH, self.opts.user)
            (status, output) = self.sshTool.getSshStatusOutput(cmd,
                                                               gp_path=gp_path)
            outputMap = self.sshTool.parseSshOutput(self.sshTool.hostNames)
            for node in status.keys():
                if (status[node] == DefaultValue.SUCCESS):
                    result = outputMap[node]
                    print(
                        "    %s:\n%s" % (node, result),
                        end="", file=outputInfo)
                else:
                    print(
                        "    %s:\n        Failed to check SSD performance." \
                        " Error: %s" % (node, outputMap[node]),
                        end="", file=outputInfo)
            self.logger.debug("Successfully checked SSD performance.")
        except Exception as e:
            raise Exception(str(e))
