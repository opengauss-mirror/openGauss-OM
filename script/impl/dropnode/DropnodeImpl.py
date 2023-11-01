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
# Description  : DropnodeImpl.py
#############################################################################

import subprocess
import sys
import re
import os
import pwd
import datetime
import grp
import socket

sys.path.append(sys.path[0] + "/../../../../")
from gspylib.threads.SshTool import SshTool
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.Common import DefaultValue
from gspylib.common.GaussLog import GaussLog
from gspylib.inspection.common.Exception import CheckException
from gspylib.common.OMCommand import OMCommand
from base_utils.os.env_util import EnvUtil
from base_utils.os.net_util import NetUtil
from domain_utils.domain_common.cluster_constants import ClusterConstants


# master 
MASTER_INSTANCE = 0
# standby 
STANDBY_INSTANCE = 1

# status failed
STATUS_FAIL = "Failure"


class DropnodeImpl():
    """
    class for drop a standby node.
    step:
        1. check whether all standby can be reached or the switchover/failover is happening
        2. shutdown the program of the target node if it can be reached
        3. flush the configuration on all nodes if it is still a HA cluster
        4. flush the configuration on primary if it is the only one left
    """

    def __init__(self, dropnode):
        """
        """
        self.context = dropnode
        self.user = self.context.user
        self.userProfile = self.context.userProfile
        self.group = self.context.group
        self.backupFilePrimary = ''
        self.localhostname = NetUtil.GetHostIpOrName()
        self.logger = self.context.logger
        self.resultDictOfPrimary = []
        self.replSlot = ''
        envFile = EnvUtil.getEnv("MPPDB_ENV_SEPARATE_PATH")
        if envFile:
            self.envFile = envFile
        else:
            self.envFile = ClusterConstants.HOME_USER_BASHRC % self.user
        gphomepath = EnvUtil.getEnv("GPHOME")
        if gphomepath:
            self.gphomepath = gphomepath
        else:
            (status, output) = subprocess.getstatusoutput("which gs_om")
            if "no gs_om in" in output:
                raise Exception(ErrorCode.GAUSS_518["GAUSS_51800"] % "$GPHOME")
            self.gphomepath = os.path.normpath(output.replace("/gs_om", ""))
        if not EnvUtil.getEnv("PGHOST"):
            GaussLog.exitWithError(ErrorCode.GAUSS_518["GAUSS_51802"] % (
                "\"PGHOST\", please import environment variable"))
        self.pghostPath = EnvUtil.getEnv("PGHOST")
        self.appPath = self.context.clusterInfo.appPath
        self.gsql_path = "source %s;%s/bin/gsql" % (self.userProfile, self.appPath)

        self.dnIdForDel = []
        for hostDelName in self.context.hostMapForDel.keys():
            self.dnIdForDel += self.context.hostMapForDel[hostDelName]['dn_id']
        self.commonOper = OperCommon(dropnode)

    def change_user(self):
        if os.getuid() == 0:
            user = self.user
            try:
                pw_record = pwd.getpwnam(user)
            except CheckException:
                GaussLog.exitWithError(ErrorCode.GAUSS_503["GAUSS_50300"] % user)
            user_uid = pw_record.pw_uid
            user_gid = pw_record.pw_gid
            os.setgid(user_gid)
            os.setuid(user_uid)

    def checkAllStandbyState(self):
        """
        check all standby state whether switchover is happening
        """
        for hostNameLoop in self.context.hostMapForExist.keys():
            sshtool_host = SshTool([hostNameLoop])
            for i in self.context.hostMapForExist[hostNameLoop]['datadir']:
                # check whether switchover/failover is happening
                self.commonOper.checkStandbyState(hostNameLoop, i,
                                                  sshtool_host,
                                                  self.userProfile)
            self.cleanSshToolFile(sshtool_host)

        for hostNameLoop in self.context.hostMapForDel.keys():
            if hostNameLoop not in self.context.failureHosts:
                sshtool_host = SshTool([hostNameLoop])
                for i in self.context.hostMapForDel[hostNameLoop]['datadir']:
                    # check whether switchover/failover is happening
                    self.commonOper.checkStandbyState(hostNameLoop, i,
                                                      sshtool_host,
                                                      self.userProfile, True)
                    self.commonOper.stopInstance(hostNameLoop, sshtool_host, i,
                                                 self.userProfile)
                cmdDelCert = "ls %s/share/sslcert/grpc/* | " \
                    "grep -v openssl.cnf | xargs rm -rf" % self.appPath
                result, output = sshtool_host.getSshStatusOutput(cmdDelCert,
                    [hostNameLoop], self.userProfile)
                if result[hostNameLoop] != 'Success':
                    self.logger.debug(output)
                    self.logger.log("[gs_dropnode]Failed to delete the GRPC "
                        "sslcert of %s." % hostNameLoop)
                    self.logger.log("[gs_dropnode]Please check and delete the "
                        "GRPC sslcert of %s manually." % hostNameLoop)
                self.cleanSshToolFile(sshtool_host)
            else:
                self.logger.log("[gs_dropnode]Cannot connect %s. Please check "
                                "and delete the GRPC sslcert of %s manually."
                                % (hostNameLoop, hostNameLoop))

    def dropNodeOnAllHosts(self):
        """
        drop the target node on the other host
        """
        for hostNameLoop in self.context.hostMapForExist.keys():
            sshtool_host = SshTool([hostNameLoop])
            # backup
            backupfile = self.commonOper.backupConf(
                self.gphomepath, self.user,
                hostNameLoop, self.userProfile, sshtool_host, self.pghostPath)
            self.logger.log(
                "[gs_dropnode]The backup file of " + hostNameLoop + " is " + backupfile)
            if hostNameLoop == self.localhostname:
                self.backupFilePrimary = backupfile
            indexForuse = 0
            for i in self.context.hostMapForExist[hostNameLoop]['datadir']:
                # parse
                resultDict = self.commonOper.parseConfigFile(hostNameLoop, i,
                                                             self.dnIdForDel,
                                                             self.context.hostIpListForDel,
                                                             sshtool_host,
                                                             self.envFile)
                resultDictForRollback = self.commonOper.parseBackupFile(
                    hostNameLoop, backupfile,
                    self.context.hostMapForExist[hostNameLoop][
                        'dn_id'][indexForuse],
                    resultDict['replStr'], sshtool_host,
                    self.envFile)
                if hostNameLoop == self.localhostname:
                    self.resultDictOfPrimary.append(resultDict)
                # try set
                try:
                    self.commonOper.SetPgsqlConf(resultDict['replStr'],
                                                 hostNameLoop, i,
                                                 resultDict['syncStandbyStr'],
                                                 sshtool_host,
                                                 self.userProfile,
                                                 '',
                                                 self.context.flagOnlyPrimary)
                except ValueError:
                    self.logger.log("[gs_dropnode]Rollback pgsql process.")
                    self.commonOper.SetPgsqlConf(resultDict['replStr'],
                                                 hostNameLoop, i,
                                                 resultDict['syncStandbyStr'],
                                                 sshtool_host,
                                                 self.userProfile,
                                                 resultDictForRollback[
                                                     'rollbackReplStr'])
                indexForuse += 1
            self.cleanSshToolFile(sshtool_host)

    def operationOnlyOnPrimary(self):
        """
        operation only need to be executed on primary node
        """
        for hostNameLoop in self.context.hostMapForExist.keys():
            try:
                self.commonOper.SetPghbaConf(self.userProfile, hostNameLoop,
                                             self.resultDictOfPrimary[0][
                                             'pghbaStr'], False)
            except ValueError:
                self.logger.log("[gs_dropnode]Rollback pghba conf.")
                self.commonOper.SetPghbaConf(self.userProfile, hostNameLoop,
                                             self.resultDictOfPrimary[0][
                                             'pghbaStr'], True)
        indexLoop = 0
        for i in self.context.hostMapForExist[self.localhostname]['datadir']:
            try:
                self.commonOper.SetReplSlot(self.localhostname, self.gsql_path,
                    self.context.hostMapForExist[self.localhostname]['port'][indexLoop],
                    self.dnIdForDel)
            except ValueError:
                self.logger.log("[gs_dropnode]Rollback replslot")
                self.commonOper.SetReplSlot(self.localhostname, self.gsql_path,
                    self.context.hostMapForExist[self.localhostname]['port'][indexLoop],
                    self.dnIdForDel, True)
                indexLoop += 1

    def modifyStaticConf(self):
        """
        Modify the cluster static conf and save it
        """
        self.logger.log("[gs_dropnode]Start to modify the cluster static conf.")
        staticConfigPath = "%s/bin/cluster_static_config" % self.appPath
        # first backup, only need to be done on primary node
        tmpDir = EnvUtil.getEnvironmentParameterValue("PGHOST", self.user,
                                                           self.userProfile)
        cmd = "cp %s %s/%s_BACKUP" % (
        staticConfigPath, tmpDir, 'cluster_static_config')
        (status, output) = subprocess.getstatusoutput(cmd)
        if status:
            self.logger.debug("[gs_dropnode]Backup cluster_static_config failed"
                              + output)
        backIpDict = self.context.backIpNameMap
        backIpDict_values = list(backIpDict.values())
        backIpDict_keys = list(backIpDict.keys())
        for ipLoop in self.context.hostIpListForDel:
            nameLoop = backIpDict_keys[backIpDict_values.index(ipLoop)]
            dnLoop = self.context.clusterInfo.getDbNodeByName(nameLoop)
            self.context.clusterInfo.dbNodes.remove(dnLoop)
        for dbNode in self.context.clusterInfo.dbNodes:
            if dbNode.name == self.localhostname:
                self.context.clusterInfo.saveToStaticConfig(staticConfigPath,
                                                            dbNode.id)
                continue
            staticConfigPath_dn = "%s/cluster_static_config_%s" % (
                tmpDir, dbNode.name)
            self.context.clusterInfo.saveToStaticConfig(staticConfigPath_dn,
                                                        dbNode.id)
        self.logger.debug(
            "[gs_dropnode]Start to scp the cluster static conf to any other node.")

        if not self.context.flagOnlyPrimary:
            cmd = "%s/script/gs_om -t refreshconf" % self.gphomepath
            subprocess.getstatusoutput(cmd)
            for hostName in self.context.hostMapForExist.keys():
                hostSsh = SshTool([hostName])
                if hostName != self.localhostname:
                    staticConfigPath_name = "%s/cluster_static_config_%s" % (
                tmpDir, hostName)
                    hostSsh.scpFiles(staticConfigPath_name, staticConfigPath,
                                     [hostName], self.envFile)
                    try:
                        os.unlink(staticConfigPath_name)
                    except FileNotFoundError:
                        pass
                self.cleanSshToolFile(hostSsh)

        self.logger.log("[gs_dropnode]End of modify the cluster static conf.")

    def cleanSshToolFile(self, sshTool):
        """
        """
        try:
            sshTool.clenSshResultFiles()
        except Exception as e:
            self.logger.debug(str(e))

    def checkUserAndGroupExists(self):
        """
        check system user and group exists and be same 
        on primary and standby nodes
        """
        inputUser = self.user
        inputGroup = self.group
        user_group_id = ""
        isUserExits = False
        localHost = socket.gethostname()
        for user in pwd.getpwall():
            if user.pw_name == self.user:
                user_group_id = user.pw_gid
                isUserExits = True
                break
        if not isUserExits:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                                   % ("User", self.user, localHost))

        isGroupExits = False
        group_id = ""
        for group in grp.getgrall():
            if group.gr_name == self.group:
                group_id = group.gr_gid
                isGroupExits = True
        if not isGroupExits:
            GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                                   % ("Group", self.group, localHost))
        if user_group_id != group_id:
            GaussLog.exitWithError("User [%s] is not in the group [%s]." \
                                   % (self.user, self.group))

        hostNames = list(self.context.hostMapForExist.keys())
        envfile = self.envFile
        sshTool = SshTool(hostNames)

        # get username in the other standy nodes
        getUserNameCmd = "cat /etc/passwd | grep -w %s" % inputUser
        resultMap, outputCollect = sshTool.getSshStatusOutput(getUserNameCmd,
                                                              [], envfile)

        for hostKey in resultMap:
            if resultMap[hostKey] == STATUS_FAIL:
                self.cleanSshToolFile(sshTool)
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                                       % ("User", self.user, hostKey))

        # get groupname in the other standy nodes
        getGroupNameCmd = "cat /etc/group | grep -w %s" % inputGroup
        resultMap, outputCollect = sshTool.getSshStatusOutput(getGroupNameCmd,
                                                              [], envfile)
        for hostKey in resultMap:
            if resultMap[hostKey] == STATUS_FAIL:
                self.cleanSshToolFile(sshTool)
                GaussLog.exitWithError(ErrorCode.GAUSS_357["GAUSS_35704"] \
                                       % ("Group", self.group, hostKey))
        self.cleanSshToolFile(sshTool)

    def restartInstance(self):
        if self.context.flagOnlyPrimary:
            self.logger.log("[gs_dropnode]Remove the dynamic conf.")
            dynamicConfigPath = "%s/bin/cluster_dynamic_config" % self.appPath
            try:
                os.unlink(dynamicConfigPath)
            except FileNotFoundError:
                pass
            msgPrint = "Only one primary node is left. It is recommended to " \
                       "restart the node.\nDo you want to restart the primary " \
                       "node now (yes/no)? "
            self.context.checkInput(msgPrint)
            sshTool = SshTool([self.localhostname])
            for i in self.context.hostMapForExist[self.localhostname]['datadir']:
                self.commonOper.stopInstance(self.localhostname, sshTool, i,
                                             self.userProfile)
                self.commonOper.startInstance(i, self.userProfile)
            self.cleanSshToolFile(sshTool)
        else:
            pass

    def run(self):
        """
        start dropnode
        """
        self.change_user()
        self.logger.log("[gs_dropnode]Start to drop nodes of the cluster.")
        self.checkAllStandbyState()
        self.dropNodeOnAllHosts()
        self.operationOnlyOnPrimary()
        self.modifyStaticConf()
        self.restartInstance()
        self.logger.log("[gs_dropnode]Success to drop the target nodes.")


class OperCommon:

    def __init__(self, dropnode):
        """
        """
        self.logger = dropnode.logger
        self.user = dropnode.user

    def checkStandbyState(self, host, dirDn, sshTool, envfile, isForDel=False):
        """
        check the existed standby node state
        Exit if the role is not standby or the state of database is not normal
        """
        sshcmd = "gs_ctl query -D %s" % dirDn
        (statusMap, output) = sshTool.getSshStatusOutput(sshcmd, [host],
                                                         envfile)
        if 'Is server running?' in output and not isForDel:
            GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51651"] % host)
        elif 'Is server running?' in output and isForDel:
            return
        else:
            res = re.findall(r'db_state\s*:\s*(\w+)', output)
            if not len(res) and isForDel:
                return
            elif not len(res):
                GaussLog.exitWithError(ErrorCode.GAUSS_516["GAUSS_51651"] % host)
            dbState = res[0]
            if dbState in ['Promoting', 'Wait', 'Demoting']:
                GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35808"] % host)

    def backupConf(self, appPath, user, host, envfile, sshTool, pghostPath):
        """
        backup the configuration file (postgresql.conf and pg_hba.conf)
        The Backup.py can do this
        """
        self.logger.log(
            "[gs_dropnode]Start to backup parameter config file on %s." % host)
        tmpPath = "%s/gs_dropnode_backup%s" % (pghostPath,
                  str(datetime.datetime.now().strftime('%Y%m%d%H%M%S')))
        backupPyPath = os.path.join(appPath, './script/local/Backup.py')
        cmd = "(find %s -type d | grep gs_dropnode_backup | xargs rm -rf;" \
              "if [ ! -d '%s' ]; then mkdir -p '%s' -m %s;fi)" \
              % (pghostPath, tmpPath, tmpPath, DefaultValue.KEY_DIRECTORY_MODE)
        sshTool.executeCommand(cmd, DefaultValue.SUCCESS, [host], envfile)
        logfile = os.path.join(tmpPath, 'gs_dropnode_call_Backup_py.log')
        cmd = "python3 %s -U %s -P %s -p --nodeName=%s -l %s" \
              % (backupPyPath, user, tmpPath, host, logfile)
        (statusMap, output) = sshTool.getSshStatusOutput(cmd, [host], envfile)
        if statusMap[host] != 'Success':
            self.logger.debug(
                "[gs_dropnode]Backup parameter config file failed." + output)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        self.logger.log(
            "[gs_dropnode]End to backup parameter config file on %s." % host)
        return '%s/parameter_%s.tar' % (tmpPath, host)

    def check_is_vip_mode(self):
        """
        Check whether the current mode is VIP
        """
        cmd = "cm_ctl res --list | awk -F \"|\" '{print $2}' | grep -w \"VIP\""
        self.logger.log("Command for Checking VIP mode: %s" % cmd)
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0 or not out:
            return False
        return True

    def get_float_ip_from_json(self, base_ip, host_ips_for_del):
        """
        Get float IP from json file by cmd
        """
        cmd = "cm_ctl res --list | grep \"VIP\" | awk -F \"|\" '{print $1}' | " \
              "xargs -i cm_ctl res --list --res_name={} --list_inst |grep \"base_ip=%s\""\
              " | awk -F \"|\" '{print $1}' | xargs -i cm_ctl res --list --res_name={}" \
              " | grep \"VIP\" | awk -F \"|\" '{print $3}'" % base_ip
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0:
            GaussLog.exitWithError(ErrorCode.GAUSS_514["GAUSS_51400"] % cmd)
        if not out:
            self.logger.log("Failed to get float IP from json. Cmd: %s" % cmd)
            return ""
        float_ip = re.findall("float_ip=([\.\d]+)", out.strip())[0]

        cmd = "cm_ctl res --list | grep \"VIP\" | awk -F \"|\" '{print $1}' | " \
              "xargs -i cm_ctl res --list --res_name={} | grep \"float_ip=%s\" | " \
              "awk -F \"|\" '{print $1}' | xargs -i cm_ctl res --list --res_name={} " \
              "--list_inst | grep \"VIP\" | awk -F \"|\" '{print $5}'" % float_ip
        stat, out= subprocess.getstatusoutput(cmd)
        if stat != 0 or not out:
            raise Exception("Failed to get base IP list from json. Cmd: %s" % cmd)
        for item in out.split('\n'):
            _ip = re.findall("base_ip=([\.\d]+)", item.strip())[0]
            if _ip not in host_ips_for_del:
                return ""

        self.logger.log("Successfully get float IP from json, %s." % float_ip)
        return float_ip

    def get_float_ip_config(self, host, dn_dir, host_ips_for_del, ssh_tool, env_file):
        """
        Get float IP configuration str
        """
        if not self.check_is_vip_mode():
            self.logger.log("The current cluster does not support VIP.")
            return ""

        float_ips_for_del = []
        for _ip in host_ips_for_del:
            float_ip = self.get_float_ip_from_json(_ip, host_ips_for_del)
            if float_ip and float_ip not in float_ips_for_del:
                float_ips_for_del.append(float_ip)
        cmd = "grep '^host.*sha256' %s" % os.path.join(dn_dir, 'pg_hba.conf')
        stat_map, output = ssh_tool.getSshStatusOutput(cmd, [host], env_file)
        if stat_map[host] != 'Success':
            self.logger.debug("[gs_dropnode]Parse pg_hba file failed:" + output)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        ret = ""
        for float_ip in float_ips_for_del:
            if float_ip in output:
                s = output.rfind('host', 0, output.find(float_ip))
                e = output.find('\n', output.find(float_ip), len(output))
                ret += output[s:e] + '|'
        return ret

    def parseConfigFile(self, host, dirDn, dnId, hostIpListForDel, sshTool,
                        envfile):
        """
        parse the postgresql.conf file and get the replication info
        """
        self.logger.log(
            "[gs_dropnode]Start to parse parameter config file on %s." % host)
        resultDict = {'replStr': '', 'syncStandbyStr': '*', 'pghbaStr': ''}
        pgConfName = os.path.join(dirDn, 'postgresql.conf')
        pghbaConfName = os.path.join(dirDn, 'pg_hba.conf')

        cmd = "grep -o '^replconninfo.*' %s | egrep -o '^replconninfo.*'" \
              % pgConfName
        (statusMap, output1) = sshTool.getSshStatusOutput(cmd, [host], envfile)
        if statusMap[host] != 'Success':
            self.logger.debug("[gs_dropnode]Parse replconninfo failed:" + output1)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        cmd = "grep -o '^synchronous_standby_names.*' %s" % pgConfName
        (statusMap, output) = sshTool.getSshStatusOutput(cmd, [host], envfile)
        if statusMap[host] != 'Success':
            self.logger.debug(
                "[gs_dropnode]Parse synchronous_standby_names failed:" + output)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        output_v = output.split("'")[-2]
        if output_v == '*':
            resultDict['syncStandbyStr'] = output_v
        else:
            resultDict['syncStandbyStr'] = self.check_syncStandbyStr(dnId,
                                                                     output_v)

        cmd = "grep '^host.*trust' %s" % pghbaConfName
        (statusMap, output) = sshTool.getSshStatusOutput(cmd, [host], envfile)
        if statusMap[host] != 'Success':
            self.logger.debug("[gs_dropnode]Parse pg_hba file failed:" + output)
        for ip in hostIpListForDel:
            if ip in output1:
                i = output1.rfind('replconninfo', 0, output1.find(ip)) + 12
                resultDict['replStr'] += output1[i]
            if ip in output:
                s = output.rfind('host', 0, output.find(ip))
                e = output.find('\n', output.find(ip), len(output))
                resultDict['pghbaStr'] += output[s:e] + '|'
        resultDict['pghbaStr'] += self.get_float_ip_config(host, dirDn, hostIpListForDel,
                                                           sshTool, envfile)
        self.logger.log(
            "[gs_dropnode]End to parse parameter config file on %s." % host)
        return resultDict

    def check_syncStandbyStr(self, dnlist, output):
        output_no = '0'
        output_result = output
        output_new_no = '1'
        if '(' in output:
            output_dn = re.findall(r'\((.*)\)', output)[0]
            output_no = re.findall(r'.*(\d) *\(.*\)', output)[0]
        else:
            output_dn = output
        output_dn_nospace = re.sub(' *', '', output_dn)
        init_no = len(output_dn_nospace.split(','))
        quorum_no = int(init_no / 2) + 1
        half_no = quorum_no - 1
        count_dn = 0
        list_output1 = '*'
        for dninst in dnlist:
            if dninst in output_dn_nospace:
                list_output1 = output_dn_nospace.split(',')
                list_output1.remove(dninst)
                list_output1 = ','.join(list_output1)
                output_dn_nospace = list_output1
                init_no -= 1
                count_dn += 1
        if count_dn == 0:
            return output_result
        if list_output1 == '':
            return ''
        if list_output1 != '*':
            output_result = output.replace(output_dn, list_output1)
        if output_no == '0':
            return output_result
        if int(output_no) == quorum_no:
            output_new_no = str(int(init_no / 2) + 1)
            output_result = output_result.replace(output_no, output_new_no, 1)
            return output_result
        elif int(output_no) > half_no and (int(output_no) - count_dn) > 0:
            output_new_no = str(int(output_no) - count_dn)
        elif int(output_no) > half_no and (int(output_no) - count_dn) <= 0:
            output_new_no = '1'
        elif int(output_no) < half_no and int(output_no) <= init_no:
            output_new_no = output_no
        elif half_no > int(output_no) > init_no:
            output_new_no = str(init_no)
        output_result = output_result.replace(output_no, output_new_no, 1)
        return output_result

    def parseBackupFile(self, host, backupfile, dnId, replstr, sshTool,
                        envfile):
        """
        parse the backup file eg.parameter_host.tar to get the value for rollback
        """
        self.logger.log(
            "[gs_dropnode]Start to parse backup parameter config file on %s." % host)
        resultDict = {'rollbackReplStr': '', 'syncStandbyStr': ''}
        backupdir = os.path.dirname(backupfile)
        cmd = "tar xf %s -C %s;grep -o '^replconninfo.*' %s/%s/%s_postgresql.conf;" \
              "grep -o '^synchronous_standby_names.*' %s/%s/%s_postgresql.conf;" \
              % (
              backupfile, backupdir, backupdir, 'parameter_' + host, dnId[3:],
              backupdir, 'parameter_' + host, dnId[3:])
        (statusMap, output) = sshTool.getSshStatusOutput(cmd, [host], envfile)
        if statusMap[host] != 'Success':
            self.logger.log(
                "[gs_dropnode]Parse backup parameter config file failed:" + output)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        for i in replstr:
            tmp_v = 'replconninfo' + i
            s = output.index(tmp_v)
            e = output.find('\n', s, len(output))
            resultDict['rollbackReplStr'] += output[s:e].split("'")[-2] + '|'
        s = output.index('synchronous_standby_names')
        resultDict['syncStandbyStr'] = output[s:].split("'")[-2]
        self.logger.log(
            "[gs_dropnode]End to parse backup parameter config file %s." % host)
        return resultDict

    def SetPgsqlConf(self, replNo, host, dndir, syncStandbyValue, sshTool, envfile,
                     replValue='', singleLeft=False):
        """
        Set the value of postgresql.conf
        """
        self.logger.log(
            "[gs_dropnode]Start to set openGauss config file on %s." % host)
        setvalue = ''
        if not replValue and replNo != '':
            for i in replNo:
                setvalue += " -c \"replconninfo%s = ''\"" % i
        if len(replValue) > 0:
            count = 0
            for i in replNo:
                setvalue += " -c \"replconninfo%s = '%s'\"" % (
                i, replValue[:-1].split('|')[count])
                count += 1
        if not singleLeft and syncStandbyValue != '*':
            setvalue += " -c \"synchronous_standby_names = '%s'\"" \
                        % syncStandbyValue
        if singleLeft:
            setvalue += " -c \"synchronous_standby_names = ''\""
        if setvalue != '':
            cmd = "[need_replace_quotes] source %s;gs_guc reload -D %s%s" % \
                (envfile, dndir, setvalue)
            self.logger.debug(
                "[gs_dropnode]Start to set pgsql by guc on %s:%s" % (host, cmd))
            (statusMap, output) = sshTool.getSshStatusOutput(cmd, [host], envfile)
            if statusMap[host] != 'Success' or "Failure to perform gs_guc" in output:
                self.logger.debug(
                    "[gs_dropnode]Failed to set pgsql by guc on %s:%s" % (host, output))
                raise ValueError(output)
        self.logger.log(
            "[gs_dropnode]End of set openGauss config file on %s." % host)

    def SetPghbaConf(self, envProfile, host, pgHbaValue,
                     flagRollback=False):
        """
        Set the value of pg_hba.conf
        """
        self.logger.log(
            "[gs_dropnode]Start of set pg_hba config file on %s." % host)
        cmd = 'source %s;' % envProfile
        if len(pgHbaValue):
            if not flagRollback:
                for i in pgHbaValue[:-1].split('|'):
                    v = i[0:i.find('/32') + 3]
                    cmd += "gs_guc set -N %s -I all -h '%s';" % (host, v)
            if flagRollback:
                for i in pgHbaValue[:-1].split('|'):
                    cmd += "gs_guc set -N %s -I all -h '%s';" \
                           % (host, i.strip())
            (status, output) = subprocess.getstatusoutput(cmd)
            result_v = re.findall(r'Failed instances: (\d)\.', output)
            if status:
                self.logger.debug(
                    "[gs_dropnode]Set pg_hba config file failed:" + output)
                raise ValueError(output)
            if len(result_v):
                if result_v[0] != '0':
                    self.logger.debug(
                        "[gs_dropnode]Set pg_hba config file failed:" + output)
                    raise ValueError(output)
            else:
                self.logger.debug(
                    "[gs_dropnode]Set pg_hba config file failed:" + output)
                raise ValueError(output)
        else:
            self.logger.log(
                "[gs_dropnode]Nothing need to do with pg_hba config file.")
        self.logger.log(
            "[gs_dropnode]End of set pg_hba config file on %s." % host)

    def get_repl_slot(self, host, gsql_path, port):
        """
        Get the replication slot (need to do it on standby for cascade_standby)
        But can't do it on standby which enabled extreme rto
        """
        self.logger.log("[gs_dropnode]Start to get repl slot on %s." % host)
        selectSQL = "SELECT slot_name,plugin,slot_type FROM pg_replication_slots;"
        sqlcmd = "%s -p %s postgres -A -t -c '%s'" % (gsql_path, port, selectSQL)
        (status, output) = subprocess.getstatusoutput(sqlcmd)
        if status or "ERROR" in output:
            self.logger.debug(
                "[gs_dropnode]Get repl slot failed:" + output)
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        return ','.join(output.split('\n'))

    def SetReplSlot(self, host, gsqlPath, port, dnid,
                    flag_rollback=False):
        self.logger.log("[gs_dropnode]Start to set repl slot on %s." % host)
        replslot = self.get_repl_slot(host, gsqlPath, port)
        setcmd = ''
        sql = ''
        if not flag_rollback:
            for i in dnid:
                if i in replslot:
                    sql += "SELECT pg_drop_replication_slot('%s');" % i
            sql = "SET enable_slot_log TO 1;" + sql
            setcmd = "sleep 5;%s -p %s postgres -A -t -c \"%s\";" % (gsqlPath, port, sql)
        if flag_rollback:
            list_o = [i.split('|') for i in replslot.split(',')]
            for r in list_o:
                if r[0] in dnid and r[2] == 'physical':
                    sql += "SELECT * FROM pg_create_physical_replication_slot('%s', " \
                        "false);" % r[0]
                elif r[0] in dnid and r[2] == 'logical':
                    sql += "SELECT * FROM pg_create_logical_replication_slot('%s', " \
                        "'%s');" % (r[0], r[1])
            setcmd = "%s -p %s postgres -A -t -c \"%s\";" % (gsqlPath, port, sql)
        if sql != '':
            (status, output) = subprocess.getstatusoutput(setcmd)
            if status or "ERROR" in output:
                self.logger.debug("[gs_dropnode]Set repl slot failed:" + output)
                raise ValueError(output)
        self.logger.log("[gs_dropnode]End of set repl slot on %s." % host)

    def stopInstance(self, host, sshTool, dirDn, env):
        """
        """
        self.logger.log("[gs_dropnode]Start to stop the target node %s." % host)
        command = "source %s ; gs_ctl stop -D %s -M immediate" % (env, dirDn)
        resultMap, outputCollect = sshTool.getSshStatusOutput(command, [host],
                                                              env)
        if 'Is server running?' in outputCollect:
            self.logger.log("[gs_dropnode]End of stop the target node %s."
                            % host)
            return
        elif resultMap[host] != 'Success':
            self.logger.debug(outputCollect)
            self.logger.log(
                "[gs_dropnode]Cannot connect the target node %s." % host)
            self.logger.log(
                "[gs_dropnode]It may be still running.")
            return
        self.logger.log("[gs_dropnode]End of stop the target node %s." % host)

    def startInstance(self, dirDn, env):
        """
        """
        self.logger.log("[gs_dropnode]Start to start the target node.")
        command = "source %s ; %s -U %s -D %s" % (env,
            OMCommand.getLocalScript("Local_StartInstance"), self.user, dirDn)
        (status, output) = subprocess.getstatusoutput(command)
        self.logger.debug(output)
        if status:
            self.logger.debug("[gs_dropnode]Failed to start the node.")
            GaussLog.exitWithError(ErrorCode.GAUSS_358["GAUSS_35809"])
        elif re.search("another server might be running", output):
            self.logger.log(output)
        elif re.search("] WARNING:", output):
            tmp = '\n'.join(re.findall(".*] WARNING:.*", output))
            self.logger.log(tmp)
        self.logger.debug("[gs_dropnode]End to start the node.")
