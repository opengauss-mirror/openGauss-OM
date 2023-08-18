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
import os
import socket
import sys
import getpass
from subprocess import PIPE

sys.path.append(sys.path[0] + "/../../")
from gspylib.common.GaussLog import GaussLog
from gspylib.common.DbClusterInfo import dbClusterInfo
from gspylib.common.Common import DefaultValue, ClusterCommand
from gspylib.common.OMCommand import OMCommand
from gspylib.threads.SshTool import SshTool
from gspylib.common.ErrorCode import ErrorCode
from gspylib.component.CM.CM_OLAP.CM_OLAP import CM_OLAP
from gspylib.component.DSS.dss_comp import Dss
from gspylib.component.Kernel.DN_OLAP.DN_OLAP import DN_OLAP
from base_utils.executor.cmd_executor import CmdExecutor
from domain_utils.cluster_file.cluster_dir import ClusterDir
from base_utils.os.env_util import EnvUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.net_util import NetUtil
from base_utils.common.fast_popen import FastPopen
from base_utils.security.sensitive_mask import SensitiveMask
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ParallelBaseOM(object):
    """
    Base class for parallel command
    """

    def __init__(self):
        '''
        Constructor
        '''
        self.logger = None
        self.clusterInfo = None
        self.oldClusterInfo = None
        self.sshTool = None
        self.action = ""

        # Cluster config file.
        self.xmlFile = ""
        self.oldXmlFile = ""

        self.logType = ClusterConstants.LOCAL_LOG_FILE
        self.logFile = ""
        self.localLog = ""
        self.user = ""
        self.group = ""
        self.mpprcFile = ""
        # Temporary catalog for install
        self.operateStepDir = EnvUtil.getTempDir(
            "%s_step" % self.__class__.__name__.lower())
        # Temporary files for install step
        self.operateStepFile = "%s/%s_step.dat" % (
            self.operateStepDir, self.__class__.__name__.lower())
        self.initStep = ""
        self.dws_mode = False
        self.rollbackCommands = []
        self.etcdCons = []
        self.cmCons = []
        self.gtmCons = []
        self.cnCons = []
        self.dnCons = []
        self.dss_cons = []
        self.dorado_cluster_mode = ""
        # localMode is same as isSingle in all OM script, expect for
        # gs_preinstall.
        # in gs_preinstall, localMode means local mode for master-standby
        # cluster.
        # in gs_preinstall, localMode also means local mode for single
        # cluster(will not create os user).
        # in gs_preinstall, isSingle means single cluster, it will create
        # os user.
        # not isSingle and not localMode : master-standby cluster global
        # mode(will create os user).
        # not isSingle and localMode : master-standby cluster local
        # mode(will not create os user).
        # isSingle and not localMode : single cluster(will create os user).
        # isSingle and localMode : single cluster(will not create os user).
        self.localMode = False
        self.isSingle = False
        # Indicates whether there is a logical cluster.
        # If elastic_group exists, the current cluster is a logical cluster.
        # Otherwise, it is a large physical cluster.
        self.isElasticGroup = False
        self.isAddElasticGroup = False
        self.lcGroup_name = ""
        # Lock the cluster mode, there are two modes: exclusive lock and
        # wait lock mode,
        # the default exclusive lock
        self.lockMode = "exclusiveLock"

        # SinglePrimaryMultiStandby support binary upgrade, inplace upgrade
        self.isSinglePrimaryMultiStandby = False

        # Adapt to 200 and 300
        self.productVersion = None

    def initComponent(self):
        """
        function: Init component
        input : NA
        output: NA
        """
        for nodeInfo in self.clusterInfo.dbNodes:
            self.initCmComponent(nodeInfo)
            self.initKernelComponent(nodeInfo)
            dss_mode = self.clusterInfo.enable_dss == 'on'
            self.init_dss_component(nodeInfo, dss_mode=dss_mode)

    def init_dss_component(self, node_info, dss_mode=False):
        if not dss_mode:
            return
        component = Dss()
        component.clusterType = self.clusterInfo.clusterType
        component.dss_mode = dss_mode
        self.dss_cons.append(component)


    def initComponentAttributes(self, component):
        """
        function: Init  component attributes on current node
        input : Object component
        output: NA
        """
        component.logger = self.logger
        component.binPath = "%s/bin" % self.clusterInfo.appPath
        component.dwsMode = self.dws_mode

    def initCmComponent(self, nodeInfo):
        """
        function: Init cm component
        input : Object nodeInfo
        output: NA
        """
        for inst in nodeInfo.cmservers:
            component = CM_OLAP()
            #init component cluster type
            component.clusterType = self.clusterInfo.clusterType
            component.instInfo = inst
            self.initComponentAttributes(component)
            self.cmCons.append(component)
        for inst in nodeInfo.cmagents:
            component = CM_OLAP()
            #init component cluster type
            component.clusterType = self.clusterInfo.clusterType
            component.instInfo = inst
            self.initComponentAttributes(component)
            self.cmCons.append(component)

    def initKernelComponent(self, nodeInfo):
        """
        function: Init kernel component
        input : Object nodeInfo
        output: NA
        """
        for inst in nodeInfo.datanodes:
            component = DN_OLAP()
            # init component cluster type
            component.clusterType = self.clusterInfo.clusterType
            component.instInfo = inst
            self.initComponentAttributes(component)
            self.dnCons.append(component)

    def initLogger(self, module=""):
        """
        function: Init logger
        input : module
        output: NA
        """
        # log level
        LOG_DEBUG = 1
        self.logger = GaussLog(self.logFile, module, LOG_DEBUG)

        dirName = os.path.dirname(self.logFile)
        self.localLog = os.path.join(dirName, ClusterConstants.LOCAL_LOG_FILE)

    def initClusterInfo(self, refreshCN=True):
        """
        function: Init cluster info
        input : NA
        output: NA
        """
        try:
            self.clusterInfo = dbClusterInfo()
            self.clusterInfo.initFromXml(self.xmlFile)
        except Exception as e:
            raise Exception(str(e))

    def initClusterInfoFromStaticFile(self, user, flag=True):
        """
        function: Function to init clusterInfo from static file
        input : user
        output: NA
        """
        try:
            self.clusterInfo = dbClusterInfo()
            self.clusterInfo.initFromStaticConfig(user)
        except Exception as e:
            raise Exception(str(e))
        if flag:
            self.logger.debug("Instance information of cluster:\n%s." %
                              str(self.clusterInfo))

    def initClusterInfoFromDynamicFile(self, user):
        """
        function: Function to init clusterInfo from dynamic file
        input : user
        output: NA
        """
        try:
            self.clusterInfo = dbClusterInfo()
            self.clusterInfo.readDynamicConfig(user)
        except Exception as e:
            raise Exception(str(e))

    def initSshTool(self, nodeNames, timeout=0):
        """
        function: Init ssh tool
        input : nodeNames, timeout
        output: NA
        """
        self.sshTool = SshTool(nodeNames, self.logger.logFile, timeout)

    def managerOperateStepDir(self, action='create', nodes=None):
        """
        function: manager operate step directory 
        input : NA
        output: currentStep
        """
        if nodes is None:
            nodes = []
        try:
            # Creating the backup directory
            if (action == "create"):
                cmd = "(if [ ! -d '%s' ];then mkdir -p '%s' -m %s;fi)" % (
                    self.operateStepDir, self.operateStepDir,
                    DefaultValue.KEY_DIRECTORY_MODE)
            else:
                cmd = "(if [ -d '%s' ];then rm -rf '%s';fi)" % (
                    self.operateStepDir, self.operateStepDir)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool,
                                            self.localMode or self.isSingle,
                                            "",
                                            nodes)
        except Exception as e:
            raise Exception(str(e))

    def readOperateStep(self):
        """
        function: read operate step signal 
        input : NA
        output: currentStep
        """
        currentStep = self.initStep

        if not os.path.exists(self.operateStepFile):
            self.logger.debug("The %s does not exits." % self.operateStepFile)
            return currentStep

        if not os.path.isfile(self.operateStepFile):
            self.logger.debug("The %s must be a file." % self.operateStepFile)
            return currentStep

        with open(self.operateStepFile, "r") as fp:
            line = fp.readline().strip()
            if line is not None and line != "":
                currentStep = line

        return currentStep

    def writeOperateStep(self, stepName, nodes=None):
        """
        function: write operate step signal 
        input : step
        output: NA
        """
        if nodes is None:
            nodes = []
        try:
            # write the step into INSTALL_STEP
            # open the INSTALL_STEP
            with open(self.operateStepFile, "w") as g_DB:
                # write the INSTALL_STEP
                g_DB.write(stepName)
                g_DB.write(os.linesep)
                g_DB.flush()
            # change the INSTALL_STEP permissions
            FileUtil.changeMode(DefaultValue.KEY_FILE_MODE, self.operateStepFile)

            # distribute file to all nodes
            cmd = "mkdir -p -m %s '%s'" % (DefaultValue.KEY_DIRECTORY_MODE,
                                           self.operateStepDir)
            CmdExecutor.execCommandWithMode(cmd,
                                            self.sshTool,
                                            self.localMode or self.isSingle,
                                            "",
                                            nodes)

            if not self.localMode and not self.isSingle:
                self.sshTool.scpFiles(self.operateStepFile,
                                      self.operateStepDir, nodes)
        except Exception as e:
            # failed to write the step into INSTALL_STEP
            raise Exception(str(e))

    def distributeFiles(self):
        """
        function: distribute package to every host
        input : NA
        output: NA
        """
        self.logger.debug("Distributing files.")
        try:
            # get the all nodes
            hosts = self.clusterInfo.getClusterNodeNames()
            if NetUtil.GetHostIpOrName() not in hosts:
                raise Exception(ErrorCode.GAUSS_516["GAUSS_51619"] %
                                NetUtil.GetHostIpOrName())
            hosts.remove(NetUtil.GetHostIpOrName())
            # Send xml file to every host
            DefaultValue.distributeXmlConfFile(self.sshTool, self.xmlFile,
                                               hosts, self.mpprcFile)
            # Successfully distributed files
            self.logger.debug("Successfully distributed files.")
        except Exception as e:
            # failed to distribute package to every host
            raise Exception(str(e))

    def checkPreInstall(self, user, flag, nodes=None):
        """
        function: check if have done preinstall on given nodes
        input : user, nodes
        output: NA
        """
        if nodes is None:
            nodes = []
        try:
            cmd = "%s -U %s -t %s" % (
                OMCommand.getLocalScript("Local_Check_PreInstall"), user, flag)
            CmdExecutor.execCommandWithMode(
                cmd, self.sshTool,
                self.localMode or self.isSingle, "", nodes)
        except Exception as e:
            raise Exception(str(e))

    def checkNodeInstall(self, nodes=None, checkParams=None,
                         strictUserCheck=True):
        """
        function: Check node install
        input : nodes, checkParams, strictUserCheck
        output: NA
        """
        if nodes is None:
            nodes = []
        if checkParams is None:
            checkParams = []
        validParam = ["shared_buffers", "max_connections"]
        cooGucParam = ""
        for param in checkParams:
            entry = param.split("=")
            if (len(entry) != 2):
                raise Exception(ErrorCode.GAUSS_500["GAUSS_50009"])
            if (entry[0].strip() in validParam):
                cooGucParam += " -C \\\"%s\\\"" % param
        self.logger.log("Checking installation environment on all nodes.")
        cmd = "%s -U %s:%s -R %s %s -l %s -X '%s'" % (
            OMCommand.getLocalScript("Local_Check_Install"), self.user,
            self.group, self.clusterInfo.appPath, cooGucParam, self.localLog,
            self.xmlFile)
        if (not strictUserCheck):
            cmd += " -O"
        self.logger.debug("Checking the install command: %s." % cmd)
        CmdExecutor.execCommandWithMode(cmd,
                                        self.sshTool,
                                        self.localMode or self.isSingle,
                                        "",
                                        nodes)

    def cleanNodeConfig(self, nodes=None, datadirs=None):
        """
        function: Clean instance
        input : nodes, datadirs
        output: NA
        """
        self.logger.log("Deleting instances from all nodes.")
        if nodes is None:
            nodes = []
        if datadirs is None:
            datadirs = []
        cmdParam = ""
        for datadir in datadirs:
            cmdParam += " -D %s " % datadir
        cmd = "%s -U %s %s -l %s" % (
            OMCommand.getLocalScript("Local_Clean_Instance"),
            self.user, cmdParam, self.localLog)
        CmdExecutor.execCommandWithMode(
            cmd, self.sshTool,
            self.localMode or self.isSingle, "", nodes)
        self.logger.log("Successfully deleted instances from all nodes.")

    def killKernalSnapshotThread(self, dnInst):
        """
        function: kill snapshot thread in Kernel,
                avoid dead lock with redistribution)
        input : NA
        output: NA
        """
        self.logger.debug("Stopping snapshot thread in database node Kernel.")
        killSnapshotSQL = "select * from kill_snapshot();"

        (status, output) = ClusterCommand.remoteSQLCommand(
            killSnapshotSQL, self.user, dnInst.hostname, dnInst.port,
            False, DefaultValue.DEFAULT_DB_NAME)
        if (status != 0):
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            killSnapshotSQL + " Error:\n%s" % str(output))
        self.logger.debug("Successfully stopped snapshot "
                          "thread in database node Kernel.")

    def createServerCa(self, hostList=None):
        """
        function: create grpc ca file
        input : NA
        output: NA
        """
        self.logger.debug("Generating CA files.")
        if hostList is None:
            hostList = []
        appPath = ClusterDir.getInstallDir(self.user)
        caPath = os.path.join(appPath, "share/sslcert/om")
        self.logger.debug("The ca file dir is: %s." % caPath)
        if (len(hostList) == 0):
            for dbNode in self.clusterInfo.dbNodes:
                hostList.append(dbNode.name)
        # Create CA dir and prepare files for using.
        self.logger.debug("Create CA file directory.")
        try:
            DefaultValue.createCADir(self.sshTool, caPath, hostList)
            self.logger.debug("Add hostname to config file.")
            DefaultValue.createServerCA(DefaultValue.SERVER_CA, caPath,
                                        self.logger)
            # Clean useless files, and change permission of ca file to 600.
            DefaultValue.cleanServerCaDir(caPath)
            self.logger.debug("Scp CA files to all nodes.")
        except Exception as e:
            certFile = caPath + "/demoCA/cacert.pem"
            if os.path.exists(certFile):
                FileUtil.removeFile(certFile)
            DefaultValue.cleanServerCaDir(caPath)
            raise Exception(str(e))
        if not self.isSingle:
            # localhost no need scp files
            for certFile in DefaultValue.SERVER_CERT_LIST:
                scpFile = os.path.join(caPath, "%s" % certFile)
                self.sshTool.scpFiles(scpFile, caPath, hostList)
        self.logger.debug("Successfully generated server CA files.")

    def createGrpcCa(self, hostList=None):
        """
        function: create grpc ca file
        input : NA
        output: NA
        """
        self.logger.debug("Generating grpc CA files.")
        if hostList is None:
            hostList = []
        appPath = ClusterDir.getInstallDir(self.user)
        caPath = os.path.join(appPath, "share/sslcert/grpc")
        self.logger.debug("The ca file dir is: %s." % caPath)
        if (len(hostList) == 0):
            for dbNode in self.clusterInfo.dbNodes:
                hostList.append(dbNode.name)
        # Create CA dir and prepare files for using.
        self.logger.debug("Create CA file directory.")
        try:
            DefaultValue.createCADir(self.sshTool, caPath, hostList)
            self.logger.debug("Add hostname to config file.")
            configPath = os.path.join(appPath,
                                      "share/sslcert/grpc/openssl.cnf")
            self.logger.debug("The ca file dir is: %s." % caPath)
            # Add hostname to openssl.cnf file.
            DefaultValue.changeOpenSslConf(configPath, hostList)
            self.logger.debug("Generate CA files.")
            DefaultValue.createCA(DefaultValue.GRPC_CA, caPath)
            # Clean useless files, and change permission of ca file to 600.
            DefaultValue.cleanCaDir(caPath)
            self.logger.debug("Scp CA files to all nodes.")
        except Exception as e:
            certFile = caPath + "/demoCA/cacertnew.pem"
            if os.path.exists(certFile):
                FileUtil.removeFile(certFile)
            DefaultValue.cleanCaDir(caPath)
            raise Exception(str(e))
        if len(hostList) == 1 and hostList[0] == socket.gethostname():
            self.logger.debug("Local host database, no need transform files.")
        else:
            for certFile in DefaultValue.GRPC_CERT_LIST:
                scpFile = os.path.join(caPath, "%s" % certFile)
                self.sshTool.scpFiles(scpFile, caPath, hostList)
        self.logger.debug("Successfully generated grpc CA files.")

    def genCipherAndRandFile(self, hostList=None, initPwd=None):
        self.logger.debug("Encrypting cipher and rand files.")
        if hostList is None:
            hostList = []
        binPath = os.path.join(ClusterDir.getInstallDir(self.user), "bin")
        retry = 0
        while True:
            if not initPwd:
                sshpwd = getpass.getpass("Please enter password for database:")
                sshpwd_check = getpass.getpass("Please repeat for database:")
            else:
                sshpwd = sshpwd_check = initPwd
            if sshpwd_check != sshpwd:
                sshpwd = ""
                sshpwd_check = ""
                self.logger.error(
                    ErrorCode.GAUSS_503["GAUSS_50306"] % "database"
                    + "The two passwords are different, "
                      "please enter password again.")
            else:
                cmd = "%s/gs_guc encrypt -M server -K '%s' -D %s " % (binPath,
                                                                    sshpwd,
                                                                    binPath)
                proc = FastPopen(cmd, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid,
                                 close_fds=True)
                stdout, stderr = proc.communicate()
                output = stdout + stderr
                sshpwd = ""
                sshpwd_check = ""
                initPwd = ""
                if proc.returncode != 0:
                    self.logger.error(
                        ErrorCode.GAUSS_503["GAUSS_50322"] % "database"
                        + "Error:\n %s" % SensitiveMask.mask_pwd(output))
                else:
                    break
            if retry >= 2:
                raise Exception(
                    ErrorCode.GAUSS_503["GAUSS_50322"] % "database")
            retry += 1
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/server.key.cipher" % binPath)
        FileUtil.changeMode(DefaultValue.KEY_FILE_MODE,
                          "'%s'/server.key.rand" % binPath)
        if len(hostList) == 0:
            for dbNode in self.clusterInfo.dbNodes:
                hostList.append(dbNode.name)
        if not self.isSingle:
            # localhost no need scp files
            for certFile in DefaultValue.BIN_CERT_LIST:
                scpFile = os.path.join(binPath, "%s" % certFile)
                self.sshTool.scpFiles(scpFile, binPath, hostList)
        self.logger.debug("Successfully encrypted cipher and rand files.")
