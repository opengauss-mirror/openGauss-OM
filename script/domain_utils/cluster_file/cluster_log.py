import os
from gspylib.common.ErrorCode import ErrorCode
from gspylib.common.GaussLog import GaussLog
from base_utils.os.user_util import UserUtil
from base_utils.security.security_checker import SecurityChecker
from domain_utils.cluster_file.cluster_config_file import ClusterConfigFile
from domain_utils.cluster_file.cluster_dir import ClusterDir
from domain_utils.domain_common.cluster_constants import ClusterConstants


class ClusterLog(object):
    @staticmethod
    def getOMLogPath(logName, user="", appPath="", xml="", action=""):
        """
        function : Get the OM log path from xml file
        input : String
        output : String
        """
        log_path = ""
        try:
            if user != "" and xml != "":
                log_path = "%s" % ClusterConfigFile.readClusterLogPath(xml)
                path = "%s/%s/om/%s" % (log_path, user, logName)
            elif action == "virtualip":
                path = "%s/%s" % (ClusterConstants.GS_VIRTULIP_LOG_PATH, logName)
            elif user != "":
                log_path = ClusterDir.getUserLogDirWithUser(user)
                path = "%s/om/%s" % (log_path, logName)
            elif appPath != "":
                user = UserUtil.getPathOwner(appPath)[0]
                if user == "":
                    user = "."
                if user == ".":
                    log_path = ClusterConstants.GAUSSDB_DIR
                else:
                    log_path = ClusterDir.getUserLogDirWithUser(user)
                path = "%s/om/%s" % (log_path, logName)
            elif xml != "":
                try:
                    appPath = ClusterConfigFile.readClusterAppPath(xml)
                    user = UserUtil.getPathOwner(appPath)[0]
                except Exception:
                    user = "."
                if user == "":
                    user = "."
                if user == ".":
                    log_path = ClusterConstants.GAUSSDB_DIR
                else:
                    log_path = ClusterDir.getUserLogDirWithUser(user)
                path = "%s/om/%s" % (log_path, logName)
            else:
                log_path = ClusterConstants.GAUSSDB_DIR
                path = "%s/om/%s" % (log_path, logName)
        except Exception:
            log_path = ClusterConstants.GAUSSDB_DIR
            path = "%s/om/%s" % (log_path, ClusterConstants.LOCAL_LOG_FILE)

        return os.path.realpath(path)

    @staticmethod
    def get_log_file_path(log_name):
        gauss_log = os.environ.get("GAUSSLOG")
        if not gauss_log:
            _, gauss_log = ClusterDir.get_env("GAUSSLOG")
            return gauss_log
        SecurityChecker.check_injection_char(gauss_log)
        return "%s/om/%s" % (gauss_log, log_name)

    @staticmethod
    def checkLogFile(log_file, user, xml_file, default_log_name):
        """
        Check log file path
        """
        if log_file == "":
            log_file = ClusterLog.getOMLogPath(default_log_name,
                                               user=user, xml=xml_file)
        if not os.path.isabs(log_file):
            GaussLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50213"] % log_file)
        UserUtil.check_path_owner(log_file)
        return log_file
