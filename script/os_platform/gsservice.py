# -*- coding:utf-8 -*-
#############################################################################

# Description  : gsservice.py is a utility to do something for service
# information.
#############################################################################

try:
    import subprocess
    import sys
    sys.path.append(sys.path[0] + "/../")
    from os_platform.UserPlatform import g_Platform
    from gspylib.common.ErrorCode import ErrorCode
except Exception as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))

# ---------------OS service action --------------------
ACTION_LIST = ["start", "stop", "restart", "status", "reload", "enable"]
FIREWALL = "firewall"
CROND = "crond"
SSHD = "sshd"
SYSLOG = "syslog"
RSYSLOG = "rsyslog"
SYSTEMD_JOURNALD = "systemd-journald"
NTPD = "ntp"
GS_OS_SERVER = "gs-OS-set"
SERVICE_LIST = [FIREWALL, CROND, SSHD, SYSLOG, RSYSLOG, SYSTEMD_JOURNALD, NTPD,
                GS_OS_SERVER]


class Service():
    """
    function: Init the Service options
    """

    def __init__(self):
        """
        constructor
        """
        pass

    def checkService(self, service):
        """
        function: check service
        """
        if (service not in SERVICE_LIST):
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50011"] % ("service",
                                                                  service))

    def checkAction(self, action):
        """
        function: check action
        """
        if (action not in ACTION_LIST):
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50011"] % ("action",
                                                                  action))

    def manageOSService(self, service, action):
        """
        function: manage OS service
        """
        self.checkService(service)
        self.checkAction(action)

        # get service commands
        if (service == FIREWALL):
            cmd = g_Platform.getManageFirewallCmd(action)
        elif (service == CROND):
            cmd = g_Platform.getManageCrondCmd(action)
        elif (service == SSHD):
            cmd = g_Platform.getManageSshdCmd(action)
        elif (service == SYSTEMD_JOURNALD):
            # systemd-journald now only supported on SuSE Platform
            cmd = g_Platform.getManageSystemdJournaldCmd(action)
        elif (service == SYSLOG):
            # syslog-ng only supported on SuSE Platform
            cmd = g_Platform.getManageSyslogCmd(action)
        elif (service == RSYSLOG):
            # rsyslog only supported on SuSE Platform
            cmd = g_Platform.getManageRsyslogCmd(action)
        elif (service == GS_OS_SERVER):
            cmd = g_Platform.getManageGsOsServerCmd(action)
        else:
            return (1, "Server(%s) is not support." % service)
        (status, output) = subprocess.getstatusoutput(cmd)
        return (status, output)


g_service = Service()
