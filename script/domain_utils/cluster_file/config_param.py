import configparser
import subprocess

from gspylib.common.ErrorCode import ErrorCode
from base_utils.os.cmd_util import CmdUtil
from base_utils.os.file_util import FileUtil
from base_utils.os.memory_util import MemoryUtil
from base_utils.os.net_util import NetUtil


class ConfigParam:

    @staticmethod
    def getMatchingResult(matchExpression, fileMatching, remoteHostName=""):
        """
        Filtering files with expressions
        """
        cmd = "%s -E '%s' %s" % (CmdUtil.getGrepCmd(), matchExpression, fileMatching)
        if "" != remoteHostName and remoteHostName != NetUtil.GetHostIpOrName():
            cmd = CmdUtil.getSshCommand(remoteHostName, cmd)
        (status, output) = subprocess.getstatusoutput(cmd)
        return status, output

    @staticmethod
    def preConfigFile(filename):
        """
        function: pretreatment configuration file, delete the ' ' or '\t' when they top of line
        input: filename
        output: NA
        """
        try:
            (status, output) = ConfigParam.getMatchingResult("^[ \\t]", filename)
            if status != 0:
                return
            list_line = output.split('\n')
            for strline in list_line:
                FileUtil.replaceFileLineContent("^%s$" % strline, strline.strip(), filename)

        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def getConfigFilePara(configFile, section, checkList=None,
                          optionsName=None):
        """
        function: get the configuration file(check_list.conf)
        input: section: the section in check_list.conf will be get
               optionsName: the parameter list will be get, if parameter
               is NULL, then get all
        output: dist
        """
        if checkList is None:
            checkList = []
        if optionsName is None:
            optionsName = []
        try:
            ConfigParam.preConfigFile(configFile)

            # read the check_list.conf
            data = {}
            fp = configparser.RawConfigParser()
            fp.read(configFile)

            # get the sections then check the section whether or not
            # in check_list.conf
            secs = fp.sections()
            if section not in secs:
                return data

            # get the parameters then check options whether or not in
            # section parameters
            optionList = fp.options(section)
            if len(optionsName) != 0 and optionsName not in optionList:
                return data
            elif len(optionsName) != 0:
                optionList = optionsName

            # get th parameter values
            for key in optionList:
                value = fp.get(section, key)
                if len(value.split()) == 0:
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50012"] % key)
                value = value.split('#')[0]
                if key in checkList and not value.isdigit():
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50003"]
                                    % (key, "digit"))
                if (section == '/etc/security/limits.conf' and
                        not value.isdigit() and value != 'unlimited'):
                    raise Exception(ErrorCode.GAUSS_500["GAUSS_50004"] % key)
                data[key] = value

            if "vm.min_free_kbytes" in list(data.keys()):
                swap_total_size = MemoryUtil.getMemTotalSize() // 1024
                multiple = data["vm.min_free_kbytes"].split('*')[1].split('%')[
                    0].strip()
                val = int(swap_total_size) * int(multiple) // 100
                data["vm.min_free_kbytes"] = str(val)

            return data
        except Exception as exception:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51234"] % configFile +
                            " Error: \n%s" % str(exception))
