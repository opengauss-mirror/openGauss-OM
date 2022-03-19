import re
import copy

from base_utils.os.env_util import EnvUtil


class EnvVariables:
    """
    for gloable environment variables.
    """
    @staticmethod
    def rmSpecLine(env_list, env_global_path):
        """del source and env_ec line"""
        envlistbak = copy.deepcopy(env_list)
        for env in envlistbak:
            if re.match("^if \[ -f .*\/env_ec", env):
                env_list.remove(env)
                continue
        for env in envlistbak:
            if env.startswith('source'):
                env_global = env.split(' ')[-1]
                if env_global_path in env_global:
                    env_list.remove(env)
                    continue
        return env_list

    @staticmethod
    def filter_env_variable(env_list, mpprc_file, mpprc_file_rm):
        """env variable """
        # mpprc_file is a tmp file when postuninstall
        if mpprc_file_rm == "":
            target_file_name = mpprc_file
        else:
            target_file_name = mpprc_file_rm
        env_global_path = EnvUtil.get_mpprc_global(target_file_name)
        # remove ec and source content from list
        env_list = EnvVariables.rmSpecLine(env_list, env_global_path)
        env_list = EnvVariables.rmSpecLine(env_list, target_file_name + "_global")
        return env_list

    @staticmethod
    def get_mpprc_wrapper(mpprc_file):
        """for difference with open gauss"""
        return EnvUtil.get_mpprc_global(mpprc_file)
