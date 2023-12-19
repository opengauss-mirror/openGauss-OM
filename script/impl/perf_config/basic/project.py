#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
# Description  :
#############################################################################

import os
import sys
import pwd
import time
import psutil
import getpass
import traceback
from enum import Enum
from datetime import datetime
from base_utils.os.cmd_util import CmdUtil
from gspylib.common.GaussLog import GaussLog


class PorjectError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class ProjectEnv(object):
    """
    Some environment-related information, including environment variables,
    path configuration, parameter configuration, etc.
    """
    def __init__(self, env=None, do_init=False):
        """
        read some environ, prepare some information, if do_init, create dir and so on.
        """
        self.id = '{0}-{1}'.format(time.time(), os.getpid())

        # GS_PERFCONFIG_OPTIONS is a environ where we can set some params to control behavior of tool.
        self.gs_perfconfig_options_str = self.read_env('GS_PERFCONFIG_OPTIONS')
        self.gs_perfconfig_options = {
            'lowest_print_log_level': ProjectLogLevel.NOTICE
        }
        self._apply_gs_perfconfig_options()

        self.env = os.path.abspath(env) if env is not None else None
        self.source_env(self.env)

        self.gauss_home = self.read_env('GAUSSHOME')
        self.gauss_data = self.read_env('PGDATA')
        self.gauss_log = self.read_env('GAUSSLOG')
        if self.gauss_home is None or self.gauss_data is None or self.gauss_log is None:
            Project.fatal('Could not find $GAUSSHOME, $GAUSSLOG or $PGDATA.\n'
                          'Please check the environment variables or specified by --env.')

        self.workspace1 = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), 'impl', 'perf_config'))
        self.workspace2 = os.path.abspath(os.path.join(self.gauss_log, 'om', 'perf_config'))

        self.preset_dir1 = os.path.join(self.workspace1, 'preset')
        self.preset_dir2 = os.path.join(self.workspace2, 'preset')

        self.run_log = os.path.join(self.workspace2, 'run.log')
        self.anti_log = os.path.join(self.workspace2, 'anti.log')
        self.report = os.path.join(self.workspace2, f'report-{self.id}.md')

        if do_init:
            self._do_init()

        Project.log('workspace1: {}'.format(self.workspace1))
        Project.log('workspace2: {}'.format(self.workspace2))
        Project.notice('Environment init done.')


    def get_builtin_script(self, name):
        """
        There are some built-in shell scripts that perform a set of shell operations.
        Pass in the script name and get the absolute path to the script.
        """
        builtin_script = os.path.join(self.workspace1, 'scripts', name)
        if not os.access(builtin_script, os.F_OK):
            Project.fatal(f'builtin script {builtin_script} does not exist.')
        return builtin_script

    def _apply_gs_perfconfig_options(self):
        """
        GS_PERFCONFIG_OPTIONS is a environ where we can set some params to control behavior of tool.
        """
        def _get_a_bool(_value, _name, _default):
            if _value in [False, '0', 'off', 'false']:
                return False
            elif _value in [True, '1', 'on', 'true']:
                return True
            else:
                Project.warning('invalid value of GS_PERFCONFIG_OPTIONS option: ' + _name)
                return _default

        if self.gs_perfconfig_options_str is None:
            return

        for option in self.gs_perfconfig_options_str.split(':'):
            kv = option.split('=')
            if len(kv) != 2:
                Project.warning('Could not parse option in GS_PERFCONFIG_OPTIONS: ' + option)
                continue
            elif kv[0] == 'lowest_print_log_level':
                try:
                    level = ProjectLogLevel.get_level_by_str(kv[1])
                    self.gs_perfconfig_options[kv[0]] = level
                    ProjectLog.set_lowest_print_level(level)
                except:
                    Project.warning('invalid value of GS_PERFCONFIG_OPTIONS option: lowest_print_log_level')
            else:
                Project.warning('Unknown option in GS_PERFCONFIG_OPTIONS: ' + option)


    def _do_init(self):
        """
        create the dir.
        """
        if not os.access(self.workspace2, os.F_OK):
            os.mkdir(self.workspace2, 0o755)

        if not os.access(self.preset_dir2, os.F_OK):
            os.mkdir(self.preset_dir2, 0o755)

    def __str__(self):
        return str({
            'id': self.id,
            'gauss_home': self.gauss_home,
            'gauss_data': self.gauss_data,
            'gauss_log': self.gauss_log,
            'workspace1': self.workspace1,
            'workspace2': self.workspace2,
            'gs_perfconfig_options_str': self.gs_perfconfig_options_str,
            'gs_perfconfig_options': self.gs_perfconfig_options
        })

    @staticmethod
    def read_env(name):
        val = os.getenv(name)
        Project.log(f'read env {name}={val}')
        return val

    @staticmethod
    def source_env(env):
        """
        read some environ from env file.
        """
        if env is None:
            return
        cmd = f'{CmdUtil.SOURCE_CMD} {env} && env'
        output = CmdUtil.execCmd(cmd)
        for line in output.splitlines():
            kv = line.split('=')
            if kv[0] not in ['GAUSSHOME', 'PGDATA', 'GAUSSLOG']:
                continue
            os.environ[kv[0]] = kv[1]
            Project.log(f'export env: {kv[0]}={kv[1]}')


class ProjectRole(object):
    """
    Role control. Check who the current user is and who the omm user is.
    Use gausslog's folder owner to automatically find omm users and optimize the use experience.
    """
    def __init__(self):
        self.current_role = getpass.getuser()

        stat = os.stat(Project.environ.gauss_log)
        self.user_name = pwd.getpwuid(stat.st_uid).pw_name
        self.user_uid = stat.st_uid
        self.user_gid = stat.st_gid

        if self.current_role != 'root' and self.current_role != self.user_name:
            Project.fatal(f'Illegal access detected. Current role is {self.current_role}, '
                          f'but owner of $GAUSSHOME is {self.user_name}.')
        
        check_dir_list = [
            Project.environ.workspace1,
            Project.environ.workspace2,
            Project.environ.preset_dir1,
            Project.environ.preset_dir2
        ]
        for diretory in check_dir_list:
            if os.access(diretory, os.F_OK):
                self.chown_to_user(Project.environ.workspace2)

        Project.notice(f'Role init done(current:{self.current_role}, user:{self.user_name}).')

    def chown_to_user(self, file):
        if self.current_role != 'root':
            assert self.current_role == self.user_name
            return
        os.chown(file, self.user_uid, self.user_gid)


class ProjectLogLevel(Enum):
    LOG = 0
    MSG = 1
    NOTICE = 2
    WARNING = 3
    ERR = 4
    FATAL = 5

    @staticmethod
    def get_level_by_str(string):
        for level in ProjectLogLevel:
            if string.lower() == level.name.lower():
                return level
        raise PorjectError('unknown level string ' + string)


class ProjectLog(object):
    # Sometimes, it is preferable not to display certain information on the screen.
    # You can set this value to control what is printed on the screen.
    # but 'ProjectLogLevel.MSG' is not controlled.
    _lowest_print_level = ProjectLogLevel.NOTICE

    @staticmethod
    def set_lowest_print_level(level):
        ProjectLog._lowest_print_level = level

    @staticmethod
    def show_lowest_print_level():
        return ProjectLog._lowest_print_level

    @staticmethod
    def reset_lowest_print_level():
        ProjectLog._lowest_print_level = Project.environ.gs_perfconfig_options['lowest_print_log_level']

    def __init__(self, file):
        self.file = file
        self._FILE = open(file, 'a')
        Project.role.chown_to_user(file)

        # just some flag
        Project.notice('Run log init done.')
        self._FILE.write('\n' * 10)
        self._FILE.write('#' * 30)
        self._FILE.write('\n>>>>>>>>>> NEW LOG START <<<<<<<<<<\n')

    def __del__(self):
        self._FILE.close()

    def do_log(self, level, content):
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S.%f")
        level_tag = '[{}]'.format(level.name)
        log_content = (content + '\n') if level == ProjectLogLevel.MSG else \
                      '{0} {1}: {2}\n'.format(formatted_time, level_tag, content)

        self._FILE.write(log_content)

        if level == ProjectLogLevel.LOG:
            ProjectLog.print_msg(log_content, level, end='')

        elif level == ProjectLogLevel.NOTICE:
            ProjectLog.print_msg(log_content, level, end='')

        elif level == ProjectLogLevel.MSG:
            ProjectLog.print_msg(log_content, level, end='')

        elif level == ProjectLogLevel.WARNING:
            ProjectLog.print_msg(log_content, level, end='')

        elif level == ProjectLogLevel.ERR:
            bt = ''.join(traceback.format_stack()[0:-1])
            ProjectLog.print_msg(log_content + '\n' + bt, level, end='')
            raise PorjectError(content + '\n' + bt)

        elif level == ProjectLogLevel.FATAL:
            bt = ''.join(traceback.format_stack()[0:-1])
            ProjectLog.print_msg(log_content + '\n' + bt, level, end='')
            exit(1)

        else:
            assert False

    @staticmethod
    def print_msg(msg, level, end='\n'):
        if level.value >= ProjectLog._lowest_print_level.value or level == ProjectLogLevel.MSG:
            GaussLog.printMessage(msg, end=end)


class ProjectReport(object):
    """
    Structure for storing reports and suggestions.
    The content needs to be assembled in advance according to the markdown style.
    """
    def __init__(self, file):
        self._file = file
        self._records = []
        self._suggestions = []
        Project.notice('Report log init done.')

    def record(self, content):
        self._records.append(content)
        self._records.append('\n')

    def suggest(self, content):
        self._suggestions.append(content)

    def dump(self):
        with open(self._file, 'w') as f:
            f.write('# Tune Report\n\n')
            f.write('\n'.join(self._records))
            if Project.getTask().tune_target.hasSuggest():
                f.write('\n\n# More Suggestions\n\n')
                f.write('\n\n'.join(self._suggestions))
        Project.role.chown_to_user(self._file)
        Project.notice('Report: ' + self._file)


class Project(object):
    """
    Project is mainly to provide some global information, module interface.
    """
    ###################################################
    # TASK
    ###################################################
    _task = None

    @staticmethod
    def getTask():
        return Project._task

    @staticmethod
    def setTask(task):
        assert Project._task is None
        Project._task = task

    ###################################################
    # ENVIRON OF PROJECT
    ###################################################
    environ = None

    @staticmethod
    def initEnviron(env=None, do_init=False):
        Project.environ = ProjectEnv(env, do_init)

    ###################################################
    # ROLE CTRL OF PROJECT
    ###################################################
    role = None

    @staticmethod
    def initRole():
        Project.role = ProjectRole()

    @staticmethod
    def haveRootPrivilege():
        return getpass.getuser() == 'root'

    ###################################################
    # LOG MODULE OF PROJECT
    ###################################################
    _log = None

    @staticmethod
    def initProjectLog(file):
        Project._log = ProjectLog(file)

    @staticmethod
    def set_lowest_print_level(level):
        ProjectLog.set_lowest_print_level(level)

    @staticmethod
    def show_lowest_print_level():
        return ProjectLog.show_lowest_print_level(level)

    @staticmethod
    def reset_lowest_print_level():
        ProjectLog.reset_lowest_print_level()


    @staticmethod
    def msg(content):
        """
        message must print on screen. and write a LOG in log file.
        """
        if Project._log is None:
            ProjectLog.print_msg(content, ProjectLogLevel.MSG)
            return

        Project._log.do_log(ProjectLogLevel.MSG, content)

    @staticmethod
    def log(content):
        if Project._log is None:
            ProjectLog.print_msg(f'{ProjectLogLevel.LOG.name}: {content}', ProjectLogLevel.LOG)
            return
        Project._log.do_log(ProjectLogLevel.LOG, content)

    @staticmethod
    def notice(content):
        if Project._log is None:
            ProjectLog.print_msg(f'{ProjectLogLevel.NOTICE.name}: {content}', ProjectLogLevel.NOTICE)
            return
        Project._log.do_log(ProjectLogLevel.NOTICE, content)

    @staticmethod
    def warning(content):
        if Project._log is None:
            ProjectLog.print_msg(f'{ProjectLogLevel.WARNING.name}: {content}', ProjectLogLevel.WARNING)
            return
        Project._log.do_log(ProjectLogLevel.WARNING, content)

    @staticmethod
    def err(content):
        if Project._log is None:
            ProjectLog.print_msg(f'{ProjectLogLevel.ERR.name}: {content}', ProjectLogLevel.ERR)
            exit(1)
        Project._log.do_log(ProjectLogLevel.ERR, content)

    @staticmethod
    def fatal(content):
        if Project._log is None:
            ProjectLog.print_msg(f'{ProjectLogLevel.FATAL.name}: {content}', ProjectLogLevel.FATAL)
            exit(1)
        Project._log.do_log(ProjectLogLevel.FATAL, content)

    ###################################################
    # PROBE AND TUNER OF PROJECT
    ###################################################
    _globalPerfProbe = None
    _globalPerfTuner = None

    @staticmethod
    def setGlobalPerfProbe(probe):
        Project._globalPerfProbe = probe

    @staticmethod
    def getGlobalPerfProbe():
        return Project._globalPerfProbe

    @staticmethod
    def setGlobalPerfTuner(tuner):
        Project._globalPerfTuner = tuner

    @staticmethod
    def getGlobalPerfTuner():
        return Project._globalPerfTuner

    ###################################################
    # Project report
    ###################################################
    report = None

    @staticmethod
    def prepareReport(file):
        Project.report = ProjectReport(file)

    ###################################################
    # openGauss operate
    ###################################################
    @staticmethod
    def startOpenGauss():
        cmd = 'gs_om -t start'
        Project.notice('start openGauss.....')

        output = CmdUtil.execCmd(cmd)

        Project.notice('start openGauss finish.')
        Project.log(output)

    @staticmethod
    def stopOpenGauss():
        cmd = 'gs_om -t stop'
        Project.notice('stop openGauss......')

        output = CmdUtil.execCmd(cmd)  

        Project.notice('stop openGauss finish.')
        Project.log(output)

    @staticmethod
    def isOpenGaussAlive():
        pmid = os.path.join(Project.environ.gauss_data, 'postmaster.pid')

        try:
            with open(pmid, 'r') as f:
                pid = int(f.readlines()[0])
            p = psutil.Process(pid)
            Project.notice(f'openGauss is running(pid:{pid} status:{p.status()})')
            return True
        except:
            Project.notice('openGauss is not running.')
            return False

    def __init__(self):
        assert False, 'Project is just a package of interface.'


