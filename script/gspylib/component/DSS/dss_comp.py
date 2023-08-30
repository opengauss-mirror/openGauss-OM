# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
# Description  : dss_comp.py is a utility to init param.

import configparser
import getpass
import os
import sys
import re
import time
import shutil
import functools

try:
    sys.path.append(sys.path[0] + "/../../../")
    from gspylib.component.BaseComponent import BaseComponent
    from gspylib.common.Common import DefaultValue
    from gspylib.component.DSS.dss_checker import DssConfig
    from base_utils.os.env_util import EnvUtil
    from base_utils.os.file_util import FileUtil
    from base_utils.os.cmd_util import CmdUtil, FastPopen
    from domain_utils.cluster_file.cluster_dir import ClusterDir
    from gspylib.common.aes_cbc_util import AesCbcUtil
    from gspylib.common.ErrorCode import ErrorCode
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


class DssInst():

    def __init__(self, cfg_path):
        self.section = 'Default'
        self.cfg_path = cfg_path

    @property
    def parser(self):
        '''
        DSS configuration parser
        '''

        items = {}
        if os.path.isfile(self.cfg_path):
            with open(self.cfg_path, "r") as fr_cfg:
                context = '[{}]\n'.format(self.section) + fr_cfg.read()
            parser = configparser.RawConfigParser()
            parser.optionxform = lambda raw: raw
            parser.read_string(context)
            items = dict(parser._sections.get(self.section))
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % self.cfg_path)
        return items
    
    @staticmethod
    def get_private_vg_num(dss_home):
        '''
        Obtaining Private Volumes
        '''


        vg_cfg = os.path.join(dss_home, 'cfg', 'dss_vg_conf.ini')
        if os.path.isfile(vg_cfg):
            try:
                with open(vg_cfg, "r") as fp:
                    context = fp.read().strip()
                    pris = re.findall(
                        '(.*):/dev/.*private_.*', context)
                    if pris:
                        return len(pris)
                    else:
                        raise Exception(ErrorCode.GAUSS_504["GAUSS_50416"] %
                                        'in dss_vg_conf.ini')
            except Exception as eds:
                raise Exception(ErrorCode.GAUSS_504["GAUSS_50414"] % eds)
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % vg_cfg)

    @staticmethod
    def get_private_vgname_by_ini(dss_home, dss_id, xlog_in_one_priv_vg):
        '''
        Obtaining a Private Volume
        '''

        if xlog_in_one_priv_vg:
            dss_id = 0
        vg_cfg = os.path.join(dss_home, 'cfg', 'dss_vg_conf.ini')
        if os.path.isfile(vg_cfg):
            try:
                with open(vg_cfg, "r") as fp:
                    context = fp.read().strip()
                    pris = re.findall(
                        '(.*):/dev/.*private_{}'.format(str(dss_id)), context)
                    if pris:
                        return pris[0].strip()
                    else:
                        raise Exception(ErrorCode.GAUSS_504["GAUSS_50416"] %
                                        'in dss_vg_conf.ini')
            except Exception as eds:
                raise Exception(ErrorCode.GAUSS_504["GAUSS_50414"] % eds)
        else:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50201"] % vg_cfg)

    @staticmethod
    def get_dms_url(nodes_list):
        '''
        The DMS port number is the DSS port number plus 10.
        '''
        try:
            # The DMS port number is the DSS port number plus 10.
            return str(DssConfig(unzip_str=nodes_list, offset=10))
        except Exception as ex:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50001"] %
                            'DSS_NODES_LIST. Error: {}'.format(ex))

    @staticmethod
    def get_current_dss_id(dss_home, cur_db_inst, dss_list=''):
        '''
        Obtains the ID of the current instance.
        '''
        try:
            cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')
            if not dss_list:
                dss_list = DssInst(cfg_path=cfg).parser.get(
                    'DSS_NODES_LIST', '')

            dss_ids, dss_ips, _ = zip(
                *[item.split(':') for item in dss_list.split(',')])

            for idx, ip in enumerate(dss_ips):
                if "'{}'".format(ip) in str(cur_db_inst):
                    return dss_ids[idx]
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50012"] % 'inst_id' +
                            'Error: {}'.format(e))

    @staticmethod
    def get_dss_id_from_key(dss_home=''):
        '''
        Obtaining INST_ID Through Configuration Items
        '''
        try:
            if not dss_home:
                dss_home = EnvUtil.get_dss_home(getpass.getuser())

            cfg = os.path.join(dss_home, 'cfg', 'dss_inst.ini')
            inst_id = DssInst(cfg_path=cfg).parser.get('INST_ID', '')
            if inst_id.isdigit():
                return int(inst_id)
            else:
                raise Exception('The dss-id is empty')

        except Exception as e:
            raise Exception(ErrorCode.GAUSS_500["GAUSS_50012"] %
                            'inst_id. Error: {}'.format(e))


class Dss(BaseComponent):
    MAX_DSS_ID = 8
    DSS_IOFENCE_FILENAME = 'dss_clear.sh'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def clear_shared_mem_with_zero():
        '''
        Clear the unused shared memory of users.
        '''

        cmd = 'ipcrm -a'
        sts, out = CmdUtil.exec_by_popen(cmd)
        if sts not in [0, 1]:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51253"] %
                            str(out).strip())

    @staticmethod
    def kill_dss_server(clear_shared=True, logger=None):
        '''
        Stop the dssserver process.
        '''

        kill_cmd = 'pkill -9 -f dssserver'
        sts, out = CmdUtil.getstatusoutput_by_fast_popen(kill_cmd)
        if sts not in [0, 1]:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51254"] %
                            str(out).strip())

        if clear_shared:
            Dss.clear_shared_mem_with_zero()
        if logger and hasattr(logger, 'debug'):
            logger.debug("The dssserver has been killed.")

        # Increase operating system reaction time
        time.sleep(0.5)

    @staticmethod
    def unreg_disk(dss_home, user='', clib_app='', logger=None):
        '''
        The minimum ID is 0 and the maximum ID is 8.
        There are nine instances in total.
        '''
        cmd_str = ''

        gauss_home = ClusterDir.get_gauss_home()
        dsscmd_path = os.path.realpath(
            os.path.join(gauss_home, 'bin', Dss.DSS_IOFENCE_FILENAME))

        un_reg_cmd_str = f'sh {dsscmd_path} {dss_home}; '

        if clib_app:
            dsscmd_path = os.path.realpath(
                os.path.join(clib_app, Dss.DSS_IOFENCE_FILENAME))
            cmd_str = f'su - {user} -c "export DSS_HOME={dss_home}; '
            cmd_str += f'export LD_LIBRARY_PATH={clib_app}; '
            cmd_str += f'export PATH={clib_app}:$PATH; '
            un_reg_cmd_str = cmd_str + f'sh {dsscmd_path} {dss_home}; "'

        if logger:
            logger.debug(f'The cmd of the unreg: {un_reg_cmd_str}')

        sts, out = CmdUtil.retry_exec_by_popen(un_reg_cmd_str)
        if not sts:
            raise Exception(ErrorCode.GAUSS_514["GAUSS_51400"] %
                            un_reg_cmd_str + " Error:\n%s" % out.strip())
        if logger:
            logger.debug(f'The result of the unreg: {out}')

    @staticmethod
    def start_dss_server(logger=None,
                         bin_path='',
                         kill_server=True,
                         unrej=False,
                         exist_so=False):
        '''
        The OM manually starts the DSS server to obtain the socket file.
        '''

        Dss.write_dss_context_with_file(exist_so=exist_so)

        if kill_server:
            Dss.kill_dss_server()

        dss_home = EnvUtil.get_dss_home(getpass.getuser())
        if unrej:
            Dss.unreg_disk(dss_home, logger=logger)
        if bin_path:
            dss_cmd = os.path.realpath(os.path.join(bin_path, 'dssserver'))
        else:
            dss_cmd = 'dssserver'

        cmd = 'sh -c "source {} && nohup {} -D {} >/dev/null 2>&1 & "'.format(
            EnvUtil.getMpprcFile(), dss_cmd, dss_home)
        proc = FastPopen(cmd)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51252"] +
                            ' Error: {}'.format(str(err + out).strip()))
        if logger:
            logger.debug('Successfully start dss server.')

    def initInstance(self):
        '''
        om init dss server
        '''
        Dss.start_dss_server(self.logger, self.binPath)
        if not DssConfig.check_process_available(
                self.logger, 'dssserver'):
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51252"])

    @staticmethod
    def catch_err(exist_so=True):
        '''
        This command is used to kill the dssserver after
        the dn initialization is complete to prevent
        the initialization process from exiting.
        '''

        def _func(func):

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    func(*args, **kwargs)
                finally:
                    if args and args[0] and hasattr(
                            args[0], 'dss_mode') and args[0].dss_mode:
                        logger = args[0].logger if hasattr(args[0],
                                                           'logger') else None
                        Dss.kill_dss_server(logger=logger)
                        dss_nodes_list = DssConfig.get_value_b64_handler(
                            'dss_nodes_list',
                            args[0].dss_config,
                            action='decode')
                        Dss.write_dss_context_with_file(
                            dss_nodes_list=dss_nodes_list, exist_so=exist_so)

            return wrapper

        return _func

    @staticmethod
    def write_dss_context_with_file(dss_nodes_list='', exist_so=True):
        dss_home = EnvUtil.get_dss_home(user=getpass.getuser())
        init_cfg = os.path.realpath(
            os.path.join(dss_home, 'cfg', 'dss_inst.ini'))
        confs = DssInst(init_cfg).parser
        if EnvUtil.get_dss_ssl_status() == 'on':
            app_dir = ClusterDir.get_gauss_home()
            cert_path = os.path.join(app_dir, 'share/sslcert/dss')
            confs = DssInitCfg(dss_ssl=True,
                               dss_nodes_list=dss_nodes_list,
                               cipher_pwd=Dss.get_dss_cipher_text(cert_path),
                               cert_path=cert_path,
                               exist_so=exist_so,
                               **confs)
        else:
            confs = DssInitCfg(dss_nodes_list=dss_nodes_list,
                               dss_ssl=False,
                               exist_so=exist_so,
                               **confs)

        if os.path.isfile(init_cfg):
            os.remove(init_cfg)
        FileUtil.write_custom_context(
            init_cfg, list(confs), authority=DefaultValue.KEY_FILE_MODE_IN_OS)

    @staticmethod
    def get_dss_cipher_text(cert_path):
        gauss_home = ClusterDir.get_gauss_home()
        dss_cmd = os.path.join(gauss_home, "bin/dsscmd")
        cmd = "{} encrypt".format(dss_cmd)
        rand_pwd = AesCbcUtil.aes_cbc_decrypt_with_path(cert_path,
                                                        cert_path,
                                                        key_name="server")
        sts, out, _ = CmdUtil.interactive_with_popen(cmd, rand_pwd)
        if sts != 0 or out.find(b'Cipher') == -1:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51255"])
        cps = re.findall(r'ipher[: \t]*(.+)', out.decode('utf-8'))
        if cps:
            return cps[0]
        else:
            raise Exception(ErrorCode.GAUSS_512["GAUSS_51256"])


class DssInitCfg():

    def __init__(self,
                 inst_id='',
                 dss_home='',
                 dss_nodes_list='',
                 exist_so=True,
                 dss_ssl=True,
                 cert_path='',
                 cipher_pwd='',
                 **kwargs):
        self.INST_ID = inst_id
        self.LSNR_PATH = dss_home
        for key, value in kwargs.items():
            setattr(self, key, value)
        if dss_nodes_list:
            self.DSS_NODES_LIST = dss_nodes_list
        self.STORAGE_MODE = "RAID"
        # _SHM_KEY value range: 1–64
        self._SHM_KEY = os.getuid() % 64 + 1
        self._LOG_LEVEL = '7'
        if exist_so:
            self.DSS_CM_SO_NAME = "libclient.so"
            if hasattr(self, 'DSS_NODES_LIST') and len(
                    self.DSS_NODES_LIST.split(',')) > 1:
                self.STORAGE_MODE = "CLUSTER_RAID"
        else:
            if hasattr(self, 'DSS_CM_SO_NAME'):
                del self.DSS_CM_SO_NAME
            if hasattr(self, 'DSS_NODES_LIST'):
                del self.DSS_NODES_LIST
        if dss_ssl:
            self.SSL_CA = os.path.join(cert_path, 'cacert.pem')
            self.SSL_KEY = os.path.join(cert_path, 'server.key')
            self.SSL_CERT = os.path.join(cert_path, 'server.crt')
            self.SSL_PWD_CIPHERTEXT = cipher_pwd

    def __iter__(self):
        for key, value in vars(self).items():
            yield '{}={}'.format(key, value)


class Udev():

    def __init__(self, attr='', **kwargs):
        # uuid soft_link_name user, group
        dev_id = ''
        dev_name = ''
        if shutil.which('hot_add'):
            self.KERNEL = 'sd*'
        else:
            self.KERNEL = 'dm*'
        self.KERNEL = 'sd*'
        self.SUBSYSTEM = 'block'
        self.RESULT, self.SYMLINK, self.OWNER, self.GROUP = '', '', '', '',
        if attr:
            dev_id, dev_name, self.SYMLINK, self.OWNER, self.GROUP = attr
        self.PROGRAM = ' '.join(['/usr/bin/udevadm', 'info', '-q', 'symlink', '/dev/$name'])
        self.RESULT = '*{}*'.format(dev_id)
        self.MODE = '0660'
        if dev_name.startswith('sd'):
            self.KERNEL = 'sd*'
        elif dev_name.startswith('nvme'):
            self.KERNEL = 'nvme*'
        elif dev_name.startswith('ultrapath'):
            self.KERNEL = 'ultrapath*'
        elif dev_name.startswith('dm-'):
            self.KERNEL = 'dm-*'

        for key, val in kwargs.items():
            setattr(self, key, val)

    @property
    def attr(self):
        return {
            'KERNEL': '==',
            'SUBSYSTEM': '==',
            'PROGRAM': '==',
            'RESULT': '==',
            'SYMLINK': '+=',
            'OWNER': '=',
            'GROUP': '=',
            'MODE': '='
        }

    def __str__(self):
        return ', '.join(list(Udev(**vars(self))))

    def __iter__(self):

        for key, value in vars(self).items():
            yield '{}{}"{}"'.format(key, self.attr.get(key, ""), value)


class UdevContext():

    CM_SHARE_NAME = os.path.join('/dev', '%s_cm_shared')
    CM_VOTE_NAME = os.path.join('/dev', '%s_cm_vote')
    DSS_SHARED_NAME = os.path.join('/dev', '%s_dss_shared')
    DSS_PRIVATE_NAME = os.path.join('/dev', '%s_dss_private_%s')
    DSS_UDEV_NAME = 'zz-dss_%s.rules'
    DSS_UDEV_DIR = '/etc/udev/rules.d/'

    def __init__(self, identity, db_info, uuid_getter='', devname_getter=''):
        self.user, self.group = identity
        self.uuid_getter = uuid_getter
        self.devname_getter = devname_getter
        self.db_info = db_info

    @property
    def lun_table_name(self):
        return {
            'dss_pri_disks': UdevContext.DSS_PRIVATE_NAME % (self.user, '%s'),
            'dss_shared_disks': UdevContext.DSS_SHARED_NAME % self.user,
            'cm_share_disk': UdevContext.CM_SHARE_NAME % self.user,
            'cm_vote_disk': UdevContext.CM_VOTE_NAME % self.user,
        }

    @staticmethod
    def get_all_vgname_disk_pair(all_shared_map, all_pri_map, user):
        '''
        Returns the LUN name and disk alias pair.
        '''
        return {
            **{
                vgname: UdevContext.DSS_SHARED_NAME % user
                for vgname in all_shared_map.keys()
            },
            **{
                vgname: UdevContext.DSS_PRIVATE_NAME % (user, idx)
                for idx, vgname in enumerate(all_pri_map.keys())
            },
        }

    @staticmethod
    def get_all_disk_alias(user, group, db_info):
        '''
        Alias of all disks
        '''
        res = []
        for key, value in UdevContext((user, group),
                                      db_info).lun_table_name.items():
            if key == 'dss_pri_disks':
                for idx, _ in enumerate(db_info.dss_pri_disks):
                    res.append(value % str(idx))
            else:
                res.append(value)
        return res

    @staticmethod
    def get_all_phy_disk(db_info):
        '''
        Gets all incoming disks.
        '''
        disks = [db_info.cm_vote_disk, db_info.cm_share_disk]
        disks.extend({
            **db_info.dss_pri_disks,
            **db_info.dss_shared_disks
        }.values())
        return disks

    def __iter__(self):

        for key, alias in self.lun_table_name.items():
            alias = alias.replace('/dev/', '', 1)
            info = getattr(self.db_info, key)
            if isinstance(info, dict) and key == 'dss_pri_disks':
                for dss_id, phy_disk in enumerate(info.values()):
                    yield str(
                        Udev((self.uuid_getter(phy_disk), self.devname_getter(phy_disk), alias % (str(dss_id)),
                              self.user, self.group)))
            elif isinstance(info, dict):
                # shared disk
                for phy_disk in info.values():
                    yield str(
                        Udev((self.uuid_getter(phy_disk), self.devname_getter(phy_disk), alias, self.user,
                              self.group)))
            elif isinstance(info, str):
                # the disk used by cm
                yield str(
                    Udev(
                        (self.uuid_getter(info), self.devname_getter(phy_disk), alias, self.user, self.group)))
