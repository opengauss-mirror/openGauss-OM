#!/usr/bin/env python3
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
# Description  : EncryptedOpenssl is a utility with create ssl cert.
#############################################################################
import subprocess
import sys

sys.dont_write_bytecode = True
try:
    import os
    import shutil
    import pwd

    sys.path.append(os.path.split(os.path.realpath(__file__))[0] + "/../../")
    from gspylib.common.Common import DefaultValue
    from base_utils.common.constantsbase import ConstantsBase
    from base_utils.common.fast_popen import FastPopen
    from base_utils.os.env_util import EnvUtil
    from base_utils.executor.cmd_executor import CmdExecutor
    from base_utils.executor.local_remote_cmd import LocalRemoteCmd


except ImportError as error:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % error)


def mock_open_ssl_passwd(cmd):
    """
    Mock password of cmd
    """
    return cmd.split("|")[1]


class OpenSslException(Exception):
    """
    OpenSslException class
    """
    def __init__(self, error_info):
        super(OpenSslException, self).__init__()
        self.error_info = error_info

    def __str__(self):
        return self.error_info


class EncryptorException(Exception):
    """
    OpenSslException class
    """
    def __init__(self, error_info):
        super(EncryptorException, self).__init__()
        self.error_info = "Encryptor error: {0}".format(error_info)

    def __str__(self):
        return self.error_info


class EncryptedOpenssl:
    """
    Class about encrypted openssl
    """
    DEFAULT_PERIOD = 10950

    def __init__(self, keys_path, encrypt_logger, pw_len=0):
        self.keys_path = keys_path
        self.logger = encrypt_logger
        self.key_names = ["cacert.pem", "server.crt", "server.key",
                          "client.crt", "client.key"]

        self.passwd = DefaultValue.get_secret(pw_len)
        # Default active period is 30 years
        self.active_period = EncryptedOpenssl.DEFAULT_PERIOD
        self.encryptor = None

        # OsConfig.check_openssl_version()

    def set_active_period(self, value):
        """
        Set active period
        """
        try:
            value = int(value)
        except ValueError:
            return
        if value > EncryptedOpenssl.DEFAULT_PERIOD:
            self.active_period = value
            self.logger.debug("OPENSSL: Days: %s." % self.active_period)

    def set_encryptor(self, encryptor):
        """
        set encryptor
        """
        if not callable(encryptor):
            return False
        self.encryptor = encryptor
        return True

    def _create_ssl_tmp_path(self):
        """
        Create tmp dirs and files for generate ssl cert.
        :return: NA
        """
        if os.path.exists(self.keys_path):
            shutil.rmtree(self.keys_path)

        os.makedirs(self.keys_path, ConstantsBase.KEY_DIRECTORY_PERMISSION)

    def _modify_ssl_config(self):
        """
        Generate config file.
        """
        self.logger.debug("OPENSSL: Create config file.")
        v3_ca_ = [
            "[ v3_ca ]",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid:always,issuer:always",
            "basicConstraints = CA:true",
            "keyUsage = keyCertSign,cRLSign",
        ]
        v3_ca = os.linesep.join(v3_ca_)

        # Create config file.
        with open(os.path.join(self.keys_path, "openssl.cnf"), "w") as fp:
            # Write config item of Signature
            fp.write(v3_ca)
        self.logger.debug("OPENSSL: Successfully create config file.")

    def __exec_openssl_with_shell(self, cmd, expect_str = ""):
        """
        spell echo cmd and execute with shell.
        """
        current_user = pwd.getpwuid(os.getuid()).pw_name
        gauss_home = EnvUtil.getEnvironmentParameterValue("GAUSSHOME", current_user)
        conf_file = os.path.realpath(os.path.join(gauss_home, "share",
                                                  "sslcert", "gsql", "openssl.cnf"))

        echo_cmd = 'export OPENSSL_CONF={2} ; echo "{0}" | openssl {1}'.format(self.passwd,
                                                                               cmd,
                                                                               conf_file)

        proc = FastPopen(echo_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         close_fds=True, preexec_fn=os.setsid)
        stdout, _ = proc.communicate(echo_cmd)
        if proc.returncode != 0:
            self.logger.debug("The encrypt command error "
                              ":CMD:{0}, OUTPUT:{1}".format(mock_open_ssl_passwd(cmd), stdout))
            raise OpenSslException("The encrypt command error "
                                   ":CMD:{0}, OUTPUT:{1}".format(mock_open_ssl_passwd(cmd),
                                                                 stdout))
        if expect_str and expect_str in stdout:
            self.logger.debug("Openssl command perform successfully.")
        CmdExecutor.execCommandWithMode(echo_cmd, None, local_mode=True)

    def check_certificate_file_exist(self, cert_names):
        """Check whether the certificate file is generated."""
        for cert_name in cert_names:
            cert_path = os.path.join(self.keys_path, cert_name)
            if not os.path.exists(cert_path):
                return False
            os.chmod(cert_path, ConstantsBase.KEY_FILE_PERMISSION)
        return True

    def __generate_cert_file(self, cmd, cert_name, expect_str=""):
        """Generate cert file."""
        try:
            self.__exec_openssl_with_shell(cmd, expect_str)
            if not self.check_certificate_file_exist([cert_name]):
                raise OpenSslException("The command openssl error :"
                                       " %s" % mock_open_ssl_passwd(cmd))
        except Exception as err:
            err_msg = str(err).replace(self.passwd, "*")
            raise Exception("Failed to generate {0}."
                            " Error: {1}".format(cert_name, err_msg))

    def _generate_root_cert(self):
        """
        Generate ca cert.
        :return: NA
        """
        self.logger.debug("Generate ca keys.")

        # cakey.pem
        cmd = (' genrsa -aes256 -f4 -passout stdin'
               ' -out {0}/cakey.pem 2048'.format(self.keys_path))
        self.__generate_cert_file(cmd, "cakey.pem", "e is 65537")

        # cacert.pem
        cmd = (' req -new -x509 -passin stdin -days {1}'
               ' -key {0}/cakey.pem -out {0}/cacert.pem'
               ' -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/'
               'CN=CA"'.format(self.keys_path, self.active_period))
        self.__generate_cert_file(cmd, "cacert.pem")

    def _generate_cert(self, role):
        """
        Generate cert of role.
        :param role: role
        :return: NA
        """
        self.logger.debug("Generate %s keys." % role)

        # key
        cmd = (" genrsa -aes256 -passout stdin -out {0}/{1}.key"
               " 2048".format(self.keys_path, role))
        cert_name = "{}.key".format(role)
        expect_str = "e is 65537"
        self.__generate_cert_file(cmd, cert_name, expect_str)

        # csr
        cmd = (' req -new -key {0}/{1}.key -passin stdin -out '
               '{0}/{1}.csr -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/'
               'CN={1}"'.format(self.keys_path, role))
        cert_name = "{}.csr".format(role)
        self.__generate_cert_file(cmd, cert_name)

        # crt
        cmd = (' x509 -req -days {2} -in {0}/{1}.csr -CA {0}/cacert.pem '
               '-CAkey {0}/cakey.pem -passin stdin -CAcreateserial '
               '-out {0}/{1}.crt -extfile '
               '{0}/openssl.cnf'.format(self.keys_path, role,
                                        self.active_period))
        cert_name = "{}.crt".format(role)
        expect_str = "Getting CA Private Key"
        self.__generate_cert_file(cmd, cert_name, expect_str)

        srl_file = os.path.join(self.keys_path, "cacert.srl")
        if os.path.exists(srl_file):
            os.unlink(srl_file)

    def _clean_useless_path(self):
        """
        Clean useless dirs and files, chmod the target files
        :return: NA
        """
        for filename in os.listdir(self.keys_path):
            if filename in [os.curdir, os.pardir]:
                continue
            file_path = os.path.join(self.keys_path, filename)
            if filename not in self.key_names:
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
            else:
                os.chmod(file_path, ConstantsBase.KEY_FILE_PERMISSION)

    def _clean_all(self):
        try:
            if os.path.exists(self.keys_path):
                shutil.rmtree(self.keys_path)
        except OSError:
            pass

    def get_key_paths(self):
        """Get all paths of keys."""
        paths = []
        for key in self.key_names:
            path = os.path.join(self.keys_path, key)
            paths.append(path)
        return paths

    def generate(self):
        """
        Generate ssl certificate
        :return: NA
        """
        self.logger.debug("Start to generate ssl certificate.")
        try:
            self._create_ssl_tmp_path()
            self._modify_ssl_config()
            self._generate_root_cert()
            self._generate_cert("server")
            self._generate_cert("client")
            # ddes cluster manager user external encryptor
            if self.encryptor:
                dest_cert_files = ["server.key.cipher",
                                   "server.key.rand",
                                   "client.key.cipher",
                                   "client.key.rand"]
                self.encryptor(self.passwd, self.keys_path, self.logger)
                self.key_names.extend(dest_cert_files)
            else:
                raise EncryptorException("Encryptor cannot be callable.")
            self._clean_useless_path()
        except Exception as ssl_err:
            raise Exception("Failed to generate ssl certificate. Error: %s"
                            % ssl_err)
        self.logger.debug("Complete to generate ssl certificate.")

        return self.get_key_paths()

    def distribute_cert(self, ssh_tool):
        """
        Distribute all certificate
        """
        self.logger.debug("Distribute cert to hosts '%s'." % ssh_tool.hostNames)
        # Prepare dir.
        LocalRemoteCmd.checkRemoteDir(ssh_tool, self.keys_path, ssh_tool.hostNames)

        # Change mode of remote files for distributing.
        self.logger.debug("Change cert mode for distributing.")
        for filename in self.key_names:
            file_path = os.path.join(self.keys_path, filename)
            cmd = "if [ -f '{}' ]; then chmod {} '{}'; fi".format(
                file_path, DefaultValue.KEY_FILE_MODE, file_path)
            ssh_tool.executeCommand(cmd, hostList=ssh_tool.hostNames)

        # Distribute
        files_ = os.path.join(self.keys_path, "*")
        ssh_tool.scpFiles(files_, self.keys_path, ssh_tool.hostNames)

        # change mode
        cmd = "chmod %s %s; chmod %s %s/*" % (DefaultValue.KEY_DIRECTORY_MODE,
                                              self.keys_path,
                                              DefaultValue.MIN_FILE_MODE,
                                              self.keys_path)
        self.logger.debug("Change cert mode.")
        ssh_tool.executeCommand(cmd, hostList=ssh_tool.hostNames)

        self.logger.debug("Successfully distribute cert to hosts")

