# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2020 Huawei Technologies Co.,Ltd.
# Portions Copyright (c) 2007 Agendaless Consulting and Contributors.
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
# Description  : os version info.
#############################################################################

import os
import re
import select
import sys

from os_platform.common import _supported_dists,SUPPORT_WHOLE_PLATFORM_LIST

ISCONFIGURETRUE = "# isConfigure = TRUE"
ISCONFIGUREFALSE = "# isConfigure = FALSE"
SESSIONTIMEOUT = 300

class LinuxDistro(object):
    """
    replace expired func linux_distribution
    """
    @staticmethod
    def _parse_release_file(num1_line):
        """
        Default to empty 'version' and 'id' strings.  Both defaults are used
        when 'num1_line' is empty.  'id' defaults to empty when an id can not
        be deduced.
        """
        version = ''
        id_num = ''

        # Parse the first line
        _hw_publish_version = re.compile(r'(.+)'
                                          ' release '
                                          '([\d.]+)'
                                          '[^(]*(?:\((.+)\))?')
        implication = _hw_publish_version.match(num1_line)
        if implication is not None:
            # LSB format: "distro release x.x (codename)"
            return tuple(implication.groups())

        # Pre-LSB format: "distro x.x (codename)"
        _publish_version = re.compile(r'([^0-9]+)'
                                      '(?: release )?'
                                      '([\d.]+)'
                                      '[^(]*(?:\((.+)\))?')
        implication = _publish_version.match(num1_line)
        if implication is not None:
            return tuple(implication.groups())

        line = num1_line.strip().split()
        if line:
            version = line[0]
            if len(line) > 1:
                id_num = line[1]
        return '', version, id_num
    
    @staticmethod
    def parse_linux_osid(filename):
        """
        Tries to determine the name of the Linux OS distribution name.

            The function first looks for a distribution release file in
            /etc and then reverts to _dist_try_harder() in case no
            suitable files are found.

            Returns a tuple (distname,version,id) which default to the
            args given as parameters.

        """
        valid_info = []
        lines_to_choose = []
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                # Ignore comment lines starting with # and empty lines
                if line and not line.startswith('#'):
                    # Separate the release name, version with spaces
                    distro, version = line.split()
                    valid_info.append({
                        'os': distro,
                        'version': version
                    })
                    lines_to_choose.append(line.strip())
        if len(lines_to_choose) == 1 or len(lines_to_choose) == 0:
            return valid_info
        for i, line in enumerate(lines_to_choose, 1):
            print(f"{i}. {line}")

        while True:
            try:
                choice = int(input("Please enter the serial number of the option:"))
                if (1 <= choice and choice <= len(lines_to_choose)):
                    chosen_line = lines_to_choose[choice - 1]
                    valid_info = valid_info[choice - 1]
                    with open(filename, 'r+') as file:
                        lines = file.readlines()
                        file.seek(0)
                        file.truncate()

                        for line in lines:
                            if line.strip().startswith('#') or line.strip() == '':
                                file.write(line)
                                continue
                            elif chosen_line in line:
                                file.write(line)
                            else:
                                file.write('#' + line)
                    LinuxDistro.write_is_configure_true(filename, ISCONFIGURETRUE)
                    break
                else:
                    print("Invalid input: Please re-enter")
            except ValueError:
                print("Invalid input: Please re-enter")
        return valid_info


    @staticmethod
    def write_is_configure_true(file_path, target_line):
        # open the file and read all the lines
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Check if any row contains target content
        has_target_line = any(target_line in line for line in lines)

        # If there is no target row, insert the target row before row 21
        if not has_target_line:
            lines.insert(20, target_line + '\n')

        # Write the modified content back to the file
        with open(file_path, 'w') as file:
            file.writelines(lines)


    @staticmethod
    def parse_linux_distributions(filename):
        """
        Tries to determine the name of the Linux OS distribution name.

            The function first looks for a distribution release file in
            /etc and then reverts to _dist_try_harder() in case no

            Returns a tuple (distname,version,id) which default to the
            args given as parameters.

        """
        is_configure = True
        valid_info = LinuxDistro.parse_linux_osid(filename)

        if len(valid_info) == 1:
            LinuxDistro.write_is_configure_true(filename, ISCONFIGURETRUE)

        with open(filename, 'r') as file:
            for line in file:
                if ISCONFIGURETRUE in line or ISCONFIGUREFALSE in line:
                    is_configure = False

        # Remind the user if new content is added to the file
        if len(valid_info) == 0 and is_configure:
            print(f"File '{filename}' has not been configured yet,"
                                "do you still need to configure it?"
                                "Enter 'yes' or 'no' to configure "
                                "the file: ", end='', flush=True)
            rlist, _, _ = select.select([sys.stdin], [], [], SESSIONTIMEOUT)
        
            if rlist:
                user_input = input().lower()
            else:
                user_input = "no"
                
            while True:
                if user_input in ('y', 'yes'):
                    LinuxDistro.write_is_configure_true(filename, ISCONFIGURETRUE)
                    os_name = input("Please enter an operating system name:")
                    version = input("Please enter the version number:")
                    with open(filename, 'a') as file:
                        file.write(f"\n{os_name} {version}\n")
                    valid_info = LinuxDistro.parse_linux_osid(filename)
                    break
                elif user_input in ('n', 'no'):
                    LinuxDistro.write_is_configure_true(filename, ISCONFIGUREFALSE)
                    break
                else:
                    LinuxDistro.write_is_configure_true(filename, ISCONFIGUREFALSE)
                    break
        return valid_info


    @staticmethod
    def select_linux_distribution(valid_info):
        # If there is no legal information, return None
        if not valid_info:
            return None

        # If there is only one line of legal information, return directly
        if len(valid_info) == 1:
            return valid_info[0]

    @staticmethod
    def linux_distribution(distname='', version='', idNum='',
                           supported_dists=_supported_dists,
                           full_distribution_name=0):
        """
        Tries to determine the name of the Linux OS distribution name.

            The function first looks for a distribution release file in
            /etc and then reverts to _dist_try_harder() in case no
            suitable files are found.

            supported_dists may be given to define the set of Linux
            distributions to look for. It defaults to a list of currently
            supported Linux distributions identified by their release file
            name.

            If full_distribution_name is true (default), the full
            distribution read from the OS is returned. Otherwise the short
            name taken from supported_dists is used.

            Returns a tuple (distname,version,id) which default to the
            args given as parameters.

        """
        is_flag_osid = False
        is_flag_oscorrect = True
        try:
            etc_dir = os.listdir('/etc')
        except os.error:
            # Probably not a Unix system
            return distname, version, idNum
        etc_dir.sort()
        gFile = None
        _release_filename = re.compile(r'(\w+)[-_](release|version)')
        for file in etc_dir:
            if os.path.islink('/etc/' + file):
                continue
            m = _release_filename.match(file)
            if m is not None:
                _distname, dummy = m.groups()
                if _distname in supported_dists:
                    gFile = file
                    distname = _distname
                    break

        # Read the first line
        if gFile is None:
            return distname, version, idNum
        with open('/etc/' + gFile, 'r') as f:
            firstline = f.readline()
        _distname, _version, _id = LinuxDistro._parse_release_file(firstline)

        if _distname and full_distribution_name:
            distname = _distname
            for dist in SUPPORT_WHOLE_PLATFORM_LIST:
                if dist.lower == _distname.lower:
                    is_flag_oscorrect = True
        if _version:
            version = _version
        if _id:
            idNum = _id
        if is_flag_oscorrect == True:
            return distname, version, idNum
        elif is_flag_oscorrect == False:
            # Read system information from configuration file
            # Call the function and pass in the filename
            osid_path = os.path.realpath(
                    os.path.join(os.path.realpath(__file__), "../../osid.conf"))
        
            if os.path.exists(osid_path):
                file_data = LinuxDistro.parse_linux_distributions(osid_path)
                
                # Output the parsed content
                selected_data = LinuxDistro.select_linux_distribution(file_data)
                
                if selected_data:
                    is_flag_osid = True

            else:
                print(f"The file '{osid_path}' does not exist.")
                
            if is_flag_osid:
                if selected_data['os']:
                    distname = selected_data['os']
                if selected_data['version']:
                    version = selected_data['version']
                if selected_data['bit']:
                    idNum = selected_data['bit']
                return distname, version, idNum
