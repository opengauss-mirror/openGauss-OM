#!/bin/bash

declare binarylib_dir='None'
declare gcc_version='10.3'
declare module_name="openGauss-OM"
declare version_number='6.0.0'
declare version_Kernel='92.298'
ROOT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
echo "ROOT_DIR : $ROOT_DIR"
declare ERR_MKGS_FAILED=1
declare LOG_FILE="${ROOT_DIR}/build.log"
declare PKG_DIR="${ROOT_DIR}/package"
declare PKG_TMP_DIR="${ROOT_DIR}/package/temp"
declare version_string="${module_name}-${version_number}"

#########################################################################
##read command line paramenters
#######################################################################

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help                         show help information
    -3rd|--binarylib_dir              the parent directory of binarylibs
    -cv|--gcc_version                 the gcc version only accepts 7.3 and 10.3
    "
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -3rd|--binarylib_dir)
            if [ "$2"X = X ]; then
                echo "no given binarylib directory values"
                exit 1
            fi
            binarylib_dir=$2
            shift 2
            ;;
        -cv|--gcc_version)
            gcc_version=$2
            shift 2
            ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

PLAT_FORM_STR=$(sh "${ROOT_DIR}/build/get_PlatForm_str.sh")
if [ "${PLAT_FORM_STR}"x == "Failed"x ]; then
    echo "We only support openEuler(aarch64), EulerOS(aarch64), FusionOS, CentOS, UOS, H3Linux, NingOS platform."
    exit 1;
fi

PLATFORM=32
bit=$(getconf LONG_BIT)
if [ "$bit" -eq 64 ]; then
    PLATFORM=64
fi

if [ X$(echo $PLAT_FORM_STR | grep "centos") != X"" ]; then
    dist_version="CentOS"
elif [ X$(echo $PLAT_FORM_STR | grep "openeuler") != X"" ]; then
    dist_version="openEuler"
elif [ X$(echo $PLAT_FORM_STR | grep "fusionos") != X"" ]; then
    dist_version="FusionOS"
elif [ X$(echo $PLAT_FORM_STR | grep "euleros") != X"" ]; then
    dist_version="EulerOS"
elif [ X$(echo $PLAT_FORM_STR | grep "ubuntu") != X"" ]; then
    dist_version="Ubuntu"
elif [ X$(echo $PLAT_FORM_STR | grep "asianux") != X"" ]; then
    dist_version="Asianux"
elif [ X$(echo $PLAT_FORM_STR | grep "kylin") != X"" ]; then
    dist_version="Kylin"
elif [ X$(echo $PLAT_FORM_STR | grep "uos") != X"" ]; then
    dist_version="UOS"
elif [ X$(echo $PLAT_FORM_STR | grep "h3linux") != X"" ]; then
    dist_version="H3Linux"
elif [ X$(echo $PLAT_FORM_STR | grep "ningos") != X"" ]; then
    dist_version="NingOS"
else
    echo "We only support openEuler(aarch64), EulerOS(aarch64), FusionOS, CentOS, Ubuntu(x86), UOS, H3Linux, NingOS platform."
    echo "Kernel is $kernel"
    exit 1
fi
os_version=$(cat /etc/os-release | grep -w VERSION_ID | awk -F '"' '{print $2}')

PLATFORM_ARCH=$(uname -p)
declare package_pre_name="${version_string}-${dist_version}${os_version}-${PLATFORM_ARCH}"
declare package_name="${package_pre_name}.tar.gz"
declare sha256_name="${package_pre_name}.sha256"

if [ ${binarylib_dir} != 'None' ] && [ -d ${binarylib_dir} ]; then
    BINARYLIBS_PATH_INSTALL_TOOLS="${binarylib_dir}/install_tools"
    BINARYLIBS_PATH="${binarylib_dir}/kernel/dependency/"
    BUILD_TOOLS_PATH="${binarylib_dir}/buildtools/"
else
    BINARYLIBS_PATH_INSTALL_TOOLS="${ROOT_DIR}/install_tools"
    BINARYLIBS_PATH="${ROOT_DIR}/binarylibs/kernel/dependency/"
    BUILD_TOOLS_PATH="${ROOT_DIR}/binarylibs/buildtools/"
fi

log()
{
    echo "[makegaussdb] $(date +%y-%m-%d' '%T): $@"
    echo "[makegaussdb] $(date +%y-%m-%d' '%T): $@" >> "$LOG_FILE" 2>&1
}

die()
{
    log "$@"
    echo "$@"
    exit $ERR_MKGS_FAILED
}

function env_check()
{
    if [ -d "$PKG_DIR" ]; then
        rm -rf ${PKG_DIR}
    fi
    mkdir -p ${PKG_TMP_DIR}
    if [ -d "$LOG_FILE" ]; then
        rm -rf $LOG_FILE
    fi
    if [ $? -eq 0 ]; then
        echo "Everything is ready."
    else
        echo "clean enviroment failed."
        exit 1
    fi
}

function copy_script_file()
{    
    cp -rf $ROOT_DIR/script $PKG_TMP_DIR/ &&
    if [ -f $PKG_TMP_DIR/script/gspylib/common/py_pstree.py ]; then
        mv $PKG_TMP_DIR/script/gspylib/common/py_pstree.py $PKG_TMP_DIR/script/py_pstree.py
    fi
    cp -rf $ROOT_DIR/other/transfer.py $PKG_TMP_DIR/script/ &&
    find $PKG_TMP_DIR/script/ -type f -print0 | xargs -0 -n 10 -r dos2unix > /dev/null 2>&1 &&
    find $PKG_TMP_DIR/script/gspylib/inspection/ -name d2utmp* -print0 | xargs -0 rm -rf &&
    if [ $? -ne 0 ]; then
        die "cp -r $ROOT_DIR/script $PKG_TMP_DIR failed "
    fi
    chmod -R +x $PKG_TMP_DIR/script/   
}

function version_cfg()
{
    gitversion=$(git log | grep commit | head -1 | awk '{print $2}' | cut -b 1-8)
    commits=$(git log | grep "See in merge request" | wc -l)
    mrid=$(git log | grep "See in merge request" | head -1 | awk -F! '{print $2}' | grep -o '[0-9]\+')
    om_version="(openGauss OM ${version_number} build $gitversion) compiled at `date -d today +\"%Y-%m-%d %H:%M:%S\"` commit $commits last mr $mrid"
    version_file=${PKG_TMP_DIR}/version.cfg
    touch ${version_file}
    echo "${module_name}-${version_number}">${version_file}
    echo "${version_Kernel}" >>${version_file}
    echo "${gitversion}" >>${version_file}

    if [ -f ${PKG_TMP_DIR}/script/domain_utils/cluster_file/version_info.py ] ; then
        sed -i -e "s/COMMON_VERSION = \"Gauss200 OM VERSION\"/COMMON_VERSION = \"$(echo ${om_version})\"/g" ${PKG_TMP_DIR}/script/domain_utils/cluster_file/version_info.py
        if [ $? -ne 0 ]; then
            die "Failed to replace OM tools version number."
        fi
    else
        sed -i "s/COMMON_VERSION = \"Gauss200 OM VERSION\"/COMMON_VERSION = \"$(echo ${om_version})\"/g" ${PKG_TMP_DIR}/script/gspylib/os/gsOSlib.py
        if [ $? -ne 0 ]; then
            die "Failed to replace OM tools version number."
        fi
    fi
}

function clib_copy()
{
    rm -rf $PKG_TMP_DIR/script/gspylib/clib
    mkdir -p $PKG_TMP_DIR/script/gspylib/clib
    cp $BUILD_TOOLS_PATH/gcc${gcc_version}/gcc/lib64/libstdc++.so.6 $PKG_TMP_DIR/script/gspylib/clib
    cp $BINARYLIBS_PATH/openssl/comm/lib/libssl.so.1.1 $PKG_TMP_DIR/script/gspylib/clib
    cp $BINARYLIBS_PATH/openssl/comm/lib/libcrypto.so.1.1 $PKG_TMP_DIR/script/gspylib/clib
    if [ -f $BINARYLIBS_PATH_INSTALL_TOOLS/libpython3.*m.so.1.0 ]
    then
        cp $BINARYLIBS_PATH_INSTALL_TOOLS/libpython3.*m.so.1.0 $PKG_TMP_DIR/script/gspylib/clib
    fi
    #cp $BUILD_DIR/bin/encrypt $BUILD_DIR/script/gspylib/clib
}

function lib_copy()
{
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/output/log
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/output/nodes
    mkdir -p ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/asn1crypto           ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/bcrypt               ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/cffi                 ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/cryptography         ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/idna                 ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/nacl                 ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/pyasn1               ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/pycparser            ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/OpenSSL              ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/ipaddress.py         ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/six.py               ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/_cffi_backend.py     ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/_cffi_backend.so*    ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/_cffi_backend_*      ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/paramiko             ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/psutil               ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/netifaces            ${PKG_TMP_DIR}/lib

    if [ -d "${BINARYLIBS_PATH_INSTALL_TOOLS}/psycopg2" ]; then
        cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/psycopg2    ${PKG_TMP_DIR}/lib
    fi

}

function main()
{
    # 1. clean install path and log file
    env_check

    # 2. copy script file
    copy_script_file

    # 3. copy clib file    
    clib_copy

    # 4. copy lib file
    lib_copy

    # 5. make version file    
    version_cfg
    
    cd $PKG_TMP_DIR
    tar -zvcf "${package_name}" ./* >>"$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        die "$package_command ${package_name} failed"
    fi
    
    sha256sum "${package_name}" | awk -F" " '{print $1}' > "$sha256_name"
    if [ $? -ne 0 ]; then
        die "generate sha256 file failed."
    fi
    mv $package_name $sha256_name ../
    cd $PKG_DIR
    rm -rf $PKG_TMP_DIR
    echo "success!"
}

main
exit 0

