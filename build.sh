#!/bin/bash

declare binarylib_dir='None'
declare module_name="openGauss"
declare version_number='1.1.0'
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
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

PLAT_FORM_STR=$(sh "${ROOT_DIR}/build/get_PlatForm_str.sh")
if [ "${PLAT_FORM_STR}"x == "Failed"x ]; then
    echo "We only support openEuler(aarch64), EulerOS(aarch64), CentOS platform."
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
elif [ X$(echo $PLAT_FORM_STR | grep "euleros") != X"" ]; then
    dist_version="EulerOS"
else
    echo "We only support openEuler(aarch64), EulerOS(aarch64), CentOS platform."
    echo "Kernel is $kernel"
    exit 1
fi

declare package_pre_name="${version_string}-${dist_version}-${PLATFORM}bit-om"
declare package_name="${package_pre_name}.tar.gz"
declare sha256_name="${package_pre_name}.sha256"

if [ ${binarylib_dir} != 'None' ] && [ -d ${binarylib_dir} ]; then
    BINARYLIBS_PATH="${binarylib_dir}/dependency/${PLAT_FORM_STR}"
    BUILD_TOOLS_PATH="${binarylib_dir}/buildtools/${PLAT_FORM_STR}"
    BINARYLIBS_PATH_INSTALL_TOOLS="${binarylib_dir}/dependency/install_tools_${PLAT_FORM_STR}"
else
    BINARYLIBS_PATH="${ROOT_DIR}/binarylibs/dependency/${PLAT_FORM_STR}"
    BUILD_TOOLS_PATH="${ROOT_DIR}/binarylibs/buildtools/${PLAT_FORM_STR}"
    BINARYLIBS_PATH_INSTALL_TOOLS="${ROOT_DIR}/dependency/install_tools_${PLAT_FORM_STR}"	
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
    cp -rf $ROOT_DIR/other/transfer.py $PKG_TMP_DIR/script/ &&
    find $PKG_TMP_DIR/script/ -type f -print0 | xargs -0 -n 10 -r dos2unix > /dev/null 2>&1 &&
    find $PKG_TMP_DIR/script/gspylib/inspection/ -name d2utmp* -print0 | xargs -0 rm -rf &&
    cp -rf $ROOT_DIR/script/gspylib/inspection/lib/checknetspeed/speed_test* $PKG_TMP_DIR/script/gspylib/inspection/lib/checknetspeed/ &&
    if [ $? -ne 0 ]; then
        die "cp -r $ROOT_DIR/script $PKG_TMP_DIR failed "
    fi
    chmod -R +x $PKG_TMP_DIR/script/
    
    cp -rf $ROOT_DIR/simpleInstall $PKG_TMP_DIR/
    if [ $? -ne 0 ]; then
        die "cp -r $ROOT_DIR/simpleInstall $PKG_TMP_DIR/ failed "
    fi    
}

function version_cfg()
{
    gitversion=$(git log | grep commit | head -1 | awk '{print $2}' | cut -b 1-8)
    commits=$(git log | grep "See in merge request" | wc -l)
    mrid=$(git log | grep "See in merge request" | head -1 | awk -F! '{print $2}' | grep -o '[0-9]\+')
    om_version="(openGauss OM 1.1.0 build $gitversion) compiled at `date -d today +\"%Y-%m-%d %H:%M:%S\"` commit $commits last mr $mrid"
    version_file=${PKG_TMP_DIR}/version.cfg
    touch ${version_file}
    echo "${module_name}-${version_number}">${version_file}
    echo "${version_Kernel}" >>${version_file}
    echo "${gitversion}" >>${version_file}

    if [ -f ${PKG_TMP_DIR}/script/gspylib/common/VersionInfo.py ] ; then
        sed -i -e "s/COMMON_VERSION = \"Gauss200 OM VERSION\"/COMMON_VERSION = \"$(echo ${om_version})\"/g" -e "s/__GAUSS_PRODUCT_STRING__/$module_name/g" ${PKG_TMP_DIR}/script/gspylib/common/VersionInfo.py
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
    cp $BUILD_TOOLS_PATH/gcc7.3/gcc/lib64/libstdc++.so.6 $PKG_TMP_DIR/script/gspylib/clib
    cp $BINARYLIBS_PATH/openssl/comm/lib/libssl.so.1.1 $PKG_TMP_DIR/script/gspylib/clib
    cp $BINARYLIBS_PATH/openssl/comm/lib/libcrypto.so.1.1 $PKG_TMP_DIR/script/gspylib/clib
    #cp $BUILD_DIR/bin/encrypt $BUILD_DIR/script/gspylib/clib
}

function lib_copy()
{
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/output/log/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/output/nodes/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/asn1crypto/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/bcrypt/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/cffi/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/cryptography/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/idna/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/nacl/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/pyasn1/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/pycparser/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/OpenSSL/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/psutil/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/netifaces/ &&
    mkdir -p ${PKG_TMP_DIR}/script/gspylib/inspection/lib/paramiko/ &&

    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/asn1crypto/       ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/bcrypt/           ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/cffi/             ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/cryptography/     ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/idna/             ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/nacl/             ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/pyasn1/           ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/pycparser/        ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/OpenSSL/          ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/ipaddress.py      ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/six.py            ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/_cffi_backend.py  ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/_cffi_backend.so* ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/psutil/           ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/netifaces/        ${PKG_TMP_DIR}/script/gspylib/inspection/lib/
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/paramiko/         ${PKG_TMP_DIR}/script/gspylib/inspection/lib/

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
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/paramiko             ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/psutil               ${PKG_TMP_DIR}/lib
    cp -rf ${BINARYLIBS_PATH_INSTALL_TOOLS}/netifaces            ${PKG_TMP_DIR}/lib
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