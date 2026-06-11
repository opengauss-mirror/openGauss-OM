#!/bin/bash

# `sh install.sh` may invoke bash in POSIX mode where process substitution is unsupported.
if [ -z "${BASH_VERSION:-}" ] || shopt -q posix 2>/dev/null
then
    if command -v bash >/dev/null 2>&1
    then
        exec bash "$0" "$@"
    fi
    echo "This script requires bash. Please run: bash $0 ..." >&2
    exit 1
fi

readonly cur_path=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd && cd - &>/dev/null)
readonly version="7.0.0-RC3"

source $cur_path"/common.sh"

function fn_print_help()
{
    echo "Usage: $0 [OPTION]
    -?|--help                         show help information
    -U|--user_name                    cluster user
    -G|--user_grp                     group of the cluster user
    -h|--host_ip                      intranet IP address of the host in the backend storage network
    -p|--port                         database server port
    -D|--install_location             installation directory of the openGauss program
    "
}

function fn_get_param()
{
    fn_prase_input_param $@
    host_name=`hostname -f`
    system_arch=`uname -p`
    system_name=`cat /etc/os-release | grep '^ID=.*' | grep -o -E '(openEuler|centos|ubuntu)'`
    install_tar="/home/$user_name/openGaussTar"     #安装包所在路径(可修改)
    if [ ! $install_location ]
    then
        install_location="/opt/$user_name"          #数据库安装位置(可修改)
    fi
    echo "install_location: $install_location"
    echo "install_tar: $install_tar"
}

function fn_prase_input_param()
{
    while [ $# -gt 0 ]; do
        case $1 in
            -\?|--help )
                fn_print_help
                exit 1
                ;;
            -U|--user_name )
                fn_check_param user_name $2
                user_name=$2
                shift 2
                ;;
            -G|--user_grp )
                fn_check_param user_grp $2
                user_grp=$2
                shift 2
                ;;
            -h|--host_ip )
                fn_check_param host_ip $2
                host_ip=$2
                shift 2
                ;;
            -p|--port )
                fn_check_param port $2
                host_port=$2
                shift 2
                ;;
            -D|--install_location )
                fn_check_param install_location $2
                install_location=$2
                shift 2
                ;;
            * )
                echo "Please input right paramtenter, the following command may help you"
                echo "sh install.sh --help or sh install.sh -?"
                exit 1
        esac
    done
}

function fn_check_param()
{
    if [ "$2"X = X ]
    then
        echo "no given $1, the following command may help you"
        echo "sh install.sh --help or sh install.sh -?"
        exit 1
    fi
}

function fn_prepare_secure_install_tar()
{
    if [ `id -u` -ne 0 ]
    then
        echo "Only root can prepare the install package directory." >&2
        return 1
    fi
    if [ -L "$install_tar" ]
    then
        echo "Install package path must not be a symbolic link: $install_tar" >&2
        return 1
    fi
    case "$install_tar" in
        "/home/$user_name"/*) ;;
        *)
            echo "Install package path must be under /home/$user_name: $install_tar" >&2
            return 1
            ;;
    esac
    mkdir -p "$install_tar" || return 1
    find "$install_tar" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
    chown root:root "$install_tar"
    chmod 755 "$install_tar"
    return 0
}

function fn_harden_package_tree()
{
    local dir="$1"

    if [ ! -d "$dir" ]
    then
        return 1
    fi
    if find "$dir" -type l -print -quit 2>/dev/null | grep -q .
    then
        echo "Refusing to harden tree with symbolic link under $dir" >&2
        return 1
    fi
    chown root:root "$dir"
    chmod 755 "$dir"
    find "$dir" -type d -exec chown root:root {} \; -exec chmod 755 {} \; 2>/dev/null
    find "$dir" -type f -exec chown root:root {} \; -exec chmod 644 {} \; 2>/dev/null
    return 0
}

function fn_assert_install_packages_trusted()
{
    local pkg
    for pkg in "$@"
    do
        fn_assert_package_file_trusted "$install_tar/$pkg" || return 1
    done
    return 0
}

function fn_get_openGauss_tar()
{
    package_arch=`uname -p`
    os_version=`cat /etc/os-release | grep -w VERSION_ID | awk -F '"' '{print $2}'`
    if [ "$system_name"X == "openEuler"X ] && [ "$package_arch"X == "aarch64"X ]
    then
        system_arch="arm"
    elif [ "$system_name"X == "openEuler"X ] && [ "$package_arch"X == "x86_64"X ]
    then
        system_arch="x86"
    elif [ "$system_name"X == "centos"X ] && [ "$package_arch"X == "x86_64"X ]
    then
        system_name="CentOS"
        system_arch="x86"
    elif [ "$system_name"X == "ubuntu"X ] && [ "$package_arch"X == "x86_64"X ]
    then
        system_name="Ubuntu"
        system_arch="x86"
    else
        echo "We only support CentOS+x86, openEuler+arm, openEuler+x86 and Ubuntu+x86 by now."
        return 1
    fi

    system_os_name="${system_name}${os_version}"
    package_pre_name="${version}-${system_os_name}-${package_arch}"
    all_tar_name="openGauss-All-${package_pre_name}.tar.gz"

    necessary_files=(
    "openGauss-OM-${package_pre_name}.tar.gz"
    "openGauss-OM-${package_pre_name}.sha256"
    "openGauss-Server-${package_pre_name}.sha256"
    "openGauss-Server-${package_pre_name}.tar.bz2"
    "upgrade_sql.sha256"
    "upgrade_sql.tar.gz"
    )

    fn_prepare_secure_install_tar
    if [ $? -ne 0 ]
    then
        return 1
    fi

    cd "$install_tar" || return 1

    if fn_check_files_exist "${necessary_files[*]}" "$cur_path/../"
    then
        fn_copy_files "${necessary_files[*]}" "$cur_path/.." "$install_tar"
        if [ $? -ne 0 ]
        then
            echo "copy Installation package error."
            return 1
        fi
        echo "copy Installation package success."
        fn_harden_package_tree "$install_tar"
        if [ $? -ne 0 ]
        then
            return 1
        fi
    elif [ "$system_name"X != "Ubuntu"X ]
    then
        url="https://opengauss.obs.cn-south-1.myhuaweicloud.com/${version}/${system_os_name}/${system_arch}/${all_tar_name}"
        echo "Downloading openGauss tar from official website at ${install_tar}"
        wget "$url" --timeout=30 --tries=3 -O "$install_tar/$all_tar_name"
        if [ $? -ne 0 ]
        then
            echo "wget error. The $install_tar need"
            fn_print_array "${necessary_files[*]}"
            return 1
        fi
        chown root:root "$install_tar/$all_tar_name"
        chmod 644 "$install_tar/$all_tar_name"
        fn_verify_tar_member_names "$install_tar/$all_tar_name"
        if [ $? -ne 0 ]
        then
            echo "Unsafe downloaded package member names."
            return 1
        fi
        tar -zxf "$install_tar/$all_tar_name" -C "$install_tar"
        if [ $? -ne 0 ]
        then
            echo "tar package error after download."
            return 1
        fi
        fn_harden_package_tree "$install_tar"
        if [ $? -ne 0 ]
        then
            return 1
        fi
        echo "wget success."
    else
        echo "Can not found openGauss install pkg. Place packages under $cur_path/.. or use a supported non-Ubuntu OS for download."
        fn_print_array "${necessary_files[*]}"
        return 1
    fi

    fn_assert_install_packages_trusted "${necessary_files[@]}"
    if [ $? -ne 0 ]
    then
        echo "Install package trust check failed."
        return 1
    fi

    fn_verify_sha256sums "$install_tar/openGauss-Server-${package_pre_name}.sha256" "$install_tar"
    if [ $? -ne 0 ]
    then
        return 1
    fi
    fn_verify_sha256sums "$install_tar/openGauss-OM-${package_pre_name}.sha256" "$install_tar"
    if [ $? -ne 0 ]
    then
        return 1
    fi
    fn_verify_sha256sums "$install_tar/upgrade_sql.sha256" "$install_tar"
    if [ $? -ne 0 ]
    then
        return 1
    fi

    return 0
}

function fn_create_file()
{
    echo "Preparing install directory, install_location: $install_location"

    # Must not be empty
    if [ -z "$install_location" ]; then
        echo "Error: install_location is empty."
        return 1
    fi

    # Must be an absolute path
    case "$install_location" in
        /*) ;;
        *)
            echo "Error: install_location must be an absolute path: $install_location"
            return 1
            ;;
    esac

    # Prevent path traversal
    case "$install_location" in
        *..*)
            echo "Error: install_location cannot contain path traversal characters: $install_location"
            return 1
            ;;
    esac

    # Normalize path: remove trailing slash to ensure consistent matching
    local clean_path="${install_location%/}"

    # Resolve real path to prevent symlink attacks (e.g., /home/user/link_to_etc -> /etc)
    # If the path doesn't exist yet, realpath might fail, but we still check the string
    local real_path=$(realpath -m "$clean_path" 2>/dev/null || echo "$clean_path")
    local path_rest

    echo "Resolved install path: $real_path"

    # Strict Whitelist: Only allow /opt/<subdir> or /home/<subdir>
    # This inherently blocks /etc, /var, /root, /usr, etc.
    case "$real_path" in
        /opt/*)
            path_rest="${real_path#/opt/}"
            ;;
        /home/*)
            path_rest="${real_path#/home/}"
            ;;
        *)
            echo "Error: install_location must be a subdirectory under /opt/ or /home/ (e.g., /opt/og): $real_path"
            return 1
            ;;
    esac
    if [ -z "$path_rest" ]
    then
        echo "Error: install_location must be a subdirectory under /opt/ or /home/ (e.g., /opt/og): $real_path"
        return 1
    fi

    # Blacklist critical system paths even under allowed prefixes (defense in depth)
    if [ "$real_path" = "/opt/system" ] || [ "$real_path" = "/home/root" ]
    then
        echo "Error: install_location cannot be a system reserved directory: $real_path"
        return 1
    fi

    # Reject existing non-empty directories to prevent recursive chmod/chown on arbitrary paths
    if [ -e "$real_path" ]; then
        if [ ! -d "$real_path" ]; then
            echo "Error: install_location exists but is not a directory: $real_path"
            return 1
        fi
        if [ -n "$(ls -A "$real_path" 2>/dev/null)" ]; then
            echo "Error: install_location already exists and is not empty: $real_path"
            echo "Use an empty directory, e.g.: sh install.sh ... -D /opt/${user_name}_new"
            echo "Or uninstall/clean the existing cluster data under $real_path before retry."
            return 1
        fi
    fi

    mkdir -p "$real_path"
    chmod -R 755 "$real_path"
    chown -R $user_name:$user_grp "$real_path"

    local install_location=${install_location//\//\\\/}

    if [ ! -e $cur_path/template.xml ]
    then
        echo "cannot find template.xml"
        return 1
    fi
    sed 's/@{host_name}/'$host_name'/g' $cur_path/template.xml | sed 's/@{host_ip}/'$host_ip'/g' | sed 's/@{user_name}/'$user_name'/g' | sed 's/@{host_port}/'$host_port'/g' | sed 's/@{install_location}/'$install_location'/g' > $cur_path/single.xml
    cp $cur_path/single.xml /home/$user_name/
    echo "create config file success, install_location: $real_path, xml: /home/$user_name/single.xml"
    return 0
}

function fn_post_check()
{
    fn_precheck
    if [ $? -ne 0 ]
    then
        echo "Precheck failed, you can check preCheck.log for more details."
        fn_precheck_result
        if [ $? -ne 0 ]
        then
            return 1
        fi
    else
        echo "Precheck success."
    fi
    fn_check_user
    if [ $? -ne 0 ]
    then
        echo "Check user failed."
        return 1
    else
        echo "Check user success."
    fi
    fn_check_input
    if [ $? -ne 0 ]
    then
        echo "Check input failed."
        return 1
    else
        echo "Check input success."
    fi
    fn_check_firewall $host_port
    if [ $? -ne 0 ]
    then
        echo "Check firewall failed."
        return 1
    else
        echo "Check firewall success."
    fi
    fn_selinux
    if [ $? -ne 0 ]
    then
        echo "Set selinux failed."
        return 1
    else
        echo "Set selinux success."
    fi
    return 0
}
function fn_precheck_result()
{
    input=$1
    if [ "$input"X = X ]
    then
        read -p "Are you sure you want to continue (yes/no)? " input
    fi
    if [ "$input"X == "yes"X ]
    then
        return 0
    elif [ "$input"X == "no"X ]
    then
        return 1
    else
        read -p "Please type 'yes' or 'no': " input
        fn_precheck_result $input
    fi
}

function fn_check_input()
{
    if [ ! "$user_name" -o ! "$user_grp" -o ! "$host_ip" -o ! "$host_port" ]
    then
        echo "Usage: sh install.sh -U user_name -G user_grp -h ip -p port"
        echo "The following command may help you"
        echo "sh install.sh --help or sh install.sh -?"
        return 1
    fi
    if [ "`netstat -anp | grep -w $host_port`" ]
    then 
        echo "port $host_port occupied, please choose another."
        return 1
    fi
    return 0
}

function fn_check_user()
{
    if [ `id -u` -ne 0 ]
    then
        echo "Only a user with the root permission can run this script."
        return 1
    fi
    return 0
}

function fn_verify_tar_member_names()
{
    local archive="$1"
    local member
    local err=0

    [ -f "$archive" ] || return 1

    while IFS= read -r member
    do
        [ -z "$member" ] && continue
        case "$member" in
            /*)
                echo "Unsafe tar member (absolute path): $member" >&2
                err=1
                break
                ;;
            ..|../*|*/..|*/../*)
                echo "Unsafe tar member (path traversal): $member" >&2
                err=1
                break
                ;;
        esac
    done <<EOF
$(tar -tzf "$archive" 2>/dev/null)
EOF
    [ "$err" -eq 0 ] || return 1
    return 0
}

function fn_assert_no_symlinks_under()
{
    local root="$1"

    if find "$root" -type l -print -quit 2>/dev/null | grep -q .; then
        echo "Unsafe install package: symbolic links are not allowed under $root" >&2
        return 1
    fi
    return 0
}

function fn_resolve_file_under()
{
    local base="$1"
    local relpath="$2"
    local base_real target_real part dir

    base_real=$(readlink -f "$base") || return 1
    dir="$base"
    for part in ${relpath//\// }; do
        [ -z "$part" ] && continue
        [ "$part" = "." ] && continue
        if [ -L "$dir/$part" ]; then
            echo "Unsafe path (symbolic link): $dir/$part" >&2
            return 1
        fi
        dir="$dir/$part"
    done
    [ -f "$dir" ] || return 1
    target_real=$(readlink -f "$dir") || return 1
    case "$target_real" in
        "$base_real"/*)
            echo "$target_real"
            return 0
            ;;
        *)
            echo "Unsafe path (outside install directory): $target_real" >&2
            return 1
            ;;
    esac
}

function fn_install()
{
    fn_tar
    if [ $? -ne 0 ]
    then
        echo "Get openGauss Installation package or tar package failed."
        return 1
    else
        echo "Get openGauss Installation package and tar package success."
    fi
    local preinstall_script
    preinstall_script=$(fn_resolve_file_under "${install_tar}" "script/gs_preinstall")
    if [ $? -ne 0 ] || [ -z "$preinstall_script" ]; then
        echo "Unsafe gs_preinstall path, aborting install."
        return 1
    fi
    export LD_LIBRARY_PATH="${install_tar}/script/gspylib/clib:"$LD_LIBRARY_PATH
    python3 "$preinstall_script" -U $user_name -G $user_grp -X '/home/'$user_name'/single.xml' --sep-env-file='/home/'$user_name'/env_single'
    if [ $? -ne 0 ]
    then
        echo "Preinstall failed."
        return 1
    else
        echo "Preinstall success."
    fi
    chmod 755 "/home/$user_name/single.xml"
    chown $user_name:$user_grp "/home/$user_name/single.xml"
    su - $user_name -c "source /home/$user_name/env_single;gs_install -X /home/$user_name/single.xml"
    if [ $? -ne 0 ]
    then
        echo "Install failed."
        return 1
    else
        echo "Install success."
    fi
    return 0
}

function fn_tar()
{
    fn_get_openGauss_tar
    if [ $? -ne 0 ]
    then
        echo "Get openGauss Installation package error."
        return 1
    else
        echo "Get openGauss Installation package success."
    fi

    local om_pkg="openGauss-OM-${package_pre_name}.tar.gz"
    cd "${install_tar}" || return 1
    fn_assert_package_file_trusted "$om_pkg"
    if [ $? -ne 0 ]
    then
        echo "OM package trust check failed."
        return 1
    fi
    fn_verify_tar_member_names "$om_pkg"
    if [ $? -ne 0 ]
    then
        echo "Unsafe OM package member names."
        return 1
    fi
    tar -zxf "$om_pkg"

    if [ $? -ne 0 ]
    then
        echo "tar package error."
        return 1
    else
        echo "tar package success."
    fi
    fn_assert_no_symlinks_under "${install_tar}"
    if [ $? -ne 0 ]
    then
        echo "Unsafe OM package content after extraction."
        return 1
    fi
    return 0
}

function fn_install_demoDB()
{
    input=$1
    if [ "$input"X = X ]
    then
        read -p "Would you like to create a demo database (yes/no)? " input
    fi
    if [ "$input"X == "yes"X ]
    then
        fn_load_demoDB 1>$cur_path/load.log 2>&1
        fn_check_demoDB
    elif [ "$input"X == "no"X ]
    then
        return 2
    else
        read -p "Please type 'yes' or 'no': " input
        fn_install_demoDB $input
    fi
    return $?
}

function fn_load_demoDB()
{
    cp $cur_path/{school.sql,finance.sql} /home/$user_name
    chown $user_name:$user_grp /home/$user_name/{school.sql,finance.sql}
    su - $user_name -c "
    source ~/env_single
    gsql -d postgres -p $host_port -f /home/$user_name/school.sql
    gsql -d postgres -p $host_port -f /home/$user_name/finance.sql
    "
}

function fn_check_demoDB()
{
    if [ "`cat $cur_path/load.log | grep ROLLBACK`" != "" ]
    then
        return 1
    elif [ "`cat $cur_path/load.log | grep '\[GAUSS-[0-9]*\]'`" != "" ]
    then
        return 1
    elif [ "`cat $cur_path/load.log | grep ERROR`" != "" ]
    then
        return 1
    elif [ "`cat $cur_path/load.log | grep Unknown`" != "" ]
    then
        return 1
    fi
    return 0
}

function main()
{
    fn_get_param $@

    fn_post_check
    if [ $? -ne 0 ]
    then
        echo "Post check failed."
        return 1
    else
        echo "Post check success."
    fi
    fn_create_user $user_name $user_grp
    if [ $? -ne 0 ]
    then
        echo "User test failed."
        return 1
    else
        echo "User test success."
    fi
    fn_create_file
    if [ $? -ne 0 ]
    then
        echo "Create file failed, install_location: $install_location"
        return 1
    else
        echo "Create file success."
    fi
    fn_install
    if [ $? -ne 0 ]
    then
        echo "Installation failed."
        return 1
    else
        echo "Installation success."
    fi
    fn_install_demoDB
    local returnFlag=$?
    if [ $returnFlag -eq 0 ]
    then
        echo "Load demoDB [school,finance] success."
    elif [ $returnFlag -eq 1 ]
    then
        echo "Load demoDB failed, you can check load.log for more details."
        return 1
    else
        echo "Input no, operation skip."
    fi
    return 0
}

main $@
exit $?

