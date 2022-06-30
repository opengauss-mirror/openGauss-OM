if [ "$COMMON_SH" ]; then
    return;
fi

function fn_create_user()
{
    user_name=$1
    user_grp=$2
    groupadd $user_grp 2>/dev/null
    egrep "^$user_name" /etc/passwd >& /dev/null
    if [ $? -ne 0 ]
    then
        useradd -g $user_grp -d /home/$user_name -m -s /bin/bash $user_name 2>/dev/null
        echo "enter password for user " $user_name
        passwd $user_name
        echo "create user success."
    else
        echo "user has already exists."
    fi
    
    return 0
}

function fn_check_firewall()
{
    host_port=$1
    firewall-cmd --permanent --add-port="$host_port/tcp"
    firewall-cmd --reload
    return 0
}

function fn_selinux()
{
    system_name=`cat /etc/os-release | grep '^ID=.*' | grep -o -E '(openEuler|centos|ubuntu)'`
    if [ "$system_name"X == "openEuler"X ] || [ "$system_name"X == "centos"X ]
    then
        sed -i "s/SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
    fi
    return 0
}

function fn_precheck()
{
    system_arch=`uname -p`
    system_name=`cat /etc/os-release | grep '^ID=.*' | grep -o -E '(openEuler|centos|ubuntu)'`
    total=0
    python3 --version >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        echo "You need install python3 or create the correct soft connection."
        return 1
    fi
    while read line
    do
        if [ "$line"x == ""x ]
        then
            continue
        fi
        
        if [ "$system_name"X == "openEuler"X ] || [ "$system_name"X == "centos"X ]
        then
            yum list installed | grep $line >/dev/null
        elif [ "$system_name"X == "ubuntu"X ]
        then
            apt list --installed 2>/dev/null | grep $line >/dev/null
        else
            echo "We only support CentOS, openEuler and Ubuntu by now."
            return 1
        fi

        if [ $? -ne 0 ]
        then
            total=`expr $total + 1`
            if [ $total -eq 1 ]
            then
                echo "You need to install: " > preCheck.log
            fi
            echo "$line" >> preCheck.log
        fi
    done < requirements_"$system_name"_"$system_arch"
    if [ $total -gt 0 ]
    then
        return 1
    fi
    return 0
}

function fn_check_files_exist()
{
    files_list=($1)
    check_path=$2

    for i in $(seq 0 $[${#files_list[*]}-1])
    do
        check_file=${files_list[i]}
        if [ ! -f "$check_path/$check_file" ]
        then
            return 1
        fi
    done
    return 0
}

function fn_print_array()
{
    array=($1)
    for i in $(seq 0 $[${#array[*]}-1])
    do
        echo ${array[i]}
    done
    return 0
}

function fn_copy_files()
{
    files_list=($1)
    src_path=$2
    dst_path=$3

    for i in $(seq 0 $[${#files_list[*]}-1])
    do
        target_file=${files_list[i]}
        cp $src_path/$target_file $dst_path
        if [ $? -ne 0 ]
        then
            return 1
        fi
    done
    return 0
}

COMMON_SH="common.sh"
