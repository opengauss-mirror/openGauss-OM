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
    sed -i "s/SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
    return 0
}

function fn_precheck()
{
    system_arch=`uname -p`
    system_name=`cat /etc/os-release | grep '^ID=".*' | grep -o -E '(openEuler|centos)'`
    total=0
    python3 --version >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        echo "You need install python3 or create the correct soft connection."
        return 1
    fi
    cat requirements_"$system_name"_"$system_arch" | while read line
    do
        if [ "$line"x == ""x ]
        then
            continue
        fi
        yum list installed | grep $line > result.log
        num=`wc -l result.log | awk '{print $1}'`
        if [ $num -eq 0 ]
        then
            echo "You need to install $line" > preCheck.log
            total=`expr $total + 1`
        fi
        echo $total>>tmp_total
    done < requirements_"$system_name"_"$system_arch"
    total=$(tail -n 1 tmp_total)
    if [ $total -gt 0 ]
    then
        rm -rf result.log tmp_total
        return 1
    fi
    rm -rf result.log tmp_total
    return 0
}

COMMON_SH="common.sh"
