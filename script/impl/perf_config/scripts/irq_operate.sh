function helper
{
echo '
RUN LIKE:
    sh irq_operate.sh bind enp1s1 "1 2 3 4 5 6"
    sh irq_operate.sh check enp1s1
    sh irq_operate.sh test enp1s1
'
}

action=$1
intf=$2
cpu_qrrqy_irq=($3)

function bind_irq
{
    cpunum=${#cpu_qrrqy_irq[*]}
    
    ethtool -L ${intf} combined $cpunum
    
    irq_list=`cat /proc/interrupts | grep $intf | awk {'print $1'} | tr -d ":"`
    irq_array_net=($irq_list)
    
    for (( i=0;i<$cpunum;i++ ))
    do
        echo "${cpu_array_irq[$i]}" > /proc/irq/${irq_array_net[$i]}/smp_affinity_list
    done
    
    for j in ${irq_array_net[@]}
    do
        cat /proc/irq/$j/smp_affinity_list
    done
}


function check_irq
{
    rx_irq_list=(`cat /proc/interrupts | grep ${intf} | awk -F':' '{print $1}'`)
    
    echo "check irf of net interface ${intf}"
    
    echo "rx"
    for rx_irq in ${rx_irq_list[@]}
    do
        echo `cat /proc/irq/$rx_irq/smp_affinity_list`
    done
}

function test_intf
{
    res=`cat /proc/interrupts | grep ${intf}`
    if [ "$res" = "" ]; then
        echo "The device ${intf} is not supported to bind irq."
        exit 1
    fi
    echo "ok"
}


if [ "$action" = "bind" ]; then
    bind_irq
elif [ "$action" = "check" ]; then
    check_irq
elif [ "$action" = "test" ]; then
    test_intf
else
    helper
    exit 0
fi
