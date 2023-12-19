action=$1
xlog_old=$2
xlog_new=$3


function isolated
{
  mv $xlog_old $xlog_new  # mv not change owner and mod
  ln -s $xlog_new $xlog_old
}

function recover
{
  rm $xlog_old
  mv $xlog_new $xlog_old   # mv not change owner and mod
}

if [ "$action" = "isolated" ]; then
    isolated
elif [ "$action" = "recover" ]; then
    recover
else
    echo 'unknown action', $action
    exit 1
fi