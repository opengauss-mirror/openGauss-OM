export GAUSSHOME=''
export GAUSSLOG=''
export PGDATA=''
vim /home/carrot/test.source   # GAUSSHOME  GAUSSLOG PGDATA.  gs_om env

# root
python3 gs_perfconfig tune
python3 gs_perfconfig tune -t os,guc,os
python3 gs_perfconfig tune -t all
python3 gs_perfconfig tune -t os,guc,os --apply
python3 gs_perfconfig tune -t all --apply
python3 gs_perfconfig tune -t os,guc,os --apply -y
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source -y
python3 gs_perfconfig tune --apply
python3 gs_perfconfig tune --apply --env /home/carrot/test.source


# user
python3 gs_perfconfig tune
python3 gs_perfconfig tune -t os
python3 gs_perfconfig tune -t os,guc,os
python3 gs_perfconfig tune -t all
python3 gs_perfconfig tune -t os,guc,os --apply
python3 gs_perfconfig tune -t all --apply
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source
python3 gs_perfconfig tune --apply -y
python3 gs_perfconfig tune --apply --env /home/carrot/test.source -y


# mix
# root
python3 gs_perfconfig tune
# user
python3 gs_perfconfig tune -t os
# root
python3 gs_perfconfig tune -t os,guc,os
# user
python3 gs_perfconfig tune -t all
# root
python3 gs_perfconfig tune -t os,guc,os --apply
# user
python3 gs_perfconfig tune -t all --apply
# root
python3 gs_perfconfig tune -t os,guc,os --apply --env /home/carrot/test.source -y
# user
python3 gs_perfconfig tune -t all --apply --env /home/carrot/test.source -y
# root
python3 gs_perfconfig tune --apply -y
# user
python3 gs_perfconfig tune --apply --env /home/carrot/test.source -y



