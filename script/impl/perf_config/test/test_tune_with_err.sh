
mv $GAUSSHOME/bin/gs_guc $GAUSSHOME/bin/gs_guc_bak

# user with env
python3 gs_perfconfig tune -t all --apply


mv $GAUSSHOME/bin/gs_guc_bak $GAUSSHOME/bin/gs_guc


