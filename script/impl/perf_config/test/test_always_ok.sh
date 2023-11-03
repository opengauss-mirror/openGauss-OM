
# user
export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=on'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=off'
python3 gs_perfconfig tune --apply
# x x n

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=0'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=1'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=true'
python3 gs_perfconfig tune --apply
# a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=false'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=xxx'
python3 gs_perfconfig tune --apply
# x x y a

export GS_PEPRFCONFIG_OPTIONS='always_choose_yes=ON'
python3 gs_perfconfig tune --apply
# x x y a