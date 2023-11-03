
python3 gs_perfconfig recover
python3 gs_perfconfig recoveR

# err
python3 gs_perfconfig tune
python3 gs_perfconfig recover

# ok
python3 gs_perfconfig tune --apply
python3 gs_perfconfig recover


# root tune, user recover. err. because os.
python3 gs_perfconfig tune --apply
python3 gs_perfconfig recover



# use tune, root recover. ok
python3 gs_perfconfig tune --apply
python3 gs_perfconfig recover

