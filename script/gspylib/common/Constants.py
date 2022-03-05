from base_utils.common.constantsbase import ConstantsBase


class Constants(ConstantsBase):
    """common constants"""
    def __init__(self):
        pass

    __slots__ = ()

    SSH_PROTECT_PATH = "~/gaussdb_tmp/ssh_protect"
    TMP_HOSTS_FILE = "/tmp/tmp_hosts_%d"
