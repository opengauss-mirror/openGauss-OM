import re
from gspylib.common.ErrorCode import ErrorCode


class PasswordUtil:
    @staticmethod
    def checkPasswordVaild(password):
        """
        function: check password vaild
        input : password
        output: NA
        """
        # check if the password contains illegal characters
        res = re.search(r'^[A-Za-z0-9~!@#%^*$-_=+?,.:/]+$', password)
        if not res:
            raise Exception(ErrorCode.GAUSS_502['GAUSS_50219'] %
                            "the password" + " The password contains illegal "
                                             "characters.")
