# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2023 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : Provides a series of methods for dialogue, question and input.
#############################################################################

import os
from gspylib.common.GaussLog import GaussLog


class DialogError(Exception):
    def __init__(self, complete_question, msg):
        self.complete_question = complete_question
        self.msg = msg

    def __str__(self):
        return self.msg


class DialogUtil(object):
    """
    Provides a set of interfaces for dialogue and interactive questioning.

    Each interface has its own label.

    If it is a question, you can select whether it is required, and the
    required question will be marked with an '*'.
    """
    @staticmethod
    def Message(message):
        """
        :param message: message
        :return: NA
        """
        complete_message = f'[ Message ] {message}\n'
        GaussLog.printMessage(complete_message)

    @staticmethod
    def yesOrNot(question, required=True, max_retry=99999):
        """
        raise a question, and want a yes or not.

        example:
            *[ yesOrNot ] Am I handsome? (y/n)? y

        :param question: question
        :param required: must input something. if not, we can return None
        :param max_retry: max retry times
        :return: True, False, None
        """
        question_tag = '{0}[ yesOrNot ]'.format('*' if required else '')
        complete_question = '{0} {1}(y/n)? '.format(
            question_tag, question
        )
        answer = input(complete_question)
        while True:
            if not required and answer == '':
                return

            if answer.lower() in ('y', 'n'):
                return answer.lower() == 'y'

            max_retry -= 1
            if max_retry < 0:
                raise DialogError(complete_question, 'Too many failed retry.')

            answer = input('Please input y or n: ')

    @staticmethod
    def singleAnswerQuestion(question, options, required=True, max_retry=99999):
        """
        raise a question, and want an option.

        example:
            *[ Single Answer Question ] What would you like for dinner?
                A. carrot
                B. rice
                C. chicken
            Single answer: a

        :param question: question
        :param options: options to choose.
        :param required: must input something. if not, we can return None
        :param max_retry: max retry times
        :return: the index of option which user choose, or None
        """
        assert len(options) <= 26
        question_tag = '{0}[ Single Answer Question '.format('*' if required else '')
        code_id = [chr(c) for c in range(ord('A'), ord('A') + len(options))]
        question_options = ''
        for i, option in enumerate(options):
            question_options += '  {0}. {1}\n'.format(code_id[i], option)

        complete_question = "{0} {1}\n{2}Single answer: ".format(
            question_tag, question, question_options)
        answer = input(complete_question)
        while True:
            if not required and answer == '':
                return
            if answer.upper() in code_id:
                return code_id.index(answer.upper())

            max_retry -= 1
            if max_retry < 0:
                raise DialogError(complete_question, 'Too many failed retry.')

            answer = input('Please input A~{}:'.format(code_id[-1]))

    @staticmethod
    def multipleAnswerQuestion(question, options, required=True, max_retry=99999):
        """
        raise a question, and want an option.

        example:
            *[ Multiple Answer Question ] What would you like for dinner?
                A. carrot
                B. rice
                C. chicken
            Multiple answer: ac

        :param question: question
        :param options: options to choose
        :param required: must input something. if not, we can return None
        :param max_retry: max retry times
        :return: the index list of option which user choose, or []
        """
        assert len(options) <= 26
        code_id = [chr(c) for c in range(ord('A'), ord('A') + len(options))]
        question_options = ''
        for i, option in enumerate(options):
            question_options += ' {0}. {1} \n'.format(code_id[i], option)
        complete_question = "{0}[ Multiple Answer Question ] {1}\n{2}Multiple answer: ".format(
            '*' if required else '', question, question_options)

        def _analyse_answer(_answer):
            _chosen = set()
            for c in _answer:
                if c == ' ' or c == '\t' or c == ',':
                    continue
                if c.upper() not in code_id:
                    GaussLog.printMessage(f'Invalid select code: {c}.', end='')
                    return
                _chosen.add(ord(c.upper()) - ord('A'))
            _res = list(_chosen)
            _res.sort()
            if required and len(_res) == 0:
                GaussLog.printMessage('Please make at least one choice.')
                return

            return _res

        answer = input(complete_question)
        while True:
            res = _analyse_answer(answer)
            if res is not None:
                return res

            max_retry -= 1
            if max_retry < 0:
                raise DialogError(complete_question, 'Too many failed retry.')

            answer = input('Please input A~{}:'.format(code_id[-1]))

    @staticmethod
    def askANumber(question, check_func=None, required=True, max_retry=99999):
        """
        ask a number.

        for example:
            *[ Input number ] How old are you?
            Please answer: 1000

        :param question: question
        :param check_func: Verify that the number entered is legitimate. Otherwise, return an error msg
        :param required: must input something. if not, we can return None
        :param max_retry: max retry times
        :return: the number, or None
        """
        complete_question = '{0}[ Input number ] {1}\nPlease answer: '.format(
            '*' if required else '', question
        )
        answer = input(complete_question)
        while True:
            retry_msg = None
            if not required and answer == '':
                return

            if not answer.isdigit():
                retry_msg = 'Invalid integer, please again: '
            elif check_func is not None:
                errmsg = check_func(int(answer))
                if errmsg is None:
                    return int(answer)
                retry_msg = f'{errmsg}. please again: '
            else:
                return int(answer)

            max_retry -= 1
            if max_retry < 0:
                raise DialogError(complete_question, 'Too many failed retry.')

            answer = input(retry_msg)

    @staticmethod
    def askAPath(question, check_access=None, required=True, max_retry=99999):
        """
        ask a path.

        for example:
            *[ Input path ] Where is the file?
            Please input the path: /home/user/abc

        :param question: question
        :param check_access: check the path is access.
        :param required: must input something. if not, we can return None
        :param max_retry: max retry times
        :return: the path, or None
        """
        complete_question = '{0}[ Input path ] {1} \nPlease input the path: '.format(
            '*' if required else '', question
        )
        answer = input(complete_question)
        while True:
            retry_msg = None
            if not required and answer == '':
                return

            if check_access and not os.access(answer, os.F_OK):
                retry_msg = 'Could not access path, please again: '
            else:
                return answer

            max_retry -= 1
            if max_retry < 0:
                raise DialogError(complete_question, 'Too many failed retry.')

            answer = input(retry_msg)


if __name__ == '__main__':
    res = DialogUtil.multipleAnswerQuestion(
        'test question',
        ['x', 'xx', 'xxx']
    )
    GaussLog.printMessage(res)

