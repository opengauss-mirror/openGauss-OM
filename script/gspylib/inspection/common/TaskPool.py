# -*- coding:utf-8 -*-
#############################################################################
import sys
import os
import signal
import threading
from queue import Queue
from gspylib.inspection.common.Exception import InterruptException


class TaskThread(threading.Thread):
    def __init__(self, queWork, queResult, iTimeout):
        """
        function: constructor
        """
        threading.Thread.__init__(self)
        # timeout for fetching task
        self.m_iTimeout = iTimeout
        self.m_bRunning = True
        self.setDaemon(True)
        self.m_queWork = queWork
        self.m_queResult = queResult
        self.start()

    def run(self):
        """
        function: run method
        input  : NA
        output : NA
        """
        while self.m_bRunning:
            if Queue is None:
                break
            try:
                # fetch a task from the queue,
                # here timout parameter MUST be asigned,
                # otherwise get() will wait for ever
                callableFun, args = self.m_queWork.get(timeout=self.m_iTimeout)
                # run the task
                Ret = callableFun(args[0])
                self.m_queResult.put(Ret)
            # if task queue is empty
            except Exception:
                self.m_bRunning = False
                continue


class Watcher:
    """
    this class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug).

    The watcher is a concurrent process (not thread) that
    waits for a signal and the process that contains the
    threads.
    """

    def __init__(self):
        """
        Creates a child thread, which returns.
        The parent thread waits for a KeyboardInterrupt
        and then kills the child thread.
        """
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        """
        function: watch
        input  : NA
        output : NA
        """
        try:
            os.wait()
        except KeyboardInterrupt:
            # I put the capital B in KeyBoardInterrupt so I can
            # tell when the Watcher gets the SIGINT
            self.kill()
            raise InterruptException()
        sys.exit()

    def kill(self):
        """
        function: kill
        input  : NA
        output : NA
        """
        os.kill(self.child, signal.SIGKILL)


class CheckThread(threading.Thread):
    def __init__(self, name, func, *args):
        """
        function: constructor
        """
        super(CheckThread, self).__init__(name=name, target=func, args=args)
        self._stop_event = threading.Event()
        self.setDaemon(True)
        self.exitcode = 0
        self.exception = None
        self.name = name
        self.func = func
        self.args = args
        self.start()

    def run(self):
        """
        function: run
        input  : NA
        output : NA
        """
        try:
            self.func(*self.args)
        except Exception as e:
            self.exitcode = 1
            self.exception = e

    def stop(self):
        """
        function: stop
        input  : NA
        output : NA
        """
        self._stop_event.set()

    def stopped(self):
        """
        function: stopped
        input  : NA
        output : NA
        """
        return self._stop_event.is_set()
