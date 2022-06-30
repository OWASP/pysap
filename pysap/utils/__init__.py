# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Author:
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#

# Standard imports
from six.moves import queue
from threading import Thread, Event
from six import binary_type, text_type


class Worker(Thread):
    """Thread Worker

    It runs a function into a new thread.
    """

    def __init__(self, decoder, function):
        Thread.__init__(self)
        self.decoder = decoder
        self.function = function
        self.stopped = Event()

    def run(self):
        while not self.stopped.is_set():
            self.function()

    def stop(self):
        self.stopped.set()


# Simple Thread Pool implementation based on http://code.activestate.com/recipes/577187-python-thread-pool/
# WorkerQueue class
class WorkerQueue(Thread):
    """Thread executing tasks from a given tasks queue"""
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(e)
            self.tasks.task_done()


# ThreadPool class
class ThreadPool(object):
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, num_threads):
        self.tasks = queue(num_threads)
        for _ in range(num_threads):
            WorkerQueue(self.tasks)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()


# All custom general purpose Python 2/3 compatibility should go here


def unicode(string):
    """Convert given string to unicode string

    :param string: String to convert
    :type string: bytes | str | unicode
    :return: six.text_type
    """
    string_type = type(string)
    if string_type == binary_type:
        return string.decode()
    elif string_type == text_type:
        return string
    raise ValueError("Expected bytes or str, got {}".format(string_type))