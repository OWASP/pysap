# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from
# Core Security's CoreLabs team.
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
# ==============


# Standard imports
from threading import Thread, Event


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
