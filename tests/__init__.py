# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
import sys
import unittest


test_suite = unittest.defaultTestLoader.discover('.', '*_test.py')


if __name__ == '__main__':
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(test_suite)
    sys.exit(not result.wasSuccessful())
