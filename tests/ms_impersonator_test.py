# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest

from examples import ms_impersonator
from pysap.SAPMS import SAPMS
from pysap.SAPNI import SAPNI


class MSImpersonatorTest(unittest.TestCase):

    def test_requires_sapms_layer(self):
        response = SAPMS()
        self.assertIs(ms_impersonator.require_sapms_response(response,
                                                              "testing"), response)
        with self.assertRaises(ValueError):
            ms_impersonator.require_sapms_response(SAPNI() / b"not-ms",
                                                    "testing")

if __name__ == "__main__":
    unittest.main()
