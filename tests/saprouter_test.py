# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2014 Core Security Technologies
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security Technologies.
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
import unittest
# External imports

# Custom imports
from pysap.SAPRouter import SAPRouterRouteHop


class PySAPRouterTest(unittest.TestCase):

    def check_route(self, route_string, route_hops):
        """Check from string to hops and back again"""
        hops = SAPRouterRouteHop.from_string(route_string)
        self.assertListEqual(hops, route_hops)

        string = SAPRouterRouteHop.from_hops(hops)
        self.assertEqual(string, route_string)

    def test_saprouter_route_string(self):
        """Test construction of SAPRouterRouteHop items"""

        # Two hops with full details
        self.check_route("/H/host1/S/service1/W/pass1/H/host2/S/service2/W/pass2",
                         [SAPRouterRouteHop(hostname="host1",
                                            port="service1",
                                            password="pass1"),
                          SAPRouterRouteHop(hostname="host2",
                                            port="service2",
                                            password="pass2")])

        # One intermediate hop with service/password
        self.check_route("/H/host1/H/host2/S/service2/W/pass2/H/host3",
                         [SAPRouterRouteHop(hostname="host1"),
                          SAPRouterRouteHop(hostname="host2",
                                            port="service2",
                                            password="pass2"),
                          SAPRouterRouteHop(hostname="host3")])

        # Example in SAP Help
        self.check_route("/H/sap_rout/H/your_rout/W/pass_to_app/H/yourapp/S/sapsrv",
                         [SAPRouterRouteHop(hostname="sap_rout"),
                          SAPRouterRouteHop(hostname="your_rout",
                                            password="pass_to_app"),
                          SAPRouterRouteHop(hostname="yourapp",
                                            port="sapsrv")])

        # Hostname with FQDN
        self.check_route("/H/some.valid.domain.com/S/3299",
                         [SAPRouterRouteHop(hostname="some.valid.domain.com",
                                            port="3299")])

        # Hostname with IP addresses
        self.check_route("/H/127.0.0.1/S/3299",
                         [SAPRouterRouteHop(hostname="127.0.0.1",
                                            port="3299")])

        # Invalid route strings
        self.assertListEqual(SAPRouterRouteHop.from_string("/S/service"), [])
        self.assertListEqual(SAPRouterRouteHop.from_string("/P/password"), [])


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPRouterTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
