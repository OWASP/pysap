#!/usr/bin/python
## ===========
## pysap - Python library for crafting SAP's network protocols packets
##
## Copyright (C) 2014 Core Security Technologies
##
## The library was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============

# Standard imports
import logging
from collections import defaultdict
from optparse import OptionParser, OptionGroup
# External imports
import wx  # TODO: Change wx to Tkinter
from scapy.config import conf
from scapy.packet import bind_layers
# Custom imports
from pysap.SAPNI import SAPNI
from pysap.SAPDiagItems import *
from pysap.SAPDiag import SAPDiag, SAPDiagDP
from pysap.SAPDiagClient import SAPDiagConnection


# Bind the SAPDiag layer
bind_layers(SAPNI, SAPDiag,)
bind_layers(SAPNI, SAPDiagDP,)
bind_layers(SAPDiagDP, SAPDiag,)
bind_layers(SAPDiag, SAPDiagItem,)
bind_layers(SAPDiagItem, SAPDiagItem,)


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = \
    """This example script renders the login screen provided by an SAP
    Netweaver Application Server using wx.
    """

    epilog = \
    """pysap - http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=pysap"""

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host", help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", help="Remote port [%default]", default=3200)
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")

    return options


class DiagScreen(wx.Frame):
    def __init__(self, parent, windows_title, height, width, session_title, dbname, cpuname):
        wx.Frame.__init__(self, parent, title=windows_title)

        self.maincontainer = wx.BoxSizer(wx.VERTICAL)

        self.session_title = wx.StaticBox(self, label=session_title)

        self.container = wx.StaticBoxSizer(self.session_title, wx.VERTICAL)
        self.maincontainer.Add(self.container, flag=wx.EXPAND|wx.ALL, border=10)

        self.buttonbar = wx.ToolBar(self)
        self.container.Add(self.buttonbar, flag=wx.EXPAND|wx.ALL, border=10)

        self.content = wx.GridBagSizer()
        self.container.Add(self.content)
        self.SetSizer(self.container)

        self.menubar = wx.MenuBar()
        self.SetMenuBar(self.menubar)

        self.toolbar = self.CreateToolBar()
        self.toolbar.Realize()

        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetFields(["", dbname, cpuname])

        self.menus = defaultdict(defaultdict)

    def add_text(self, x, y, maxlength, text, tooltip=None):
        text_control = wx.StaticText(self, label=text)
        if tooltip:
            text_control.SetTooltip(tooltip)
        self.content.Add(text_control, pos=(y, x), flag=wx.TOP|wx.LEFT|wx.BOTTOM, border=5)

    def add_text_box(self, x, y, maxlength, text, invisible=0):
        if invisible:
            textbox_control = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        else:
            textbox_control = wx.TextCtrl(self)
        textbox_control.SetMaxLength(maxlength)
        textbox_control.SetValue(text)
        self.content.Add(textbox_control, pos=(y, x), flag=wx.TOP|wx.LEFT|wx.BOTTOM, border=5)

    def add_button(self, text):
        button = wx.Button(self.buttonbar, wx.ID_ANY, text)
        self.buttonbar.AddControl(button)

    def add_toolbar(self, text):
        toolbar = wx.Button(self.toolbar, wx.ID_ANY, text)
        self.toolbar.AddControl(toolbar)

    def add_menu(self, pos1, text):
        self.menus[pos1][0] = wx.Menu()
        self.menubar.Append(self.menus[pos1][0], text)

    def add_child_menu(self, text, pos1, pos2=0, pos3=0, pos4=0, sel=0, men=0, sep=0):
        # XXX: Support menus of level 4, need to use another structure for storing the menus and their handles
        if pos4 > 0:
            return
        if sep:
            self.menus[pos1][0].AppendSeparator()
        else:
            if men:
                    self.menus[pos1][pos2] = wx.Menu()
                    item = self.menus[pos1][0].AppendMenu(wx.ID_ANY, text, self.menus[pos1][pos2])
            else:
                if pos3 > 0:
                    item = self.menus[pos1][pos2].Append(wx.ID_ANY, text)
                else:
                    item = self.menus[pos1][0].Append(wx.ID_ANY, text)
            item.Enable(sel == 1)


def render_diag_screen(screen, verbose):
    """
    Renders the Dynt Atom items of a message

    """

    def get_item_value(screen, item_type, item_id, item_sid, i=0):
        item = screen.get_item(item_type, item_id, item_sid)
        if (len(item) > 0):
            return item[i].item_value
        else:
            return []

    areasize = get_item_value(screen, 0x10, 0x0c, 0x07)
    dbname = get_item_value(screen, 0x10, 0x06, 0x02)
    cpuname = get_item_value(screen, 0x10, 0x06, 0x03)
    client = get_item_value(screen, 0x10, 0x06, 0x0c)
    session_icon = get_item_value(screen, 0x10, 0x0c, 0x0a)
    session_title = get_item_value(screen, 0x10, 0x0c, 0x09)
    atoms = get_item_value(screen, 0x12, 0x09, 0x02)
    menus = get_item_value(screen, 0x12, 0x0b, 0x01)
    menudetails = get_item_value(screen, 0x12, 0x0b, 0x02)
    buttonbars = get_item_value(screen, 0x12, 0x0b, 0x03)
    toolbars = get_item_value(screen, 0x12, 0x0b, 0x04)

    if verbose:
        print "[*] DB Name:", dbname
        print "[*] CPU Name:", cpuname
        print "[*] Client:", client
        print "[*] Session Icon:", session_icon
        print "[*] Session Title:", session_title
        print "[*] Window Size:", areasize.window_height, "x", areasize.window_width

    app = wx.App(False)
    login_frame = DiagScreen(None, "%s (%s)" % (session_icon, client), areasize.window_height, areasize.window_width, session_title, dbname, cpuname)

    # Render the atoms (control boxes and labels)
    if len(atoms) > 0:
        for atom in atoms.items:
            if atom.etype in [123, 132]:  # DIAG_DGOTYP_KEYWORD_1 or DIAG_DGOTYP_KEYWORD_2
                if atom.text.find("@\Q") >= 0:
                    tooltip = atom.text.split("@")[1][2:]
                    atom.text = atom.text.split("@")[2]
                else:
                    tooltip = None
                if verbose:
                    print "[*] Found text label at %d,%d: \"%s\" (maxlength=%d) (tooltip=\"%s\")" % (atom.col, atom.row, atom.text.strip(), atom.maxnrchars, tooltip)
                login_frame.add_text(atom.col, atom.row, atom.maxnrchars, atom.text)
            elif atom.etype in [121, 130]:  # DIAG_DGOTYP_EFIELD_1 or DIAG_DGOTYP_EFIELD_2
                if verbose:
                    print "[*] Found text box at %d,%d: \"%s\" (maxlength=%d)" % (atom.col, atom.row, atom.text.strip(), atom.maxnrchars)
                login_frame.add_text_box(atom.col, atom.row, atom.maxnrchars, atom.text.strip(), atom.attr_DIAG_BSD_INVISIBLE == 1)

    # Render the menus
    if len(menus) > 0:
        for menu in menus.entries:
            if verbose:
                print "[*] Found menu item: \"%s\"" % menu.text
            login_frame.add_menu(menu.position_1, menu.text)

        # Render the submenus
        if len(menudetails) > 0:
            for menu in menudetails.entries:
                if verbose:
                    print "[*] Found child menu item: \"%s\", pos %d, %d, %d, %d" % (menu.text, menu.position_1, menu.position_2, menu.position_3, menu.position_4)
                login_frame.add_child_menu(menu.text, menu.position_1, menu.position_2, menu.position_3, menu.position_4, menu.flag_TERM_SEL, menu.flag_TERM_MEN, menu.flag_TERM_SEP)

    # Render the buttonbar
    if len(buttonbars) > 0:
        for button in buttonbars.entries:
            if verbose:
                print "[*] Found button item: \"%s\"" % button.text
            login_frame.add_button(button.text)

    # Render the toolbar
    if len(toolbars) > 0:
        for toolbar in toolbars.entries:
            if verbose:
                print "[*] Found toolbar item: \"%s\"" % toolbar.text
            login_frame.add_toolbar(toolbar.text)

    login_frame.Show(True)
    app.MainLoop()


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Create the connection to the SAP Netweaver server
    print "[*] Connecting to", options.remote_host, "port", options.remote_port
    connection = SAPDiagConnection(options.remote_host, options.remote_port)

    # Send the initialization packet and store the response (login screen)
    login_screen = connection.init()

    print "[*] Login screen grabbed, rendering it"
    render_diag_screen(login_screen[SAPDiag], options.verbose)

    # Close the connection
    connection.close()


if __name__ == "__main__":
    main()
