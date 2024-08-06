#!/usr/bin/env python3
# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
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
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import logging
from collections import defaultdict
from argparse import ArgumentParser

# External imports
from scapy.config import conf
from scapy.packet import bind_layers

# Custom imports
import pysap
from pysap.SAPNI import SAPNI
from pysap.SAPDiagItems import *
from pysap.SAPDiag import SAPDiag, SAPDiagDP
from pysap.SAPDiagClient import SAPDiagConnection

# Tkinter imports
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

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
    description = "This example script renders the login screen provided by an SAP Netweaver Application Server using Tkinter."
    usage = "%(prog)s [options] -d <remote host>"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host", help="Remote host")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=3200, help="Remote port [%(default)d]")
    target.add_argument("--route-string", dest="route_string", help="Route string for connecting through a SAP Router")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    misc.add_argument("--terminal", dest="terminal", default=None, help="Terminal name")

    options = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")

    return options

class DiagScreen(tk.Tk):
    def __init__(self, windows_title, height, width, session_title, dbname, cpuname):
        super().__init__()

        self.title(windows_title)
        self.geometry(f"{width}x{height}")

        self.session_title = ttk.Label(self, text=session_title)
        self.session_title.pack(pady=10)

        self.content = ttk.Frame(self)
        self.content.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.buttonbar = ttk.Frame(self)
        self.buttonbar.pack(fill=tk.X, padx=10, pady=5)

        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)

        self.statusbar = ttk.Label(self, text=f"{dbname} | {cpuname}")
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.menus = defaultdict(dict)

    def add_text(self, x, y, maxlength, text, tooltip=None):
        label = ttk.Label(self.content, text=text)
        label.grid(row=y, column=x, padx=5, pady=5, sticky='w')
        if tooltip:
            ToolTip(label, tooltip)

    def add_text_box(self, x, y, maxlength, text, invisible=0):
        entry = ttk.Entry(self.content)
        entry.grid(row=y, column=x, padx=5, pady=5)
        entry.insert(0, text)
        if invisible:
            entry.config(show="*")

    def add_button(self, text):
        ttk.Button(self.buttonbar, text=text).pack(side=tk.LEFT, padx=2, pady=2)

    def add_menu(self, pos1, text):
        menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=text, menu=menu)
        self.menus[pos1][0] = menu

    def add_child_menu(self, text, pos1, pos2=0, pos3=0, pos4=0, sel=0, men=0, sep=0):
        if pos4 > 0:
            return
        if sep:
            self.menus[pos1][0].add_separator()
        else:
            if men:
                submenu = tk.Menu(self.menus[pos1][0], tearoff=0)
                self.menus[pos1][0].add_cascade(label=text, menu=submenu)
                self.menus[pos1][pos2] = submenu
            else:
                if pos3 > 0:
                    self.menus[pos1][pos2].add_command(label=text, state=tk.NORMAL if sel == 1 else tk.DISABLED)
                else:
                    self.menus[pos1][0].add_command(label=text, state=tk.NORMAL if sel == 1 else tk.DISABLED)

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tooltip = None

    def enter(self, event=None):
        x = y = 0
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

def render_diag_screen(screen, verbose):
    def get_item_value(screen, item_type, item_id, item_sid, i=0):
        item = screen.get_item(item_type, item_id, item_sid)
        if item:
            return item[i].item_value
        else:
            return []

    areasize = get_item_value(screen, "APPL", "VARINFO", "AREASIZE")
    dbname = get_item_value(screen, "APPL", "ST_R3INFO", "DBNAME")
    cpuname = get_item_value(screen, "APPL", "ST_R3INFO", "CPUNAME")
    client = get_item_value(screen, "APPL", "ST_R3INFO", "CLIENT")
    session_icon = get_item_value(screen, "APPL", "VARINFO", "SESSION_ICON")
    session_title = get_item_value(screen, "APPL", "VARINFO", "SESSION_TITLE")
    menus = get_item_value(screen, "APPL4", "MNUENTRY", "MENU_ACT")
    menudetails = get_item_value(screen, "APPL4", "MNUENTRY", "MENU_MNU")
    buttonbars = get_item_value(screen, "APPL4", "MNUENTRY", "MENU_PFK")
    toolbars = get_item_value(screen, "APPL4", "MNUENTRY", "MENU_KYB")

    if verbose:
        print(f"[*] DB Name: {dbname}")
        print(f"[*] CPU Name: {cpuname}")
        print(f"[*] Client: {client}")
        print(f"[*] Session Icon: {session_icon}")
        print(f"[*] Session Title: {session_title}")
        print(f"[*] Window Size: {areasize.window_height} x {areasize.window_width}")

    app = DiagScreen(f"{session_icon} ({client})", areasize.window_height, areasize.window_width, session_title, dbname, cpuname)

    # Render the atoms (control boxes and labels)
    atoms = screen.get_item(["APPL", "APPL4"], "DYNT", "DYNT_ATOM")
    if atoms:
        for atom_item in [atom for atom_item in atoms for atom in atom_item.item_value.items]:
            if atom_item.etype in [121, 123]:
                text = atom_item.field1_text
                maxnrchars = atom_item.field1_maxnrchars
            elif atom_item.etype in [130, 132]:
                text = atom_item.field2_text
                maxnrchars = atom_item.field2_maxnrchars
            else:
                text = None
                maxnrchars = 0

            if text is not None:
                if atom_item.etype in [123, 132]:  # DIAG_DGOTYP_KEYWORD_1 or DIAG_DGOTYP_KEYWORD_2
                    if text.find("@\\Q") >= 0:
                        tooltip = text.split("@")[1][2:]
                        text = text.split("@")[2]
                    else:
                        tooltip = None
                    if verbose:
                        print(f"[*] Found text label at {atom_item.col},{atom_item.row}: \"{text.strip()}\" (maxlength={maxnrchars}) (tooltip=\"{tooltip}\")")
                    app.add_text(atom_item.col, atom_item.row, maxnrchars, text, tooltip)
                elif atom_item.etype in [121, 130]:  # DIAG_DGOTYP_EFIELD_1 or DIAG_DGOTYP_EFIELD_2
                    if verbose:
                        print(f"[*] Found text box at {atom_item.col},{atom_item.row}: \"{text.strip()}\" (maxlength={maxnrchars})")
                    app.add_text_box(atom_item.col, atom_item.row, maxnrchars, text.strip(), atom_item.attr_DIAG_BSD_INVISIBLE == 1)
            else:
                print("[*] Found label without text")

    # Render the menus
    if menus:
        for menu in menus.entries:
            if verbose:
                print(f"[*] Found menu item: \"{menu.text}\"")
            app.add_menu(menu.position_1, menu.text)

        # Render the submenus
        if menudetails:
            for menu in menudetails.entries:
                if verbose:
                    print(f"[*] Found child menu item: \"{menu.text}\", pos {menu.position_1}, {menu.position_2}, {menu.position_3}, {menu.position_4}")
                app.add_child_menu(menu.text, menu.position_1, menu.position_2, menu.position_3, menu.position_4, menu.flag_TERM_SEL, menu.flag_TERM_MEN, menu.flag_TERM_SEP)

    # Render the buttonbar
    if buttonbars:
        for button in buttonbars.entries:
            if verbose:
                print(f"[*] Found button item: \"{button.text}\"")
            app.add_button(button.text)

    # Render the toolbar
    if toolbars:
        for toolbar in toolbars.entries:
            if verbose:
                print(f"[*] Found toolbar item: \"{toolbar.text}\"")
            # Note: Toolbar rendering is not implemented in this version

    app.mainloop()

def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Create the connection to the SAP Netweaver server
    print(f"[*] Connecting to {options.remote_host} port {options.remote_port}")
    connection = SAPDiagConnection(options.remote_host,
                                   options.remote_port,
                                   terminal=options.terminal,
                                   route=options.route_string)

    # Send the initialization packet and store the response (login screen)
    login_screen = connection.init()

    print("[*] Login screen grabbed, rendering it")
    render_diag_screen(login_screen[SAPDiag], options.verbose)

    # Close the connection
    connection.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[*] Canceled by the user ...")
        exit(0)