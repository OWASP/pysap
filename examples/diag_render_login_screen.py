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
import re
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

# Try to import wx, failing gracefully if not installed
try:
    import wx
    has_wx = True
except ImportError:
    has_wx = False

# Bind SAP Diag protocol layers
bind_layers(SAPNI, SAPDiag)
bind_layers(SAPNI, SAPDiagDP)
bind_layers(SAPDiagDP, SAPDiag)
bind_layers(SAPDiag, SAPDiagItem)
bind_layers(SAPDiagItem, SAPDiagItem)

conf.verb = 0

_SAP_ICON_RE = re.compile(r'@[^@]+@')


def _strip_icons(text):
    """Remove SAP icon escape sequences (@XX@) from display text."""
    return _SAP_ICON_RE.sub('', text)


def _decode(value):
    """Decode bytes to str; pass strings through unchanged."""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def _get_item_value(screen, item_type, item_id, item_sid, i=0):
    """Return the value of a SAPDiag item, or an empty list if not found."""
    item = screen.get_item(item_type, item_id, item_sid)
    return item[i].item_value if item else []


def _parse_atom(atom_item):
    """
    Extract (text, mlen, maxnrchars, readonly) from a Dynt atom item.
    Returns None for unhandled atom types.
    """
    etype = atom_item.etype
    if etype in (121, 122, 123):
        text, mlen, maxnrchars = atom_item.field1_text, atom_item.field1_mlen, atom_item.field1_maxnrchars
    elif etype in (130, 131, 132):
        text, mlen, maxnrchars = atom_item.field2_text, atom_item.field2_mlen, atom_item.field2_maxnrchars
    elif etype == 115:  # PUSHBUTTON_2
        text = atom_item.pushbutton_text
        mlen = maxnrchars = len(text) if text else 0
    elif etype == 127:  # FRAME_1
        text = atom_item.frame_text
        mlen = maxnrchars = len(text) if text else 0
    else:
        return None
    return _decode(text), mlen, maxnrchars, etype in (122, 131)


if has_wx:
    # SAP GUI colour palette (Corbu/classic theme)
    _SAP_BG        = wx.Colour(236, 236, 236)  # window / label background
    _SAP_FIELD_BG  = wx.Colour(255, 255, 255)  # editable input field
    _SAP_OFIELD_BG = wx.Colour(214, 214, 214)  # read-only output field
    _SAP_BLUE      = wx.Colour(0,   70,  127)  # SAP dark blue (titles)
    _SAP_FG        = wx.Colour(0,   0,   0)    # foreground text


class DiagScreen(wx.Frame if has_wx else object):
    def __init__(self, parent, title, height, width, session_title, dbname, cpuname):
        wx.Frame.__init__(self, parent, title=title)

        # Monospace font — measured once to derive the character-cell grid size
        self._font = wx.Font(10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        dc = wx.ScreenDC()
        dc.SetFont(self._font)
        self._cw, self._ch = dc.GetTextExtent("X")

        self.menubar = wx.MenuBar()
        self.SetMenuBar(self.menubar)

        self.toolbar = self.CreateToolBar(wx.TB_HORIZONTAL | wx.TB_FLAT | wx.TB_NODIVIDER)
        self.toolbar.SetBackgroundColour(_SAP_BG)
        self.toolbar.Realize()

        self._outer = wx.Panel(self)
        self._outer.SetBackgroundColour(_SAP_BG)
        chrome = wx.BoxSizer(wx.VERTICAL)

        title_label = wx.StaticText(self._outer, label=_strip_icons(session_title))
        title_label.SetFont(wx.Font(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD))
        title_label.SetForegroundColour(_SAP_BLUE)
        chrome.Add(title_label, flag=wx.ALL, border=4)
        chrome.Add(wx.StaticLine(self._outer), flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=4)

        self._canvas = wx.ScrolledWindow(self._outer, style=wx.VSCROLL | wx.HSCROLL)
        self._canvas.SetBackgroundColour(_SAP_BG)
        self._canvas.SetScrollRate(self._cw, self._ch)
        self._canvas.SetVirtualSize(width * self._cw, height * self._ch)
        chrome.Add(self._canvas, proportion=1, flag=wx.EXPAND | wx.ALL, border=4)

        chrome.Add(wx.StaticLine(self._outer), flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=4)
        self._pfk_panel = wx.Panel(self._outer)
        self._pfk_panel.SetBackgroundColour(_SAP_BG)
        self._pfk_sizer = wx.WrapSizer(wx.HORIZONTAL)
        self._pfk_panel.SetSizer(self._pfk_sizer)
        chrome.Add(self._pfk_panel, flag=wx.EXPAND | wx.ALL, border=2)

        self._outer.SetSizer(chrome)
        frame_sizer = wx.BoxSizer(wx.VERTICAL)
        frame_sizer.Add(self._outer, proportion=1, flag=wx.EXPAND)
        self.SetSizer(frame_sizer)

        self.SetClientSize(wx.Size(width * self._cw + 24, height * self._ch + 100))

        self.statusbar = self.CreateStatusBar(3)
        self.statusbar.SetStatusText("", 0)
        self.statusbar.SetStatusText(dbname, 1)
        self.statusbar.SetStatusText(cpuname, 2)

        self.menus = defaultdict(dict)
        self._ofield_bg = None
        self._ofield_bg_origin = (0, 0)

    def _cell_pos(self, x, y):
        return wx.Point(x * self._cw, y * self._ch)

    def _cell_size(self, cols):
        return wx.Size(max(cols * self._cw, 24), self._ch + 2)

    def create_ofield_background(self, col, row, width_cols, height_rows):
        """Create the single unified gray box for all OFIELD content."""
        self._ofield_bg = wx.Panel(self._canvas,
                                   pos=self._cell_pos(col, row),
                                   size=wx.Size(width_cols * self._cw, height_rows * self._ch))
        self._ofield_bg.SetBackgroundColour(_SAP_OFIELD_BG)
        self._ofield_bg_origin = (col, row)

    def add_text(self, x, y, mlen, text, tooltip=None):
        text = _strip_icons(text)
        ctrl = wx.StaticText(self._canvas, label=text,
                             pos=self._cell_pos(x, y),
                             size=self._cell_size(max(mlen, len(text))))
        ctrl.SetFont(self._font)
        ctrl.SetForegroundColour(_SAP_FG)
        ctrl.SetBackgroundColour(_SAP_BG)
        if tooltip:
            ctrl.SetToolTip(tooltip)

    def add_text_box(self, x, y, mlen, maxnrchars, text, invisible=False, readonly=False):
        text = _strip_icons(text)
        if readonly:
            if self._ofield_bg is not None:
                ox, oy = self._ofield_bg_origin
                ctrl = wx.StaticText(self._ofield_bg, label=text,
                                     pos=wx.Point((x - ox) * self._cw, (y - oy) * self._ch),
                                     size=wx.Size(len(text) * self._cw + self._cw, self._ch))
            else:
                ctrl = wx.StaticText(self._canvas, label=text,
                                     pos=self._cell_pos(x, y),
                                     size=wx.Size(max(mlen, len(text)) * self._cw, self._ch))
            ctrl.SetFont(self._font)
            ctrl.SetForegroundColour(_SAP_FG)
        else:
            style = wx.TE_PASSWORD if invisible else 0
            ctrl = wx.TextCtrl(self._canvas, style=style,
                               pos=self._cell_pos(x, y),
                               size=self._cell_size(mlen))
            ctrl.SetFont(self._font)
            ctrl.SetBackgroundColour(_SAP_FIELD_BG)
            ctrl.SetForegroundColour(_SAP_FG)
            ctrl.SetMaxLength(maxnrchars)
            ctrl.SetValue(text)

    def add_button(self, text):
        btn = wx.Button(self._pfk_panel, wx.ID_ANY, text, style=wx.BU_EXACTFIT)
        btn.SetFont(wx.Font(8, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL))
        self._pfk_sizer.Add(btn, flag=wx.ALL, border=1)

    def add_toolbar(self, text):
        btn = wx.Button(self.toolbar, wx.ID_ANY, text, style=wx.BU_EXACTFIT)
        btn.SetFont(wx.Font(8, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL))
        self.toolbar.AddControl(btn)

    def add_menu(self, pos1, text):
        self.menus[pos1][0] = wx.Menu()
        self.menubar.Append(self.menus[pos1][0], text)

    def add_child_menu(self, text, pos1, pos2=0, pos3=0, pos4=0, sel=False, men=False, sep=False):
        if pos4 > 0:
            return
        if sep:
            self.menus[pos1][0].AppendSeparator()
            return
        if men:
            self.menus[pos1][pos2] = wx.Menu()
            item = self.menus[pos1][0].AppendSubMenu(self.menus[pos1][pos2], text)
        elif pos3 > 0:
            item = self.menus[pos1][pos2].Append(wx.ID_ANY, text)
        else:
            item = self.menus[pos1][0].Append(wx.ID_ANY, text)
        item.Enable(bool(sel))


def render_diag_screen(screen, verbose):
    """Render the Dynt Atom items from a SAPDiag login screen packet."""
    areasize    = _get_item_value(screen, "APPL", "VARINFO", "AREASIZE")
    dbname      = _decode(_get_item_value(screen, "APPL", "ST_R3INFO", "DBNAME"))
    cpuname     = _decode(_get_item_value(screen, "APPL", "ST_R3INFO", "CPUNAME"))
    client      = _decode(_get_item_value(screen, "APPL", "ST_R3INFO", "CLIENT"))
    session_icon  = _decode(_get_item_value(screen, "APPL", "VARINFO", "SESSION_ICON"))
    session_title = _decode(_get_item_value(screen, "APPL", "VARINFO", "SESSION_TITLE"))
    menus       = _get_item_value(screen, "APPL4", "MNUENTRY", "MENU_ACT")
    menudetails = _get_item_value(screen, "APPL4", "MNUENTRY", "MENU_MNU")
    buttonbars  = _get_item_value(screen, "APPL4", "MNUENTRY", "MENU_PFK")
    toolbars    = _get_item_value(screen, "APPL4", "MNUENTRY", "MENU_KYB")

    if verbose:
        print("[*] DB Name: %s"      % dbname)
        print("[*] CPU Name: %s"     % cpuname)
        print("[*] Client: %s"       % client)
        print("[*] Session Icon: %s" % session_icon)
        print("[*] Session Title: %s"% session_title)
        print("[*] Window Size: %d x %d" % (areasize.window_height, areasize.window_width))

    app = wx.App(False)
    login_frame = DiagScreen(None, "%s (%s)" % (session_icon, client),
                             areasize.window_height, areasize.window_width,
                             session_title, dbname, cpuname)

    atoms = screen.get_item(["APPL", "APPL4"], "DYNT", "DYNT_ATOM")
    if atoms:
        all_atoms = [atom for item in atoms for atom in item.item_value.items]

        # Split atoms into background (readonly OFIELD) and foreground (form elements).
        # Background atoms are rendered first so foreground widgets sit on top in Z-order.
        # Atoms with unhandled etypes are logged in verbose mode and skipped.
        bg_atoms, fg_atoms = [], []
        for atom_item in all_atoms:
            parsed = _parse_atom(atom_item)
            if parsed is None:
                if verbose:
                    etype_name = diag_atom_etypes.get(atom_item.etype, str(atom_item.etype))
                    print("[*] Skipped at %d,%d: %s" % (atom_item.col, atom_item.row, etype_name))
                continue
            (bg_atoms if parsed[3] else fg_atoms).append((atom_item, parsed))

        # The right edge of form elements (excluding decorative frames).
        form_right = max(
            (atom_item.col + parsed[1]
             for atom_item, parsed in fg_atoms
             if atom_item.etype != 127),
            default=0
        )

        # Use the FRAME_1 position to anchor OFIELDs. The frame border takes
        # 1 char on each side, so the interior starts at frame_col+1, frame_row+1.
        bg_frame_atoms = [(a.col, a.row) for a, _ in fg_atoms
                          if a.etype == 127 and a.col > form_right]
        if bg_frame_atoms:
            frame_col, frame_row = min(bg_frame_atoms, key=lambda t: t[0])
            ofield_col_offset = frame_col + 1
            ofield_row_offset = frame_row + 1
        else:
            ofield_col_offset = form_right + 2 if form_right > 0 else 0
            ofield_row_offset = 0

        # Compute OFIELD display width and absolute row span for the background box.
        max_ofield_display = 0
        ofield_abs_rows = []
        for atom_item, (text, mlen, _, _readonly) in bg_atoms:
            display_width = max(mlen, len(_strip_icons(text)))
            max_ofield_display = max(max_ofield_display, display_width)
            ofield_abs_rows.append(atom_item.row + ofield_row_offset)

        # Create the single unified gray background box before rendering OFIELD rows.
        if ofield_abs_rows and max_ofield_display > 0:
            min_row = min(ofield_abs_rows)
            login_frame.create_ofield_background(
                ofield_col_offset, min_row,
                max_ofield_display,
                max(ofield_abs_rows) - min_row + 1)

        # Resize canvas and window to fit both the form and the OFIELD section.
        total_cols = max(areasize.window_width, ofield_col_offset + max_ofield_display)
        login_frame._canvas.SetVirtualSize(total_cols * login_frame._cw,
                                           areasize.window_height * login_frame._ch)
        login_frame.SetClientSize(wx.Size(total_cols * login_frame._cw + 24,
                                          areasize.window_height * login_frame._ch + 100))

        for atom_item, (text, mlen, maxnrchars, readonly) in bg_atoms + fg_atoms:
            col = atom_item.col + (ofield_col_offset if readonly else 0)
            row = atom_item.row + (ofield_row_offset if readonly else 0)
            etype = atom_item.etype

            if etype in (123, 132):  # KEYWORD — label
                if "@\\Q" in text:
                    parts = text.split("@")
                    tooltip, text = parts[1][2:], parts[2]
                else:
                    tooltip = None
                if verbose:
                    print("[*] Label   at %d,%d: %r (mlen=%d, tooltip=%r)"
                          % (atom_item.col, atom_item.row, text.strip(), mlen, tooltip))
                login_frame.add_text(col, row, mlen, text, tooltip)

            elif etype in (121, 122, 130, 131):  # EFIELD / OFIELD
                if verbose:
                    print("[*] Field   at %d,%d: %r (mlen=%d, maxnrchars=%d, readonly=%s)"
                          % (atom_item.col, atom_item.row, text.strip(), mlen, maxnrchars, readonly))
                login_frame.add_text_box(col, row, mlen, maxnrchars, text.strip(),
                                         atom_item.attr_DIAG_BSD_INVISIBLE == 1, readonly)

            elif etype == 115:  # PUSHBUTTON_2
                if verbose:
                    print("[*] Button  at %d,%d: %r" % (atom_item.col, atom_item.row, text.strip()))
                login_frame.add_button(text.strip())

            elif etype == 127:  # FRAME_1 — renders as the section label
                if verbose:
                    print("[*] Frame   at %d,%d: %r" % (atom_item.col, atom_item.row, text.strip()))
                login_frame.add_text(col, row, mlen, text)

    if menus:
        for menu in menus.entries:
            text = _decode(menu.text)
            if verbose:
                print("[*] Menu: %r" % text)
            login_frame.add_menu(menu.position_1, text)

        if menudetails:
            for menu in menudetails.entries:
                text = _decode(menu.text)
                if verbose:
                    print("[*] Submenu: %r pos=%d,%d,%d,%d"
                          % (text, menu.position_1, menu.position_2, menu.position_3, menu.position_4))
                login_frame.add_child_menu(
                    text, menu.position_1, menu.position_2, menu.position_3, menu.position_4,
                    menu.flag_TERM_SEL, menu.flag_TERM_MEN, menu.flag_TERM_SEP)

    if buttonbars:
        for button in buttonbars.entries:
            text = _decode(button.text)
            if verbose:
                print("[*] PFK button: %r" % text)
            login_frame.add_button(text)

    if toolbars:
        for toolbar in toolbars.entries:
            text = _decode(toolbar.text)
            if verbose:
                print("[*] Toolbar button: %r" % text)
            login_frame.add_toolbar(text)

    login_frame.toolbar.Realize()
    login_frame._pfk_panel.Layout()
    login_frame._canvas.Refresh()
    login_frame.Show(True)
    app.MainLoop()


def parse_options():
    description = ("This example script renders the login screen provided by an "
                   "SAP Netweaver Application Server using wxPython.")
    usage = "%(prog)s [options] -d <remote host>"
    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host", help="Remote host")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=3200,
                        help="Remote port [%(default)d]")
    target.add_argument("--route-string", dest="route_string",
                        help="Route string for connecting through a SAP Router")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    misc.add_argument("--terminal", dest="terminal", default=None, help="Terminal name")

    options = parser.parse_args()
    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")
    return options


def main():
    options = parse_options()

    if not has_wx:
        print("[-] Required library not found. Please install it from https://wxpython.org/")
        return

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print("[*] Connecting to %s port %d" % (options.remote_host, options.remote_port))
    connection = SAPDiagConnection(options.remote_host,
                                   options.remote_port,
                                   terminal=options.terminal,
                                   route=options.route_string)

    login_screen = connection.init()
    print("[*] Login screen grabbed, rendering it")
    render_diag_screen(login_screen[SAPDiag], options.verbose)

    connection.close()


if __name__ == "__main__":
    main()
