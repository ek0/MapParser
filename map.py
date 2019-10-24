import ida_kernwin
import ida_bytes
import ida_name

# Class listening to UI notification
hooks = None
map_file = {}
mapfile_chooser = None

class MapFileMenuHandler(ida_kernwin.action_handler_t):
    """
        Menu handler. File/Load file/Load MAP...
    """
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        path = ida_kernwin.ask_file(0, "*.map", "Open MAP File")
        if path is None:
            raise FileNotFoundError
        print("MapParser: Loading MAP file...")
        load_map(path)
        print("MapParser: MAP file loaded.")
        global mapfile_chooser
        mapfile_chooser = MapFileChooser()
        mapfile_chooser.Show()

class MapFileShowSymbols(ida_kernwin.action_handler_t):
    """
        Menu handler. File/Load file/Load MAP...
    """
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        if map_file is None:
            print("MapParser: No MAP file loaded...")
        mapfile_chooser.Show()


class MapFileRenameSymbolAtCursorHandler(ida_kernwin.action_handler_t):
    """
        Contextual menu for renaming functions
    """
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx):
        if ctx.form_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def activate(self, ctx):
        if len(map_file) is 0:
            # No symbol loaded, aborting
            return
        srva = int(ida_name.get_name_ea(here(), ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())[0]))
        ida_name.set_name(srva, map_file[srva].replace("~", "::Destruct"), ida_name.SN_CHECK)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)


class MapFileRenameSymbolHandler(ida_kernwin.action_handler_t):
    """
        Contextual menu for renaming functions
    """
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET

    def activate(self, ctx):
        if len(map_file) is 0:
            # No symbol loaded, aborting
            return
        for i in mapfile_chooser.GetSelectedItems():
            srva = int(mapfile_chooser.GetLine(i)[0], 16)
            name = mapfile_chooser.GetLine(i)[2]
            print("{} {}".format(srva, name))
            ida_name.set_name(srva, name.replace("~", "::Destruct"), ida_name.SN_CHECK)
            ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(form, popup, "mapfile:rename_symbol_at_cursor", None)


def load_map(path):
    with open(path, "r") as f:
        while f.readline()[:9] != "  Address":
            continue
        f.readline()
        tmp = f.readline()
        while tmp:
            if tmp == "\n":
                break
            global map_file
            map_file[int(tmp.split()[2], 16)] = tmp.split()[1]
            tmp = f.readline()


class MapFileChooser(ida_kernwin.Choose):
    def __init__(self):
        self.items = []
        self.selected_items = []
        columns = [["Address", 18], ["Current Name", 50], ["Symbol Name", 50]]
        ida_kernwin.Choose.__init__(self, "Symbols", columns, ida_kernwin.Choose.CH_MULTI)
        for key, val in map_file.items():
            line = ["{:#016X}".format(key), ida_name.get_name(key), val]
            self.items.append(line)

    def OnPopup(self, form, popup_handle):
        ida_kernwin.attach_action_to_popup(form, popup_handle, "mapfile:rename_symbol", None)

    def OnGetLine(self, idx):
        return self.items[idx]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        ea = int(self.items[n[0]][0], 16)
        if ida_bytes.is_mapped(ea):
            ida_kernwin.jumpto(ea)

    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list

    def GetSelectedItems(self):
        return self.selected_items

    def GetLine(self, idx):
        return self.items[idx]


def unload():
    """
        If you ever need to clean up
    """
    ida_kernwin.unregister_action("mapfile:rename_symbol_at_cursor")
    ida_kernwin.unregister_action("mapfile:load_map")
    ida_kernwin.unregister_action("mapfile:view_symbols")
    ida_kernwin.unregister_action("mapfile:rename_symbol")
    global hooks
    global map_file
    global mapfile_chooser
    if hooks is not None:
        hooks.unhook()
        hooks = None
    del map_file
    del mapfile_chooser


def register_actions():
    ida_kernwin.register_action(ida_kernwin.action_desc_t("mapfile:rename_symbol_at_cursor", "Get Symbol", MapFileRenameSymbolAtCursorHandler(), "", "Get the symbol for a given address"))
    ida_kernwin.register_action(ida_kernwin.action_desc_t("mapfile:load_map", "Load MAP...", MapFileMenuHandler(), "", "Load map file"))
    ida_kernwin.register_action(ida_kernwin.action_desc_t("mapfile:view_symbols", "MAP Symbols", MapFileShowSymbols(), "", "View map file symbols"))
    ida_kernwin.register_action(ida_kernwin.action_desc_t("mapfile:rename_symbol", "Rename/Create symbol at address", MapFileRenameSymbolHandler(), "", "Rename/Create symbol at address"))
    ida_kernwin.attach_action_to_menu("File/Load file/", "mapfile:load_map", ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu("View/Open subviews/", "mapfile:view_symbols", ida_kernwin.SETMENU_APP)
    global hooks
    if hooks is None:
        hooks = Hooks()
        hooks.hook()

if __name__ == "__main__":
    register_actions()

