import idc
import idautils
import idaapi
import ida_ua

# Class listening to UI notification
hooks = None
map_file = {}

class MapFileMenuHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

        def activate(self, ctx):
            path = idaapi.ask_file(0, "*.map", "Open MAP File")
            if path is None:
                raise FileNotFoundError
            load_map(path)
            print("Importing MAP file")

class MapFileGetSymbolHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET

        def activate(self, ctx):
            if len(map_file) is not 0:
                return
            srva = get_name_ea(here(), idaapi.get_highlight(idaapi.get_current_viewer())[0])
            idc.set_name(srva, map_file[srva].replace("~", "::Destruct"), SN_CHECK)

class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "mapfile:get_symbol", None)

#class MapFile():
#    def __init__(self, path):
#        self.index = 0
#        self.functions = {}
#        f = open(path, "r")
#        while f.readline()[:9] != "  Address":
#            continue
#        f.readline()
#        tmp = f.readline()
#        while tmp:
#            if tmp == "\n":
#                break
#            self.functions[int(tmp.split()[2], 16)] = tmp.split()[1]
#            #self.functions.append(entry)
#            tmp = f.readline()
#
#    def __iter__(self):
#        return iter(self.functions)
#
#    def __next__(self):
#        return next(self.functions)
#
#    def __getitem__(self, key):
#        return self.functions[self.__keytransform__(key)]
#        #if type(key) == int or type(key) == long:
#        #    for i in self.functions:
#        #        if i.address == key:
#        #            return i
#        #if type(key) == str:
#        #    for i in self.functions:
#        #        if i.name == key:
#        #            return i
#        #else:
#        #    raise TypeError
#
#    def __len__(self):
#        return len(self.functions)
#    
#    def __keytransform__(self, key):
#        return key

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
            #self.functions.append(entry)
            tmp = f.readline()

class MapFileChooser(idaapi.Choose):
    def __init__(self, title):
        self.items = []
        columns = [["Address", 18], ["Symbol Name", 50]]
        idaapi.Choose.__init__(self, title, columns, idaapi.Choose.CH_MULTI)
        for key, val in map_file.items():
            line = ["{:#016X}".format(key), val]
            self.items.append(line)
    
    def OnGetLine(self, idx):
        return self.items[idx]
    
    def OnGetSize(self):
        return len(self.items)

def unload():
    """
        If you ever need to clean up
    """
    idaapi.unregister_action("mapfile:get_symbol")
    idaapi.unregister_action("mapfile:load_map")
    global hooks
    global map_file
    if hooks is not None:
        hooks.unhook()
        hooks = None
    del map_file
    map_file = None


def register_actions():
    idaapi.register_action(idaapi.action_desc_t("mapfile:get_symbol", "Get Symbol", MapFileGetSymbolHandler(), "", "Get the symbol for a given address"))
    idaapi.register_action(idaapi.action_desc_t("mapfile:load_map", "Load MAP...", MapFileMenuHandler(), "", "Load map file"))
    idaapi.attach_action_to_menu("File/Load file/", "mapfile:load_map", idaapi.SETMENU_APP)
    global hooks
    if hooks is None:
        hooks = Hooks()
        hooks.hook()

