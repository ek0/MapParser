import idc
import idautils
import idaapi
import ida_ua

get_symbol = "helper:get_symbol"
# Class listening to UI notification
hooks = None
map_file = None

class HelperGetSymbol(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_FORM if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_FORM

        def activate(self, ctx):
            srva = get_name_ea(here(), idaapi.get_highlighted_identifier())
            print(srva)
            MakeName(srva, map_file[srva].replace("~", "::Destruct"))

class Hooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, get_symbol, None)

class MapFile():
    def __init__(self, path):
        self.index = 0
        self.functions = {}
        f = open(path, "r")
        while f.readline()[:9] != "  Address":
            continue
        f.readline()
        tmp = f.readline()
        while tmp:
            if tmp == "\n":
                break
            self.functions[int(tmp.split()[2], 16)] = tmp.split()[1]
            #self.functions.append(entry)
            tmp = f.readline()

    def __iter__(self):
        return iter(self.functions)

    def __next__(self):
        return next(self.functions)

    def __getitem__(self, key):
        return self.functions[self.__keytransform__(key)]
        #if type(key) == int or type(key) == long:
        #    for i in self.functions:
        #        if i.address == key:
        #            return i
        #if type(key) == str:
        #    for i in self.functions:
        #        if i.name == key:
        #            return i
        #else:
        #    raise TypeError

    def __len__(self):
        return len(self.functions)
    
    def __keytransform__(self, key):
        return key

def load_map(path):
    idaapi.register_action(idaapi.action_desc_t(get_symbol, "Get Symbol", HelperGetSymbol(), "", "Get the symbol for address and copy it to clipboard"))
    global hooks
    global map_file
    map_file = MapFile(path)
    if hooks is None:
        hooks = Hooks()
        hooks.hook()

def unload_map():
    idaapi.unregister_action(get_symbol)
    global hooks
    if hooks is not None:
        hooks.unhook()
        hooks = None
