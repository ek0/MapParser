#class MapEntry():
#    def __init__(self, address, name):
#        self.address = address
#        self.name = name
#
#    def __repr__(self):
#        return "MapEntry({:#08x}, \"{}\")".format(self.address, self.name)
#
#    def __str__(self):
#        return self.name


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
