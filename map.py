class MapEntry():
    def __init__(self, address, name):
        self.address = address
        self.name = name

    def __repr__(self):
        return "{}: {}".format(self.address, self.name)


class MapFile():
    def __init__(self, path):
        self.index = 0
        self.functions = []
        f = open(path, "r")
        while f.readline()[:9] != "  Address":
            continue
        f.readline()
        tmp = f.readline()
        while tmp:
            if tmp == "\n":
                break
            entry = MapEntry(int(tmp.split()[2], 16), tmp.split()[1])
            self.functions.append(entry)
            tmp = f.readline()

    def __iter__(self):
        return iter(self.functions)

    def __next__(self):
        return next(self.functions)

    def __getitem__(self, key):
        if type(key) == int:
            for i in self.functions:
                if i.address == key:
                    return i
        if type(key) == str:
            for i in self.functions:
                if i.name == key:
                    return i
        else:
            raise IndexError
