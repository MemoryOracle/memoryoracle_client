#!/usr/bin/env python
# -*- encoding UTF-8 -*-

import gdb
import gdb.types
import collections
import re
import time
import networkx as nx


class AlreadyFound(Exception):
    pass


class Oracle(object):

    MAX_QUEUE_SIZE = 100
    _selectedFrame = gdb.selected_frame()
    _initialProcessor = True
    found = collections.deque()
    described = collections.deque()
    explored = set()
    arrays = dict()

    network = nx.DiGraph()

    _lookup = {
        gdb.TYPE_CODE_PTR: "Pointer",
        gdb.TYPE_CODE_ARRAY: "Array",
        gdb.TYPE_CODE_STRUCT: "Struct",
        gdb.TYPE_CODE_UNION: "Union",
        gdb.TYPE_CODE_ENUM: "Enum",
        gdb.TYPE_CODE_FUNC: "Function",
        gdb.TYPE_CODE_INT: "Int",
        gdb.TYPE_CODE_FLT: "Float",
        gdb.TYPE_CODE_VOID: "Void",
        gdb.TYPE_CODE_STRING: "String",
        gdb.TYPE_CODE_ERROR: "TypeDetectionError",
        gdb.TYPE_CODE_METHOD: "Method",
        gdb.TYPE_CODE_METHODPTR: "MethodPointer",
        gdb.TYPE_CODE_MEMBERPTR: "MemberPointer",
        gdb.TYPE_CODE_REF: "Reference",
        gdb.TYPE_CODE_CHAR: "Character",
        gdb.TYPE_CODE_BOOL: "Bool",
        gdb.TYPE_CODE_COMPLEX: "ComplexFloat",
        gdb.TYPE_CODE_TYPEDEF: "AliasedAddressable",
        gdb.TYPE_CODE_NAMESPACE: "Namespace",
        gdb.TYPE_CODE_INTERNAL_FUNCTION: "DebuggerFunction",
    }

    knownIndexes = set()

    def run(self):

        Oracle._extract_symbols()

        searchers = [Searcher() for i in range(1)]

        for searcher in searchers:
            searcher.daemon = True
            # searcher.start()
            searcher.run()

        gdb.write("Joined!\n")

    @classmethod
    def _extract_symbols(cls):
        try:
            for symbol in cls._selectedFrame.block():
                try:
                    foundObj = dict()
                    foundObj["value"] = symbol.value(Oracle._selectedFrame)
                    foundObj["name"] = symbol.name
                    foundObj["parent"] = None
                    foundObj["is_valid"] = symbol.is_valid()
                    foundObj.update(cls._extract(foundObj["value"]))
                    cls.found.append(foundObj)
                except AlreadyFound:
                    continue
        except RuntimeError as e:
            gdb.write(str(e))

    @classmethod
    def _extract(cls, v):
        foundObj = dict()
        foundObj["frame"] = str(Oracle._selectedFrame)
        foundObj["address"] = str(v.address)
        foundObj["type"] = cls.true_type_name(v.type)
        foundObj["tag"] = v.type.tag
        foundObj["type_code"] = v.type.code
        addr = foundObj["address"]
        code = foundObj["type_code"]
        index = (code, addr, foundObj["type"])
        foundObj["index"] = index
        if index not in Oracle.knownIndexes:
            Oracle.knownIndexes.add(index)
            # gdb.write("Found index " + Oracle._lookup[index[0]] + " " + index[1] + "\n")
        else:
            # gdb.write("Already knew " + Oracle._lookup[index[0]] + " " + index[1] + "\n")
            raise AlreadyFound("Already found index " + str(index))
        return foundObj


    #hack!
    @staticmethod
    def true_type_name(typ):
        t = typ.strip_typedefs()
        typeName = collections.deque()
        while t.code in {gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY}:
            if t.code == gdb.TYPE_CODE_ARRAY:
                start, end = t.range()
                typeName.append("[" + str(end - start) + "]")
            elif t.code == gdb.TYPE_CODE_PTR:
                typeName.append("*")
            t = t.target()

        name = t.name

        while len(typeName):
            name += typeName.pop()

        return name


class Searcher(object):

    MAX_SEARCHERS = 4
    _arrowMatch = re.compile(r"([>,:<])")

    def run(self):

        missCount = 0
        while True:
            try:
                x = Oracle.found.popleft()
                missCount = 0
                self._describe(x)
                self._explore_object(x)
            except IndexError as e:
                if missCount >= 3:
                    return
                else:
                    gdb.write("Queue miss!\n")
                    missCount += 1
                    time.sleep(0.1)

    def _explore_object(self, x):
        code = x["value"].type.strip_typedefs().code
        if code == gdb.TYPE_CODE_ARRAY:
            self._explore_array(x)
        elif code == gdb.TYPE_CODE_STRUCT:
            self._explore_struct(x)
        elif code == gdb.TYPE_CODE_PTR:
            self._explore_pointer(x)

    def _describe(self, x):
        try:
            if (x["index"][1] != 'None'):
                Oracle.network.add_node(x["index"])
                Oracle.described.append(x)
        except gdb.MemoryError:
            gdb.write("debug: encountered invalid memory\n")

    def _explore_range(self, x, startRange, endRange):
        for element in range(int(startRange), int(endRange + 1)):
            foundObj = dict()
            foundObj.update(x)
            foundObj["value"] = x["value"][element]
            foundObj["name"] = x["name"] + "[" + str(element) + "]"
            foundObj["parent"] = x["index"]
            foundObj.update(Oracle._extract(foundObj["value"]))
            if element == int(startRange):
                Oracle.network.add_edge(foundObj["parent"], foundObj["index"], label="[]")
            if int(foundObj["address"], 16):
                Oracle.found.append(foundObj)

    def _explore_array(self, x):
        startRange, endRange = x["value"].type.strip_typedefs().range()
        self._explore_range(x, startRange, endRange)

    def _explore_struct(self, x):
        if x["index"][1] in {'None', None, 0x0, "0x0"}:
            return
        itr = x["value"].type.fields()
        fields = [x["index"]]
        for element in itr:
            foundObj = dict()
            foundObj.update(x)
            foundObj["value"] = x["value"][element]
            foundObj["parent"] = x["index"]
            try:
                foundObj.update(Oracle._extract(foundObj["value"]))
            except AlreadyFound:
                return
            if foundObj["address"] not in {'None', 0x0, "0x0", 0}:
                Oracle.found.append(foundObj)

    def _explore_pointer(self, x):
        foundObj = dict()
        foundObj.update(x)
        ## TODO: Make this handle char* correctly
        try:
            foundObj["value"] = x["value"].dereference()
            addr = int(foundObj["value"].address)
            foundObj["parent"] = x["index"]
            if addr not in Oracle.explored:
                if addr in NewBreak.allocated:
                    typeSize = foundObj["value"].type.sizeof
                    size = NewBreak.allocated[addr]
                    gdb.write("Found " + str(size / typeSize) + "\n")
                    # realType = foundObj["value"].type.array(0, size / typeSize - 1)
                    self._explore_range(x, 0, size / typeSize - 1)
                    Oracle.explored.add(addr)
                else:
                    foundObj["name"] = "*" + x["name"]
                    foundObj.update(Oracle._extract(foundObj["value"]))
                    if foundObj["address"] != "None":
                        Oracle.network.add_edge(foundObj["parent"], foundObj["index"], label="*")
                        Oracle.found.append(foundObj)
                        Oracle.explored.add(addr)
            else:
                foundObj.update(Oracle._extract(foundObj["value"]))
                Oracle.network.add_edge(foundObj["parent"], foundObj["index"], label="*")
        except gdb.MemoryError as e:
            gdb.write(str(e))
            return
        except gdb.error as e:
            gdb.write(str(e))
            return
        except AlreadyFound:
            gdb.write("Already found that one!\n")
            return


class x86_64(object):

    @staticmethod
    def get_arg(num):
        return int(gdb.selected_frame().read_register(['rdi', 'rsi'][num]))

    @staticmethod
    def get_ret():
        return int(gdb.selected_frame().read_register('rax'))


class NewFinishBreak(gdb.FinishBreakpoint):

    def __init__(self, size):
        super(NewFinishBreak, self).__init__(internal=True)
        self.size = size
        self.silent = True

    def stop(self):
        addr = x86_64.get_ret()
        NewBreak.allocated[addr] = self.size
        Oracle.explored.discard(addr)
        return False


class NewBreak(gdb.Breakpoint):

    allocated = dict()

    def __init__(self, internal=True, temporary=False):
        super(NewBreak, self).__init__("operator new", internal=internal, temporary=temporary)
        self.silent = True

    def stop(self):
        size = x86_64.get_arg(0)
        fb = NewFinishBreak(size)
        return False


class NewArrayBreak(gdb.Breakpoint):

    def __init__(self, internal=True, temporary=False):
        super(NewArrayBreak, self).__init__("operator new[]", internal=internal, temporary=temporary)
        self.silent = True

    def stop(self):
        size = x86_64.get_arg(0)
        # gdb.write("Broke on array allocation of size " + str(size) + "\n")
        fb = NewFinishBreak(size)
        return False

# b = NewBreak()
b2 = NewArrayBreak()
