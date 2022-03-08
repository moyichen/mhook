# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2020/6/1
from CmdHelper import *
from utils import *


class Addr2line(object):
    class Dso(object):
        def __init__(self):
            self.symbol_to_address = {'mangled_name'}

    def __init__(self):
        self.so_map = {}
        self.line_cache = {}

    def get_so_map(self, so):
        if so in self.so_map:
            return self.so_map[so]

        symbol_to_address = {}
        symbols = GetCmdOutput(['arm-linux-androideabi-nm', '-DC', so])
        symbols = symbols.split('\n')
        for i in symbols:
            m = re.match('(\\w+) [UVWTA] (.*)', i.strip())
            if m:
                addr = int(m.group(1), 16)
                sym = m.group(2)
                symbol_to_address[sym] = addr

        self.so_map[so] = symbol_to_address
        return symbol_to_address

    def get_symbol_address(self, so, sym):
        symbol_to_address = self.get_so_map(so)
        if sym in symbol_to_address:
            return symbol_to_address[sym]
        return 0

    def convert_one_rva(self, so, rva):
        idx = so+hex(rva)
        if idx in self.line_cache:
            return self.line_cache[idx]

        symbol_to_address = self.get_so_map(so)
        if len(symbol_to_address) == 0:
            return "" + hex(rva)

        o = GetCmdOutput(['arm-linux-androideabi-addr2line', '-pifC', '-e', so, hex(rva)])
        log_debug(o)

        # o = o.strip().split('\n')
        # f_name = o[0].strip()
        # if f_name in symbol_to_address:
        #     f_name = f_name + '+' + hex(rva - symbol_to_address[f_name])
        # source_line = o[1].strip()

        result = o.strip()#f_name + " at " + source_line
        self.line_cache[idx] = result
        return result

    def convert_rva_list(self, so_rva, so_path):
        output = []
        for so, rva in so_rva:
            so = os.path.join(so_path, os.path.basename(so))
            o = self.convert_one_rva(so, rva)
            output.append(o)

        return output

    def convert_bacaktrace(self, so_rva_list, so_path):
        backtraces = self.convert_rva_list(so_rva_list, so_path)

        rvas = []
        depth = 0
        for (so, rva), f in zip(so_rva_list, backtraces):
            rvas.append("#%02d pc 0x%08x : %s (%s)" % (depth, rva, so, f))
            depth += 1
        return rvas
