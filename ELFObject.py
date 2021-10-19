# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: qiyichen
# date:   2020/6/12
import os
import re
import prettytable

import CmdHelper
from utils import log_info, log_error, log_fatal


def demangle_symbol(mangled_symbol, options=''):
    output = CmdHelper.GetCmdOutput(['arm-linux-androideabi-c++filt', options, mangled_symbol])
    r = re.match("([\\w:]+)", output.strip())
    return r.group(1)


def demangle_symbols(mangled_symbols, options=''):
    output = CmdHelper.GetCmdOutput(['arm-linux-androideabi-c++filt', options] + mangled_symbols)
    output = output.strip()
    output = output.split('\n')
    assert len(mangled_symbols) == len(output)
    return output


class ELFObject(object):
    def __init__(self, elf):
        self.elf = elf
        self.so_name = os.path.basename(elf)
        self.symbols = []
        self.machine = "arm"  # AArch64
        self.parse_header()
        self.nm = 'arm-linux-androideabi-nm'
        if self.machine == 'aarch64':
            self.nm = 'aarch64-linux-android-nm'

        self.parse_sym()

    def parse_header(self):
        output = CmdHelper.GetCmdOutput(['arm-linux-androideabi-readelf', '-h', self.elf])
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            r = re.match("^Machine:\\s+(.*)", line)
            if r:
                self.machine = r.group(1).strip().lower()

    def parse_sym(self):
        so_name = os.path.basename(self.elf)
        output1 = CmdHelper.GetCmdOutput([self.nm, '-a', self.elf])
        nm_options = '-aS'
        if output1.startswith(self.nm):
            nm_options = '-DS'
        output1 = CmdHelper.GetCmdOutput([self.nm, nm_options, self.elf])
        output2 = CmdHelper.GetCmdOutput([self.nm, nm_options+'C', self.elf])
        lines1 = output1.split('\n')
        lines2 = output2.split('\n')
        # 0025655c T _ZThn8_N9GNS_FRAME9CGPackageD0Ev
        for line1, line2 in zip(lines1, lines2):
            line1 = line1.strip()
            line2 = line2.strip()
            m1 = re.match('(\\w+) (\\w+) ([UWVTAt]) (.*)', line1)
            m2 = re.match('(\\w+) (\\w+) ([UWVTAt]) (.*)', line2)
            if m1 and m2:
                sym_rva = int(m1.group(1), 16)
                sym_size = int(m1.group(2), 16)
                sym_type = m1.group(3)
                sym_low_name = m1.group(4)
                sym_user_name = m2.group(4)
                m3 = re.match('(.*)\\(', sym_user_name)
                if m3:
                    sys_short_name = m3.group(1)
                else:
                    sys_short_name = sym_user_name
                # print("{}\n----{}".format(sym_user_name, sys_short_name))
                self.symbols.append({'rva': sym_rva, 'hex': hex(sym_rva), 'size': sym_size, 'type': sym_type,
                                     'low_name': sym_low_name, 'user_name': sym_user_name, 'so_name': so_name,
                                     'short_name': sys_short_name})

    def print_all_symbols(self):
        tb = prettytable.PrettyTable()
        tb.field_names = ['rva', 'size', 'type', 'name', 'user_name']
        tb.align = 'l'
        for v in self.symbols:
            tb.add_row([v['rva'], v['size'], v['type'], v['low_name'], v['user_name']])
        log_info(tb.get_string())

    def find_symbol(self, reg_str, type_filters=[]):
        result = []

        for sym in self.symbols:
            if sym['type'] in type_filters:
                continue

            if sym['user_name'].startswith('non-virtual') or \
                    sym['user_name'].startswith('vtable') or \
                    sym['user_name'].startswith('base::internal::') or \
                    sym['user_name'].startswith('typeinfo'):
                continue

            r = re.search(reg_str, sym['user_name'], re.IGNORECASE)
            if r:
                # 过滤掉rva相同的
                is_exist = False
                for s in result:
                    if s['rva'] == sym['rva'] and s['so_name'] == sym['so_name']:
                        is_exist = True
                if not is_exist:
                    result.append(sym)

        return result if len(result) > 0 else None


if __name__ == '__main__':
    pass
    elf = ELFObject('output/com.autonavi.amapauto/pkg.5.5.0.103155/symbol/libGFrame.so')
