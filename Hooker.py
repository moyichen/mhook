# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/3/23
import json
import shutil
import threading
from pprint import pprint

import threadpool
from time import sleep

import Hookee
from AndroidDevice import AndroidDevice
from ELFObject import ELFObject
from HookLog import HookLog
from utils import *
from progressbar import *


class SymbolLoader(object):
    def __init__(self, _symbol_dir):
        self.lock = threading.Lock()
        self.soes = []
        self.symbol_dir = _symbol_dir

    def load_symbol(self, fn):
        if not fn.endswith('.so'):
            return

        elf = ELFObject(os.path.join(self.symbol_dir, fn))
        self.lock.acquire()
        self.soes.append(elf)
        self.lock.release()

    def load(self, files):
        pool = threadpool.ThreadPool(int(len(files) / 2) + 1)
        requests = threadpool.makeRequests(self.load_symbol, files)
        [pool.putRequest(req) for req in requests]

        pool.wait()
        log_info('Completed to load all symbols!')
        return self.soes

    def findSymbol(self, filter_so, filter_sym, type_filters):
        result = []
        if filter_so:
            log_info('find symbol `{}` in `{}`'.format(filter_sym, filter_so))

        for elf in self.soes:
            if filter_so and elf.so_name != filter_so:
                continue

            matched_syms = elf.find_symbol(filter_sym, type_filters)
            if matched_syms:
                result.extend(matched_syms)

        return result


class LibrarySymbol(object):
    def __init__(self):
        self.library = {}

    def addSymbol(self, sym):
        so_name = sym["so_name"]
        low_name = sym["low_name"]
        if so_name not in self.library:
            self.library[so_name] = {}

        if low_name not in self.library[so_name]:
            self.library[so_name][low_name] = sym

    def addSymbols(self, syms):
        for sym in syms:
            self.addSymbol(sym)

    def hasSymbols(self):
        return len(self.library) > 0

    def toJson(self):
        return json.dumps(self.library, indent=4, sort_keys=True)


class Hooker(object):
    def __init__(self, hookee: Hookee, device: AndroidDevice, auto_start=False):
        self.auto_start = auto_start
        self.hookee = hookee
        self.device = device
        self.modules = None
        self.timestamp = None
        self.local_log = None
        self.debugMode = False  # 同步输出到控制台
        self.log_dir = "./output/{}/{}/log".format(self.hookee.name, self.hookee.version)
        self.report_dir = "./output/{}/{}/report".format(self.hookee.name, self.hookee.version)
        self.config = None  # hookconfig.json or js code

    def setDebugMode(self, debugMode: bool):
        self.debugMode = debugMode

    def gen_config(self, sym_list, backtrace):
        pass

    def prepare(self):
        return False

    def clear(self):
        pass

    def start_hook(self):
        pass

    def stop_hook(self):
        pass

    def clip(self, begin_reg, end_reg):
        hooklog = HookLog(self.local_log)
        hooklog.clip(begin_reg, end_reg)

    def gen_report(self, needPie=False, isDuration=True):
        app_info = [('app', self.hookee.name), ('version', self.hookee.version)]
        device_info = self.device.get_device_info(['manufacturer', 'model', 'resolution',
                                                   'android', 'SurfaceFlinger refresh-rate'])
        app_info = app_info + device_info

        hooklog = HookLog(self.local_log)

        modules = self.device.get_modules(self.hookee.name)
        if not modules:
            modules = self.modules
        backtrace_filename = '{}/hook-{}-{}-{}.backtrace'.format(self.report_dir, self.hookee.name, self.hookee.version,
                                                                 self.timestamp)
        hooklog.gen_backtrace(backtrace_filename, modules, self.hookee.symbol_dir)

        json_filename = '{}/hook-{}-{}-{}.speedscope.json'.format(self.report_dir, self.hookee.name,
                                                                  self.hookee.version, self.timestamp)
        hooklog.gen_speedscope_json(json_filename, True)

        report_filename = '{}/hook-{}-{}-{}.html'.format(self.report_dir, self.hookee.name, self.hookee.version,
                                                         self.timestamp)
        hooklog.gen_report(report_filename, app_info, True, needPie=needPie, isDuration=isDuration)

        open_file(self.local_log)

    def get_thread_id_name_dict(self):
        threads = {}
        pid = self.device.pidof(self.hookee.name)
        app_thread_list = self.device.get_thread_list(pid)
        if len(app_thread_list) > 0:
            for t in app_thread_list:
                threads[t['TID']] = t['T_NAME']
        else:
            log_error('cannot retrieve the thread list of {}.'.format(self.hookee.name))

        return threads

    def start_app(self):
        self.device.start_app(self.hookee.name)

    def stop_app(self):
        self.device.stop_app(self.hookee.name)

    # 查看是否存在任意符号文件
    def is_any_symbol(self):
        if os.listdir(self.hookee.symbol_dir):
            return True

        return False

    def download_miss_so(self):
        log_info('download the so file from the device to the local directory: ' + self.hookee.symbol_dir)
        shutil.rmtree(self.hookee.symbol_dir)
        safe_make_dirs(self.hookee.symbol_dir)

        pid = self.device.pidof(self.hookee.name)
        if pid == -1:
            self.start_app()
            sleep(5)

        modules = self.device.get_modules(self.hookee.name)

        # 将缺失的so拷贝到本地
        for m in modules.keys():
            if not m.endswith('so'):
                continue

            so_basename = os.path.basename(m)
            so = os.path.join(self.hookee.symbol_dir, so_basename)
            if not os.path.exists(so):
                self.device.download_file(m, so)

    def get_so_files(self, syms):
        # 指定so的情况下，只加载指定的so
        so_files = []
        for sym in syms:
            sym_and_so = sym.split('#')
            if len(sym_and_so) > 1:
                if sym_and_so[1] not in so_files:
                    so_files.append(sym_and_so[1])
            else:
                # 有一个未指定就需要遍历所有的so
                so_files = os.listdir(self.hookee.symbol_dir)
                break
        return so_files

    def get_full_symbols_dict(self, sym_list, type_filters=[]):
        '''

        :param sym_list: ["abc#libXXX.so", "efg", ...]
        :param type_filters:
        :return: {'so_name': xxx, [{'user_name': xxx, 'low_name': xxx, 'rva': xxx}, {}, ...]}
        '''
        result = LibrarySymbol()
        unfounded_syms = []

        symLoader = SymbolLoader(self.hookee.symbol_dir)
        so_files = self.get_so_files(sym_list)
        symLoader.load(so_files)

        for sym in sym_list:
            sym_and_so = sym.split('#')
            filter_sym = sym_and_so[0]
            filter_so = None
            if len(sym_and_so) > 1:
                filter_so = sym_and_so[1]

            matched_syms = symLoader.findSymbol(filter_so, filter_sym, type_filters)
            if len(matched_syms) == 0:
                unfounded_syms.append(sym)
            else:
                result.addSymbols(matched_syms)

        if result.hasSymbols():
            log_info('the following symbols will be hooked.')
            s = result.toJson()
            log_info(s)

        if len(unfounded_syms) > 0:
            if len(sym_list) == len(unfounded_syms):
                log_error('the following symbols have not been founded in any dynamic libraries:')
                log_error("\n".join(unfounded_syms))
                result = None
            else:
                log_warning('the following symbols have not been founded in any dynamic libraries:')
                log_warning("\n".join(unfounded_syms))

        return result, unfounded_syms

    def gen_config_from_file(self, filename, print_log):
        with open(filename, 'r') as f:
            self.config = f.readlines()
            self.config = "".join(self.config)
