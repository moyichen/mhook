# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/3/23
import re
from FridaAgent import *
from Hookee import Hookee
from Hooker import Hooker
from utils import *
from progressbar import *


class FridaHooker(Hooker):
    def __init__(self, hookee: Hookee, device: AndroidDevice, auto_start=False):
        super().__init__(hookee, device, auto_start)
        self.fridaAgent = FridaAgent()
        self.fridaAgent.check_version()

    def prepare(self):
        pass

    def start_hook(self):
        self.start_app()
        self.fridaAgent.connect()
        success = self.fridaAgent.attach(self.hookee.name)
        if not success:
            return

        if not self.auto_start:
            input('Press any key to start tracing.')
        else:
            log_info("Automatically start tracing.")

        self.modules = self.device.get_modules(self.hookee.name)
        self.fridaAgent.inject(self.config)

    def stop_hook(self):
        threads = self.get_thread_id_name_dict()
        log = self.convert_2_auto_hook_log(self.fridaAgent.log_buffer, threads)
        log_info("the log length is {}.".format(len(log)))

        self.timestamp = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
        self.local_log = "{}/hook-{}-{}.log".format(self.log_dir, self.hookee.name, self.timestamp)
        safe_make_dirs(os.path.dirname(self.local_log))
        with open(self.local_log, 'w+') as f:
            f.write(log)

    def make_js_code(self, sym, backtrace):
        if backtrace:
            js_code = '''
                hookMethodWithBt("{so_name}", 
                            "{user_name}",
                            "{low_name}",
                            {rva:#x});
            '''.format(so_name=sym['so_name'], user_name=sym['user_name'], low_name=sym['low_name'], rva=sym['rva'] + 1)
        else:
            js_code = '''
                hookMethod("{so_name}", 
                            "{user_name}",
                            "{low_name}",
                            {rva:#x});
            '''.format(so_name=sym['so_name'], user_name=sym['user_name'], low_name=sym['low_name'], rva=sym['rva'] + 1)
        return js_code

    def gen_config_from_file(self, filename, print_log):
        super().gen_config_from_file(filename, print_log)
        self.fridaAgent.setDebugMode(print_log)

    def gen_config(self, sym_list, backtrace=False):
        log_info("generate hook config: {} with option {}.".format(sym_list, backtrace))
        syms, unfounded_syms = self.get_full_symbols(sym_list)
        self.config = jscode_global
        for s in syms:
            if s['size'] <= 4:
                log_warning('{}:{} is too small to hook well. Skip it.'.format(s['user_name'], s['so_name']))
                continue
            self.config += self.make_js_code(s, backtrace)
        self.fridaAgent.setDebugMode(self.debugMode)

    def convert_2_auto_hook_log(self, log, threads):
        log_info('Convert frida log to auto hook log.')
        r = re.compile('^([\\d\\.]+) (\\d+) (.*) (begin|end)(.*)$')
        hooklog = []
        for line in log:
            m = r.match(line)
            if m:
                timestamp = float(m.group(1))
                tid = int(m.group(2))
                f_name = m.group(3)
                tag = m.group(4)
                bt = m.group(5)
                if tid not in threads:
                    log_warning("Can not find the name of thread {} in {}.".format(tid, threads))
                    t_name = 'NA'
                else:
                    t_name = threads[tid]

                d = datetime.datetime.fromtimestamp(timestamp)
                # 精确到毫秒
                str_st = d.strftime("%m-%d %H:%M:%S.%f")
                line = "{} {:.6f} 0.000000 0.000000 {} {} {}".format(str_st, timestamp, tid, f_name, tag)
                if tag == 'begin':
                    if len(bt) == 0:
                        line = line + ' [' + t_name + ']'
                    else:
                        line = line + bt
            hooklog.append(line)
        return "\n".join(hooklog)
