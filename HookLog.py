# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: qiyichen
# date:   2021/3/9
import json
import re

from Addr2line import *
from PyechartHelper import plot_scatter, plot_report, plot_pie
from utils import *
from progressbar import *
import numpy as np


class HookLog(object):
    """
    filename为libhook.so生成的日志文件。
    时间戳1 - 时间戳2 - 线程时间 - 进程时间 - 线程Id - 函数名 - ...
    03-08 15:16:26.491269 1615187786.491269 0.430672 4.670938 29185 GNS_FRAME::CGFragment::inflater begin [MainScreen] invocation 0x7bc0ee7f
    03-08 15:16:26.491500 1615187786.491500 0.430904 4.671170 29185 GNS_FRAME::CGFragment::inflater end
    """
    def __init__(self, filename):
        self.line_header_reg = ".{21} (?P<timestamp>[\\d\\.]+) [\\d\\.]+ [\\d\\.]+ (?P<tid>\\d+) (?P<f_name>[\\w:~\\(\\*,\\s\\[\\]<>&\\)]+) (?P<tag>begin|end)"
        self.filename = filename
        with open(filename, 'r') as f:
            self.log = "".join(f.readlines())

        log_info('parse the hook log file to get thread {tid, thread_name}.')
        # 线程名与线程Id关系
        self.threads = {}
        # 下面日志中的函数名为有效函数名，用于过滤其他日志
        # 03-08 15:16:26.491269 1615187786.491269 0.430672 4.670938 29185 GNS_FRAME::CGFragment::inflater begin [MainScreen]
        self.functions = set()
        result = re.findall(self.line_header_reg + " \\[(.+)\\]", self.log)
        for timestamp, tid, f_name, tag, t_name in result:
            if tid not in self.threads:
                self.threads[tid] = t_name
            self.functions.add(f_name)

    def clip(self, begin_reg, end_reg):
        # begin_reg = ".*ShowSearchResultFragment.*begin"
        # end_reg = ".*commitRenderNode.*end"
        log_info("clip log: begin {}, end {}.".format(begin_reg, end_reg))
        if not begin_reg and not end_reg:
            return

        begin = re.search(begin_reg, self.log)
        if not begin:
            return
        start_idx = begin.start(0)
        end = re.search(end_reg, self.log[begin.end(0):])
        if not end:
            return
        end_idx = end.end(0) + begin.end(0)
        self.log = self.log[start_idx:end_idx]
        log_info("clip log: \n>> {}\n<< {}".format(begin.group(0), end.group(0)))
        with open(self.filename, 'w+') as f:
            f.write(self.log)
        # print(self.log)

    def get_function_call_lifecycles(self):
        """
            Returns: { thread_name: {function_name: [(begin_time, end_time)]} }
        """
        r2 = re.compile(self.line_header_reg)
        matched_index = self.get_matched_call()
        result = {}
        callstacks = {}
        progress = ProgressBar(maxval=len(matched_index)).start()
        first_timestamp = None
        log_buffer = self.log.split('\n')
        for i, idx in enumerate(matched_index):
            l = log_buffer[idx].strip()
            m = r2.match(l)
            if m:
                if not first_timestamp:
                    first_timestamp = float(m.group('timestamp'))
                timestamp = (float(m.group('timestamp')) - first_timestamp)
                tid = m.group('tid')
                if tid in self.threads:
                    t_name = self.threads[tid]
                else:
                    t_name = 'NA'
                f_name = m.group('f_name').strip()
                tag = m.group('tag').strip()

                if tid not in callstacks:
                    callstacks[tid] = []

                if tag == 'begin':
                    callstacks[tid].append({'function_name': f_name, 'begin_time': timestamp})
                elif tag == 'end':
                    if len(callstacks[tid]) > 0:
                        last_function = callstacks[tid].pop()
                        if last_function['function_name'] == f_name:
                            # add record
                            t_name = self.threads[tid]
                            if t_name not in result:
                                result[t_name] = {}
                            if f_name not in result[t_name]:
                                result[t_name][f_name] = []
                            result[t_name][f_name].append((last_function['begin_time'], timestamp))

                progress.update(i)
        progress.finish()

        return result

    def va2rva(self, modules, va):
        for m in modules.values():
            if m['start_address'] <= va < m['end_address']:
                return m['name'], va - m['start_address']
        log_warning('Can not find ' + hex(va) + ' in maps.')
        return 'na', va

    def gen_backtrace(self, filename, module_map, so_path):
        backtraces = []
        # {'backtrace': 'call stack'}
        backtrace_cache_dict = {}

        lines = self.log.split('\n')
        progress = ProgressBar(maxval=len(lines)).start()

        count = 0
        addr2line = Addr2line()
        for i, line in enumerate(lines):
            backtraces.append(line)
            r = re.match(self.line_header_reg + " backtrace \\d+:(?P<f_bt>.*)", line)
            if not r:
                continue

            count = count + 1
            timestamp = r.group('timestamp')
            tid = r.group('tid')
            f_name = r.group('f_name')
            f_bt = r.group('f_bt')
            rvas = ["=================================={}".format(timestamp),
                      "Thread #{}({})".format(tid, self.threads[tid]),
                      f_name + " called from"]

            for depth, va in enumerate(f_bt.strip(', ').split(',')):
                va = int(va, 16)
                if va in backtrace_cache_dict:
                    stack_line = backtrace_cache_dict[va]
                else:
                    so, rva = self.va2rva(module_map, va)
                    source_line = addr2line.convert_one_rva(os.path.join(so_path, os.path.basename(so)), rva)
                    stack_line = "pc 0x%08x : %s (%s)" % (rva, so, source_line)
                    backtrace_cache_dict[va] = stack_line

                rvas.append("#%02d %s" % (depth, stack_line))

            backtraces.append("\n\t\t".join(rvas))
            progress.update(i)

        progress.finish()
        log_info('parse the hook log file to get all the backtrace. total record = {}.'.format(count))
        if count > 0:
            safe_make_dirs(os.path.dirname(filename))
            with open(filename, 'w+') as f:
                f.write("\n".join(backtraces))
            # log_info("\n\n".join(backtraces))
            log_info('you also can open ' + filename + ' to check.')

        return backtraces

    def get_matched_call(self):
        matched_index = []
        r2 = re.compile(self.line_header_reg)
        stack = {}
        log_buffer = self.log.split('\n')
        for lineno, l in enumerate(log_buffer):
            l = l.strip()
            m = r2.match(l)
            if m:
                tid = m.group('tid')
                f_name = m.group('f_name').strip()
                tag = m.group('tag').strip()

                if f_name not in self.functions:
                    continue

                if tid not in stack:
                    stack[tid] = []

                if tag == 'begin':
                    # 入栈
                    stack[tid].append((lineno, tid, tag))
                else:
                    if len(stack[tid]) > 0:
                        (_lineno, _tid, _tag) = stack[tid].pop()
                        matched_index.append(_lineno)   # begin行号入栈
                        matched_index.append(lineno)    # end行号入栈
                    else:
                        print('ad')
        matched_index.sort()
        return matched_index

    def gen_speedscope_json(self, filename, auto_open=False):
        speedscope = {
            "exporter": "speedscope@1.13.0",
            "name": os.path.basename(filename),
            "activeProfileIndex": 0,
            "$schema": "https://www.speedscope.app/file-format-schema.json",
            "shared": {
                "frames": [
                ]
            },
            "profiles": [
            ]
        }

        r2 = re.compile(self.line_header_reg)
        frames_index = {}
        events = {}
        first_timestamp = None
        matched_index = self.get_matched_call()
        log_buffer = self.log.split('\n')
        for idx in matched_index:
            l = log_buffer[idx].strip()
            m = r2.match(l)
            if m:
                if not first_timestamp:
                    first_timestamp = float(m.group('timestamp'))
                timestamp = (float(m.group('timestamp')) - first_timestamp)
                tid = m.group('tid')
                if tid in self.threads:
                    t_name = self.threads[tid]
                else:
                    t_name = 'NA'
                f_name = m.group('f_name').strip()
                tag = m.group('tag').strip()

                if tid not in events:
                    events[tid] = {
                        "type": "evented",
                        "name": "{} tid: {}".format(t_name, tid),
                        "unit": "seconds",
                        "startValue": 0x7fffffff,
                        "endValue": 0,
                        "events": []
                    }
                    speedscope["profiles"].append(events[tid])

                if f_name not in frames_index:
                    frames_index[f_name] = len(speedscope["shared"]["frames"])
                    speedscope["shared"]["frames"].append(
                        {
                            "name": f_name,
                            # "file": "bbbb"
                        }
                    )

                if events[tid]["startValue"] > timestamp:
                    events[tid]["startValue"] = timestamp
                if events[tid]["endValue"] < timestamp:
                    events[tid]["endValue"] = timestamp

                if tag == 'begin':
                    events[tid]["events"].append(
                        {
                            "type": "O",
                            "frame": frames_index[f_name],
                            "at": timestamp
                        }
                    )
                else:
                    events[tid]["events"].append(
                        {
                            "type": "C",
                            "frame": frames_index[f_name],
                            "at": timestamp
                        }
                    )

        safe_make_dirs(os.path.dirname(filename))
        with open(filename, "w+") as f:
            f.write(json.dumps(speedscope))

        if auto_open:
            open_file(filename)

    def gen_report(self, report_filename, extra_info=[], auto_open=False, needPie=False, isDuration=True):
        function_calls = self.get_function_call_lifecycles()
        traces = []

        for (k, v) in extra_info:
            traces.append('<p>{}: {}</p>'.format(k, v))

        for thread_name in function_calls.keys():
            for function_name in function_calls[thread_name].keys():
                if isDuration:
                    # 获取单次调用耗时序列
                    x, y = self.get_call_durations(function_calls[thread_name][function_name])
                else:
                    # 获取两次调用耗时序列
                    x, y = self.get_call_gap(function_calls[thread_name][function_name])
                if not x or not y:
                    continue

                scatter = {
                    'x': x,
                    'y': y,
                    'name': function_name
                }
                c = plot_scatter([scatter], title=thread_name + ': ' + function_name, xaxis='timestamp',
                                 yaxis='elapsed time(ms)')
                traces.append(c)
                if needPie:
                    dn = np.array(y)
                    v1 = dn.max()
                    v1 = int((v1 + 9) / 10) + 1
                    v0 = 0
                    xx = []
                    yy = []
                    for v in range(0, v1):
                        p = np.where((v0 * 10 < dn) & (dn <= v * 10))[0].size
                        if p > 0:
                            yy.append(p)
                            xx.append("({}, {}]".format(v0 * 10, v * 10))
                        v0 = v
                    c = plot_pie({'x': xx, 'y': yy, 'kwargs': {'hole': .5}})
                    traces.append(c)

        plot_report(traces, report_filename)
        if auto_open:
            open_file(report_filename)

        return report_filename

    def get_call_durations(self, call_times):
        # [(begin_time, end_time), (begin_time, end_time), ...]
        x = []
        y = []
        for begin_time, end_time in call_times:
            d = int((end_time - begin_time) * 1000)
            x.append(begin_time)
            y.append(d)
        return x, y

    def get_call_gap(self, call_times):
        # [(begin_time, end_time), (begin_time, end_time), ...]
        if len(call_times) < 2:
            return None, None

        x = []
        y = []
        last_begin_time, last_end_time = call_times[0]
        for begin_time, end_time in call_times[1:]:
            d = int((begin_time - last_begin_time) * 1000)
            x.append(begin_time)
            y.append(d)
            last_begin_time = begin_time
        return x, y


if __name__ == '__main__':
    pass
