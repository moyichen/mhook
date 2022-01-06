# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: qiyichen
# date:   2021/12/30
import atexit
import datetime
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from pprint import pprint, pformat

import frida

from AndroidDevice import AndroidDevice
from utils import log_info, log_error, log_warning

my_source = """
    var libGFrame_so = [
        {
            "user_name": "GNS_FRAME::CGWorkStation::onVsync(unsigned int, long long, int, bool)",
            "short_name": "GNS_FRAME::CGWorkStation::onVsync",
            "low_name": "_ZN9GNS_FRAME13CGWorkStation7onVsyncEjxib",
            // "parameters": { "in": [], "out": [], "return": '' },
            "rva": 1972485
        },
    ];
    hookMethods("libGFrame.so", libGFrame_so, false);
    hook_libraries["libGFrame.so"] = libGFrame_so;
"""

log_reg = "(?P<ts>.{21}) (?P<tid>\\d+) (?P<f_name>[\\w:~\\(\\*,\\s\\[\\]<>&\\)]+) (?P<tag>begin|end)(?P<tail>.*)"
begin_log_reg = "(?P<ts>.{21}) (?P<tid>\\d+) (?P<f_name>[\\w:~\\(\\*,\\s\\[\\]<>&\\)]+) (?P<tag>begin)(?P<tail>.*)"


@dataclass
class AgentConfig(object):
    name: str
    host: str = None
    port: int = None
    device_type: str = 'usb'
    device_id: str = None
    foremost: bool = False
    spawn: bool = False
    pause: bool = True
    debugger: bool = False


def convert_timestamp(log):
    ts_reg = re.compile('^([\\d\\.]+) (.*)', re.DOTALL)

    t = ts_reg.match(log)
    if not t:
        return log

    timestamp = float(t.group(1))
    msg = t.group(2)

    # 精确到毫秒
    d = datetime.datetime.fromtimestamp(timestamp)
    line_header = "{}".format(d.strftime("%m-%d %H:%M:%S.%f"))

    return "{} {}".format(line_header, msg)


def extract_tid(log):
    m = re.match(begin_log_reg, log, re.DOTALL)

    if not m:
        return None

    return int(m.group('tid'))


def add_thread_name(log, thread_name):
    m = re.match(begin_log_reg, log, re.DOTALL)

    if not m:
        return log

    ts = m.group('ts')
    tid = int(m.group('tid'))
    f_name = m.group('f_name')
    tag = m.group('tag')
    tail = m.group('tail')

    msg = "{} {} {} {} [{}]{}".format(ts, tid, f_name, tag, thread_name, tail)

    return msg


def get_thread_id_name_dict(pid):
    threads = {}
    device = AndroidDevice()
    app_thread_list = device.get_thread_list(pid)
    if len(app_thread_list) > 0:
        for t in app_thread_list:
            threads[t['TID']] = t['T_NAME']
    else:
        log_error('cannot retrieve the thread list of {}.'.format(pid))

    return threads


class OutputHandlers(object):
    logfile: Path = None
    pid: int = None
    threads: dict = None
    threads_no_name: list = []

    def __init__(self, filename: str):
        OutputHandlers.logfile = filename
        with open(OutputHandlers.logfile, 'w+') as f:
            pass

    def device_output(self):
        pass

    def device_lost(self):
        pass

    @staticmethod
    def session_on_detached(message: dict, crash):
        try:
            if message:
                log_info("(session detach message) {}".format(message))

            if crash:
                log_info("(process crash report)")
                log_info("\t{}".format(crash.report))
        except Exception as e:
            log_error("Failed to process an incoming message for a session detach signal: {}.".format(e))
            raise e

    @staticmethod
    def script_on_message(message: dict, data):
        try:
            if message and 'payload' in message:
                payload = message['payload']
                content = None
                if len(payload) > 0:
                    if isinstance(payload, dict):
                        content = json.dumps(payload)
                    elif isinstance(payload, str):
                        content = convert_timestamp(payload)

                        tid = extract_tid(content)
                        if tid:
                            # 尝试更新线程信息
                            if OutputHandlers.threads is None or (tid not in OutputHandlers.threads and tid not in OutputHandlers.threads_no_name):
                                OutputHandlers.threads = get_thread_id_name_dict(OutputHandlers.pid)

                            if tid in OutputHandlers.threads:
                                content = add_thread_name(content, OutputHandlers.threads[tid])
                            else:
                                OutputHandlers.threads_no_name.append(tid)
                    elif isinstance(payload, list):
                        content = pformat(payload)
                    else:
                        log_info("Dumping unknown agent message")
                        pprint(payload)
                if content:
                    log_info("(agent) {}".format(content))
                    with open(OutputHandlers.logfile, 'a+') as f:
                        f.write(content+"\n")
        except Exception as e:
            log_error("Failed to process an incoming message from agent: {}.".format(e))
            raise e


class Agent(object):
    config: AgentConfig = None
    device: frida.core.Device = None
    session: frida.core.Session = None
    script: frida.core.Script = None

    handlers: OutputHandlers = None
    pid: int = None
    resumed: bool = True
    agent_path: Path = None

    user_scripts: list = []

    def __init__(self, config: AgentConfig):
        self.config = config
        log_info("agent config: {}".format(self.config))
        self.handlers = OutputHandlers(Path(__file__).parent / 'message.log')
        self.agent_path = Path(__file__).parent / 'agent.js'
        atexit.register(self.teardown)

    def set_device(self):
        if self.config.device_id:
            self.device = frida.get_device(self.config.device_id)
        elif self.config.device_type:
            for dev in frida.enumerate_devices():
                if dev.type == self.config.device_type:
                    self.device = dev
                    break
        else:
            self.device = frida.get_local_device()

        if self.device is None:
            raise Exception("Unable to find device.")

        # Device(id="s24.btos.cn:7482", name="SX11M", type='usb')
        log_info("Device determined as: {}".format(self.device))
        params = self.device.query_system_parameters()
        log_info(pformat(params))

    def set_target(self):
        if self.config.foremost:
            try:
                log_info("Get the foremost application...")
                app = self.device.get_frontmost_application()
                if app is None:
                    raise Exception("No foremost application on {}.".format(self.device))

                # Application(identifier="com.autonavi.amapauto", name="高德地图", pid=18510, parameters={})
                log_info("The foremost application on {} is {}.".format(self.device, app))
                self.pid = app.pid
            except Exception as e:
                log_error("Could not get the foremost application on {}: {}.".format(self.device, e))
        elif self.config.spawn:
            try:
                log_info("Spawning `{}`...".format(self.config.name))
                self.pid = self.device.spawn(self.config.name)
                self.resumed = False
                log_info("Spawned `{}`.".format(self.config.name))
            except Exception as e:
                log_error("Could not spawn application {} on {}: {}.".format(self.config.name, self.device, e))
        else:
            try:
                self.pid = int(self.config.name)
            except ValueError:
                pass

            if self.pid is None:
                try:
                    self.pid = self.device.get_process(self.config.name).pid
                except Exception as e:
                    log_error("Could not get process {} on {}: {}.".format(self.config.name, self.device, e))

        OutputHandlers.pid = self.pid
        log_info("process PID determined as {}.".format(self.pid))

    def attach(self):
        if self.pid is None:
            raise Exception("A PID needs to be set before attach().")

        self.session = self.device.attach(self.pid)
        self.session.on('detached', self.handlers.session_on_detached)

        self.script = self.session.create_script(source=self._get_agent_source())
        self.script.on('message', self.handlers.script_on_message)
        self.script.load()

    def resume(self):
        if self.resumed:
            return

        if self.pid is None:
            raise Exception("Cannot resume without PID.")

        log_info("Resuming `{}`...".format(self.config.name))
        self.device.resume(self.pid)
        self.resumed = True

    def run(self):
        self.set_device()
        self.set_target()
        self.attach()

        if not self.config.pause:
            log_info("Asked to run without pausing, so resuming in run().")
            self.resume()

        log_info("{}".format(self.exports().env_frida()))

    def attach_script(self, source):
        session = self.device.attach(self.pid)
        script = session.create_script(source=source)
        script.on('message', self.handlers.script_on_message)
        script.load()
        self.user_scripts.append(script)

    def attach_script_file(self, filename):
        if not filename:
            filename = './frida.js'
        with open(filename, 'r') as f:
            source = "\n".join(f.readlines())
        self.attach_script(source)

    def exports(self) -> frida.core.ScriptExports:
        if not self.script:
            raise Exception("Needs a script created before reading exports().")

        return self.script.exports

    def _get_agent_source(self) -> str:
        """
            Loads the frida-compiled agent from disk.

            :return:
        """

        with open(self.agent_path, 'r', encoding='utf-8') as f:
            src = f.readlines()

        return ''.join([str(x) for x in src])

    def teardown(self):
        log_info("Cleanup...")
        try:
            if self.script:
                log_info("Unloading agent script...")
                self.script.unload()

            log_info("Unloading user scripts...")
            for s in self.user_scripts:
                s.unload()
        except frida.InvalidOperationError as e:
            log_error("Unable to run cleanups: {}.".format(e))


if __name__ == '__main__':
    # c = AgentConfig(name="高德地图", spawn=False)
    c = AgentConfig(name="com.autonavi.amapauto", spawn=True)
    a = Agent(c)
    a.run()
    a.attach_script(my_source)
    a.resume()
    log_info("start tracing. press any key to stop.")
    sys.stdin.read(1)
    api = a.exports()
    exports = api.android_file_ls("/data/local/tmp")
    pprint(exports)
    sys.stdin.read(1)
