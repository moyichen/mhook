# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/3/31
import os
import re
import time
import click
import CmdHelper
from utils import safe_make_dirs, log_info, log_error, log_debug, log_warning, open_file


class AndroidDevice(object):
    busybox = '/data/local/tmp/busybox'

    @staticmethod
    def get_online_devices():
        """ Get the list of active attached devices.
        Returns:

        """
        output = CmdHelper.GetCmdOutput(['adb', 'devices'])
        # re_device = re.compile('^(emulator-[0-9]+)\tdevice', re.MULTILINE)
        # re_device = re.compile('^([a-zA-Z0-9_:.-]+)\toffline$', re.MULTILINE)
        re_device = re.compile('^([\\w:.-]+)\tdevice$', re.MULTILINE)
        devices = re_device.findall(output)
        return devices

    def __init__(self, device_serial: str = None):
        online_devices = self.get_online_devices()
        if device_serial:
            if device_serial in online_devices:
                self._device_serial = device_serial
            else:
                raise Exception("The device {} is offline.".format(device_serial))
        else:
            choice = 0
            if len(online_devices) == 0:
                raise Exception("No device connected.")
            elif len(online_devices) > 1:
                for i, d in enumerate(online_devices):
                    click.secho("{}. {}".format(i, d))
                choice = int(input("There are more than one device connected, please choose one to use."))

            self._device_serial = online_devices[choice]

        self.arch = self.ShellCmd(['getprop', 'ro.product.cpu.abi']).strip()
        log_info("device: {}".format(self._device_serial))
        log_info("arch: {}".format(self.arch))

        self._install_busybox_shell()

    def _install_busybox_shell(self):
        if not self.file_exist(self.busybox):
            self.upload_file('./bin/arm/busybox', self.busybox)
            self.chmod(self.busybox, '777')
        try:
            self.ShellCmd([self.busybox])
            log_info('busybox works well.')
        finally:
            log_info('busybox can not work well on the device {}.'.format(self._device_serial))

    # =================================================
    # app commands
    # =================================================
    def install(self, app):
        self.AdbProgressCmd(['install', '-r', app])

    def uninstall(self, app):
        self.AdbCmd(['uninstall', app])

    def start_app(self, app):
        activity = self.get_app_info(app)['launch_activity']
        log_info('launch: ' + activity)
        self.ShellCmd(['am', 'start', '-n', activity])

    def stop_app(self, app):
        log_info('stop: ' + app)
        if isinstance(app, int):
            self.ShellCmd(['kill', '-9', app])
        else:
            self.ShellCmd(['am', 'force-stop', app])

    def signal(self, app, sig):
        _pid = self.pidof(app)
        if _pid != -1:
            self.ShellCmd(['kill', '-' + sig, str(_pid)])

    def tombstone(self, pid):
        if isinstance(pid, str):
            real_pid = self.pidof(pid)
        else:
            real_pid = pid

        if not real_pid:
            log_error('Can not find {}'.format(pid))
            return None

        output = self.ShellCmd(['debuggerd', str(real_pid)])

        local_file = './output/tombstone_{}.log'.format(pid)
        if output.startswith('*** *** *** *** ***'):
            with open(local_file, "w+") as f:
                f.write(output)
        else:
            # file list
            output = output.strip().split('\n')
            if len(output) != 2:
                log_error(output)
                return None

            _, tombstone = output[1].split(':')
            tombstone = tombstone.strip()
            self.download_file(tombstone, local_file)
        return local_file

    def list_app(self):
        apps = []
        output = self.ShellCmd(['pm', 'list', 'packages', '-3'])
        lines = output.split('\n')

        if len(lines) == 0:
            return None

        for line in lines:
            aa = line.strip().split(':')
            if len(aa) > 1:
                apps.append(aa[1])
        apps.sort()
        return apps

    def get_app_info(self, app):
        result = {'version': None, 'launch_activity': None}
        output = self.ShellCmd(['dumpsys', 'package', app])
        m = re.search('versionName=(.*)', output)
        if m:
            result['version'] = m.group(1).strip()
        else:
            log_error('get_app_info : ' + output)
            return None

        a = app.replace('.', '\\.')
        pattern = 'android\\.intent\\.action\\.MAIN:.*?{}/([\\w\\.]+)'.format(a)
        r = re.search(pattern, output, re.DOTALL)
        if r:
            result['launch_activity'] = app + '/' + r.group(1)
        # log_debug(result)
        return result

    def get_thread_list(self, ps_filter=None):
        """
            +------+------+--------+-----------------+----+-----+---+------------+-------+-----+-----+
            | PID  | TID  | P_NAME |      T_NAME     | PR | CPU | S |    VSS     |  RSS  | PCY | UID |
            +------+------+--------+-----------------+----+-----+---+------------+-------+-----+-----+
            | 3101 | 3101 |  amap  | tonavi.amapauto | 20 |  0  | S | 1178710016 | 22016 |  0  | aaa |
            | 3101 | 4208 |  amap  | Defalut Executo | 20 |  0  | S | 1178710016 | 22017 |  0  | aaa |
            +------+------+--------+-----------------+----+-----+---+------------+-------+-----+-----+
        """
        threads = []

        p = self.ps(ps_filter)
        if len(p) == 0:
            return threads

        p = p[0]
        p_id = p['PID']
        filter_name = p['NAME']

        log_info('get_thread_list: {} {}'.format(filter_name, p_id))
        output = self.ShellCmd([self.busybox, 'ps', '-T'])
        output = output.split('\n')

        for line in output[1:]:
            line = line.strip()
            r = re.match('\\s*(\\d+)\\s+(\\w+)\\s+[0-9,:h]+\\s+(.*)$', line)
            if r:
                t_id = int(r.group(1))
                u_id = r.group(2)
                command = r.group(3).strip()
                if command.startswith('['):
                    p_name = command[1:-1]
                    t_name = p_name
                elif command.startswith('{'):
                    r = re.match('\\{(.*)\\}\\s+(.*)', command)
                    if r:
                        t_name = r.group(1)
                        p_name = r.group(2)
                else:
                    p_name = command
                    t_name = command

                if p_name == filter_name:
                    t = {
                        'PID': p_id,
                        'TID': t_id,
                        'P_NAME': p_name,
                        'T_NAME': t_name,
                        'PR': 0,
                        'CPU': 0,
                        'S': 'NA',
                        'VSS': 0,
                        'RSS': 0,
                        'PCY': 0,
                        'UID': u_id
                    }
                    threads.append(t)

        return threads

    # 6a4f2000-6a634000 r--p 00000000 b3:04 211818     /data/dalvik-cache/data@app@com.autonavi.amapauto-1.apk@classes.dex
    def get_modules(self, app):
        log_info("get the modules of {}".format(app))

        pid = self.pidof(app)
        if pid == -1:
            log_warning('the app {} have not been launched yet.'.format(app))
            return None

        modules = {}
        maps = self.ShellCmd(['cat', '/proc/' + str(pid) + '/maps'])

        p = re.compile(
            '(?P<saddr>[0-9a-fA-F]+)\\-(?P<eaddr>[0-9a-fA-F]+)\\s+[rwpxs\\-]{4}\\s+[0-9a-fA-F]+\\s+\\w+:\\w+\\s+\\d+\\s+(?P<name>.*)')
        lines = maps.split('\n')
        for l in lines:
            m = p.match(l)
            if not m:
                continue

            name = m.group('name').strip()
            if not name.endswith('.so'):
                continue

            start_address = int(m.group('saddr'), 16)
            end_address = int(m.group('eaddr'), 16)
            if name not in modules:
                modules[name] = {'name': name, 'start_address': start_address, 'end_address': end_address}
            else:
                if modules[name]['start_address'] > start_address:
                    modules[name]['start_address'] = start_address
                if modules[name]['end_address'] < end_address:
                    modules[name]['end_address'] = end_address

        return modules

    def pidof(self, app):
        output = self.ShellCmd([self.busybox, 'pidof', app])
        output = output.strip()
        if len(output) == 0:
            return -1
        return int(output)

    # =================================================
    # touch/key commands
    # =================================================
    def touch_tap(self, x: int, y: int):
        self.ShellCmd(['input', 'tap', str(x), str(y)])

    def touch_back(self):
        self.ShellCmd(['input', 'keyevent', '4'])

    def touch_home(self):
        self.ShellCmd(['input', 'keyevent', 'KEYCODE_HOME'])

    def touch_swipe(self, x0, y0, x1, y1, d):
        self.ShellCmd(['input', 'swipe', str(x0), str(y0), str(x1), str(y1), str(d)])

    # =================================================
    # file/directory commands
    # =================================================
    def upload_file(self, local_filename, remote_filename):
        log_info('upload: {} -> {}.'.format(local_filename, remote_filename))
        self.AdbProgressCmd(['push', local_filename, remote_filename])

    def download_file(self, remote_filename, local_filename):
        log_info('download: {} -> {}.'.format(remote_filename, local_filename))
        safe_make_dirs(os.path.dirname(local_filename))
        self.AdbProgressCmd(['pull', remote_filename, local_filename])

    def file_exist(self, remote_filename):
        output = self.ShellCmd(['ls', remote_filename])
        if output.find("No such file or directory") > 0:
            return False
        return True

    # =================================================
    # common shell commands
    # =================================================
    def ls(self, directory, flags=None):
        cmd = ['ls', directory]
        if flags:
            cmd.append(flags)
        output = self.ShellCmd(cmd)
        output = output.splitlines()
        result = []
        for line in output:
            if line.find('No such file or directory') == -1:
                result.append(line)

        if len(result) == 0:
            result = None
        return result

    def ps(self, ps_filter=None):
        """
            List all of the processes on the device.
            ps command output on the following format:
            PID   USER     TIME  COMMAND
            1     0        0:01  /init
            2     0        0:00 [kthreadd] ads

            Returns:
                [{PID, VSIZE, RSS, NAME}, ...]
        """
        procs = []

        # 纯数字判定为pid
        filter_pid = None
        if isinstance(ps_filter, int):
            filter_pid = ps_filter
        elif ps_filter and re.match('\\d+', ps_filter):
            filter_pid = int(ps_filter)

        output = self.ShellCmd([self.busybox, 'ps'])
        output = output.split('\n')

        for line in output[1:]:
            line = line.strip()

            # 过滤名字太长
            if len(line) > 128:
                continue

            r = re.match('(\\d+)\\s+\\w+\\s+[0-9,:h]+\\s+(.*)$', line)
            if not r:
                continue

            p_id = int(r.group(1))
            if filter_pid and p_id != filter_pid:
                continue

            p_name = r.group(2).strip()
            if p_name.startswith('['):
                p_name = p_name[1:-1]
            elif p_name.startswith('{'):
                r = re.match('\\{.*\\}\\s+(.*)', p_name)
                if r:
                    p_name = r.group(1)

            if not filter_pid and ps_filter and not re.search(ps_filter, p_name, re.IGNORECASE):
                continue

            procs.append({"NAME": p_name, "PID": p_id, "VSIZE": 0, "RSS": 0})

        if len(procs) == 0:
            log_warning('The process `{}` does not exist.'.format(ps_filter))

        return procs

    def rm(self, remote_filename, flags=None):
        output = self.ShellCmd(['rm', flags, remote_filename])
        log_debug(output)
        if output.find("No such file or directory") > 0:
            return False
        return True

    def cat(self, filename):
        output = self.ShellCmd(['cat', filename])
        return output

    def chmod(self, filename, mode):
        output = self.ShellCmd(['chmod', mode, filename])
        log_debug(output)
        if output.find("No such file or directory") > 0:
            return False
        return True

    def echo(self, content, filename):
        self.ShellCmd(['echo', content, '>', filename])

    # =================================================
    # other commands
    # =================================================
    def reboot(self):
        output = self.ShellCmd(['reboot'])
        return output

    def screen_shot(self):
        pic_dir = os.path.join(os.path.expanduser('~'), 'Pictures')
        safe_make_dirs(pic_dir)

        short_name = time.strftime("screenshot_%Y_%m_%d_%H_%M_%S.png", time.localtime())
        local_png = os.path.join(pic_dir, short_name)
        remote_png = '/data/local/tmp/a.png'

        self.ShellCmd(['screencap', '-p', remote_png])
        self.download_file(remote_png, local_png)
        log_info('screenshot: ' + local_png)
        return os.path.abspath(local_png)

    def get_arch(self):
        return self.arch

    def get_device_info(self, names):
        device_info = []
        for n in names:
            #  adb shell cat /system/build.prop
            if n == 'manufacturer':
                output = self.ShellCmd(['getprop ro.product.manufacturer'])  # 设备名
                device_info.append(('manufacturer', output.strip()))
            if n == 'name':
                output = self.ShellCmd(['getprop ro.product.name'])  # 设备名
                device_info.append(('name', output.strip()))
            if n == 'brand':
                output = self.ShellCmd(['getprop ro.product.brand'])  # 品牌
                device_info.append(('brand', output.strip()))
            if n == 'model':
                output = self.ShellCmd(['getprop ro.product.model'])  # 型号Nexus 5
                device_info.append(('model', output.strip()))
            if n == 'board':
                output = self.ShellCmd(['getprop ro.product.board'])  # 处理器型号
                device_info.append(('board', output.strip()))
            if n == 'abi':
                output = self.ShellCmd(['getprop ro.product.cpu.abi'])  # abi
                device_info.append(('abi', output.strip()))
            if n == 'mac':
                output = self.ShellCmd(['cat /sys/class/net/wlan0/address'])  # mac
                device_info.append(('mac', output.strip()))
            if n == 'resolution':
                output = self.ShellCmd(['wm size'])  # 分辨率
                device_info.append(('resolution', output.split(':')[1].strip()))
            if n == 'dpi':
                output = self.ShellCmd(['wm density'])  # dpi
                device_info.append(('dpi', output.split(':')[1].strip()))
            if n == 'android':
                output = self.ShellCmd(['getprop ro.build.version.release'])  # android系统版本
                device_info.append(('android', output.strip()))
            if n == 'sdk':
                output = self.ShellCmd(['getprop ro.build.version.sdk'])  # sdk版本
                device_info.append(('sdk', output.strip()))
            if n == 'security_patch':
                output = self.ShellCmd(['getprop ro.build.version.security_patch'])  # Android 安全补丁程序级别
                device_info.append(('security_patch', output.strip()))
            if n == 'heapsize':
                output = self.ShellCmd(['getprop dalvik.vm.heapsize'])  # 每个应用程序的内存上限
                device_info.append(('heapsize', output.strip()))
            if n == 'OTG':
                output = self.ShellCmd(['getprop persist.sys.isUsbOtgEnabled'])  # 是否支持 OTG
                device_info.append(('OTG', output.strip()))
            if n == 'fingerprint':
                output = self.ShellCmd(['getprop ro.build.fingerprint'])  # 是否支持 OTG
                device_info.append(('fingerprint', output.strip()))
            if n == 'GPU':
                output = self.ShellCmd(['dumpsys SurfaceFlinger'])  # 是否支持 OTG
                r = re.search("^GLES:\\s+(.*)$", output,
                              re.MULTILINE)  # refresh-rate              : 60.000002 fps
                gles = ''
                if r:
                    gles = r.group(1).strip()
                log_debug(gles)
                device_info.append(('GPU', gles))
            if n == 'SurfaceFlinger refresh-rate':
                output = self.ShellCmd(['dumpsys SurfaceFlinger'])  # flinger refresh rate
                r = re.search("refresh-rate\\s+:\\s*(\\d+)", output,
                              re.MULTILINE)  # refresh-rate              : 60.000002 fps
                fps = ''
                if r:
                    fps = r.group(1)
                device_info.append(('SurfaceFlinger refresh-rate', fps + ' fps'))
            if n == 'linux version':
                output = self.ShellCmd(['cat', '/proc/version'])  # linux version
                log_debug(output)
                version = output.strip()
                m = re.match("Linux version ([\\d\\.]+)", output.strip())
                if m:
                    version = m.group(1)
                device_info.append(('linux version', version))
            if n == 'storage':
                output = self.ShellCmd(['df', '/sdcard'])
                log_debug(output)
                lines = output.splitlines()
                if len(lines) == 2:
                    fields = lines[0].split()
                    values = lines[1].split()
                    n_v = {}
                    for n, v in zip(fields, values):
                        n_v[n] = v
                    device_info.append(('sdcard', '{} / {}'.format(n_v['Free'], n_v['Size'])))
        return device_info

    def AdbCmd(self, args: list):
        cmd = ['adb', '-s', self._device_serial] + args
        status, output = CmdHelper.GetCmdStatusAndOutput(cmd)
        if status != 0 or output[:len('error:')] == 'error:':
            log_error('Run command error, exit code %s, output: %s' % (status, output))
        return output

    def AdbProgressCmd(self, args: list):
        cmd = ['adb', '-s', self._device_serial] + args
        CmdHelper.ProgressCmd(cmd)

    def ShellCmd(self, args: list):
        return self.AdbCmd(['shell'] + args)

    def ShellProgressCmd(self, args: list):
        self.AdbProgressCmd(['shell'] + args)
