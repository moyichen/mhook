# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: qiyichen
# date:   2021/12/31
import click
import frida

import CmdHelper
from AndroidDevice import AndroidDevice
from utils import log_info, log_exit, log_fatal


class FridaServer(object):
    version: str = frida.__version__
    server_url: str = "https://github.com/frida/frida/releases"
    device: AndroidDevice = None

    def __init__(self):
        self.device = AndroidDevice()
        abi = self.device.get_device_info(['abi'])[0][1]
        log_info("eabi : " + abi)
        self.server_version = '15.0.15'
        if 'armeabi-v7a' in abi:
            self.server_local = './bin/arm/frida-server-{}-android-arm'.format(self.server_version)
        else:
            self.server_local = './bin/arm/frida-server-{}-android-arm64'.format(self.server_version)
        self.server_remote = "/data/local/tmp/frida-server"

    def check_version(self):
        if self.version.split('.')[0] != self.server_version.split('.')[0]:
            log_fatal("the frida and frida server major version is not the same. {} vs {}."
                      "please go to website {} to download the matched version.", self.version, self.server_version,
                      self.server_url)

        self.install()
        self.start_server()

    def install(self):
        """
            install the frida server.
        """
        if not self.device.ls(self.server_remote):
            self.device.upload_file(self.server_local, self.server_remote)
            self.device.chmod(self.server_remote, '755')
            log_info("The frida server has been installed at `{}` successfully.".format(self.server_remote))
        else:
            log_info("frida-server is already installed at `{}`.".format(self.server_remote))

    def start_server(self):
        pid = self.device.pidof('frida-server')
        if pid == -1:
            pipe = CmdHelper.Popen(['adb', 'shell', '/data/local/tmp/frida-server', '&'])
            log_info("{}".format(pipe))
            pid = self.device.pidof('frida-server')
            if pid == -1:
                log_exit('frida-server is not running.'
                         'You need to start frida server manually.'
                          '- adb shell {} &'.format(self.server_remote))
                return False
            else:
                log_info('frida-server is running now. (pid={})'.format(pid))
        else:
            log_info('frida-server already is running. (pid={})'.format(pid))
        return True

    def stop_server(self):
        pid = self.device.pidof('frida-server')
        if pid != -1:
            self.device.stop_app(pid)


@click.command()
def start_frida():
    """
        start frida server
    """
    c = FridaServer()
    c.install()
    c.start_server()


@click.command()
def kill_frida():
    """
        kill frida server
    """
    c = FridaServer()
    c.stop_server()
