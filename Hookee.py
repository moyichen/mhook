# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/3/25
from AndroidDevice import AndroidDevice
from utils import safe_make_dirs, log_exit, print_table, log_warning


class Hookee(object):
    def __init__(self, app, debug, device: AndroidDevice):
        self.name = app
        self.debug = debug
        self.device = device

        info = self.device.get_app_info(app)
        if not info or 'version' not in info:
            apps = self.device.list_app()
            tb = print_table(apps, ['package'])
            log_warning('The following apps are available:')
            log_warning(tb.get_string())
            log_exit("make sure you have installed {}".format(app))

        self.version = info['version']
        self.arch = self.device.get_arch()
        self.symbol_dir = "./output/{}/{}/symbol".format(self.name, self.version)

    @property
    def symbol_dir(self):
        return self._symbol_dir

    @symbol_dir.setter
    def symbol_dir(self, path):
        self._symbol_dir = path
        safe_make_dirs(self._symbol_dir)
