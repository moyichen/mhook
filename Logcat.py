# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/3/23
import re
import threading
import subprocess

from AndroidDevice import AndroidDevice
from utils import bytes_to_str


class Logcat(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.exit = False
        self.filter = 'hook'

    def run(self) -> None:
        adb = AndroidDevice.get_device()
        adb.AdbCmd(['logcat', '-c'])
        ps = subprocess.Popen('adb logcat -v time', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)

        for line in ps.stdout:
            if self.exit:
                break
            try:
                line = bytes_to_str(line).strip()
                if re.search(self.filter, line):
                    print(line)
            except:
                print(line)

        adb.AdbCmd(['logcat', '-c'])

    def quit(self):
        self.exit = True
        self.join(timeout=10)
