# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2020/6/16

from AndroidDevice import AndroidDevice
from utils import *


@click.command()
@click.option('--auto-open', '-a', help='auto open', required=False, default=True, is_flag=True)
def shot(auto_open):
    """
        capture the screen, and save it into ~/Pictures directory.
    """
    device = AndroidDevice.get_device()
    image = device.screen_shot()
    log_info(image)
    if auto_open:
        open_file(image)
