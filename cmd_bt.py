# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/9/10

import click
from AndroidDevice import AndroidDevice
from utils import open_file


@click.command()
@click.argument('pid')
def bt(pid):
    """
        dump tombstone for pid
    """
    device = AndroidDevice.get_device()

    local_file = device.tombstone(pid)
    if local_file:
        open_file(local_file)
