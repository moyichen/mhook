# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/10/15
import os.path
import re
import stat

import click

from utils import list_files, print_table


def format_size(size):
    if size < 1024:
        return '{} B '.format(size)
    elif size < 1024 * 1024:
        return '{:.2f} KB'.format(size/1024)
    else:
        return '{:.2f} MB'.format(size/1024/1024)


def list_files(path, regx='.*'):
    all_files = []
    for root, dirs, files in os.walk(path):
        for f in files:
            f = os.path.join(root, f)
            if re.search(regx, f):
                all_files.append(f)
    return all_files


@click.command()
@click.argument('path')
@click.argument('regx')
def find(path='.', regx='*'):
    files = list_files(path=path, regx=regx)
    result = []
    total_size = 0
    for i, f in enumerate(files):
        short_name = f[len(path)+1:]
        s = os.stat(f)
        # S_IRUSR = 0o0400  # read by owner
        # S_IWUSR = 0o0200  # write by owner
        # S_IXUSR = 0o0100  # execute by owner
        # S_IRGRP = 0o0040  # read by group
        # S_IWGRP = 0o0020  # write by group
        # S_IXGRP = 0o0010  # execute by group
        # S_IROTH = 0o0004  # read by others
        # S_IWOTH = 0o0002  # write by others
        # S_IXOTH = 0o0001  # execute by others
        size = s.st_size
        mode = oct(s.st_mode)
        total_size += size
        result.append({"#": i+1, "name": short_name, "size": format_size(size), "mode": mode})

    t = print_table(result, ['#', 'name', 'size', 'mode'], alignment='llrl')
    print('{}'.format(path))
    print(t)
    print('total size: {}'.format(format_size(total_size)))
