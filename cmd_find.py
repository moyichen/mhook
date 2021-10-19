# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2021/10/15
import click

from utils import list_files


@click.command()
@click.argument('path')
@click.argument('fitler')
def find(path='.', fitler='*.*'):
    files = list_files(path, filter)
    print(files)