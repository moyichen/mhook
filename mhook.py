# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2020/9/10


# Start the Click command group
import click

from cmd_bt import bt
from cmd_find import find
from cmd_hook import hook, fps, hook2, script
from cmd_shot import shot


@click.group()
def cli() -> None:
    pass


cli.add_command(bt)
cli.add_command(shot)
cli.add_command(hook)
cli.add_command(hook2)
cli.add_command(script)
cli.add_command(fps)
cli.add_command(find)


if __name__ == '__main__':
    cli()
