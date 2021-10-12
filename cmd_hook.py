# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2020/6/1
from AndroidDevice import AndroidDevice
from HookLog import HookLog
from Hookee import Hookee
from FridaHooker import FridaHooker
from utils import *
from progressbar import *


@click.command()
@click.option('--filename', '-f', help='the log file name.', required=False)
@click.option('--output', '-o', help='the report file name.', required=False)
def report(filename, output):
    hooklog = HookLog(filename)

    if output is None:
        output = filename

    report_filename = '{}.html'.format(os.path.splitext(output)[0])
    hooklog.gen_report(report_filename, auto_open=True)

    json_filename = "{}.speedscope.json".format(os.path.splitext(output)[0])
    hooklog.gen_speedscope_json(json_filename, True)


@click.command()
@click.option('--app', '-p', required=True, help='package name')
@click.option('--function', '-i', help='function name. support regex e.g. `-i ".*click.*[#libXXX.so]"`. '
                                       'If not set, it will use --filename.', required=False, multiple=True)
@click.option('--backtrace', '-b', help='catch the call backtrace.', default=False, is_flag=True)
@click.option('--update-so', '-u', help='Update the so from remote device.', default=False, is_flag=True)
@click.option('--auto-start', '-a', help='auto start hook.', default=False, is_flag=True)
@click.option('--engine', help='hook engine xxx or frida.', default='frida')
@click.option('--clip-begin', help='clip begin tag.')
@click.option('--clip-end', help='clip end tag.')
@click.option('--debug', '-d', help='Enable the debug mode.', default=False, is_flag=True)
@click.option('--filename', '-f', help='get config from file.', required=False)
@click.option('--restart', '-r', help='restart app.', default=False, is_flag=True)
def hook(app, function, backtrace, update_so, auto_start, engine, clip_begin, clip_end, debug, filename, restart):
    """
        hook functions
    """
    device = AndroidDevice()
    hookee = Hookee(app, debug, device)

    log_info(function)
    log_info(backtrace)
    log_info("hook: {} {}".format(app, hookee.version))

    if engine == 'frida':
        hooker = FridaHooker(hookee, device, auto_start)
    else:
        log_exit("Do not support {}".format(engine))

    hooker.setDebugMode(debug)

    if update_so:
        hooker.download_miss_so()

    if filename:
        hooker.gen_config_from_file(filename, debug)
    else:
        hooker.gen_config(function, backtrace)

    if restart:
        hooker.stop_app()

    hooker.clear()

    hooker.prepare()

    hooker.start_hook()
    hooker.stop_hook()
    hooker.clip(clip_begin, clip_end)

    hooker.gen_report()

    hooker.clear()


@click.command()
@click.option('--app', '-p', help='package name')
@click.option('--update-so', '-u', help='Update the so from remote device.', default=False, is_flag=True)
@click.option('--auto-start', '-a', help='auto start hook.', default=False, is_flag=True)
@click.option('--engine', help='hook engine xxx or frida.', default='frida')
@click.option('--clip-begin', help='clip begin tag.')
@click.option('--clip-end', help='clip end tag.')
@click.option('--debug', '-d', help='Enable the debug mode.', default=False, is_flag=True)
@click.option('--filename', '-f', help='get config from file.', required=False)
@click.option('--restart', '-r', help='restart app.', default=False, is_flag=True)
def fps(app, update_so, auto_start, engine, clip_begin, clip_end, debug, filename, restart):
    """
        hook functions
    """
    device = AndroidDevice()
    hookee = Hookee(app, debug, device)

    if engine == 'frida':
        hooker = FridaHooker(hookee, device, auto_start)
    else:
        log_exit("Do not support {}".format(engine))

    hooker.setDebugMode(debug)

    if update_so:
        hooker.download_miss_so()

    if filename:
        hooker.gen_config_from_file(filename, debug)
    else:
        hooker.gen_config(['eglSwapBuffers#libEGL.so'], backtrace=False)

    if restart:
        hooker.stop_app()

    hooker.clear()

    hooker.prepare()

    hooker.start_hook()
    hooker.stop_hook()
    hooker.clip(clip_begin, clip_end)

    hooker.gen_report(needPie=True, isDuration=False)

    hooker.clear()


if __name__ == '__main__':
    pass
