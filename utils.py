# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2019/10/18


import errno
import logging
import lzma
import os
import os.path
import shutil
import sys
import zipfile

import click
import prettytable
import requests
import six
from progressbar import ProgressBar

BSD = sys.platform.find('bsd') != -1
LINUX = sys.platform.startswith('linux')
MACOS = sys.platform.startswith('darwin')
SUNOS = sys.platform.startswith('sunos')
WINDOWS = sys.platform.startswith('win')


def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))


def safe_make_dirs(path):
    """A safe function for creating a directory tree."""
    try:
        os.makedirs(path)
    except OSError as err:
        if err.errno == errno.EEXIST:
            if not os.path.isdir(path):
                raise
        else:
            raise


def is_windows():
    return sys.platform == 'win32' or sys.platform == 'cygwin'


def is_darwin():
    return sys.platform == 'darwin'


def get_platform():
    if is_windows():
        return 'windows'
    if is_darwin():
        return 'darwin'
    return 'linux'


class LogFileHandler(logging.FileHandler):
    """
        增加目录创建功能
    """
    def __init__(self, filename: str, mode: str = 'a', encoding: str = None, delay: bool = False) -> None:
        safe_make_dirs(os.path.dirname(filename))
        logging.FileHandler.__init__(self, filename, mode, encoding, delay)


def secho_hook(message: str, **kwargs) -> None:
    """
       同步记录到日志文件
    """
    logging.info(message)
    origin_secho(message, **kwargs)


"""
变量 格式 变量描述
asctime     %(asctime)s     将日志的时间构造成可读的形式，默认情况下是精确到毫秒，如 2018-10-13 23:24:57,832，可以额外指定 datefmt 参数来指定该变量的格式
name        %(name)         日志对象的名称
filename    %(filename)s    不包含路径的文件名
pathname    %(pathname)s    包含路径的文件名
funcName    %(funcName)s    日志记录所在的函数名
levelname   %(levelname)s   日志的级别名称
message     %(message)s     具体的日志信息
lineno      %(lineno)d      日志记录所在的行号
pathname    %(pathname)s    完整路径
process     %(process)d     当前进程ID
processName %(processName)s 当前进程名称
thread      %(thread)d      当前线程ID
threadName  %threadName)s   当前线程名称
"""
logpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'output')
logger = logging.getLogger()
handler = LogFileHandler(os.path.join(logpath, 'mhook.log'))
formatter = logging.Formatter('%(asctime)s %(levelname)-8s\n%(message)s\n')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# hook secho
origin_secho = click.secho
click.secho = secho_hook


def log_debug(msg):
    click.secho("{}".format(msg), fg='bright_black')


def log_info(msg):
    click.secho("{}".format(msg), fg='green')


def log_warning(msg):
    click.secho("{}".format(msg), fg='yellow')


def log_error(msg):
    click.secho("{}".format(msg), fg='red')


def log_fatal(msg):
    click.secho("{}".format(msg), fg='red')
    raise Exception(msg)


def log_exit(msg):
    click.secho("{}".format(msg), fg='red')
    sys.exit()


def bytes_to_str(bytes_value):
    if not bytes_value:
        return ''
    if not six.PY3:
        return bytes_value
    return bytes_value.decode('utf-8')


def open_file(filename):
    """ open a file with the default app on the os"""
    filename = os.path.abspath(filename)
    if is_windows():
        os.startfile(filename)
    else:
        os.system('open ' + filename)


def list_files(path, ext=None):
    all_files = []
    need_ext_filter = (ext != None)
    for root, dirs, files in os.walk(path):
        for f in files:
            f = os.path.join(root, f)
            extentsion = os.path.splitext(f)[1][1:]
            if need_ext_filter and extentsion in ext:
                all_files.append(f)
            elif not need_ext_filter:
                all_files.append(f)
    return all_files


def print_table(info: list, header: list = None, alignment: str = 'l') -> prettytable.PrettyTable:
    if len(info) == 0:
        log_warning("print_table: the list is empty.")
        return None

    tb = prettytable.PrettyTable()
    tb.field_names = header
    tb.align = alignment
    for v in info:
        if isinstance(v, tuple):
            tb.add_row(v)
        elif isinstance(v, dict):
            tb.add_row(v.values())
        else:
            tb.add_row([v])
    return tb


def download_file(url: str, path: str = "./"):
    filename = os.path.join(path, os.path.basename(url))
    log_debug(filename)
    if os.path.exists(filename):
        return filename

    log_info("download: {}".format(url))
    req = requests.get(url, stream=True)
    headers = req.headers
    print(headers)

    progress = ProgressBar(maxval=int(headers['Content-Length'])).start()
    total = 0
    safe_make_dirs(os.path.dirname(filename))
    with open(filename, "wb+") as f:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
                total += len(chunk)
                progress.update(total)

    progress.finish()

    return filename


def unzip_file(zip_src, dst_dir):
    log_info("unzip: {} -> {}".format(zip_src, dst_dir))
    safe_make_dirs(dst_dir)
    r = zipfile.is_zipfile(zip_src)
    if r:
        fz = zipfile.ZipFile(zip_src, 'r')
        for file in fz.namelist():
            fz.extract(file, dst_dir)
    else:
        log_error('This is not zip')


def unxz_file(xz_src, dst_dir):
    log_info("unzip: {} -> {}".format(xz_src, dst_dir))
    safe_make_dirs(dst_dir)
    basename = os.path.basename(xz_src)
    basename = os.path.splitext(basename)[0]
    filename = os.path.join(dst_dir, basename)

    with lzma.open(xz_src, 'rb') as src_file:
        with open(filename, 'wb') as dst_file:
            shutil.copyfileobj(src_file, dst_file)

    return filename

