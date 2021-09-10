# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2020/3/10

import pipes
import signal
import string
import subprocess
import re
import sys
import pexpect
import six
from progressbar import ProgressBar
import click


_SafeShellChars = frozenset(string.ascii_letters + string.digits + '@%_-+=:,./')


def SingleQuote(s):
    """Return an shell-escaped version of the string using single quotes.

  Reliably quote a string which may contain unsafe characters (e.g. space,
  quote, or other special characters such as '$').

  The returned value can be used in a shell command line as one token that gets
  to be interpreted literally.

  Args:
    s: The string to quote.

  Return:
    The string quoted using single quotes.
  """
    return pipes.quote(s)


def DoubleQuote(s):
    """Return an shell-escaped version of the string using double quotes.

  Reliably quote a string which may contain unsafe characters (e.g. space
  or quote characters), while retaining some shell features such as variable
  interpolation.

  The returned value can be used in a shell command line as one token that gets
  to be further interpreted by the shell.

  The set of characters that retain their special meaning may depend on the
  shell implementation. This set usually includes: '$', '`', '\', '!', '*',
  and '@'.

  Args:
    s: The string to quote.

  Return:
    The string quoted using double quotes.
  """
    if not s:
        return '""'
    elif all(c in _SafeShellChars for c in s):
        return s
    else:
        return '"' + s.replace('"', '\\"') + '"'


def _ValidateAndLogCommand(args, cwd, shell):
    if isinstance(args, str):
        if not shell:
            raise Exception('string args must be run with shell=True')
    else:
        if shell:
            raise Exception('array args must be run with shell=False')
        args = ' '.join(SingleQuote(str(c)) for c in args)
    if cwd is None:
        cwd = ''
    else:
        cwd = ':' + cwd
    click.secho('    {}> {}'.format(cwd, args), fg="bright_black")
    return args


def Popen(args,
          stdin=None,
          stdout=None,
          stderr=None,
          shell=None,
          cwd=None,
          env=None):
    # preexec_fn isn't supported on windows.
    # pylint: disable=unexpected-keyword-arg
    if sys.platform == 'win32':
        close_fds = (stdin is None and stdout is None and stderr is None)
        preexec_fn = None
    else:
        close_fds = True
        preexec_fn = lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    if six.PY2:
        return subprocess.Popen(
            args=args,
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=shell,
            close_fds=close_fds,
            env=env,
            preexec_fn=preexec_fn
        )
    else:
        # opens stdout in text mode, so that caller side always get 'str',
        # and there will be no type mismatch error.
        # Ignore any decoding error, so that caller will not crash due to
        # uncaught exception. Decoding errors are unavoidable, as we
        # do not know the encoding of the output, and in some output there
        # will be multiple encodings (e.g. adb logcat)
        return subprocess.Popen(
            args=args,
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=shell,
            close_fds=close_fds,
            env=env,
            preexec_fn=preexec_fn,
            universal_newlines=True,
            encoding='utf-8',
            errors='ignore'
        )


def Call(args, stdout=None, stderr=None, shell=None, cwd=None, env=None):
    pipe = Popen(args, stdout=stdout, stderr=stderr, shell=shell, cwd=cwd,
                 env=env)
    pipe.communicate()
    return pipe.wait()


def RunCmd(args, cwd=None):
    """Opens a subprocess to execute a program and returns its return value.
    Args:
        args: A string or a sequence of program arguments. The program to execute is
          the string or the first item in the args sequence.
        cwd: If not None, the subprocess's current directory will be changed to
          |cwd| before it's executed.
    Returns:
        Return code from the command execution.
  """
    click.secho(str(args) + ' ' + (cwd or ''), fg="bright_black")
    return Call(args, cwd=cwd)


def GetCmdOutput(args, cwd=None, shell=False):
    """Open a subprocess to execute a program and returns its output.
      Args:
        args: A string or a sequence of program arguments. The program to execute is
          the string or the first item in the args sequence.
        cwd: If not None, the subprocess's current directory will be changed to
          |cwd| before it's executed.
        shell: Whether to execute args as a shell command.
      Returns:
        Captures and returns the command's stdout.
        Prints the command's stderr to logger (which defaults to stdout).
  """
    (_, output) = GetCmdStatusAndOutput(args, cwd, shell)
    return output


def GetCmdStatusOutputAndError(args,
                               cwd=None,
                               shell=False,
                               env=None,
                               merge_stderr=False):
    """Executes a subprocess and returns its exit code, output, and errors.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command. Must be True if args
      is a string and False if args is a sequence.
    env: If not None, a mapping that defines environment variables for the
      subprocess.
    merge_stderr: If True, captures stderr as part of stdout.

  Returns:
    The 3-tuple (exit code, stdout, stderr).
  """
    _ValidateAndLogCommand(args, cwd, shell)
    stderr = subprocess.STDOUT if merge_stderr else subprocess.PIPE
    pipe = Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=stderr,
        shell=shell,
        cwd=cwd,
        env=env)
    stdout, stderr = pipe.communicate()
    return pipe.returncode, stdout, stderr


def GetCmdStatusAndOutput(args, cwd=None, shell=False,
                          env=None, merge_stderr=False):
    """Executes a subprocess and returns its exit code and output.

      Args:
        args: A string or a sequence of program arguments. The program to execute is
          the string or the first item in the args sequence.
        cwd: If not None, the subprocess's current directory will be changed to
          |cwd| before it's executed.
        shell: Whether to execute args as a shell command. Must be True if args
          is a string and False if args is a sequence.
        env: If not None, a mapping that defines environment variables for the
          subprocess.
        merge_stderr: If True, captures stderr as part of stdout.

      Returns:
        The 2-tuple (exit code, stdout).
      """
    status, stdout, stderr = GetCmdStatusOutputAndError(args, cwd=cwd, shell=shell, env=env, merge_stderr=merge_stderr)

    stdout = stdout.strip()
    stderr = stderr.strip()
    if stderr:
        click.secho('    >_< ' + stderr, fg="red")
    if len(stdout) == 0 and len(stderr) > 0:
        stdout = stderr
    return status, stdout


def IterCmdOutputLines(args, timeout=30, cwd=None, shell=False):
    cmd = _ValidateAndLogCommand(args, cwd, shell)
    child = pexpect.spawn(cmd, timeout=timeout)
    try:
        while True:
            child.expect('^..*$')
            after = child.after.decode().strip()
            yield after
    except pexpect.EOF:
        pass


def ProgressCmd(cmd, percentage='(\\d+)%'):
    progress = ProgressBar(maxval=100).start()
    for line in IterCmdOutputLines(cmd):
        m = re.search(percentage, line)
        if m:
            progress.update(int(m.group(1)))
        else:
            if progress.percent == 100:
                progress.finish()
            print(line)
