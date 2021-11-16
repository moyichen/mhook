# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2019/12/16
import json
import os.path
import sys
import time
from pprint import pprint, pformat

import click
import frida
import requests
from PIL import Image

import CmdHelper
from AndroidDevice import AndroidDevice
from utils import log_info, log_warning, log_fatal, safe_make_dirs, log_error, log_exit, download_file, unzip_file, \
    unxz_file

jscode_global = '''
/**
 * author: moyichen
 * https://www.runoob.com/js/js-tutorial.html
 * https://frida.re/docs/javascript-api/
 * 
 * onEnter: function(args)
 * onLeave: function(retval)
 * @this {object} - Object allowing you to store state for use in onLeave.
 * @param {array} args - Function arguments represented as an array of NativePointer objects.
 * @param {NativePointer} retval - Return value represented as a NativePointer object.
 * 
 * 通过指针生成object
  var msg = {
     what:   args[1].add(0x00).readS32(),
     result: args[1].add(0x04).readS32(),
     arg1:   args[1].add(0x08).readS32(),
     arg2:   args[1].add(0x0c).readS32(),
     arg3:   args[1].add(0x10).readS32(),
     arg4:   args[1].add(0x14).readS32(),
     ptr:    args[1].add(0x18).readPointer(),
     callback: args[1].add(0x1c).readPointer(),
     target:   args[1].add(0x20).readPointer(),
     when:     args[1].add(0x24).readPointer()};
 * 读取字符串 setTextInner(CGString const&)
     var pcData = args[1].add(4).readPointer();
     var = pcData.readUtf8String();
     var = pcData.readUtf16String();
 * CGView控件id，因为控件是多重继承，args[0]需指向CGView，才能使用下面代码获取控件id
    var id = args[0].add(288).readS32();
 */
// ==============================================================================
String.prototype.times = function(n) {
    if (n < 0) return "";
    return (new Array(n+1)).join(this);
};

var hook_libraries = [];
function hook_dlopen(_dlopen_) {
    var f = Module.findExportByName(null, _dlopen_);
    if (f) {
        console.log("hook: " + _dlopen_);
        Interceptor.attach(f, {
            onEnter: function(args) {
                var pathptr = args[0];
                if (pathptr != undefined && pathptr != null) {
                    var fn = ptr(pathptr).readCString();
                    var idx = fn.lastIndexOf("/");
                    if (idx >= 0) {
                        fn = fn.slice(idx+1);
                    }
                    if (hook_libraries[fn]) {
                        this.params = fn;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.params) {
                    console.log("hook: " + this.params + " has been loaded.");
                    hookMethods(this.params, hook_libraries[this.params]);
                }
            }
        });
    }
}

hook_dlopen("dlopen");
//hook_dlopen("android_dlopen_ext");

// 获取时间戳，返回值秒为单位，精确到小数点后6位：123456789.123456s
// js只能精确到毫秒：var timestamp = new Date().getTime();
var clock_gettime = new NativeFunction(Module.findExportByName(null, "clock_gettime"), "int32", ['int32', 'pointer']);
function getTickCountUS() {
    var timespec = Memory.alloc(8);
    var ret = clock_gettime(0, timespec);
    var sec = timespec.readS32();
    var nsec = timespec.add(4).readS32();
    var ts = sec + nsec/1000000000;
    return ts.toFixed(6);
}

function getMsgHeader() {
    var ts = getTickCountUS();
    var aa = ts + " " + Process.getCurrentThreadId() + " ";
    return aa;
}

function findFunction(moduleName, functionName, offset) {
    // console.log("findFunction: " + functionName + " : " + moduleName + " at " + offset);
    var f = Module.findExportByName(moduleName, functionName);
    if (f == null) {
        var rva = new NativePointer(offset);
        if (!rva.equals(0)) {
            var base = Module.findBaseAddress(moduleName);
            if (base != null)
            {
                f = rva.add(base);
                // console.log("hook: " + functionName + " " + "-".times(60-functionName.length) + " : " + moduleName + " at " + f + " <= " + base + " + " + rva);
            }
        }
    }
    if (f==null) {
        console.log("Cann't find function address with: " + functionName + " : " + moduleName + " : " + offset);
    }

    return f;
}

function hex2float(v) {   
    var buf = new ArrayBuffer(4);
    var i = new Int32Array(buf);
    i[0] = v.toInt32();
    var f = new Float32Array(buf);
    return f[0];
}

function bool(v) {
    return Boolean(v.toInt32());
}

function obj2str(obj, name) {
    var first = true;
    var str = name + " {";
    for (var k in obj) {
        if (first)
            str += "\\n";
        else
            str += ",\\n";
        str += "    " + k +": " + obj[k];
    }
    str += "\\n}";
    return str;
}

function get_arg_value(arg_type, arg_value) {
    switch (arg_type) {
        case 'this':
        case 'pointer':
            return arg_value;
        case 'uint32_t':
            return arg_value.toInt32();
        case '*uint32_t':
            return Memory.readU32(arg_value);
        case 'int32_t':
            return arg_value.toInt32();
        case '*int32_t':
            return Memory.readS32(arg_value);
        case 'bool':
            return bool(arg_value);
        case 'utf-8':
            return Memory.readUtf8String(arg_value);
        case 'utf-16':
            return Memory.readUtf16String(arg_value);
        case 'float':
            return hex2float(arg_value);
        default:
            return ' ';
    }
}

function getArgs(args, signature) {
    var arg_str = "";

    if (signature.length > 0) {
        arg_str = get_arg_value(signature[0], args[0]);
        for (var i = 1; i < signature.length; i++) {
            arg_str += ", " + get_arg_value(signature[i], args[i]);
        }
    }

    return arg_str;
}

function hookMethod(so_name, user_name, low_name, rva, signature, backtrace=false) {
    var f = findFunction(so_name, low_name, rva);
    if (f) {
        console.log("hook: " + user_name + " " + "-".times(60-user_name.length) + " : " + so_name + " at " + f);
        Interceptor.attach(f, {
            onEnter: function(args) {
                var msgHdr = getMsgHeader();
                send(msgHdr + user_name + " begin");
                // backtrace
                if (backtrace) {
                    var backtraces = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    send(msgHdr + user_name + " begin backtrace " + backtraces.length + ":" + backtraces.join(','));
                }
                // input parameters
                if (signature.hasOwnProperty("in")) {
                    send(msgHdr + user_name + "  in: " + getArgs(args, signature["in"]));

                    if (signature.hasOwnProperty("out")) {
                        this.args = [];
                        for (var i = 0; i < signature['out'].length; i++) {
                            this.args[i] = args[i];
                        }
                    }
                }
            },

            onLeave: function(retval) {
                var msgHdr = getMsgHeader();
                // output paramters
                if (signature.hasOwnProperty("out")) {
                    send(msgHdr + user_name + " out: " + getArgs(this.args, signature["out"]));
                }
                // return value
                if (signature.hasOwnProperty("return")) {
                    send(msgHdr + user_name + " return: " + get_arg_value(signature["return"], retval));
                }
                send(msgHdr + user_name + " end");
            }
        });
    }
}

function hookMethods(so_name, symbols, backtrace=false) {
    var base = Module.findBaseAddress(so_name);
    if (base == null) {
        console.log("hook: " + so_name + " hasn't been loaded.");
        return;
    }
    
    for (var idx in symbols) {
        var sym = symbols[idx];
        var signature = {};
        if (sym.hasOwnProperty("parameters")) {
            signature = sym["parameters"];
        }
        hookMethod(so_name, sym["short_name"], sym["low_name"], sym["rva"], signature, backtrace);
    }
}

/*
"parameters": 
{
    "in": ["this", "int32_t", "*uint32_t", ...],
    "out": ['', '', '', '*uint32_t'],
    "return": 'bool'
}
*/
// ==============================================================================
'''

jscode_enumerate_modules = '''
var count = 0;
console.log("====================================================")
console.log("= Enumerate Modules")
console.log("====================================================")
Process.enumerateModules( {
    onMatch: function (module) {
        count = count + 1;
        send("[MODULE]: " + module.name + "," + module.base + "," + module.size + "," + module.path);
    },

    onComplete: function () {
        send("enumerate module completed!\\n");
    }
});
'''

jscode_enumerate_threads = '''
var count = 0;
console.log("====================================================")
console.log("= Enumerate Threads")
console.log("====================================================")
Process.enumerateThreads( {
    onMatch: function (thread) {
        count = count + 1;
        send("[" + count + "] tid = " + thread.id + ", state = " + thread.state + ", context = " + JSON.stringify(thread.context));
        // return "stop";
    },

    onComplete: function () {
        send("enumerate thread completed!\\n");
    }
});
'''

jscode_c_file_ops = '''
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        this.filename = Memory.readUtf8String(args[0]);
        this.mode = Memory.readUtf8String(args[1]);
    },
    onLeave: function(retval) {
        send("fopen(" + this.filename + ", " + this.mode + "), return " + retval);
        printLog("fopen(" + this.filename + ", " + this.mode + "), return " + retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "fseek"), {
    onEnter: function(args) {
        printLog("fseek(fp=" + args[0] + ", offset=" + args[1].toInt32() + ", pos=" + args[2].toInt32() + ")");
    }
});

Interceptor.attach(Module.findExportByName(null, "fread"), {
    onEnter: function(args) {
        printLog("fread(buffer=" + args[0] + ", size=" + args[1].toInt32() + ", count=" + args[2].toInt32() + ", fp=" + args[3] + ")");
    }
});

Interceptor.attach(Module.findExportByName(null, "fwrite"), {
    onEnter: function(args) {
        printLog("fwrite(buffer=" + args[0] + ", size=" + args[1].toInt32() + ", count=" + args[2].toInt32() + ", fp=" + args[3] + ")");
    }
});

Interceptor.attach(Module.findExportByName(null, "fclose"), {
    onEnter: function(args) {
        printLog("fclose(fp=" + args[0] + ")");
    }
});
'''

jscode_memory_malloc = '''
var f = Module.findExportByName("libc.so", "malloc");
Interceptor.attach(f, {
    onEnter: function(args) {   
        backtrace(this.context, "malloc(" + args[0].toInt32() + ")");
    }
});
'''


class FridaServerUpdater(object):
    FRIDA_SERVER_LATEST_RELEASE = 'https://api.github.com/repos/frida/frida/releases/latest'
    FRIDA_SERVER_TAGGED_RELEASE = 'https://api.github.com/repos/frida/frida/releases/tags/{tag}'
    FRIDA_SERVER_RELEASE = 'https://github.com/frida/frida/releases'
    config = {}
    config_file = os.path.expanduser('~/.mhook/frida_server_versions.json')
    local_path = os.path.expanduser('~/.mhook/android/')

    architectures = {
        'armeabi': 'arm',
        'armeabi-v7a': 'arm',
        'arm64': 'arm64',
        'arm64-v8a': 'arm64',
        'x86': 'x86',
        'x86_64': 'x86_64',
    }

    def __init__(self):
        self.request_cache = {}

        safe_make_dirs(self.local_path)

        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                self.config = json.load(f)

    def get_latest_version(self):
        r = self._call(self.FRIDA_SERVER_LATEST_RELEASE)
        if 'tag_name' in r:
            latest_version = r['tag_name']
            self.config['latest_version'] = latest_version
            self.update_config()
            return self.config['latest_version']
        else:
            log_error(r)
            return self.config['current_version']

    def get_latest_version2(self):
        r = self._call(self.FRIDA_SERVER_RELEASE)
        if 'tag_name' in r:
            latest_version = r['tag_name']
            self.config['latest_version'] = latest_version
            self.update_config()
            return self.config['latest_version']
        else:
            log_error(r)
            return self.config['current_version']

    def get_assets(self) -> dict:
        assets = self._call(self.FRIDA_SERVER_TAGGED_RELEASE.format(tag=self.config['latest_version']))
        if 'assets' in assets:
            return assets['assets']
        else:
            log_error('Unable to determine assets for frida server version {}'.format(self.config['latest_version']))
            return {}

    def get_download_url(self, arch) -> str:
        url_start = 'frida-server-'
        url_end = '-android-{}.xz'.format(arch)

        for asset in self.get_assets():
            if asset['name'].startswith(url_start) and asset['name'].endswith(url_end):
                return asset['browser_download_url']

        log_warning('Unable to determine URL to download the library.')
        return ""

    def download_latest_version(self, arch):
        latest_version = self.get_latest_version()
        url = self.get_download_url(arch)

        filename = download_file(url, self.local_path)
        unzip_filename = unxz_file(filename, self.local_path)

        self.config['current_version'] = latest_version
        self.update_config()
        return unzip_filename

    def update_config(self):
        with open(self.config_file, "w+") as f:
            json.dump(self.config, f)

    def check_update(self, arch):
        want_to_update = False
        if 'current_version' in self.config:
            latest_version = self.get_latest_version()
            if latest_version == self.config['current_version'] or not want_to_update:
                return os.path.join(self.local_path, 'frida-server-{}-android-{}'.format(self.config['current_version'], arch))

        unzip_filename = self.download_latest_version(arch)
        return unzip_filename

    def _call(self, url) -> dict:
        if url in self.request_cache:
            return self.request_cache[url]

        results = requests.get(url).json()
        self.request_cache[url] = results

        return results


class FridaAgent(object):
    def __init__(self):
        self.log_buffer = []
        self.data_buffer = []
        self.debugMode = False
        self.device = None
        self.session = None
        self.script = None
        self.app = None
        self.version = frida.__version__
        self.server_url = "https://github.com/frida/frida/releases"

        shell = AndroidDevice.get_device()
        abi = shell.get_device_info(['abi'])[0][1]
        log_info("eabi : " + abi)
        fsu = FridaServerUpdater()
        self.server_local = fsu.check_update('arm')
        self.server_version = fsu.get_latest_version()
        # self.server_local = './bin/arm/frida-server-{}-android-arm'.format(self.server_version)
        # if 'armeabi-v7a' in abi:
        #     self.server_local = './bin/arm/frida-server-{}-android-arm'.format(self.server_version)
        # else:
        #     self.server_local = './bin/arm/frida-server-{}-android-arm64'.format(self.server_version)
        self.server_remote = "/data/local/tmp/frida-server"

    def setDebugMode(self, debugMode):
        self.debugMode = debugMode

    def update_frida_server(self):
        pass

    def check_version(self):
        if self.version.split('.')[0] != self.server_version.split('.')[0]:
            log_fatal("the frida and frida server major version is not the same. {} vs {}."
                      "please go to website {} to download the matched version.", self.version, self.server_version,
                      self.server_url)

        self.install()
        self.start_server()

    def install(self):
        """
            install the frida server.
        """
        shell = AndroidDevice.get_device()
        if not shell.ls(self.server_remote):
            shell.upload_file(self.server_local, self.server_remote)
            shell.chmod(self.server_remote, '755')
            log_info("The frida server has been installed at `{}` successfully.".format(self.server_remote))
        else:
            log_info("frida-server is already installed at `{}`.".format(self.server_remote))

    def start_server(self):
        shell = AndroidDevice.get_device()
        pid = shell.pidof('frida-server')
        if pid == -1:
            pipe = CmdHelper.Popen(['adb', 'shell', '/data/local/tmp/frida-server', '&'])
            log_info("{}".format(pipe))
            pid = shell.pidof('frida-server')
            if pid == -1:
                log_exit('frida-server is not running.'
                         'You need to start frida server manually.'
                          '- adb shell {} &'.format(self.server_remote))
                return False
            else:
                log_info('frida-server is running now. (pid={})'.format(pid))
        else:
            log_info('frida-server already is running. (pid={})'.format(pid))
        return True

    def stop_server(self):
        shell = AndroidDevice.get_device()
        pid = shell.pidof('frida-server')
        if pid != -1:
            shell.stop_app(pid)

    def connect(self):
        self.device = frida.get_usb_device()
        log_info('Using USB device `{}`.'.format(self.device.name))
        params = self.device.query_system_parameters()
        log_info(pformat(params))

    def attach(self, app):
        shell = AndroidDevice.get_device()
        shell.start_app(app)
        pid = shell.pidof(app)
        # pid = self.device.spawn([app])
        # self.device.resume(pid)
        log_info('attach to {} (pid={})...'.format(app, pid))
        for i in range(3):
            try:
                self.session = self.device.attach(pid)
                self.session.on('detached', self.on_detach)
                self.app = app
                return True
            except Exception as e:
                log_warning("warning: {}".format(e))
                log_info('try attach to {} : {}.'.format(app, i))
                time.sleep(5)

        log_error('Please make sure the frida server or {} is running.'.format(app))

        return False

    def inject(self, js):
        log_info("loading js code...")
        with open('./frida.js', 'w+') as f:
            f.write(js)

        def on_message(message: dict, data):
            # click.secho(json.dumps(message, indent=2, sort_keys=True), dim=True)
            try:
                if message['type'] == 'send':
                    payload = None
                    if isinstance(message['payload'], dict):
                        payload = json.dumps(message['payload'])
                    elif isinstance(message['payload'], str):
                        payload = message['payload']
                    else:
                        log_warning('Unknown message:')
                        pprint(message['payload'])

                    if self.debugMode:
                        click.secho("--- " + payload, fg="bright_blue")
                    self.log_buffer.append(payload)

                    if data:
                        log_info("received extra data {} bytes.".format(len(data)))
                        ts = "{}".format(time.time_ns())
                        self.data_buffer.append((ts, data))
                elif message['type'] == 'error':
                    log_warning(message['stack'])
                else:
                    log_warning(message)
            except Exception as e:
                log_error('Failed to process an incoming message from target: {}'.format(e))
                raise e

        self.script = self.session.create_script(js)
        self.script.on('message', on_message)
        self.script.load()

        log_info("start tracing. press any key to stop.")
        sys.stdin.read(1)

        self.unload()

    def unload(self):
        log_info("unload js code.")
        self.script.unload()

    def exports(self) -> frida.core.ScriptExports:
        return self.script.exports

    def dump_texture(self, data_buffer, path):
        log_info("dump textures...")
        safe_make_dirs(path)
        for (ts, data) in data_buffer:
            if len(data) < 16:
                log_error("bad data: " + data)
                continue

            tid = int.from_bytes(data[0:3], byteorder='little')
            w = int.from_bytes(data[4:7], byteorder='little')
            h = int.from_bytes(data[8:11], byteorder='little')
            rgba = int.from_bytes(data[12:15], byteorder='little')
            pixels = data[16:]
            if rgba == 1:
                mode = 'L'
            elif rgba == 2:  # 按565格式展开
                mode = 'RGB'
                pixles_str = []
                for x in range(w):
                    for y in range(h):
                        b0 = data[16 + (y * w + x) * 2 + 0]
                        b1 = data[16 + (y * w + x) * 2 + 1]
                        b = ((b0 & 0x1f) << 3) & 0xff
                        g = (((b0 >> 5) | (b1 << 0x1f)) << 2) & 0xff
                        r = ((b1 >> 3) << 3) & 0xff
                        pixles_str.append("%02x %02x %02x" % (r, g, b))
                pixels = bytes.fromhex(" ".join(pixles_str))
            elif rgba == 3:
                mode = 'RGB'
            elif rgba == 4:
                mode = 'RGBA'
            else:
                mode = 'BAD'

            log_info(
                "dump texture: tid = {}, size = {} x {}, rgba = {}, mode = {}, data size = {}".format(tid, w, h, rgba,
                                                                                                      mode,
                                                                                                      len(pixels)))
            if w == 0 or h == 0 or w * h * rgba > len(pixels):
                log_error('bad texture data.')
                continue
            img = Image.new(mode, (w, h))
            img.frombytes(pixels)
            fn = "{}/{}_{}_{}x{}_{}.png".format(path, ts, tid, w, h, mode)
            with open(fn, "wb+") as f:
                img.save(f)

    @staticmethod
    def on_detach(message: str, crash):
        try:
            if message:
                log_info("session detach message: " + message)

            if crash:
                log_error("process crash report")
                log_error("\n\t{}".format(crash.report))
        except Exception as e:
            log_error("Failed to process an incoming message for a session detach signal: {}".format(e))
            raise e


if __name__ == '__main__':
    xz_src = '/Users/qiyichen/.mhook/android/frida-server-15.1.3-android-arm.xz'
    basename = os.path.basename(xz_src)
    basename = os.path.splitext(basename)[0]

    fsu = FridaServerUpdater()
    fsu.get_latest_version2()
