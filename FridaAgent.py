# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2019/12/16
import json
import sys
import time
from pprint import pprint, pformat

import click
import frida
from PIL import Image

from AndroidDevice import AndroidDevice
from utils import log_info, log_warning, log_fatal, safe_make_dirs, log_error, log_exit

jscode_global = '''
/**
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
var clock_gettime = new NativeFunction(Module.findExportByName(null, "clock_gettime"), "int32", ['int32', 'pointer']);
function getMsgHeader() {
    var timespec = Memory.alloc(8);
    var ret = clock_gettime(0, timespec);
    var sec = timespec.readS32();
    var nsec = timespec.add(4).readS32();
    var ts = sec + nsec/1000000000;
    var aa = ts.toFixed(6) + " " + Process.getCurrentThreadId() + " ";
    return aa;
}

function findFunction(moduleName, functionName, offset) {
    var f = Module.findExportByName(moduleName, functionName);
    if (f == null) {
        var rva = new NativePointer(offset);
        if (!rva.equals(0)) {
            var base = Module.findBaseAddress(moduleName);
            f = rva.add(base);
            console.log("hook " + functionName + ":" + moduleName + " with rva, " + base+"+"+rva+"="+f);
        }
    }
    if (f==null) {
        console.log("Cann't find function address with: " + functionName + " : " + moduleName + " : " + rva);
    }
    return f;
}

function hex2float(v)
{   
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

jscode_dlopen = '''
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        printLog("dlopen(" + Memory.readUtf8String(args[0]) + ", " + args[1] + ")");
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
        self.server_version = '15.0.15'
        self.server_url = "https://github.com/frida/frida/releases"

        shell = AndroidDevice()
        abi = shell.get_device_info(['abi'])[0][1]
        log_info("eabi : " + abi)
        if 'armeabi-v7a' in abi:
            self.server_local = './bin/arm/frida-server-{}-android-arm'.format(self.server_version)
        else:
            self.server_local = './bin/arm/frida-server-{}-android-arm64'.format(self.server_version)
        self.server_remote = "/data/local/tmp/frida-server"

    def setDebugMode(self, debugMode):
        self.debugMode = debugMode

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
        shell = AndroidDevice()
        if not shell.ls(self.server_remote):
            shell.upload_file(self.server_local, self.server_remote)
            shell.chmod(self.server_remote, '755')
            log_info("The frida server has been installed at `{}` successfully.".format(self.server_remote))
        else:
            log_info("frida-server is already installed at `{}`.".format(self.server_remote))

    def start_server(self):
        shell = AndroidDevice()
        pid = shell.pidof('frida-server')
        if pid == -1:
            log_exit('frida-server is not running.'
                     'You need to start frida server manually.'
                      '- adb shell {} &'.format(self.server_remote))
            return False
        else:
            log_info('frida-server already is running.')
            return True

    def stop_server(self):
        shell = AndroidDevice()
        pid = shell.pidof('frida-server')
        if pid != -1:
            shell.stop_app(pid)

    def connect(self):
        self.device = frida.get_usb_device()
        log_info('Using USB device `{}`.'.format(self.device.name))
        params = self.device.query_system_parameters()
        log_info(pformat(params))

    def attach(self, app):
        shell = AndroidDevice()
        pid = shell.pidof(app)

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