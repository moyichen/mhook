# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: qiyichen
# date:   2021/12/30
import os

import click

from Hooker import LibrarySymbol, SymbolLoader
from utils import log_info, log_warning, log_error

libjs = '''
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
 * json dump对象：JSON.stringify(o)
 */
// ==============================================================================
String.prototype.times = function(n) {
    if (n < 0) return "";
    return (new Array(n+1)).join(this);
};

function enumerateModules() {
    var modules = Process.enumerateModules();
    // console.log(JSON.stringify(modules));
    send(modules);
}
//enumerateModules();

var hook_libraries = [];
function hook_dlopen(_dlopen_) {
    var f = Module.findExportByName(null, _dlopen_);
    if (f) {
        console.log("dlopen: " + _dlopen_);
        Interceptor.attach(f, {
            onEnter: function(args) {
                var pathptr = args[0];
                if (pathptr != undefined && pathptr != null) {
                    var fn = ptr(pathptr).readCString();
                    var idx = fn.lastIndexOf("/");
                    if (idx >= 0) {
                        fn = fn.slice(idx+1);
                    }
                    this.params = fn;
                }
            },
            onLeave: function(retval) {
                console.log("Library " + this.params + " has been loaded at " + Module.getBaseAddress(this.params) + ".");
                if (hook_libraries[this.params]) {
                    hookMethods(this.params, hook_libraries[this.params]['functions'], hook_libraries[this.params]['backtrace']);
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

function getCurrentThreadName() {
    var tn = '';

    if (Java.available) {
        Java.perform(() => {
            const Thread = Java.use('java.lang.Thread');
            tn = `[${Thread.currentThread().getName()}]`;
        });
    }

    return tn;
}

function getMsgHeader(threadId) {
    var ts = getTickCountUS();
    var aa = ts + " " + threadId + " ";
    return aa;
}

function findFunction(moduleName, functionName, offset) {
    console.log("findFunction: " + functionName + " : " + moduleName + " at " + offset);
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

function dumpArg(arg_type, arg_value) {
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
            return Boolean(arg_value.toInt32());
        case 'utf-8':
            return Memory.readUtf8String(arg_value);
        case 'utf-16':
            return Memory.readUtf16String(arg_value);
        case 'float':
            return hex2float(arg_value);
        case 'CGString':
            var pcData = arg_value.add(4).readPointer();
            return Memory.readUtf16String(pcData);
        default:
            return 'NA';
    }
}

function dumpArgs(arg_types, arg_values) {
    var args = [];
    for (var i = 0; i < arg_types.length; i++) {
        args.push(dumpArg(arg_types[i], arg_values[i]));
    }
    return args.join(", ");
}

function getBacktrace(context) {
    var result = [];

    var backtraces = Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    for (var i = 0; i < backtraces.length; i++) {
        var index = "" + i;
        // 占2位
        index = "0".repeat(2-index.length) + index;
        result[i] = "    #" + index + ": " + backtraces[i];
    }

    return result.join('\\n');
}

function hookMethod(so_name, user_name, low_name, rva, arg_types, backtrace) {
    var f = findFunction(so_name, low_name, rva);
    if (f) {
        console.log("hook: " + user_name + " " + "-".times(60-user_name.length) + " : " + so_name + " at " + f);
        Interceptor.attach(f, {
            onEnter: function(args) {
                var msgHdr = getMsgHeader(this.threadId);
                
                // backtrace
                var strBacktrace = "";
                if (backtrace) {
                    strBacktrace = "\\n Called from:\\n" + getBacktrace(this.context);
                }
                
                // input parameters
                var strInArgs = "";
                if (arg_types.hasOwnProperty("in")) {
                    strInArgs = "\\n param[in]: " + dumpArgs(arg_types["in"], args);

                    if (arg_types.hasOwnProperty("out")) {
                        this.args = [];
                        for (var i = 0; i < arg_types['out'].length; i++) {
                            this.args[i] = args[i];
                        }
                    }
                }
                
                send(msgHdr + user_name + " begin " + getCurrentThreadName() + strInArgs + strBacktrace);
            },

            onLeave: function(retval) {
                var msgHdr = getMsgHeader(this.threadId);
                // output paramters
                var strOutArgs = "";
                if (arg_types.hasOwnProperty("out")) {
                    strOutArgs = "\\n param[out]: " + dumpArgs(arg_types["out"], this.args);
                }
                // return value
                var strReturn = "";
                if (arg_types.hasOwnProperty("return")) {
                    strReturn = "\\n return: " + dumpArg(arg_types["return"], retval);
                }
                send(msgHdr + user_name + " end" + strOutArgs + strReturn);
            }
        });
    }
}

function hookMethods(so_name, symbols, backtrace) {
    var base = Module.findBaseAddress(so_name);
    if (base == null) {
        console.log("Library " + so_name + " hasn't been loaded. All the methods of it will be hooked when it's loaded.");
        return;
    }

    for (var idx in symbols) {
        var sym = symbols[idx];
        var arg_types = {};
        if (sym.hasOwnProperty("parameters")) {
            arg_types = sym["parameters"];
        }
        hookMethod(so_name, sym["short_name"], sym["low_name"], sym["rva"], arg_types, backtrace);
    }
}

/*
如果打印中间的参数，需要有空的占位；支持的类型参见dumpArg方法；
"parameters": 
{
    "in": ["this", "int32_t", "*uint32_t", ...],
    "out": ['', '', '', '*uint32_t'],
    "return": 'bool'
}
*/
// ==============================================================================
'''


def get_so_files(syms, symbol_dir):
    # 指定so的情况下，只加载指定的so
    so_files = []
    for sym in syms:
        sym_and_so = sym.split('#')
        if len(sym_and_so) > 1:
            if sym_and_so[1] not in so_files:
                so_files.append(sym_and_so[1])
        else:
            # 有一个未指定就需要遍历所有的so
            so_files = os.listdir(symbol_dir)
            break
    return so_files


def get_full_symbols_dict(sym_list, symbol_dir, type_filters=[]):
    '''

    :param sym_list: ["abc#libXXX.so", "efg", ...]
    :param type_filters:
    :return: {'so_name': xxx, [{'user_name': xxx, 'low_name': xxx, 'rva': xxx}, {}, ...]}
    '''
    result = LibrarySymbol()
    unfounded_syms = []

    symLoader = SymbolLoader(symbol_dir)
    so_files = get_so_files(sym_list, symbol_dir)
    symLoader.load(so_files)

    for sym in sym_list:
        sym_and_so = sym.split('#')
        filter_sym = sym_and_so[0]
        filter_so = None
        if len(sym_and_so) > 1:
            filter_so = sym_and_so[1]

        matched_syms = symLoader.findSymbol(filter_so, filter_sym, type_filters)
        if len(matched_syms) == 0:
            unfounded_syms.append(sym)
        else:
            result.addSymbols(matched_syms)

    if result.hasSymbols():
        log_info('the following symbols will be hooked.')
        s = result.toJson()
        log_info(s)

    if len(unfounded_syms) > 0:
        if len(sym_list) == len(unfounded_syms):
            log_error('the following symbols have not been founded in any dynamic libraries:')
            log_error("\n".join(unfounded_syms))
            result = None
        else:
            log_warning('the following symbols have not been founded in any dynamic libraries:')
            log_warning("\n".join(unfounded_syms))

    return result, unfounded_syms


def genFridaAgentScript(sym_list, symbol_dir, backtrace=False) -> str:
    log_info("generate hook config: {} with option {}.".format(sym_list, backtrace))

    config, unfounded_syms = get_full_symbols_dict(sym_list, symbol_dir)
    syms = config.library

    # 将bool型backtrace转换成js bool型
    backtrace = "true" if backtrace else "false"
    # 先加上基础函数
    hookscript = libjs

    # 对每一个so循环
    for so_name in syms:
        so_function_scripts = []

        # 对当前so内的符号循环
        for low_name in syms[so_name]:
            size = syms[so_name][low_name]["size"]
            user_name = syms[so_name][low_name]["user_name"]
            short_name = syms[so_name][low_name]["short_name"]
            rva = syms[so_name][low_name]["rva"] + 1
            if size <= 4:
                log_warning('{}:{} is too small to hook well. Skip it.'.format(user_name, so_name))
                continue

            f_script = [
                '''    "user_name": "{}"'''.format(user_name),
                '''    "short_name": "{}"'''.format(short_name),
                '''    "low_name": "{}"'''.format(low_name),
                '''    // "parameters": { "in": [], "out": [], "return": '' }''',
                '''    "rva": "{}"'''.format(rva)
            ]
            so_function_scripts.append("\n".join(['{', ',\n'.join(f_script), '}']))

        c_so_name = so_name.replace(".", "_")
        so_script = [
            '''var {} = ['''.format(c_so_name),
            ''',\n'''.join(so_function_scripts),
            '''];''',
            '''hookMethods("{}", {}, {});'''.format(so_name, c_so_name, backtrace),
            '''hook_libraries["{}"] = {{ 'functions': {}, 'backtrace': {} }}; '''.format(so_name, c_so_name, backtrace)
        ]
        hookscript += "\n".join(so_script)
    return hookscript
