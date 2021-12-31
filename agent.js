(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){

/**
 * Array#filter.
 *
 * @param {Array} arr
 * @param {Function} fn
 * @param {Object=} self
 * @return {Array}
 * @throw TypeError
 */

module.exports = function (arr, fn, self) {
  if (arr.filter) return arr.filter(fn, self);
  if (void 0 === arr || null === arr) throw new TypeError;
  if ('function' != typeof fn) throw new TypeError;
  var ret = [];
  for (var i = 0; i < arr.length; i++) {
    if (!hasOwn.call(arr, i)) continue;
    var val = arr[i];
    if (fn.call(self, val, i, arr)) ret.push(val);
  }
  return ret;
};

var hasOwn = Object.prototype.hasOwnProperty;

},{}],2:[function(require,module,exports){
(function (global){(function (){
'use strict';

var objectAssign = require('object-assign');

// compare and isBuffer taken from https://github.com/feross/buffer/blob/680e9e5e488f22aac27599a57dc844a6315928dd/index.js
// original notice:

/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
function compare(a, b) {
  if (a === b) {
    return 0;
  }

  var x = a.length;
  var y = b.length;

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }

  if (x < y) {
    return -1;
  }
  if (y < x) {
    return 1;
  }
  return 0;
}
function isBuffer(b) {
  if (global.Buffer && typeof global.Buffer.isBuffer === 'function') {
    return global.Buffer.isBuffer(b);
  }
  return !!(b != null && b._isBuffer);
}

// based on node assert, original notice:
// NB: The URL to the CommonJS spec is kept just for tradition.
//     node-assert has evolved a lot since then, both in API and behavior.

// http://wiki.commonjs.org/wiki/Unit_Testing/1.0
//
// THIS IS NOT TESTED NOR LIKELY TO WORK OUTSIDE V8!
//
// Originally from narwhal.js (http://narwhaljs.org)
// Copyright (c) 2009 Thomas Robinson <280north.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var util = require('util/');
var hasOwn = Object.prototype.hasOwnProperty;
var pSlice = Array.prototype.slice;
var functionsHaveNames = (function () {
  return function foo() {}.name === 'foo';
}());
function pToString (obj) {
  return Object.prototype.toString.call(obj);
}
function isView(arrbuf) {
  if (isBuffer(arrbuf)) {
    return false;
  }
  if (typeof global.ArrayBuffer !== 'function') {
    return false;
  }
  if (typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(arrbuf);
  }
  if (!arrbuf) {
    return false;
  }
  if (arrbuf instanceof DataView) {
    return true;
  }
  if (arrbuf.buffer && arrbuf.buffer instanceof ArrayBuffer) {
    return true;
  }
  return false;
}
// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

var regex = /\s*function\s+([^\(\s]*)\s*/;
// based on https://github.com/ljharb/function.prototype.name/blob/adeeeec8bfcc6068b187d7d9fb3d5bb1d3a30899/implementation.js
function getName(func) {
  if (!util.isFunction(func)) {
    return;
  }
  if (functionsHaveNames) {
    return func.name;
  }
  var str = func.toString();
  var match = str.match(regex);
  return match && match[1];
}
assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  if (options.message) {
    this.message = options.message;
    this.generatedMessage = false;
  } else {
    this.message = getMessage(this);
    this.generatedMessage = true;
  }
  var stackStartFunction = options.stackStartFunction || fail;
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, stackStartFunction);
  } else {
    // non v8 browsers so we can have a stacktrace
    var err = new Error();
    if (err.stack) {
      var out = err.stack;

      // try to strip useless frames
      var fn_name = getName(stackStartFunction);
      var idx = out.indexOf('\n' + fn_name);
      if (idx >= 0) {
        // once we have located the function frame
        // we need to strip out everything before it (and its line)
        var next_line = out.indexOf('\n', idx + 1);
        out = out.substring(next_line + 1);
      }

      this.stack = out;
    }
  }
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function truncate(s, n) {
  if (typeof s === 'string') {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}
function inspect(something) {
  if (functionsHaveNames || !util.isFunction(something)) {
    return util.inspect(something);
  }
  var rawname = getName(something);
  var name = rawname ? ': ' + rawname : '';
  return '[Function' +  name + ']';
}
function getMessage(self) {
  return truncate(inspect(self.actual), 128) + ' ' +
         self.operator + ' ' +
         truncate(inspect(self.expected), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

assert.deepStrictEqual = function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'deepStrictEqual', assert.deepStrictEqual);
  }
};

function _deepEqual(actual, expected, strict, memos) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;
  } else if (isBuffer(actual) && isBuffer(expected)) {
    return compare(actual, expected) === 0;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if ((actual === null || typeof actual !== 'object') &&
             (expected === null || typeof expected !== 'object')) {
    return strict ? actual === expected : actual == expected;

  // If both values are instances of typed arrays, wrap their underlying
  // ArrayBuffers in a Buffer each to increase performance
  // This optimization requires the arrays to have the same type as checked by
  // Object.prototype.toString (aka pToString). Never perform binary
  // comparisons for Float*Arrays, though, since e.g. +0 === -0 but their
  // bit patterns are not identical.
  } else if (isView(actual) && isView(expected) &&
             pToString(actual) === pToString(expected) &&
             !(actual instanceof Float32Array ||
               actual instanceof Float64Array)) {
    return compare(new Uint8Array(actual.buffer),
                   new Uint8Array(expected.buffer)) === 0;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else if (isBuffer(actual) !== isBuffer(expected)) {
    return false;
  } else {
    memos = memos || {actual: [], expected: []};

    var actualIndex = memos.actual.indexOf(actual);
    if (actualIndex !== -1) {
      if (actualIndex === memos.expected.indexOf(expected)) {
        return true;
      }
    }

    memos.actual.push(actual);
    memos.expected.push(expected);

    return objEquiv(actual, expected, strict, memos);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b, strict, actualVisitedObjects) {
  if (a === null || a === undefined || b === null || b === undefined)
    return false;
  // if one is a primitive, the other must be same
  if (util.isPrimitive(a) || util.isPrimitive(b))
    return a === b;
  if (strict && Object.getPrototypeOf(a) !== Object.getPrototypeOf(b))
    return false;
  var aIsArgs = isArguments(a);
  var bIsArgs = isArguments(b);
  if ((aIsArgs && !bIsArgs) || (!aIsArgs && bIsArgs))
    return false;
  if (aIsArgs) {
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b, strict);
  }
  var ka = objectKeys(a);
  var kb = objectKeys(b);
  var key, i;
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length !== kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] !== kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key], strict, actualVisitedObjects))
      return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

assert.notDeepStrictEqual = notDeepStrictEqual;
function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'notDeepStrictEqual', notDeepStrictEqual);
  }
}


// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  }

  try {
    if (actual instanceof expected) {
      return true;
    }
  } catch (e) {
    // Ignore.  The instanceof check doesn't work for arrow functions.
  }

  if (Error.isPrototypeOf(expected)) {
    return false;
  }

  return expected.call({}, actual) === true;
}

function _tryBlock(block) {
  var error;
  try {
    block();
  } catch (e) {
    error = e;
  }
  return error;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (typeof block !== 'function') {
    throw new TypeError('"block" argument must be a function');
  }

  if (typeof expected === 'string') {
    message = expected;
    expected = null;
  }

  actual = _tryBlock(block);

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  var userProvidedMessage = typeof message === 'string';
  var isUnwantedException = !shouldThrow && util.isError(actual);
  var isUnexpectedException = !shouldThrow && actual && !expected;

  if ((isUnwantedException &&
      userProvidedMessage &&
      expectedException(actual, expected)) ||
      isUnexpectedException) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws(true, block, error, message);
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/error, /*optional*/message) {
  _throws(false, block, error, message);
};

assert.ifError = function(err) { if (err) throw err; };

// Expose a strict only variant of assert
function strict(value, message) {
  if (!value) fail(value, true, message, '==', strict);
}
assert.strict = objectAssign(strict, assert, {
  equal: assert.strictEqual,
  deepEqual: assert.deepStrictEqual,
  notEqual: assert.notStrictEqual,
  notDeepEqual: assert.notDeepStrictEqual
});
assert.strict.strict = assert.strict;

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    if (hasOwn.call(obj, key)) keys.push(key);
  }
  return keys;
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"object-assign":49,"util/":5}],3:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],4:[function(require,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],5:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./support/isBuffer":4,"_process":30,"inherits":3}],6:[function(require,module,exports){
(function (global){(function (){
'use strict';

var filter = require('array-filter');

module.exports = function availableTypedArrays() {
	return filter([
		'BigInt64Array',
		'BigUint64Array',
		'Float32Array',
		'Float64Array',
		'Int16Array',
		'Int32Array',
		'Int8Array',
		'Uint16Array',
		'Uint32Array',
		'Uint8Array',
		'Uint8ClampedArray'
	], function (typedArray) {
		return typeof global[typedArray] === 'function';
	});
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"array-filter":1}],7:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],8:[function(require,module,exports){

},{}],9:[function(require,module,exports){
arguments[4][8][0].apply(exports,arguments)
},{"dup":8}],10:[function(require,module,exports){
'use strict';

var GetIntrinsic = require('get-intrinsic');

var callBind = require('./');

var $indexOf = callBind(GetIntrinsic('String.prototype.indexOf'));

module.exports = function callBoundIntrinsic(name, allowMissing) {
	var intrinsic = GetIntrinsic(name, !!allowMissing);
	if (typeof intrinsic === 'function' && $indexOf(name, '.prototype.') > -1) {
		return callBind(intrinsic);
	}
	return intrinsic;
};

},{"./":11,"get-intrinsic":35}],11:[function(require,module,exports){
'use strict';

var bind = require('function-bind');
var GetIntrinsic = require('get-intrinsic');

var $apply = GetIntrinsic('%Function.prototype.apply%');
var $call = GetIntrinsic('%Function.prototype.call%');
var $reflectApply = GetIntrinsic('%Reflect.apply%', true) || bind.call($call, $apply);

var $gOPD = GetIntrinsic('%Object.getOwnPropertyDescriptor%', true);
var $defineProperty = GetIntrinsic('%Object.defineProperty%', true);
var $max = GetIntrinsic('%Math.max%');

if ($defineProperty) {
	try {
		$defineProperty({}, 'a', { value: 1 });
	} catch (e) {
		// IE 8 has a broken defineProperty
		$defineProperty = null;
	}
}

module.exports = function callBind(originalFunction) {
	var func = $reflectApply(bind, $call, arguments);
	if ($gOPD && $defineProperty) {
		var desc = $gOPD(func, 'length');
		if (desc.configurable) {
			// original length, plus the receiver, minus any additional arguments (after the receiver)
			$defineProperty(
				func,
				'length',
				{ value: 1 + $max(0, originalFunction.length - (arguments.length - 1)) }
			);
		}
	}
	return func;
};

var applyBind = function applyBind() {
	return $reflectApply(bind, $apply, arguments);
};

if ($defineProperty) {
	$defineProperty(module.exports, 'apply', { value: applyBind });
} else {
	module.exports.apply = applyBind;
}

},{"function-bind":34,"get-intrinsic":35}],12:[function(require,module,exports){
function Reader(endian) {
  this.endian = null;

  if (endian)
    this.setEndian(endian);
};
module.exports = Reader;

Reader.prototype.setEndian = function setEndian(endian) {
  this.endian = /le|lsb|little/i.test(endian) ? 'le' : 'be';
};

Reader.prototype.readUInt8 = function readUInt8(buf, offset) {
  return buf.readUInt8(offset);
};

Reader.prototype.readInt8 = function readInt8(buf, offset) {
  return buf.readInt8(offset);
};

Reader.prototype.readUInt16 = function readUInt16(buf, offset) {
  if (this.endian === 'le')
    return buf.readUInt16LE(offset);
  else
    return buf.readUInt16BE(offset);
};

Reader.prototype.readInt16 = function readInt16(buf, offset) {
  if (this.endian === 'le')
    return buf.readInt16LE(offset);
  else
    return buf.readInt16BE(offset);
};

Reader.prototype.readUInt32 = function readUInt32(buf, offset) {
  if (this.endian === 'le')
    return buf.readUInt32LE(offset);
  else
    return buf.readUInt32BE(offset);
};

Reader.prototype.readInt32 = function readInt32(buf, offset) {
  if (this.endian === 'le')
    return buf.readInt32LE(offset);
  else
    return buf.readInt32BE(offset);
};

Reader.prototype.readUInt64 = function readUInt64(buf, offset) {
  var a = this.readUInt32(buf, offset);
  var b = this.readUInt32(buf, offset + 4);
  if (this.endian === 'le')
    return a + b * 0x100000000;
  else
    return b + a * 0x100000000;
};

Reader.prototype.readInt64 = function readInt64(buf, offset) {
  if (this.endian === 'le') {
    var a = this.readUInt32(buf, offset);
    var b = this.readInt32(buf, offset + 4);
    return a + b * 0x100000000;
  } else {
    var a = this.readInt32(buf, offset);
    var b = this.readUInt32(buf, offset + 4);
    return b + a * 0x100000000;
  }
};

},{}],13:[function(require,module,exports){
'use strict';

var GetIntrinsic = require('get-intrinsic');

var $gOPD = GetIntrinsic('%Object.getOwnPropertyDescriptor%');
if ($gOPD) {
	try {
		$gOPD([], 'length');
	} catch (e) {
		// IE 8 has a broken gOPD
		$gOPD = null;
	}
}

module.exports = $gOPD;

},{"get-intrinsic":35}],14:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function eventListener() {
      if (errorListener !== undefined) {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };
    var errorListener;

    // Adding an error listener is not optional because
    // if an error is thrown on an event emitter we cannot
    // guarantee that the actual event we are waiting will
    // be fired. The result could be a silent way to create
    // memory or file descriptor leaks, which is something
    // we should avoid.
    if (name !== 'error') {
      errorListener = function errorListener(err) {
        emitter.removeListener(name, eventListener);
        reject(err);
      };

      emitter.once('error', errorListener);
    }

    emitter.once(name, eventListener);
  });
}

},{}],15:[function(require,module,exports){

var hasOwn = Object.prototype.hasOwnProperty;
var toString = Object.prototype.toString;

module.exports = function forEach (obj, fn, ctx) {
    if (toString.call(fn) !== '[object Function]') {
        throw new TypeError('iterator must be a function');
    }
    var l = obj.length;
    if (l === +l) {
        for (var i = 0; i < l; i++) {
            fn.call(ctx, obj[i], i, obj);
        }
    } else {
        for (var k in obj) {
            if (hasOwn.call(obj, k)) {
                fn.call(ctx, obj[k], k, obj);
            }
        }
    }
};


},{}],16:[function(require,module,exports){
(function (global){(function (){
/*
 * Short-circuit auto-detection in the buffer module to avoid a Duktape
 * compatibility issue with __proto__.
 */
global.TYPED_ARRAY_SUPPORT = true;

module.exports = require('buffer/');

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"buffer/":17}],17:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')
var customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol['for'] === 'function') // eslint-disable-line dot-notation
    ? Symbol['for']('nodejs.util.inspect.custom') // eslint-disable-line dot-notation
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    var proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof SharedArrayBuffer !== 'undefined' &&
      (isInstance(value, SharedArrayBuffer) ||
      (value && isInstance(value.buffer, SharedArrayBuffer)))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    var copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      if (pos + buf.length > buffer.length) {
        Buffer.from(buf).copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (var i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
var hexSliceLookupTable = (function () {
  var alphabet = '0123456789abcdef'
  var table = new Array(256)
  for (var i = 0; i < 16; ++i) {
    var i16 = i * 16
    for (var j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

}).call(this)}).call(this,require("buffer").Buffer)

},{"base64-js":7,"buffer":16,"ieee754":40}],18:[function(require,module,exports){
(function (process,Buffer){(function (){
const stream = require('stream');

const {platform, pointerSize} = Process;

const universalConstants = {
  S_IFMT: 0xf000,
  S_IFREG: 0x8000,
  S_IFDIR: 0x4000,
  S_IFCHR: 0x2000,
  S_IFBLK: 0x6000,
  S_IFIFO: 0x1000,
  S_IFLNK: 0xa000,
  S_IFSOCK: 0xc000,

  S_IRWXU: 448,
  S_IRUSR: 256,
  S_IWUSR: 128,
  S_IXUSR: 64,
  S_IRWXG: 56,
  S_IRGRP: 32,
  S_IWGRP: 16,
  S_IXGRP: 8,
  S_IRWXO: 7,
  S_IROTH: 4,
  S_IWOTH: 2,
  S_IXOTH: 1,

  DT_UNKNOWN: 0,
  DT_FIFO: 1,
  DT_CHR: 2,
  DT_DIR: 4,
  DT_BLK: 6,
  DT_REG: 8,
  DT_LNK: 10,
  DT_SOCK: 12,
  DT_WHT: 14,
};
const platformConstants = {
  darwin: {
    O_RDONLY: 0x0,
    O_WRONLY: 0x1,
    O_RDWR: 0x2,
    O_CREAT: 0x200,
    O_EXCL: 0x800,
    O_NOCTTY: 0x20000,
    O_TRUNC: 0x400,
    O_APPEND: 0x8,
    O_DIRECTORY: 0x100000,
    O_NOFOLLOW: 0x100,
    O_SYNC: 0x80,
    O_DSYNC: 0x400000,
    O_SYMLINK: 0x200000,
    O_NONBLOCK: 0x4,
  },
  linux: {
    O_RDONLY: 0x0,
    O_WRONLY: 0x1,
    O_RDWR: 0x2,
    O_CREAT: 0x40,
    O_EXCL: 0x80,
    O_NOCTTY: 0x100,
    O_TRUNC: 0x200,
    O_APPEND: 0x400,
    O_DIRECTORY: 0x10000,
    O_NOATIME: 0x40000,
    O_NOFOLLOW: 0x20000,
    O_SYNC: 0x101000,
    O_DSYNC: 0x1000,
    O_DIRECT: 0x4000,
    O_NONBLOCK: 0x800,
  },
};
const constants = Object.assign({}, universalConstants, platformConstants[platform] || {});

const SEEK_SET = 0;
const SEEK_CUR = 1;
const SEEK_END = 2;

const EINTR = 4;

class ReadStream extends stream.Readable {
  constructor(path) {
    super({
      highWaterMark: 4 * 1024 * 1024
    });

    this._input = null;
    this._readRequest = null;

    const pathStr = Memory.allocUtf8String(path);
    const fd = getApi().open(pathStr, constants.O_RDONLY, 0);
    if (fd.value === -1) {
      this.emit('error', new Error(`Unable to open file (${getErrorString(fd.errno)})`));
      this.push(null);
      return;
    }

    this._input = new UnixInputStream(fd.value, { autoClose: true });
  }

  _read(size) {
    if (this._readRequest !== null)
      return;

    this._readRequest = this._input.read(size)
    .then(buffer => {
      this._readRequest = null;

      if (buffer.byteLength === 0) {
        this._closeInput();
        this.push(null);
        return;
      }

      if (this.push(Buffer.from(buffer)))
        this._read(size);
    })
    .catch(error => {
      this._readRequest = null;
      this._closeInput();
      this.push(null);
    });
  }

  _closeInput() {
    if (this._input !== null) {
      this._input.close();
      this._input = null;
    }
  }
}

class WriteStream extends stream.Writable {
  constructor(path) {
    super({
      highWaterMark: 4 * 1024 * 1024
    });

    this._output = null;
    this._writeRequest = null;

    const pathStr = Memory.allocUtf8String(path);
    const flags = constants.O_WRONLY | constants.O_CREAT;
    const mode = constants.S_IRUSR | constants.S_IWUSR | constants.S_IRGRP | constants.S_IROTH;
    const fd = getApi().open(pathStr, flags, mode);
    if (fd.value === -1) {
      this.emit('error', new Error(`Unable to open file (${getErrorString(fd.errno)})`));
      this.push(null);
      return;
    }

    this._output = new UnixOutputStream(fd.value, { autoClose: true });
    this.on('finish', () => this._closeOutput());
    this.on('error', () => this._closeOutput());
  }

  _write(chunk, encoding, callback) {
    if (this._writeRequest !== null)
      return;

    this._writeRequest = this._output.writeAll(chunk)
    .then(size => {
      this._writeRequest = null;

      callback();
    })
    .catch(error => {
      this._writeRequest = null;

      callback(error);
    });
  }

  _closeOutput() {
    if (this._output !== null) {
      this._output.close();
      this._output = null;
    }
  }
}

const direntSpecs = {
  'linux-32': {
    'd_name': [11, 'Utf8String'],
    'd_type': [10, 'U8']
  },
  'linux-64': {
    'd_name': [19, 'Utf8String'],
    'd_type': [18, 'U8']
  },
  'darwin-32': {
    'd_name': [21, 'Utf8String'],
    'd_type': [20, 'U8']
  },
  'darwin-64': {
    'd_name': [21, 'Utf8String'],
    'd_type': [20, 'U8']
  }
};

const direntSpec = direntSpecs[`${platform}-${pointerSize * 8}`];

function readdirSync(path) {
  const entries = [];
  enumerateDirectoryEntries(path, entry => {
    const name = readDirentField(entry, 'd_name');
    entries.push(name);
  });
  return entries;
}

function list(path) {
  const entries = [];
  enumerateDirectoryEntries(path, entry => {
    entries.push({
      name: readDirentField(entry, 'd_name'),
      type: readDirentField(entry, 'd_type')
    });
  });
  return entries;
}

function enumerateDirectoryEntries(path, callback) {
  const {opendir, opendir$INODE64, closedir, readdir, readdir$INODE64} = getApi();

  const opendirImpl = opendir$INODE64 || opendir;
  const readdirImpl = readdir$INODE64 || readdir;

  const dir = opendirImpl(Memory.allocUtf8String(path));
  const dirHandle = dir.value;
  if (dirHandle.isNull())
    throw new Error(`Unable to open directory (${getErrorString(dir.errno)})`);

  try {
    let entry;
    while (!((entry = readdirImpl(dirHandle)).isNull())) {
      callback(entry);
    }
  } finally {
    closedir(dirHandle);
  }
}

function readDirentField(entry, name) {
  const [offset, type] = direntSpec[name];

  const read = (typeof type === 'string') ? Memory['read' + type] : type;

  const value = read(entry.add(offset));
  if (value instanceof Int64 || value instanceof UInt64)
    return value.valueOf();

  return value;
}

function readFileSync(path, options = {}) {
  if (typeof options === 'string')
    options = { encoding: options };
  const {encoding = null} = options;

  const {open, close, lseek, read} = getApi();

  const pathStr = Memory.allocUtf8String(path);
  const openResult = open(pathStr, constants.O_RDONLY, 0);
  const fd = openResult.value;
  if (fd === -1)
    throw new Error(`Unable to open file (${getErrorString(openResult.errno)})`);

  try {
    const fileSize = lseek(fd, 0, SEEK_END).valueOf();

    lseek(fd, 0, SEEK_SET);

    const buf = Memory.alloc(fileSize);
    let readResult, n, readFailed;
    do {
      readResult = read(fd, buf, fileSize);
      n = readResult.value.valueOf();
      readFailed = n === -1;
    } while (readFailed && readResult.errno === EINTR);

    if (readFailed)
      throw new Error(`Unable to read ${path} (${getErrorString(readResult.errno)})`);

    if (n !== fileSize.valueOf())
      throw new Error('Short read');

    if (encoding === 'utf8') {
      return buf.readUtf8String(fileSize);
    }

    const value = Buffer.from(buf.readByteArray(fileSize));
    if (encoding !== null) {
      return value.toString(encoding);
    }

    return value;
  } finally {
    close(fd);
  }
}

function readlinkSync(path) {
  const api = getApi();

  const pathStr = Memory.allocUtf8String(path);

  const linkSize = lstatSync(path).size.valueOf();
  const buf = Memory.alloc(linkSize);

  const result = api.readlink(pathStr, buf, linkSize);
  const n = result.value.valueOf();
  if (n === -1)
    throw new Error(`Unable to read link (${getErrorString(result.errno)})`);

  return buf.readUtf8String(n);
}

function unlinkSync(path) {
  const {unlink} = getApi();

  const pathStr = Memory.allocUtf8String(path);

  const result = unlink(pathStr);
  if (result.value === -1)
    throw new Error(`Unable to unlink (${getErrorString(result.errno)})`);
}

const statFields = new Set([
  'dev',
  'mode',
  'nlink',
  'uid',
  'gid',
  'rdev',
  'blksize',
  'ino',
  'size',
  'blocks',
  'atimeMs',
  'mtimeMs',
  'ctimeMs',
  'birthtimeMs',
  'atime',
  'mtime',
  'ctime',
  'birthtime',
]);
const statSpecs = {
  'darwin-32': {
    size: 108,
    fields: {
      'dev': [ 0, 'S32' ],
      'mode': [ 4, 'U16' ],
      'nlink': [ 6, 'U16' ],
      'ino': [ 8, 'U64' ],
      'uid': [ 16, 'U32' ],
      'gid': [ 20, 'U32' ],
      'rdev': [ 24, 'S32' ],
      'atime': [ 28, readTimespec32 ],
      'mtime': [ 36, readTimespec32 ],
      'ctime': [ 44, readTimespec32 ],
      'birthtime': [ 52, readTimespec32 ],
      'size': [ 60, 'S64' ],
      'blocks': [ 68, 'S64' ],
      'blksize': [ 76, 'S32' ],
    }
  },
  'darwin-64': {
    size: 144,
    fields: {
      'dev': [ 0, 'S32' ],
      'mode': [ 4, 'U16' ],
      'nlink': [ 6, 'U16' ],
      'ino': [ 8, 'U64' ],
      'uid': [ 16, 'U32' ],
      'gid': [ 20, 'U32' ],
      'rdev': [ 24, 'S32' ],
      'atime': [ 32, readTimespec64 ],
      'mtime': [ 48, readTimespec64 ],
      'ctime': [ 64, readTimespec64 ],
      'birthtime': [ 80, readTimespec64 ],
      'size': [ 96, 'S64' ],
      'blocks': [ 104, 'S64' ],
      'blksize': [ 112, 'S32' ],
    }
  },
  'linux-32': {
    size: 88,
    fields: {
      'dev': [ 0, 'U64' ],
      'mode': [ 16, 'U32' ],
      'nlink': [ 20, 'U32' ],
      'ino': [ 12, 'U32' ],
      'uid': [ 24, 'U32' ],
      'gid': [ 28, 'U32' ],
      'rdev': [ 32, 'U64' ],
      'atime': [ 56, readTimespec32 ],
      'mtime': [ 64, readTimespec32 ],
      'ctime': [ 72, readTimespec32 ],
      'size': [ 44, 'S32' ],
      'blocks': [ 52, 'S32' ],
      'blksize': [ 48, 'S32' ],
    }
  },
  'linux-64': {
    size: 144,
    fields: {
      'dev': [ 0, 'U64' ],
      'mode': [ 24, 'U32' ],
      'nlink': [ 16, 'U64' ],
      'ino': [ 8, 'U64' ],
      'uid': [ 28, 'U32' ],
      'gid': [ 32, 'U32' ],
      'rdev': [ 40, 'U64' ],
      'atime': [ 72, readTimespec64 ],
      'mtime': [ 88, readTimespec64 ],
      'ctime': [ 104, readTimespec64 ],
      'size': [ 48, 'S64' ],
      'blocks': [ 64, 'S64' ],
      'blksize': [ 56, 'S64' ],
    },
  },
};
const statSpec = statSpecs[`${platform}-${pointerSize * 8}`] || null;
const statBufSize = 256;

function Stats() {
}

function statSync(path) {
  const api = getApi();
  const impl = api.stat64 || api.stat;
  return performStat(impl, path);
}

function lstatSync(path) {
  const api = getApi();
  const impl = api.lstat64 || api.lstat;
  return performStat(impl, path);
}

function performStat(impl, path) {
  if (statSpec === null)
    throw new Error('Current OS is not yet supported; please open a PR');

  const buf = Memory.alloc(statBufSize);
  const result = impl(Memory.allocUtf8String(path), buf);
  if (result.value !== 0)
    throw new Error(`Unable to stat ${path} (${getErrorString(result.errno)})`);

  return new Proxy(new Stats(), {
    has(target, property) {
      return statsHasField(property);
    },
    get(target, property, receiver) {
      switch (property) {
        case 'prototype':
        case 'constructor':
        case 'toString':
          return target[property];
        case 'hasOwnProperty':
          return statsHasField;
        case 'valueOf':
          return receiver;
        case 'buffer':
          return buf;
        default:
          const value = statsReadField.call(receiver, property);
          return (value !== null) ? value : undefined;
      }
    },
    set(target, property, value, receiver) {
      return false;
    },
    ownKeys(target) {
      return Array.from(statFields);
    },
    getOwnPropertyDescriptor(target, property) {
      return {
        writable: false,
        configurable: true,
        enumerable: true
      };
    },
  });
}

function statsHasField(name) {
  return statFields.has(name);
}

function statsReadField(name) {
  let field = statSpec.fields[name];
  if (field === undefined) {
    if (name === 'birthtime') {
      return statsReadField.call(this, 'ctime');
    }

    const msPos = name.lastIndexOf('Ms');
    if (msPos === name.length - 2) {
      return statsReadField.call(this, name.substr(0, msPos)).getTime();
    }

    return undefined;
  }

  const [offset, type] = field;

  const read = (typeof type === 'string') ? Memory['read' + type] : type;

  const value = read(this.buffer.add(offset));
  if (value instanceof Int64 || value instanceof UInt64)
    return value.valueOf();

  return value;
}

function readTimespec32(address) {
  const sec = address.readU32();
  const nsec = address.add(4).readU32();
  const msec = nsec / 1000000;
  return new Date((sec * 1000) + msec);
}

function readTimespec64(address) {
  // FIXME: Improve UInt64 to support division
  const sec = address.readU64().valueOf();
  const nsec = address.add(8).readU64().valueOf();
  const msec = nsec / 1000000;
  return new Date((sec * 1000) + msec);
}

function getErrorString(errno) {
  return getApi().strerror(errno).readUtf8String();
}

function callbackify(original) {
  return function (...args) {
    const numArgsMinusOne = args.length - 1;

    const implArgs = args.slice(0, numArgsMinusOne);
    const callback = args[numArgsMinusOne];

    process.nextTick(function () {
      try {
        const result = original(...implArgs);
        callback(null, result);
      } catch (e) {
        callback(e);
      }
    });
  };
}

const SF = SystemFunction;
const NF = NativeFunction;

const ssizeType = (pointerSize === 8) ? 'int64' : 'int32';
const sizeType = 'u' + ssizeType;
const offsetType = (platform === 'darwin' || pointerSize === 8) ? 'int64' : 'int32';

const apiSpec = [
  ['open', SF, 'int', ['pointer', 'int', '...', 'int']],
  ['close', NF, 'int', ['int']],
  ['lseek', NF, offsetType, ['int', offsetType, 'int']],
  ['read', SF, ssizeType, ['int', 'pointer', sizeType]],
  ['opendir', SF, 'pointer', ['pointer']],
  ['opendir$INODE64', SF, 'pointer', ['pointer']],
  ['closedir', NF, 'int', ['pointer']],
  ['readdir', NF, 'pointer', ['pointer']],
  ['readdir$INODE64', NF, 'pointer', ['pointer']],
  ['readlink', SF, ssizeType, ['pointer', 'pointer', sizeType]],
  ['unlink', SF, 'int', ['pointer']],
  ['stat', SF, 'int', ['pointer', 'pointer']],
  ['stat64', SF, 'int', ['pointer', 'pointer']],
  ['lstat', SF, 'int', ['pointer', 'pointer']],
  ['lstat64', SF, 'int', ['pointer', 'pointer']],
  ['strerror', NF, 'pointer', ['int']],
];

let cachedApi = null;
function getApi() {
  if (cachedApi === null) {
    cachedApi = apiSpec.reduce((api, entry) => {
      addApiPlaceholder(api, entry);
      return api;
    }, {});
  }
  return cachedApi;
}

function addApiPlaceholder(api, entry) {
  const [name] = entry;

  Object.defineProperty(api, name, {
    configurable: true,
    get() {
      const [, Ctor, retType, argTypes] = entry;

      let impl = null;
      const address = Module.findExportByName(null, name);
      if (address !== null)
        impl = new Ctor(address, retType, argTypes);

      Object.defineProperty(api, name, { value: impl });

      return impl;
    }
  });
}

module.exports = {
  constants,
  createReadStream(path) {
    return new ReadStream(path);
  },
  createWriteStream(path) {
    return new WriteStream(path);
  },
  readdir: callbackify(readdirSync),
  readdirSync,
  list,
  readFile: callbackify(readFileSync),
  readFileSync,
  readlink: callbackify(readlinkSync),
  readlinkSync,
  unlink: callbackify(unlinkSync),
  unlinkSync,
  stat: callbackify(statSync),
  statSync,
  lstat: callbackify(lstatSync),
  lstatSync,
};

}).call(this)}).call(this,require('_process'),require("buffer").Buffer)

},{"_process":30,"buffer":16,"stream":56}],19:[function(require,module,exports){
'use strict';

exports.IncomingMessage = require('./lib/_http_incoming').IncomingMessage;

exports.OutgoingMessage = require('./lib/_http_outgoing').OutgoingMessage;

exports.METHODS = require('./lib/_http_common').methods.slice().sort();

const agent = require('./lib/_http_agent');
exports.Agent = agent.Agent;
exports.globalAgent = agent.globalAgent;

const server = require('./lib/_http_server');
exports.ServerResponse = server.ServerResponse;
exports.STATUS_CODES = server.STATUS_CODES;
exports._connectionListener = server._connectionListener;
const Server = exports.Server = server.Server;

exports.createServer = function(requestListener) {
  return new Server(requestListener);
};

const client = require('./lib/_http_client');
const ClientRequest = exports.ClientRequest = client.ClientRequest;

exports.request = function(options, cb) {
  return new ClientRequest(options, cb);
};

exports.get = function(options, cb) {
  var req = exports.request(options, cb);
  req.end();
  return req;
};

},{"./lib/_http_agent":20,"./lib/_http_client":21,"./lib/_http_common":22,"./lib/_http_incoming":23,"./lib/_http_outgoing":24,"./lib/_http_server":25}],20:[function(require,module,exports){
(function (process){(function (){
'use strict';

const net = require('net');
const util = require('util');
const EventEmitter = require('events');

// New Agent code.

// The largest departure from the previous implementation is that
// an Agent instance holds connections for a variable number of host:ports.
// Surprisingly, this is still API compatible as far as third parties are
// concerned. The only code that really notices the difference is the
// request object.

// Another departure is that all code related to HTTP parsing is in
// ClientRequest.onSocket(). The Agent is now *strictly*
// concerned with managing a connection pool.

function Agent(options) {
  if (!(this instanceof Agent))
    return new Agent(options);

  EventEmitter.call(this);

  var self = this;

  self.defaultPort = 80;
  self.protocol = 'http:';

  self.options = util._extend({}, options);

  // don't confuse net and make it think that we're connecting to a pipe
  self.options.path = null;
  self.requests = {};
  self.sockets = {};
  self.freeSockets = {};
  self.keepAliveMsecs = self.options.keepAliveMsecs || 1000;
  self.keepAlive = self.options.keepAlive || false;
  self.maxSockets = self.options.maxSockets || Agent.defaultMaxSockets;
  self.maxFreeSockets = self.options.maxFreeSockets || 256;

  self.on('free', function(socket, options) {
    var name = self.getName(options);

    if (socket.writable &&
        self.requests[name] && self.requests[name].length) {
      self.requests[name].shift().onSocket(socket);
      if (self.requests[name].length === 0) {
        // don't leak
        delete self.requests[name];
      }
    } else {
      // If there are no pending requests, then put it in
      // the freeSockets pool, but only if we're allowed to do so.
      var req = socket._httpMessage;
      if (req &&
          req.shouldKeepAlive &&
          socket.writable &&
          self.keepAlive) {
        var freeSockets = self.freeSockets[name];
        var freeLen = freeSockets ? freeSockets.length : 0;
        var count = freeLen;
        if (self.sockets[name])
          count += self.sockets[name].length;

        if (count > self.maxSockets || freeLen >= self.maxFreeSockets) {
          socket.destroy();
        } else {
          freeSockets = freeSockets || [];
          self.freeSockets[name] = freeSockets;
          socket.setKeepAlive(true, self.keepAliveMsecs);
          socket.unref();
          socket._httpMessage = null;
          self.removeSocket(socket, options);
          freeSockets.push(socket);
        }
      } else {
        socket.destroy();
      }
    }
  });
}

util.inherits(Agent, EventEmitter);
exports.Agent = Agent;

Agent.defaultMaxSockets = Infinity;

Agent.prototype.createConnection = net.createConnection;

// Get the key for a given set of request options
Agent.prototype.getName = function(options) {
  var name = options.host || 'localhost';

  name += ':';
  if (options.port)
    name += options.port;

  name += ':';
  if (options.localAddress)
    name += options.localAddress;

  // Pacify parallel/test-http-agent-getname by only appending
  // the ':' when options.family is set.
  if (options.family === 4 || options.family === 6)
    name += ':' + options.family;

  return name;
};

Agent.prototype.addRequest = function(req, options) {
  // Legacy API: addRequest(req, host, port, localAddress)
  if (typeof options === 'string') {
    options = {
      host: options,
      port: arguments[2],
      localAddress: arguments[3]
    };
  }

  options = util._extend({}, options);
  options = util._extend(options, this.options);

  if (!options.servername) {
    options.servername = options.host;
    const hostHeader = req.getHeader('host');
    if (hostHeader) {
      options.servername = hostHeader.replace(/:.*$/, '');
    }
  }

  var name = this.getName(options);
  if (!this.sockets[name]) {
    this.sockets[name] = [];
  }

  var freeLen = this.freeSockets[name] ? this.freeSockets[name].length : 0;
  var sockLen = freeLen + this.sockets[name].length;

  if (freeLen) {
    // we have a free socket, so use that.
    var socket = this.freeSockets[name].shift();

    // don't leak
    if (!this.freeSockets[name].length)
      delete this.freeSockets[name];

    socket.ref();
    req.onSocket(socket);
    this.sockets[name].push(socket);
  } else if (sockLen < this.maxSockets) {
    // If we are under maxSockets create a new one.
    this.createSocket(req, options, function(err, newSocket) {
      if (err) {
        process.nextTick(function() {
          req.emit('error', err);
        });
        return;
      }
      req.onSocket(newSocket);
    });
  } else {
    // We are over limit so we'll add it to the queue.
    if (!this.requests[name]) {
      this.requests[name] = [];
    }
    this.requests[name].push(req);
  }
};

Agent.prototype.createSocket = function(req, options, cb) {
  var self = this;
  options = util._extend({}, options);
  options = util._extend(options, self.options);

  if (!options.servername) {
    options.servername = options.host;
    const hostHeader = req.getHeader('host');
    if (hostHeader) {
      options.servername = hostHeader.replace(/:.*$/, '');
    }
  }

  var name = self.getName(options);
  options._agentKey = name;

  options.encoding = null;
  var called = false;
  const newSocket = self.createConnection(options, oncreate);
  if (newSocket)
    oncreate(null, newSocket);
  function oncreate(err, s) {
    if (called)
      return;
    called = true;
    if (err)
      return cb(err);
    if (!self.sockets[name]) {
      self.sockets[name] = [];
    }
    self.sockets[name].push(s);

    function onFree() {
      self.emit('free', s, options);
    }
    s.on('free', onFree);

    function onClose(err) {
      // This is the only place where sockets get removed from the Agent.
      // If you want to remove a socket from the pool, just close it.
      // All socket errors end in a close event anyway.
      self.removeSocket(s, options);
    }
    s.on('close', onClose);

    function onRemove() {
      // We need this function for cases like HTTP 'upgrade'
      // (defined by WebSockets) where we need to remove a socket from the
      // pool because it'll be locked up indefinitely
      self.removeSocket(s, options);
      s.removeListener('close', onClose);
      s.removeListener('free', onFree);
      s.removeListener('agentRemove', onRemove);
    }
    s.on('agentRemove', onRemove);
    cb(null, s);
  }
};

Agent.prototype.removeSocket = function(s, options) {
  var name = this.getName(options);
  var sets = [this.sockets];

  // If the socket was destroyed, remove it from the free buffers too.
  if (!s.writable)
    sets.push(this.freeSockets);

  for (var sk = 0; sk < sets.length; sk++) {
    var sockets = sets[sk];

    if (sockets[name]) {
      var index = sockets[name].indexOf(s);
      if (index !== -1) {
        sockets[name].splice(index, 1);
        // Don't leak
        if (sockets[name].length === 0)
          delete sockets[name];
      }
    }
  }

  if (this.requests[name] && this.requests[name].length) {
    var req = this.requests[name][0];
    // If we have pending requests and a socket gets closed make a new one
    this.createSocket(req, options, function(err, newSocket) {
      if (err) {
        process.nextTick(function() {
          req.emit('error', err);
        });
        return;
      }
      newSocket.emit('free');
    });
  }
};

Agent.prototype.destroy = function() {
  var sets = [this.freeSockets, this.sockets];
  for (var s = 0; s < sets.length; s++) {
    var set = sets[s];
    var keys = Object.keys(set);
    for (var v = 0; v < keys.length; v++) {
      var setName = set[keys[v]];
      for (var n = 0; n < setName.length; n++) {
        setName[n].destroy();
      }
    }
  }
};

exports.globalAgent = new Agent();

}).call(this)}).call(this,require('_process'))

},{"_process":30,"events":14,"net":28,"util":78}],21:[function(require,module,exports){
(function (process){(function (){
'use strict';

const util = require('util');
const net = require('net');
const url = require('url');
const HTTPParser = require('./http_parser').HTTPParser;
const assert = require('assert').ok;
const common = require('./_http_common');
const httpSocketSetup = common.httpSocketSetup;
const parsers = common.parsers;
const freeParser = common.freeParser;
const OutgoingMessage = require('./_http_outgoing').OutgoingMessage;
const Agent = require('./_http_agent');
const Buffer = require('buffer').Buffer;


function ClientRequest(options, cb) {
  var self = this;
  OutgoingMessage.call(self);

  if (typeof options === 'string') {
    options = url.parse(options);
    if (!options.hostname) {
      throw new Error('Unable to determine the domain name');
    }
  } else {
    options = util._extend({}, options);
  }

  var agent = options.agent;
  var defaultAgent = options._defaultAgent || Agent.globalAgent;
  if (agent === false) {
    agent = new defaultAgent.constructor();
  } else if ((agent === null || agent === undefined) &&
             typeof options.createConnection !== 'function') {
    agent = defaultAgent;
  }
  self.agent = agent;

  var protocol = options.protocol || defaultAgent.protocol;
  var expectedProtocol = defaultAgent.protocol;
  if (self.agent && self.agent.protocol)
    expectedProtocol = self.agent.protocol;

  if (options.path && / /.test(options.path)) {
    // The actual regex is more like /[^A-Za-z0-9\-._~!$&'()*+,;=/:@]/
    // with an additional rule for ignoring percentage-escaped characters
    // but that's a) hard to capture in a regular expression that performs
    // well, and b) possibly too restrictive for real-world usage. That's
    // why it only scans for spaces because those are guaranteed to create
    // an invalid request.
    throw new TypeError('Request path contains unescaped characters');
  } else if (protocol !== expectedProtocol) {
    throw new Error('Protocol "' + protocol + '" not supported. ' +
                    'Expected "' + expectedProtocol + '"');
  }

  const defaultPort = options.defaultPort ||
                      self.agent && self.agent.defaultPort;

  var port = options.port = options.port || defaultPort || 80;
  var host = options.host = options.hostname || options.host || 'localhost';

  if (options.setHost === undefined) {
    var setHost = true;
  }

  self.socketPath = options.socketPath;
  self.timeout = options.timeout;

  var method = self.method = (options.method || 'GET').toUpperCase();
  if (!common._checkIsHttpToken(method)) {
    throw new TypeError('Method must be a valid HTTP token');
  }
  self.path = options.path || '/';
  if (cb) {
    self.once('response', cb);
  }

  if (!Array.isArray(options.headers)) {
    if (options.headers) {
      var keys = Object.keys(options.headers);
      for (var i = 0, l = keys.length; i < l; i++) {
        var key = keys[i];
        self.setHeader(key, options.headers[key]);
      }
    }
    if (host && !this.getHeader('host') && setHost) {
      var hostHeader = host;
      var posColon = -1;

      // For the Host header, ensure that IPv6 addresses are enclosed
      // in square brackets, as defined by URI formatting
      // https://tools.ietf.org/html/rfc3986#section-3.2.2
      if (-1 !== (posColon = hostHeader.indexOf(':')) &&
          -1 !== (posColon = hostHeader.indexOf(':', posColon)) &&
          '[' !== hostHeader[0]) {
        hostHeader = `[${hostHeader}]`;
      }

      if (port && +port !== defaultPort) {
        hostHeader += ':' + port;
      }
      this.setHeader('Host', hostHeader);
    }
  }

  if (options.auth && !this.getHeader('Authorization')) {
    //basic auth
    this.setHeader('Authorization', 'Basic ' +
                   Buffer.from(options.auth).toString('base64'));
  }

  if (method === 'GET' ||
      method === 'HEAD' ||
      method === 'DELETE' ||
      method === 'OPTIONS' ||
      method === 'CONNECT') {
    self.useChunkedEncodingByDefault = false;
  } else {
    self.useChunkedEncodingByDefault = true;
  }

  if (Array.isArray(options.headers)) {
    self._storeHeader(self.method + ' ' + self.path + ' HTTP/1.1\r\n',
                      options.headers);
  } else if (self.getHeader('expect')) {
    self._storeHeader(self.method + ' ' + self.path + ' HTTP/1.1\r\n',
                      self._renderHeaders());
  }

  var called = false;
  if (self.socketPath) {
    self._last = true;
    self.shouldKeepAlive = false;
    const optionsPath = {
      path: self.socketPath,
      timeout: self.timeout
    };
    const newSocket = self.agent.createConnection(optionsPath, oncreate);
    if (newSocket && !called) {
      called = true;
      self.onSocket(newSocket);
    } else {
      return;
    }
  } else if (self.agent) {
    // If there is an agent we should default to Connection:keep-alive,
    // but only if the Agent will actually reuse the connection!
    // If it's not a keepAlive agent, and the maxSockets==Infinity, then
    // there's never a case where this socket will actually be reused
    if (!self.agent.keepAlive && !Number.isFinite(self.agent.maxSockets)) {
      self._last = true;
      self.shouldKeepAlive = false;
    } else {
      self._last = false;
      self.shouldKeepAlive = true;
    }
    self.agent.addRequest(self, options);
  } else {
    // No agent, default to Connection:close.
    self._last = true;
    self.shouldKeepAlive = false;
    if (typeof options.createConnection === 'function') {
      const newSocket = options.createConnection(options, oncreate);
      if (newSocket && !called) {
        called = true;
        self.onSocket(newSocket);
      } else {
        return;
      }
    } else {
      self.onSocket(net.createConnection(options));
    }
  }

  function oncreate(err, socket) {
    if (called)
      return;
    called = true;
    if (err) {
      process.nextTick(function() {
        self.emit('error', err);
      });
      return;
    }
    self.onSocket(socket);
    self._deferToConnect(null, null, function() {
      self._flush();
      self = null;
    });
  }

  self._deferToConnect(null, null, function() {
    self._flush();
    self = null;
  });

  this._ended = false;
}

util.inherits(ClientRequest, OutgoingMessage);

exports.ClientRequest = ClientRequest;

ClientRequest.prototype.aborted = undefined;

ClientRequest.prototype._finish = function() {
  OutgoingMessage.prototype._finish.call(this);
};

ClientRequest.prototype._implicitHeader = function() {
  this._storeHeader(this.method + ' ' + this.path + ' HTTP/1.1\r\n',
                    this._renderHeaders());
};

ClientRequest.prototype.abort = function() {
  if (this.aborted === undefined) {
    process.nextTick(emitAbortNT, this);
  }
  // Mark as aborting so we can avoid sending queued request data
  // This is used as a truthy flag elsewhere. The use of Date.now is for
  // debugging purposes only.
  this.aborted = Date.now();

  // If we're aborting, we don't care about any more response data.
  if (this.res)
    this.res._dump();
  else
    this.once('response', function(res) {
      res._dump();
    });

  // In the event that we don't have a socket, we will pop out of
  // the request queue through handling in onSocket.
  if (this.socket) {
    // in-progress
    this.socket.destroy();
  }
};


function emitAbortNT(self) {
  self.emit('abort');
}


function createHangUpError() {
  var error = new Error('socket hang up');
  error.code = 'ECONNRESET';
  return error;
}


function socketCloseListener() {
  var socket = this;
  var req = socket._httpMessage;

  // Pull through final chunk, if anything is buffered.
  // the ondata function will handle it properly, and this
  // is a no-op if no final chunk remains.
  socket.read();

  // NOTE: It's important to get parser here, because it could be freed by
  // the `socketOnData`.
  var parser = socket.parser;
  req.emit('close');
  if (req.res && req.res.readable) {
    // Socket closed before we emitted 'end' below.
    req.res.emit('aborted');
    var res = req.res;
    res.on('end', function() {
      res.emit('close');
    });
    res.push(null);
  } else if (!req.res && !req.socket._hadError) {
    // This socket error fired before we started to
    // receive a response. The error needs to
    // fire on the request.
    req.emit('error', createHangUpError());
    req.socket._hadError = true;
  }

  // Too bad.  That output wasn't getting written.
  // This is pretty terrible that it doesn't raise an error.
  // Fixed better in v0.10
  if (req.output)
    req.output.length = 0;
  if (req.outputEncodings)
    req.outputEncodings.length = 0;

  if (parser) {
    parser.finish();
    freeParser(parser, req, socket);
  }
}

function socketErrorListener(err) {
  var socket = this;
  var req = socket._httpMessage;

  if (req) {
    req.emit('error', err);
    // For Safety. Some additional errors might fire later on
    // and we need to make sure we don't double-fire the error event.
    req.socket._hadError = true;
  }

  // Handle any pending data
  socket.read();

  var parser = socket.parser;
  if (parser) {
    parser.finish();
    freeParser(parser, req, socket);
  }

  // Ensure that no further data will come out of the socket
  socket.removeListener('data', socketOnData);
  socket.removeListener('end', socketOnEnd);
  socket.destroy();
}

function freeSocketErrorListener(err) {
  var socket = this;
  socket.destroy();
  socket.emit('agentRemove');
}

function socketOnEnd() {
  var socket = this;
  var req = this._httpMessage;
  var parser = this.parser;

  if (!req.res && !req.socket._hadError) {
    // If we don't have a response then we know that the socket
    // ended prematurely and we need to emit an error on the request.
    req.emit('error', createHangUpError());
    req.socket._hadError = true;
  }
  if (parser) {
    parser.finish();
    freeParser(parser, req, socket);
  }
  socket.destroy();
}

function socketOnData(d) {
  var socket = this;
  var req = this._httpMessage;
  var parser = this.parser;

  assert(parser && parser.socket === socket);

  var ret = parser.execute(d);
  if (ret instanceof Error) {
    freeParser(parser, req, socket);
    socket.destroy();
    req.emit('error', ret);
    req.socket._hadError = true;
  } else if (parser.incoming && parser.incoming.upgrade) {
    // Upgrade or CONNECT
    var bytesParsed = ret;
    var res = parser.incoming;
    req.res = res;

    socket.removeListener('data', socketOnData);
    socket.removeListener('end', socketOnEnd);
    parser.finish();

    var bodyHead = d.slice(bytesParsed, d.length);

    var eventName = req.method === 'CONNECT' ? 'connect' : 'upgrade';
    if (req.listenerCount(eventName) > 0) {
      req.upgradeOrConnect = true;

      // detach the socket
      socket.emit('agentRemove');
      socket.removeListener('close', socketCloseListener);
      socket.removeListener('error', socketErrorListener);

      // TODO(isaacs): Need a way to reset a stream to fresh state
      // IE, not flowing, and not explicitly paused.
      socket._readableState.flowing = null;

      req.emit(eventName, res, socket, bodyHead);
      req.emit('close');
    } else {
      // Got Upgrade header or CONNECT method, but have no handler.
      socket.destroy();
    }
    freeParser(parser, req, socket);
  } else if (parser.incoming && parser.incoming.complete &&
             // When the status code is 100 (Continue), the server will
             // send a final response after this client sends a request
             // body. So, we must not free the parser.
             parser.incoming.statusCode !== 100) {
    socket.removeListener('data', socketOnData);
    socket.removeListener('end', socketOnEnd);
    freeParser(parser, req, socket);
  }
}


// client
function parserOnIncomingClient(res, shouldKeepAlive) {
  var socket = this.socket;
  var req = socket._httpMessage;


  // propagate "domain" setting...
  if (req.domain && !res.domain) {
    res.domain = req.domain;
  }

  if (req.res) {
    // We already have a response object, this means the server
    // sent a double response.
    socket.destroy();
    return;
  }
  req.res = res;

  // Responses to CONNECT request is handled as Upgrade.
  if (req.method === 'CONNECT') {
    res.upgrade = true;
    return 2; // skip body, and the rest
  }

  // Responses to HEAD requests are crazy.
  // HEAD responses aren't allowed to have an entity-body
  // but *can* have a content-length which actually corresponds
  // to the content-length of the entity-body had the request
  // been a GET.
  var isHeadResponse = req.method === 'HEAD';

  if (res.statusCode === 100) {
    // restart the parser, as this is a continue message.
    delete req.res; // Clear res so that we don't hit double-responses.
    req.emit('continue');
    return true;
  }

  if (req.shouldKeepAlive && !shouldKeepAlive && !req.upgradeOrConnect) {
    // Server MUST respond with Connection:keep-alive for us to enable it.
    // If we've been upgraded (via WebSockets) we also shouldn't try to
    // keep the connection open.
    req.shouldKeepAlive = false;
  }


  req.res = res;
  res.req = req;

  // add our listener first, so that we guarantee socket cleanup
  res.on('end', responseOnEnd);
  req.on('prefinish', requestOnPrefinish);
  var handled = req.emit('response', res);

  // If the user did not listen for the 'response' event, then they
  // can't possibly read the data, so we ._dump() it into the void
  // so that the socket doesn't hang there in a paused state.
  if (!handled)
    res._dump();

  return isHeadResponse;
}

// client
function responseKeepAlive(res, req) {
  var socket = req.socket;

  if (!req.shouldKeepAlive) {
    if (socket.writable) {
      socket.destroySoon();
    }
    assert(!socket.writable);
  } else {
    if (req.timeoutCb) {
      socket.setTimeout(0, req.timeoutCb);
      req.timeoutCb = null;
    }
    socket.removeListener('close', socketCloseListener);
    socket.removeListener('error', socketErrorListener);
    socket.once('error', freeSocketErrorListener);
    // Mark this socket as available, AFTER user-added end
    // handlers have a chance to run.
    process.nextTick(emitFreeNT, socket);
  }
}

function responseOnEnd() {
  const res = this;
  const req = this.req;

  req._ended = true;
  if (!req.shouldKeepAlive || req.finished)
    responseKeepAlive(res, req);
}

function requestOnPrefinish() {
  const req = this;
  const res = this.res;

  if (!req.shouldKeepAlive)
    return;

  if (req._ended)
    responseKeepAlive(res, req);
}

function emitFreeNT(socket) {
  socket.emit('free');
}

function tickOnSocket(req, socket) {
  var parser = parsers.alloc();
  req.socket = socket;
  req.connection = socket;
  parser.reinitialize(HTTPParser.RESPONSE);
  parser.socket = socket;
  parser.incoming = null;
  parser.outgoing = req;
  req.parser = parser;

  socket.parser = parser;
  socket._httpMessage = req;

  // Setup "drain" propagation.
  httpSocketSetup(socket);

  // Propagate headers limit from request object to parser
  if (typeof req.maxHeadersCount === 'number') {
    parser.maxHeaderPairs = req.maxHeadersCount << 1;
  } else {
    // Set default value because parser may be reused from FreeList
    parser.maxHeaderPairs = 2000;
  }

  parser.onIncoming = parserOnIncomingClient;
  socket.removeListener('error', freeSocketErrorListener);
  socket.on('error', socketErrorListener);
  socket.on('data', socketOnData);
  socket.on('end', socketOnEnd);
  socket.on('close', socketCloseListener);

  if (req.timeout) {
    socket.once('timeout', () => req.emit('timeout'));
  }
  req.emit('socket', socket);
}

ClientRequest.prototype.onSocket = function(socket) {
  process.nextTick(onSocketNT, this, socket);
};

function onSocketNT(req, socket) {
  if (req.aborted) {
    // If we were aborted while waiting for a socket, skip the whole thing.
    socket.emit('free');
  } else {
    tickOnSocket(req, socket);
  }
}

ClientRequest.prototype._deferToConnect = function(method, arguments_, cb) {
  // This function is for calls that need to happen once the socket is
  // connected and writable. It's an important promisy thing for all the socket
  // calls that happen either now (when a socket is assigned) or
  // in the future (when a socket gets assigned out of the pool and is
  // eventually writable).
  var self = this;

  function callSocketMethod() {
    if (method)
      self.socket[method].apply(self.socket, arguments_);

    if (typeof cb === 'function')
      cb();
  }

  var onSocket = function() {
    if (self.socket.writable) {
      callSocketMethod();
    } else {
      self.socket.once('connect', callSocketMethod);
    }
  };

  if (!self.socket) {
    self.once('socket', onSocket);
  } else {
    onSocket();
  }
};

ClientRequest.prototype.setTimeout = function(msecs, callback) {
  if (callback) this.once('timeout', callback);

  var self = this;
  function emitTimeout() {
    self.emit('timeout');
  }

  if (this.socket && this.socket.writable) {
    if (this.timeoutCb)
      this.socket.setTimeout(0, this.timeoutCb);
    this.timeoutCb = emitTimeout;
    this.socket.setTimeout(msecs, emitTimeout);
    return this;
  }

  // Set timeoutCb so that it'll get cleaned up on request end
  this.timeoutCb = emitTimeout;
  if (this.socket) {
    var sock = this.socket;
    this.socket.once('connect', function() {
      sock.setTimeout(msecs, emitTimeout);
    });
    return this;
  }

  this.once('socket', function(sock) {
    sock.setTimeout(msecs, emitTimeout);
  });

  return this;
};

ClientRequest.prototype.setNoDelay = function() {
  const argsLen = arguments.length;
  const args = new Array(argsLen);
  for (var i = 0; i < argsLen; i++)
    args[i] = arguments[i];
  this._deferToConnect('setNoDelay', args);
};
ClientRequest.prototype.setSocketKeepAlive = function() {
  const argsLen = arguments.length;
  const args = new Array(argsLen);
  for (var i = 0; i < argsLen; i++)
    args[i] = arguments[i];
  this._deferToConnect('setKeepAlive', args);
};

ClientRequest.prototype.clearTimeout = function(cb) {
  this.setTimeout(0, cb);
};

}).call(this)}).call(this,require('_process'))

},{"./_http_agent":20,"./_http_common":22,"./_http_outgoing":24,"./http_parser":26,"_process":30,"assert":2,"buffer":16,"net":28,"url":73,"util":78}],22:[function(require,module,exports){
'use strict';

const binding = require('./http_parser');
const methods = binding.methods;
const HTTPParser = binding.HTTPParser;

const FreeList = require('./internal/freelist').FreeList;
const incoming = require('./_http_incoming');
const IncomingMessage = incoming.IncomingMessage;
const readStart = incoming.readStart;
const readStop = incoming.readStop;

exports.CRLF = '\r\n';
exports.chunkExpression = /chunk/i;
exports.continueExpression = /100-continue/i;
exports.methods = methods;

const kOnHeaders = HTTPParser.kOnHeaders | 0;
const kOnHeadersComplete = HTTPParser.kOnHeadersComplete | 0;
const kOnBody = HTTPParser.kOnBody | 0;
const kOnMessageComplete = HTTPParser.kOnMessageComplete | 0;
const kOnExecute = HTTPParser.kOnExecute | 0;

// Only called in the slow case where slow means
// that the request headers were either fragmented
// across multiple TCP packets or too large to be
// processed in a single run. This method is also
// called to process trailing HTTP headers.
function parserOnHeaders(headers, url) {
  // Once we exceeded headers limit - stop collecting them
  if (this.maxHeaderPairs <= 0 ||
      this._headers.length < this.maxHeaderPairs) {
    this._headers = this._headers.concat(headers);
  }
  this._url += url;
}

// `headers` and `url` are set only if .onHeaders() has not been called for
// this request.
// `url` is not set for response parsers but that's not applicable here since
// all our parsers are request parsers.
function parserOnHeadersComplete(versionMajor, versionMinor, headers, method,
                                 url, statusCode, statusMessage, upgrade,
                                 shouldKeepAlive) {
  var parser = this;

  if (!headers) {
    headers = parser._headers;
    parser._headers = [];
  }

  if (!url) {
    url = parser._url;
    parser._url = '';
  }

  parser.incoming = new IncomingMessage(parser.socket);
  parser.incoming.httpVersionMajor = versionMajor;
  parser.incoming.httpVersionMinor = versionMinor;
  parser.incoming.httpVersion = versionMajor + '.' + versionMinor;
  parser.incoming.url = url;

  var n = headers.length;

  // If parser.maxHeaderPairs <= 0 assume that there's no limit.
  if (parser.maxHeaderPairs > 0)
    n = Math.min(n, parser.maxHeaderPairs);

  parser.incoming._addHeaderLines(headers, n);

  if (typeof method === 'number') {
    // server only
    parser.incoming.method = methods[method];
  } else {
    // client only
    parser.incoming.statusCode = statusCode;
    parser.incoming.statusMessage = statusMessage;
  }

  if (upgrade && parser.outgoing !== null && !parser.outgoing.upgrading) {
    // The client made non-upgrade request, and server is just advertising
    // supported protocols.
    //
    // See RFC7230 Section 6.7
    upgrade = false;
  }

  parser.incoming.upgrade = upgrade;

  var skipBody = 0; // response to HEAD or CONNECT

  if (!upgrade) {
    // For upgraded connections and CONNECT method request, we'll emit this
    // after parser.execute so that we can capture the first part of the new
    // protocol.
    skipBody = parser.onIncoming(parser.incoming, shouldKeepAlive);
  }

  if (typeof skipBody !== 'number')
    return skipBody ? 1 : 0;
  else
    return skipBody;
}

// XXX This is a mess.
// TODO: http.Parser should be a Writable emits request/response events.
function parserOnBody(b, start, len) {
  var parser = this;
  var stream = parser.incoming;

  // if the stream has already been removed, then drop it.
  if (!stream)
    return;

  var socket = stream.socket;

  // pretend this was the result of a stream._read call.
  if (len > 0 && !stream._dumped) {
    var slice = b.slice(start, start + len);
    var ret = stream.push(slice);
    if (!ret)
      readStop(socket);
  }
}

function parserOnMessageComplete() {
  var parser = this;
  var stream = parser.incoming;

  if (stream) {
    stream.complete = true;
    // Emit any trailing headers.
    var headers = parser._headers;
    if (headers) {
      parser.incoming._addHeaderLines(headers, headers.length);
      parser._headers = [];
      parser._url = '';
    }

    // For emit end event
    stream.push(null);
  }

  // force to read the next incoming message
  readStart(parser.socket);
}


var parsers = new FreeList('parsers', 1000, function() {
  var parser = new HTTPParser(HTTPParser.REQUEST);

  parser._headers = [];
  parser._url = '';
  parser._consumed = false;

  parser.socket = null;
  parser.incoming = null;
  parser.outgoing = null;

  // Only called in the slow case where slow means
  // that the request headers were either fragmented
  // across multiple TCP packets or too large to be
  // processed in a single run. This method is also
  // called to process trailing HTTP headers.
  parser[kOnHeaders] = parserOnHeaders;
  parser[kOnHeadersComplete] = parserOnHeadersComplete;
  parser[kOnBody] = parserOnBody;
  parser[kOnMessageComplete] = parserOnMessageComplete;
  parser[kOnExecute] = null;

  return parser;
});
exports.parsers = parsers;


// Free the parser and also break any links that it
// might have to any other things.
// TODO: All parser data should be attached to a
// single object, so that it can be easily cleaned
// up by doing `parser.data = {}`, which should
// be done in FreeList.free.  `parsers.free(parser)`
// should be all that is needed.
function freeParser(parser, req, socket) {
  if (parser) {
    parser._headers = [];
    parser.onIncoming = null;
    if (parser._consumed)
      parser.unconsume();
    parser._consumed = false;
    if (parser.socket)
      parser.socket.parser = null;
    parser.socket = null;
    parser.incoming = null;
    parser.outgoing = null;
    parser[kOnExecute] = null;
    if (parsers.free(parser) === false)
      parser.close();
    parser = null;
  }
  if (req) {
    req.parser = null;
  }
  if (socket) {
    socket.parser = null;
  }
}
exports.freeParser = freeParser;


function ondrain() {
  if (this._httpMessage) this._httpMessage.emit('drain');
}


function httpSocketSetup(socket) {
  socket.removeListener('drain', ondrain);
  socket.on('drain', ondrain);
}
exports.httpSocketSetup = httpSocketSetup;

/**
 * Verifies that the given val is a valid HTTP token
 * per the rules defined in RFC 7230
 * See https://tools.ietf.org/html/rfc7230#section-3.2.6
 *
 * Allowed characters in an HTTP token:
 * ^_`a-z  94-122
 * A-Z     65-90
 * -       45
 * 0-9     48-57
 * !       33
 * #$%&'   35-39
 * *+      42-43
 * .       46
 * |       124
 * ~       126
 *
 * This implementation of checkIsHttpToken() loops over the string instead of
 * using a regular expression since the former is up to 180% faster with v8 4.9
 * depending on the string length (the shorter the string, the larger the
 * performance difference)
 *
 * Additionally, checkIsHttpToken() is currently designed to be inlinable by v8,
 * so take care when making changes to the implementation so that the source
 * code size does not exceed v8's default max_inlined_source_size setting.
 **/
function isValidTokenChar(ch) {
  if (ch >= 94 && ch <= 122)
    return true;
  if (ch >= 65 && ch <= 90)
    return true;
  if (ch === 45)
    return true;
  if (ch >= 48 && ch <= 57)
    return true;
  if (ch === 34 || ch === 40 || ch === 41 || ch === 44)
    return false;
  if (ch >= 33 && ch <= 46)
    return true;
  if (ch === 124 || ch === 126)
    return true;
  return false;
}
function checkIsHttpToken(val) {
  if (typeof val !== 'string' || val.length === 0)
    return false;
  if (!isValidTokenChar(val.charCodeAt(0)))
    return false;
  const len = val.length;
  if (len > 1) {
    if (!isValidTokenChar(val.charCodeAt(1)))
      return false;
    if (len > 2) {
      if (!isValidTokenChar(val.charCodeAt(2)))
        return false;
      if (len > 3) {
        if (!isValidTokenChar(val.charCodeAt(3)))
          return false;
        for (var i = 4; i < len; i++) {
          if (!isValidTokenChar(val.charCodeAt(i)))
            return false;
        }
      }
    }
  }
  return true;
}
exports._checkIsHttpToken = checkIsHttpToken;

/**
 * True if val contains an invalid field-vchar
 *  field-value    = *( field-content / obs-fold )
 *  field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 *  field-vchar    = VCHAR / obs-text
 *
 * checkInvalidHeaderChar() is currently designed to be inlinable by v8,
 * so take care when making changes to the implementation so that the source
 * code size does not exceed v8's default max_inlined_source_size setting.
 **/
function checkInvalidHeaderChar(val) {
  val += '';
  if (val.length < 1)
    return false;
  var c = val.charCodeAt(0);
  if ((c <= 31 && c !== 9) || c > 255 || c === 127)
    return true;
  if (val.length < 2)
    return false;
  c = val.charCodeAt(1);
  if ((c <= 31 && c !== 9) || c > 255 || c === 127)
    return true;
  if (val.length < 3)
    return false;
  c = val.charCodeAt(2);
  if ((c <= 31 && c !== 9) || c > 255 || c === 127)
    return true;
  for (var i = 3; i < val.length; ++i) {
    c = val.charCodeAt(i);
    if ((c <= 31 && c !== 9) || c > 255 || c === 127)
      return true;
  }
  return false;
}
exports._checkInvalidHeaderChar = checkInvalidHeaderChar;

},{"./_http_incoming":23,"./http_parser":26,"./internal/freelist":27}],23:[function(require,module,exports){
'use strict';

const util = require('util');
const Stream = require('stream');

function readStart(socket) {
  if (socket && !socket._paused && socket.readable)
    socket.resume();
}
exports.readStart = readStart;

function readStop(socket) {
  if (socket)
    socket.pause();
}
exports.readStop = readStop;


/* Abstract base class for ServerRequest and ClientResponse. */
function IncomingMessage(socket) {
  Stream.Readable.call(this);

  // Set this to `true` so that stream.Readable won't attempt to read more
  // data on `IncomingMessage#push` (see `maybeReadMore` in
  // `_stream_readable.js`). This is important for proper tracking of
  // `IncomingMessage#_consuming` which is used to dump requests that users
  // haven't attempted to read.
  this._readableState.readingMore = true;

  this.socket = socket;
  this.connection = socket;

  this.httpVersionMajor = null;
  this.httpVersionMinor = null;
  this.httpVersion = null;
  this.complete = false;
  this.headers = {};
  this.rawHeaders = [];
  this.trailers = {};
  this.rawTrailers = [];

  this.readable = true;

  this.upgrade = null;

  // request (server) only
  this.url = '';
  this.method = null;

  // response (client) only
  this.statusCode = null;
  this.statusMessage = null;
  this.client = socket;

  // flag for backwards compatibility grossness.
  this._consuming = false;

  // flag for when we decide that this message cannot possibly be
  // read by the user, so there's no point continuing to handle it.
  this._dumped = false;
}
util.inherits(IncomingMessage, Stream.Readable);


exports.IncomingMessage = IncomingMessage;


IncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (callback)
    this.on('timeout', callback);
  this.socket.setTimeout(msecs);
  return this;
};


IncomingMessage.prototype.read = function(n) {
  if (!this._consuming)
    this._readableState.readingMore = false;
  this._consuming = true;
  this.read = Stream.Readable.prototype.read;
  return this.read(n);
};


IncomingMessage.prototype._read = function(n) {
  // We actually do almost nothing here, because the parserOnBody
  // function fills up our internal buffer directly.  However, we
  // do need to unpause the underlying socket so that it flows.
  if (this.socket.readable)
    readStart(this.socket);
};


// It's possible that the socket will be destroyed, and removed from
// any messages, before ever calling this.  In that case, just skip
// it, since something else is destroying this connection anyway.
IncomingMessage.prototype.destroy = function(error) {
  if (this.socket)
    this.socket.destroy(error);
};


IncomingMessage.prototype._addHeaderLines = function(headers, n) {
  if (headers && headers.length) {
    var raw, dest;
    if (this.complete) {
      raw = this.rawTrailers;
      dest = this.trailers;
    } else {
      raw = this.rawHeaders;
      dest = this.headers;
    }

    for (var i = 0; i < n; i += 2) {
      var k = headers[i];
      var v = headers[i + 1];
      raw.push(k);
      raw.push(v);
      this._addHeaderLine(k, v, dest);
    }
  }
};


// Add the given (field, value) pair to the message
//
// Per RFC2616, section 4.2 it is acceptable to join multiple instances of the
// same header with a ', ' if the header in question supports specification of
// multiple values this way. If not, we declare the first instance the winner
// and drop the second. Extended header fields (those beginning with 'x-') are
// always joined.
IncomingMessage.prototype._addHeaderLine = function(field, value, dest) {
  field = field.toLowerCase();
  switch (field) {
    // Array headers:
    case 'set-cookie':
      if (dest[field] !== undefined) {
        dest[field].push(value);
      } else {
        dest[field] = [value];
      }
      break;

    /* eslint-disable max-len */
    // list is taken from:
    // https://mxr.mozilla.org/mozilla/source/netwerk/protocol/http/src/nsHttpHeaderArray.cpp
    /* eslint-enable max-len */
    case 'content-type':
    case 'content-length':
    case 'user-agent':
    case 'referer':
    case 'host':
    case 'authorization':
    case 'proxy-authorization':
    case 'if-modified-since':
    case 'if-unmodified-since':
    case 'from':
    case 'location':
    case 'max-forwards':
    case 'retry-after':
    case 'etag':
    case 'last-modified':
    case 'server':
    case 'age':
    case 'expires':
      // drop duplicates
      if (dest[field] === undefined)
        dest[field] = value;
      break;

    default:
      // make comma-separated list
      if (typeof dest[field] === 'string') {
        dest[field] += ', ' + value;
      } else {
        dest[field] = value;
      }
  }
};


// Call this instead of resume() if we want to just
// dump all the data to /dev/null
IncomingMessage.prototype._dump = function() {
  if (!this._dumped) {
    this._dumped = true;
    this.resume();
  }
};

},{"stream":56,"util":78}],24:[function(require,module,exports){
(function (process){(function (){
'use strict';

const assert = require('assert').ok;
const Stream = require('stream');
const timers = require('timers');
const util = require('util');
const Buffer = require('buffer').Buffer;
const common = require('./_http_common');

const CRLF = common.CRLF;
const trfrEncChunkExpression = common.chunkExpression;

const upgradeExpression = /^Upgrade$/i;
const transferEncodingExpression = /^Transfer-Encoding$/i;
const contentLengthExpression = /^Content-Length$/i;
const dateExpression = /^Date$/i;
const expectExpression = /^Expect$/i;
const trailerExpression = /^Trailer$/i;
const connectionExpression = /^Connection$/i;
const connCloseExpression = /(^|\W)close(\W|$)/i;
const connUpgradeExpression = /(^|\W)upgrade(\W|$)/i;

const automaticHeaders = {
  connection: true,
  'content-length': true,
  'transfer-encoding': true,
  date: true
};


var dateCache;
function utcDate() {
  if (!dateCache) {
    var d = new Date();
    dateCache = d.toUTCString();
    timers.enroll(utcDate, 1000 - d.getMilliseconds());
    timers._unrefActive(utcDate);
  }
  return dateCache;
}
utcDate._onTimeout = function() {
  dateCache = undefined;
};


function OutgoingMessage() {
  Stream.call(this);

  // Queue that holds all currently pending data, until the response will be
  // assigned to the socket (until it will its turn in the HTTP pipeline).
  this.output = [];
  this.outputEncodings = [];
  this.outputCallbacks = [];

  // `outputSize` is an approximate measure of how much data is queued on this
  // response. `_onPendingData` will be invoked to update similar global
  // per-connection counter. That counter will be used to pause/unpause the
  // TCP socket and HTTP Parser and thus handle the backpressure.
  this.outputSize = 0;

  this.writable = true;

  this._last = false;
  this.upgrading = false;
  this.chunkedEncoding = false;
  this.shouldKeepAlive = true;
  this.useChunkedEncodingByDefault = true;
  this.sendDate = false;
  this._removedHeader = {};

  this._contentLength = null;
  this._hasBody = true;
  this._trailer = '';

  this.finished = false;
  this._headerSent = false;

  this.socket = null;
  this.connection = null;
  this._header = null;
  this._headers = null;
  this._headerNames = {};

  this._onPendingData = null;
}
util.inherits(OutgoingMessage, Stream);


exports.OutgoingMessage = OutgoingMessage;


OutgoingMessage.prototype.setTimeout = function(msecs, callback) {

  if (callback) {
    this.on('timeout', callback);
  }

  if (!this.socket) {
    this.once('socket', function(socket) {
      socket.setTimeout(msecs);
    });
  } else {
    this.socket.setTimeout(msecs);
  }
  return this;
};


// It's possible that the socket will be destroyed, and removed from
// any messages, before ever calling this.  In that case, just skip
// it, since something else is destroying this connection anyway.
OutgoingMessage.prototype.destroy = function(error) {
  if (this.socket)
    this.socket.destroy(error);
  else
    this.once('socket', function(socket) {
      socket.destroy(error);
    });
};


// This abstract either writing directly to the socket or buffering it.
OutgoingMessage.prototype._send = function(data, encoding, callback) {
  // This is a shameful hack to get the headers and first body chunk onto
  // the same packet. Future versions of Node are going to take care of
  // this at a lower level and in a more general way.
  if (!this._headerSent) {
    if (typeof data === 'string' &&
        encoding !== 'hex' &&
        encoding !== 'base64') {
      data = this._header + data;
    } else {
      this.output.unshift(this._header);
      this.outputEncodings.unshift('latin1');
      this.outputCallbacks.unshift(null);
      this.outputSize += this._header.length;
      if (typeof this._onPendingData === 'function')
        this._onPendingData(this._header.length);
    }
    this._headerSent = true;
  }
  return this._writeRaw(data, encoding, callback);
};


OutgoingMessage.prototype._writeRaw = function(data, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = null;
  }

  var connection = this.connection;
  if (connection &&
      connection._httpMessage === this &&
      connection.writable &&
      !connection.destroyed) {
    // There might be pending data in the this.output buffer.
    var outputLength = this.output.length;
    if (outputLength > 0) {
      this._flushOutput(connection);
    } else if (data.length === 0) {
      if (typeof callback === 'function')
        process.nextTick(callback);
      return true;
    }

    // Directly write to socket.
    return connection.write(data, encoding, callback);
  } else if (connection && connection.destroyed) {
    // The socket was destroyed.  If we're still trying to write to it,
    // then we haven't gotten the 'close' event yet.
    return false;
  } else {
    // buffer, as long as we're not destroyed.
    return this._buffer(data, encoding, callback);
  }
};


OutgoingMessage.prototype._buffer = function(data, encoding, callback) {
  this.output.push(data);
  this.outputEncodings.push(encoding);
  this.outputCallbacks.push(callback);
  this.outputSize += data.length;
  if (typeof this._onPendingData === 'function')
    this._onPendingData(data.length);
  return false;
};


OutgoingMessage.prototype._storeHeader = function(firstLine, headers) {
  // firstLine in the case of request is: 'GET /index.html HTTP/1.1\r\n'
  // in the case of response it is: 'HTTP/1.1 200 OK\r\n'
  var state = {
    sentConnectionHeader: false,
    sentConnectionUpgrade: false,
    sentContentLengthHeader: false,
    sentTransferEncodingHeader: false,
    sentDateHeader: false,
    sentExpect: false,
    sentTrailer: false,
    sentUpgrade: false,
    messageHeader: firstLine
  };

  if (headers) {
    var keys = Object.keys(headers);
    var isArray = Array.isArray(headers);
    var field, value;

    for (var i = 0, l = keys.length; i < l; i++) {
      var key = keys[i];
      if (isArray) {
        field = headers[key][0];
        value = headers[key][1];
      } else {
        field = key;
        value = headers[key];
      }

      if (Array.isArray(value)) {
        for (var j = 0; j < value.length; j++) {
          storeHeader(this, state, field, value[j]);
        }
      } else {
        storeHeader(this, state, field, value);
      }
    }
  }

  // Are we upgrading the connection?
  if (state.sentConnectionUpgrade && state.sentUpgrade)
    this.upgrading = true;

  // Date header
  if (this.sendDate === true && state.sentDateHeader === false) {
    state.messageHeader += 'Date: ' + utcDate() + CRLF;
  }

  // Force the connection to close when the response is a 204 No Content or
  // a 304 Not Modified and the user has set a "Transfer-Encoding: chunked"
  // header.
  //
  // RFC 2616 mandates that 204 and 304 responses MUST NOT have a body but
  // node.js used to send out a zero chunk anyway to accommodate clients
  // that don't have special handling for those responses.
  //
  // It was pointed out that this might confuse reverse proxies to the point
  // of creating security liabilities, so suppress the zero chunk and force
  // the connection to close.
  var statusCode = this.statusCode;
  if ((statusCode === 204 || statusCode === 304) &&
      this.chunkedEncoding === true) {
    this.chunkedEncoding = false;
    this.shouldKeepAlive = false;
  }

  // keep-alive logic
  if (this._removedHeader.connection) {
    this._last = true;
    this.shouldKeepAlive = false;
  } else if (state.sentConnectionHeader === false) {
    var shouldSendKeepAlive = this.shouldKeepAlive &&
        (state.sentContentLengthHeader ||
         this.useChunkedEncodingByDefault ||
         this.agent);
    if (shouldSendKeepAlive) {
      state.messageHeader += 'Connection: keep-alive\r\n';
    } else {
      this._last = true;
      state.messageHeader += 'Connection: close\r\n';
    }
  }

  if (state.sentContentLengthHeader === false &&
      state.sentTransferEncodingHeader === false) {
    if (!this._hasBody) {
      // Make sure we don't end the 0\r\n\r\n at the end of the message.
      this.chunkedEncoding = false;
    } else if (!this.useChunkedEncodingByDefault) {
      this._last = true;
    } else {
      if (!state.sentTrailer &&
          !this._removedHeader['content-length'] &&
          typeof this._contentLength === 'number') {
        state.messageHeader += 'Content-Length: ' + this._contentLength +
                               '\r\n';
      } else if (!this._removedHeader['transfer-encoding']) {
        state.messageHeader += 'Transfer-Encoding: chunked\r\n';
        this.chunkedEncoding = true;
      } else {
        // We should only be able to get here if both Content-Length and
        // Transfer-Encoding are removed by the user.
        // See: test/parallel/test-http-remove-header-stays-removed.js
      }
    }
  }

  this._header = state.messageHeader + CRLF;
  this._headerSent = false;

  // wait until the first body chunk, or close(), is sent to flush,
  // UNLESS we're sending Expect: 100-continue.
  if (state.sentExpect) this._send('');
};

function storeHeader(self, state, field, value) {
  if (!common._checkIsHttpToken(field)) {
    throw new TypeError(
      'Header name must be a valid HTTP Token ["' + field + '"]');
  }
  if (common._checkInvalidHeaderChar(value) === true) {
    throw new TypeError('The header content contains invalid characters');
  }
  state.messageHeader += field + ': ' + escapeHeaderValue(value) + CRLF;

  if (connectionExpression.test(field)) {
    state.sentConnectionHeader = true;
    if (connCloseExpression.test(value)) {
      self._last = true;
    } else {
      self.shouldKeepAlive = true;
    }
    if (connUpgradeExpression.test(value))
      state.sentConnectionUpgrade = true;
  } else if (transferEncodingExpression.test(field)) {
    state.sentTransferEncodingHeader = true;
    if (trfrEncChunkExpression.test(value)) self.chunkedEncoding = true;

  } else if (contentLengthExpression.test(field)) {
    state.sentContentLengthHeader = true;
  } else if (dateExpression.test(field)) {
    state.sentDateHeader = true;
  } else if (expectExpression.test(field)) {
    state.sentExpect = true;
  } else if (trailerExpression.test(field)) {
    state.sentTrailer = true;
  } else if (upgradeExpression.test(field)) {
    state.sentUpgrade = true;
  }
}


OutgoingMessage.prototype.setHeader = function(name, value) {
  if (!common._checkIsHttpToken(name))
    throw new TypeError(
      'Header name must be a valid HTTP Token ["' + name + '"]');
  if (value === undefined)
    throw new Error('"value" required in setHeader("' + name + '", value)');
  if (this._header)
    throw new Error('Can\'t set headers after they are sent.');
  if (common._checkInvalidHeaderChar(value) === true) {
    throw new TypeError('The header content contains invalid characters');
  }
  if (this._headers === null)
    this._headers = {};

  var key = name.toLowerCase();
  this._headers[key] = value;
  this._headerNames[key] = name;

  if (automaticHeaders[key])
    this._removedHeader[key] = false;
};


OutgoingMessage.prototype.getHeader = function(name) {
  if (arguments.length < 1) {
    throw new Error('"name" argument is required for getHeader(name)');
  }

  if (!this._headers) return;

  var key = name.toLowerCase();
  return this._headers[key];
};


OutgoingMessage.prototype.removeHeader = function(name) {
  if (arguments.length < 1) {
    throw new Error('"name" argument is required for removeHeader(name)');
  }

  if (this._header) {
    throw new Error('Can\'t remove headers after they are sent');
  }

  var key = name.toLowerCase();

  if (key === 'date')
    this.sendDate = false;
  else if (automaticHeaders[key])
    this._removedHeader[key] = true;

  if (this._headers) {
    delete this._headers[key];
    delete this._headerNames[key];
  }
};


OutgoingMessage.prototype._renderHeaders = function() {
  if (this._header) {
    throw new Error('Can\'t render headers after they are sent to the client');
  }

  var headersMap = this._headers;
  if (!headersMap) return {};

  var headers = {};
  var keys = Object.keys(headersMap);
  var headerNames = this._headerNames;

  for (var i = 0, l = keys.length; i < l; i++) {
    var key = keys[i];
    headers[headerNames[key]] = headersMap[key];
  }
  return headers;
};

OutgoingMessage.prototype._implicitHeader = function() {
  throw new Error('_implicitHeader() method is not implemented');
};

Object.defineProperty(OutgoingMessage.prototype, 'headersSent', {
  configurable: true,
  enumerable: true,
  get: function() { return !!this._header; }
});


OutgoingMessage.prototype.write = function(chunk, encoding, callback) {
  if (this.finished) {
    var err = new Error('write after end');
    process.nextTick(writeAfterEndNT, this, err, callback);

    return true;
  }

  if (!this._header) {
    this._implicitHeader();
  }

  if (!this._hasBody) {
    return true;
  }

  if (typeof chunk !== 'string' && !(chunk instanceof Buffer)) {
    throw new TypeError('First argument must be a string or Buffer');
  }


  // If we get an empty string or buffer, then just do nothing, and
  // signal the user to keep writing.
  if (chunk.length === 0) return true;

  var len, ret;
  if (this.chunkedEncoding) {
    if (typeof chunk === 'string' &&
        encoding !== 'hex' &&
        encoding !== 'base64' &&
        encoding !== 'latin1') {
      len = Buffer.byteLength(chunk, encoding);
      chunk = len.toString(16) + CRLF + chunk + CRLF;
      ret = this._send(chunk, encoding, callback);
    } else {
      // buffer, or a non-toString-friendly encoding
      if (typeof chunk === 'string')
        len = Buffer.byteLength(chunk, encoding);
      else
        len = chunk.length;

      if (this.connection && !this.connection.corked) {
        this.connection.cork();
        process.nextTick(connectionCorkNT, this.connection);
      }
      this._send(len.toString(16), 'latin1', null);
      this._send(crlf_buf, null, null);
      this._send(chunk, encoding, null);
      ret = this._send(crlf_buf, null, callback);
    }
  } else {
    ret = this._send(chunk, encoding, callback);
  }

  return ret;
};


function writeAfterEndNT(self, err, callback) {
  self.emit('error', err);
  if (callback) callback(err);
}


function connectionCorkNT(conn) {
  conn.uncork();
}


function escapeHeaderValue(value) {
  // Protect against response splitting. The regex test is there to
  // minimize the performance impact in the common case.
  return /[\r\n]/.test(value) ? value.replace(/[\r\n]+[ \t]*/g, '') : value;
}


OutgoingMessage.prototype.addTrailers = function(headers) {
  this._trailer = '';
  var keys = Object.keys(headers);
  var isArray = Array.isArray(headers);
  var field, value;
  for (var i = 0, l = keys.length; i < l; i++) {
    var key = keys[i];
    if (isArray) {
      field = headers[key][0];
      value = headers[key][1];
    } else {
      field = key;
      value = headers[key];
    }
    if (!common._checkIsHttpToken(field)) {
      throw new TypeError(
        'Trailer name must be a valid HTTP Token ["' + field + '"]');
    }
    if (common._checkInvalidHeaderChar(value) === true) {
      throw new TypeError('The trailer content contains invalid characters');
    }
    this._trailer += field + ': ' + escapeHeaderValue(value) + CRLF;
  }
};


const crlf_buf = Buffer.from('\r\n');


OutgoingMessage.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') {
    callback = data;
    data = null;
  } else if (typeof encoding === 'function') {
    callback = encoding;
    encoding = null;
  }

  if (data && typeof data !== 'string' && !(data instanceof Buffer)) {
    throw new TypeError('First argument must be a string or Buffer');
  }

  if (this.finished) {
    return false;
  }

  if (!this._header) {
    if (data) {
      if (typeof data === 'string')
        this._contentLength = Buffer.byteLength(data, encoding);
      else
        this._contentLength = data.length;
    } else {
      this._contentLength = 0;
    }
    this._implicitHeader();
  }

  if (data && !this._hasBody) {
    data = null;
  }

  if (this.connection && data)
    this.connection.cork();

  var ret;
  if (data) {
    // Normal body write.
    this.write(data, encoding);
  }

  if (typeof callback === 'function')
    this.once('finish', callback);

  const finish = () => {
    this.emit('finish');
  };

  if (this._hasBody && this.chunkedEncoding) {
    ret = this._send('0\r\n' + this._trailer + '\r\n', 'latin1', finish);
  } else {
    // Force a flush, HACK.
    ret = this._send('', 'latin1', finish);
  }

  if (this.connection && data)
    this.connection.uncork();

  this.finished = true;

  // There is the first message on the outgoing queue, and we've sent
  // everything to the socket.
  if (this.output.length === 0 &&
      this.connection &&
      this.connection._httpMessage === this) {
    this._finish();
  }

  return ret;
};


OutgoingMessage.prototype._finish = function() {
  assert(this.connection);
  this.emit('prefinish');
};


// This logic is probably a bit confusing. Let me explain a bit:
//
// In both HTTP servers and clients it is possible to queue up several
// outgoing messages. This is easiest to imagine in the case of a client.
// Take the following situation:
//
//    req1 = client.request('GET', '/');
//    req2 = client.request('POST', '/');
//
// When the user does
//
//   req2.write('hello world\n');
//
// it's possible that the first request has not been completely flushed to
// the socket yet. Thus the outgoing messages need to be prepared to queue
// up data internally before sending it on further to the socket's queue.
//
// This function, outgoingFlush(), is called by both the Server and Client
// to attempt to flush any pending messages out to the socket.
OutgoingMessage.prototype._flush = function() {
  var socket = this.socket;
  var ret;

  if (socket && socket.writable) {
    // There might be remaining data in this.output; write it out
    ret = this._flushOutput(socket);

    if (this.finished) {
      // This is a queue to the server or client to bring in the next this.
      this._finish();
    } else if (ret) {
      // This is necessary to prevent https from breaking
      this.emit('drain');
    }
  }
};

OutgoingMessage.prototype._flushOutput = function _flushOutput(socket) {
  var ret;
  var outputLength = this.output.length;
  if (outputLength <= 0)
    return ret;

  var output = this.output;
  var outputEncodings = this.outputEncodings;
  var outputCallbacks = this.outputCallbacks;
  socket.cork();
  for (var i = 0; i < outputLength; i++) {
    ret = socket.write(output[i], outputEncodings[i],
                       outputCallbacks[i]);
  }
  socket.uncork();

  this.output = [];
  this.outputEncodings = [];
  this.outputCallbacks = [];
  if (typeof this._onPendingData === 'function')
    this._onPendingData(-this.outputSize);
  this.outputSize = 0;

  return ret;
};


OutgoingMessage.prototype.flushHeaders = function() {
  if (!this._header) {
    this._implicitHeader();
  }

  // Force-flush the headers.
  this._send('');
};

OutgoingMessage.prototype.flush = function() {
  this.flushHeaders();
};

}).call(this)}).call(this,require('_process'))

},{"./_http_common":22,"_process":30,"assert":2,"buffer":16,"stream":56,"timers":72,"util":78}],25:[function(require,module,exports){
'use strict';

const util = require('util');
const net = require('net');
const HTTPParser = require('./http_parser').HTTPParser;
const assert = require('assert').ok;
const common = require('./_http_common');
const parsers = common.parsers;
const freeParser = common.freeParser;
const CRLF = common.CRLF;
const continueExpression = common.continueExpression;
const chunkExpression = common.chunkExpression;
const httpSocketSetup = common.httpSocketSetup;
const OutgoingMessage = require('./_http_outgoing').OutgoingMessage;

const STATUS_CODES = exports.STATUS_CODES = {
  100: 'Continue',
  101: 'Switching Protocols',
  102: 'Processing',                 // RFC 2518, obsoleted by RFC 4918
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  203: 'Non-Authoritative Information',
  204: 'No Content',
  205: 'Reset Content',
  206: 'Partial Content',
  207: 'Multi-Status',               // RFC 4918
  208: 'Already Reported',
  226: 'IM Used',
  300: 'Multiple Choices',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  305: 'Use Proxy',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',         // RFC 7238
  400: 'Bad Request',
  401: 'Unauthorized',
  402: 'Payment Required',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  407: 'Proxy Authentication Required',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  411: 'Length Required',
  412: 'Precondition Failed',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable',
  417: 'Expectation Failed',
  418: 'I\'m a teapot',              // RFC 2324
  421: 'Misdirected Request',
  422: 'Unprocessable Entity',       // RFC 4918
  423: 'Locked',                     // RFC 4918
  424: 'Failed Dependency',          // RFC 4918
  425: 'Unordered Collection',       // RFC 4918
  426: 'Upgrade Required',           // RFC 2817
  428: 'Precondition Required',      // RFC 6585
  429: 'Too Many Requests',          // RFC 6585
  431: 'Request Header Fields Too Large', // RFC 6585
  451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error',
  501: 'Not Implemented',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
  505: 'HTTP Version Not Supported',
  506: 'Variant Also Negotiates',    // RFC 2295
  507: 'Insufficient Storage',       // RFC 4918
  508: 'Loop Detected',
  509: 'Bandwidth Limit Exceeded',
  510: 'Not Extended',               // RFC 2774
  511: 'Network Authentication Required' // RFC 6585
};

const kOnExecute = HTTPParser.kOnExecute | 0;


function ServerResponse(req) {
  OutgoingMessage.call(this);

  if (req.method === 'HEAD') this._hasBody = false;

  this.sendDate = true;

  if (req.httpVersionMajor < 1 || req.httpVersionMinor < 1) {
    this.useChunkedEncodingByDefault = chunkExpression.test(req.headers.te);
    this.shouldKeepAlive = false;
  }
}
util.inherits(ServerResponse, OutgoingMessage);

ServerResponse.prototype._finish = function() {
  OutgoingMessage.prototype._finish.call(this);
};


exports.ServerResponse = ServerResponse;

ServerResponse.prototype.statusCode = 200;
ServerResponse.prototype.statusMessage = undefined;

function onServerResponseClose() {
  // EventEmitter.emit makes a copy of the 'close' listeners array before
  // calling the listeners. detachSocket() unregisters onServerResponseClose
  // but if detachSocket() is called, directly or indirectly, by a 'close'
  // listener, onServerResponseClose is still in that copy of the listeners
  // array. That is, in the example below, b still gets called even though
  // it's been removed by a:
  //
  //   var EventEmitter = require('events');
  //   var obj = new EventEmitter();
  //   obj.on('event', a);
  //   obj.on('event', b);
  //   function a() { obj.removeListener('event', b) }
  //   function b() { throw "BAM!" }
  //   obj.emit('event');  // throws
  //
  // Ergo, we need to deal with stale 'close' events and handle the case
  // where the ServerResponse object has already been deconstructed.
  // Fortunately, that requires only a single if check. :-)
  if (this._httpMessage) this._httpMessage.emit('close');
}

ServerResponse.prototype.assignSocket = function(socket) {
  assert(!socket._httpMessage);
  socket._httpMessage = this;
  socket.on('close', onServerResponseClose);
  this.socket = socket;
  this.connection = socket;
  this.emit('socket', socket);
  this._flush();
};

ServerResponse.prototype.detachSocket = function(socket) {
  assert(socket._httpMessage === this);
  socket.removeListener('close', onServerResponseClose);
  socket._httpMessage = null;
  this.socket = this.connection = null;
};

ServerResponse.prototype.writeContinue = function(cb) {
  this._writeRaw('HTTP/1.1 100 Continue' + CRLF + CRLF, 'ascii', cb);
  this._sent100 = true;
};

ServerResponse.prototype._implicitHeader = function() {
  this.writeHead(this.statusCode);
};

ServerResponse.prototype.writeHead = function(statusCode, reason, obj) {
  var headers;

  if (typeof reason === 'string') {
    // writeHead(statusCode, reasonPhrase[, headers])
    this.statusMessage = reason;
  } else {
    // writeHead(statusCode[, headers])
    this.statusMessage =
        this.statusMessage || STATUS_CODES[statusCode] || 'unknown';
    obj = reason;
  }
  this.statusCode = statusCode;

  if (this._headers) {
    // Slow-case: when progressive API and header fields are passed.
    if (obj) {
      var keys = Object.keys(obj);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k) this.setHeader(k, obj[k]);
      }
    }
    // only progressive api is used
    headers = this._renderHeaders();
  } else {
    // only writeHead() called
    headers = obj;
  }

  statusCode |= 0;
  if (statusCode < 100 || statusCode > 999)
    throw new RangeError(`Invalid status code: ${statusCode}`);

  if (common._checkInvalidHeaderChar(this.statusMessage))
    throw new Error('Invalid character in statusMessage.');

  var statusLine = 'HTTP/1.1 ' + statusCode.toString() + ' ' +
                   this.statusMessage + CRLF;

  if (statusCode === 204 || statusCode === 304 ||
      (100 <= statusCode && statusCode <= 199)) {
    // RFC 2616, 10.2.5:
    // The 204 response MUST NOT include a message-body, and thus is always
    // terminated by the first empty line after the header fields.
    // RFC 2616, 10.3.5:
    // The 304 response MUST NOT contain a message-body, and thus is always
    // terminated by the first empty line after the header fields.
    // RFC 2616, 10.1 Informational 1xx:
    // This class of status code indicates a provisional response,
    // consisting only of the Status-Line and optional headers, and is
    // terminated by an empty line.
    this._hasBody = false;
  }

  // don't keep alive connections where the client expects 100 Continue
  // but we sent a final status; they may put extra bytes on the wire.
  if (this._expect_continue && !this._sent100) {
    this.shouldKeepAlive = false;
  }

  this._storeHeader(statusLine, headers);
};

ServerResponse.prototype.writeHeader = function() {
  this.writeHead.apply(this, arguments);
};


function Server(requestListener) {
  if (!(this instanceof Server)) return new Server(requestListener);
  net.Server.call(this, { allowHalfOpen: true });

  if (requestListener) {
    this.addListener('request', requestListener);
  }

  /* eslint-disable max-len */
  // Similar option to this. Too lazy to write my own docs.
  // http://www.squid-cache.org/Doc/config/half_closed_clients/
  // http://wiki.squid-cache.org/SquidFaq/InnerWorkings#What_is_a_half-closed_filedescriptor.3F
  /* eslint-enable max-len */
  this.httpAllowHalfOpen = false;

  this.addListener('connection', connectionListener);

  this.timeout = 2 * 60 * 1000;

  this._pendingResponseData = 0;
}
util.inherits(Server, net.Server);


Server.prototype.setTimeout = function(msecs, callback) {
  this.timeout = msecs;
  if (callback)
    this.on('timeout', callback);
  return this;
};


exports.Server = Server;


function connectionListener(socket) {
  var self = this;
  var outgoing = [];
  var incoming = [];
  var outgoingData = 0;

  function updateOutgoingData(delta) {
    // `outgoingData` is an approximate amount of bytes queued through all
    // inactive responses. If more data than the high watermark is queued - we
    // need to pause TCP socket/HTTP parser, and wait until the data will be
    // sent to the client.
    outgoingData += delta;
    if (socket._paused && outgoingData < socket._writableState.highWaterMark)
      return socketOnDrain();
  }

  function abortIncoming() {
    while (incoming.length) {
      var req = incoming.shift();
      req.emit('aborted');
      req.emit('close');
    }
    // abort socket._httpMessage ?
  }

  function serverSocketCloseListener() {
    // mark this parser as reusable
    if (this.parser) {
      freeParser(this.parser, null, this);
    }

    abortIncoming();
  }

  httpSocketSetup(socket);

  // If the user has added a listener to the server,
  // request, or response, then it's their responsibility.
  // otherwise, destroy on timeout by default
  if (self.timeout)
    socket.setTimeout(self.timeout);
  socket.on('timeout', function() {
    var req = socket.parser && socket.parser.incoming;
    var reqTimeout = req && !req.complete && req.emit('timeout', socket);
    var res = socket._httpMessage;
    var resTimeout = res && res.emit('timeout', socket);
    var serverTimeout = self.emit('timeout', socket);

    if (!reqTimeout && !resTimeout && !serverTimeout)
      socket.destroy();
  });

  var parser = parsers.alloc();
  parser.reinitialize(HTTPParser.REQUEST);
  parser.socket = socket;
  socket.parser = parser;
  parser.incoming = null;

  // Propagate headers limit from server instance to parser
  if (typeof this.maxHeadersCount === 'number') {
    parser.maxHeaderPairs = this.maxHeadersCount << 1;
  } else {
    // Set default value because parser may be reused from FreeList
    parser.maxHeaderPairs = 2000;
  }

  socket.addListener('error', socketOnError);
  socket.addListener('close', serverSocketCloseListener);
  parser.onIncoming = parserOnIncoming;
  socket.on('end', socketOnEnd);
  socket.on('data', socketOnData);

  // We are consuming socket, so it won't get any actual data
  socket.on('resume', onSocketResume);
  socket.on('pause', onSocketPause);

  socket.on('drain', socketOnDrain);

  // Override on to unconsume on `data`, `readable` listeners
  socket.on = socketOnWrap;

  parser[kOnExecute] = onParserExecute;

  // TODO(isaacs): Move all these functions out of here
  function socketOnError(e) {
    // Ignore further errors
    this.removeListener('error', socketOnError);
    this.on('error', () => {});

    if (!self.emit('clientError', e, this))
      this.destroy(e);
  }

  function socketOnData(d) {
    assert(!socket._paused);
    var ret = parser.execute(d);

    onParserExecuteCommon(ret, d);
  }

  function onParserExecute(ret, d) {
    socket._unrefTimer();
    onParserExecuteCommon(ret, undefined);
  }

  function onParserExecuteCommon(ret, d) {
    if (ret instanceof Error) {
      socketOnError.call(socket, ret);
    } else if (parser.incoming && parser.incoming.upgrade) {
      // Upgrade or CONNECT
      var bytesParsed = ret;
      var req = parser.incoming;

      if (!d)
        d = parser.getCurrentBuffer();

      socket.removeListener('data', socketOnData);
      socket.removeListener('end', socketOnEnd);
      socket.removeListener('close', serverSocketCloseListener);
      parser.finish();
      freeParser(parser, req, null);
      parser = null;

      var eventName = req.method === 'CONNECT' ? 'connect' : 'upgrade';
      if (self.listenerCount(eventName) > 0) {
        var bodyHead = d.slice(bytesParsed, d.length);

        // TODO(isaacs): Need a way to reset a stream to fresh state
        // IE, not flowing, and not explicitly paused.
        socket._readableState.flowing = null;
        self.emit(eventName, req, socket, bodyHead);
      } else {
        // Got upgrade header or CONNECT method, but have no handler.
        socket.destroy();
      }
    }

    if (socket._paused && socket.parser) {
      // onIncoming paused the socket, we should pause the parser as well
      socket.parser.pause();
    }
  }

  function socketOnEnd() {
    var socket = this;
    var ret = parser.finish();

    if (ret instanceof Error) {
      socketOnError.call(socket, ret);
      return;
    }

    if (!self.httpAllowHalfOpen) {
      abortIncoming();
      if (socket.writable) socket.end();
    } else if (outgoing.length) {
      outgoing[outgoing.length - 1]._last = true;
    } else if (socket._httpMessage) {
      socket._httpMessage._last = true;
    } else {
      if (socket.writable) socket.end();
    }
  }


  // The following callback is issued after the headers have been read on a
  // new message. In this callback we setup the response object and pass it
  // to the user.

  socket._paused = false;
  function socketOnDrain() {
    var needPause = outgoingData > socket._writableState.highWaterMark;

    // If we previously paused, then start reading again.
    if (socket._paused && !needPause) {
      socket._paused = false;
      if (socket.parser)
        socket.parser.resume();
      socket.resume();
    }
  }

  function parserOnIncoming(req, shouldKeepAlive) {
    incoming.push(req);

    // If the writable end isn't consuming, then stop reading
    // so that we don't become overwhelmed by a flood of
    // pipelined requests that may never be resolved.
    if (!socket._paused) {
      var needPause = socket._writableState.needDrain ||
          outgoingData >= socket._writableState.highWaterMark;
      if (needPause) {
        socket._paused = true;
        // We also need to pause the parser, but don't do that until after
        // the call to execute, because we may still be processing the last
        // chunk.
        socket.pause();
      }
    }

    var res = new ServerResponse(req);
    res._onPendingData = updateOutgoingData;

    res.shouldKeepAlive = shouldKeepAlive;

    if (socket._httpMessage) {
      // There are already pending outgoing res, append.
      outgoing.push(res);
    } else {
      res.assignSocket(socket);
    }

    // When we're finished writing the response, check if this is the last
    // response, if so destroy the socket.
    res.on('finish', resOnFinish);
    function resOnFinish() {
      // Usually the first incoming element should be our request.  it may
      // be that in the case abortIncoming() was called that the incoming
      // array will be empty.
      assert(incoming.length === 0 || incoming[0] === req);

      incoming.shift();

      // if the user never called req.read(), and didn't pipe() or
      // .resume() or .on('data'), then we call req._dump() so that the
      // bytes will be pulled off the wire.
      if (!req._consuming && !req._readableState.resumeScheduled)
        req._dump();

      res.detachSocket(socket);

      if (res._last) {
        socket.destroySoon();
      } else {
        // start sending the next message
        var m = outgoing.shift();
        if (m) {
          m.assignSocket(socket);
        }
      }
    }

    if (req.headers.expect !== undefined &&
        (req.httpVersionMajor == 1 && req.httpVersionMinor == 1)) {
      if (continueExpression.test(req.headers.expect)) {
        res._expect_continue = true;

        if (self.listenerCount('checkContinue') > 0) {
          self.emit('checkContinue', req, res);
        } else {
          res.writeContinue();
          self.emit('request', req, res);
        }
      } else {
        if (self.listenerCount('checkExpectation') > 0) {
          self.emit('checkExpectation', req, res);
        } else {
          res.writeHead(417);
          res.end();
        }
      }
    } else {
      self.emit('request', req, res);
    }
    return false; // Not a HEAD response. (Not even a response!)
  }
}
exports._connectionListener = connectionListener;

function onSocketResume() {
  // It may seem that the socket is resumed, but this is an enemy's trick to
  // deceive us! `resume` is emitted asynchronously, and may be called from
  // `incoming.readStart()`. Stop the socket again here, just to preserve the
  // state.
  //
  // We don't care about stream semantics for the consumed socket anyway.
  if (this._paused) {
    this.pause();
    return;
  }

  if (this._handle && !this._handle.reading) {
    this._handle.reading = true;
    this._handle.readStart();
  }
}

function onSocketPause() {
  if (this._handle && this._handle.reading) {
    this._handle.reading = false;
    this._handle.readStop();
  }
}

function socketOnWrap(ev, fn) {
  var res = net.Socket.prototype.on.call(this, ev, fn);
  if (!this.parser) {
    this.on = net.Socket.prototype.on;
    return res;
  }

  return res;
}

},{"./_http_common":22,"./_http_outgoing":24,"./http_parser":26,"assert":2,"net":28,"util":78}],26:[function(require,module,exports){
'use strict';

const HTTPParser = require('http-parser-js').HTTPParser;

module.exports = {
  methods: [
    'DELETE',
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'CONNECT',
    'OPTIONS',
    'TRACE',
    'COPY',
    'LOCK',
    'MKCOL',
    'MOVE',
    'PROPFIND',
    'PROPPATCH',
    'SEARCH',
    'UNLOCK',
    'BIND',
    'REBIND',
    'UNBIND',
    'ACL',
    'REPORT',
    'MKACTIVITY',
    'CHECKOUT',
    'MERGE',
    'M-SEARCH',
    'NOTIFY',
    'SUBSCRIBE',
    'UNSUBSCRIBE',
    'PATCH',
    'PURGE',
    'MKCALENDAR',
    'LINK',
    'UNLINK'
  ],
  HTTPParser: HTTPParser
};

},{"http-parser-js":39}],27:[function(require,module,exports){
'use strict';

// This is a free list to avoid creating so many of the same object.
exports.FreeList = function(name, max, constructor) {
  this.name = name;
  this.constructor = constructor;
  this.max = max;
  this.list = [];
};


exports.FreeList.prototype.alloc = function() {
  return this.list.length ? this.list.pop() :
                            this.constructor.apply(this, arguments);
};


exports.FreeList.prototype.free = function(obj) {
  if (this.list.length < this.max) {
    this.list.push(obj);
    return true;
  }
  return false;
};

},{}],28:[function(require,module,exports){
(function (process,global){(function (){
const EventEmitter = require('events');
const stream = require('stream');
const timers = require('timers');
const util = require('util');
const assert = require('assert');
const ipaddr = require('ipaddr.js');

const Buffer = require('buffer').Buffer;
const {
  TCP,
  Pipe,
  TCPConnectWrap,
  PipeConnectWrap,
  ShutdownWrap,
  WriteWrap
} = require('./lib/adapter');

const FridaSocket = global.Socket;


function noop() {}

function createHandle(fd) {
  var type = FridaSocket.type(fd);
  if (type === 'unix:stream') return new Pipe();
  if (type === 'tcp' || type === 'tcp6') return new TCP();
  throw new TypeError('Unsupported fd type: ' + type);
}


function isPipeName(s) {
  return typeof s === 'string' && toNumber(s) === false;
}

exports.createServer = function(options, connectionListener) {
  return new Server(options, connectionListener);
};


// Target API:
//
// var s = net.connect({port: 80, host: 'google.com'}, function() {
//   ...
// });
//
// There are various forms:
//
// connect(options, [cb])
// connect(port, [host], [cb])
// connect(path, [cb]);
//
exports.connect = exports.createConnection = function() {
  var args = new Array(arguments.length);
  for (var i = 0; i < arguments.length; i++)
    args[i] = arguments[i];
  args = normalizeArgs(args);
  var s = new Socket(args[0]);

  if (args[0].timeout) {
    s.setTimeout(args[0].timeout);
  }

  return Socket.prototype.connect.apply(s, args);
};

// Returns an array [options, cb], where cb can be null.
// It is the same as the argument of Socket.prototype.connect().
// This is used by Server.prototype.listen() and Socket.prototype.connect().
function normalizeArgs(args) {
  var options = {};

  if (args.length === 0) {
    return [options];
  } else if (args[0] !== null && typeof args[0] === 'object') {
    // connect(options, [cb])
    options = args[0];
  } else if (isPipeName(args[0])) {
    // connect(path, [cb]);
    options.path = args[0];
  } else {
    // connect(port, [host], [cb])
    options.port = args[0];
    if (args.length > 1 && typeof args[1] === 'string') {
      options.host = args[1];
    }
  }

  var cb = args[args.length - 1];
  if (typeof cb !== 'function')
    cb = null;
  return [options, cb];
}
exports._normalizeArgs = normalizeArgs;


// called when creating new Socket, or when re-using a closed Socket
function initSocketHandle(self) {
  self.destroyed = false;
  self._bytesDispatched = 0;
  self._sockname = null;

  // Handle creation may be deferred to bind() or connect() time.
  if (self._handle) {
    self._handle.owner = self;
    self._handle.onread = onread;

    // If handle doesn't support writev - neither do we
    if (!self._handle.writev)
      self._writev = null;
  }
}


const BYTES_READ = Symbol('bytesRead');


function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);

  this.connecting = false;
  this._hadError = false;
  this._handle = null;
  this._parent = null;
  this._host = null;

  if (typeof options === 'number')
    options = { fd: options }; // Legacy interface.
  else if (options === undefined)
    options = {};

  stream.Duplex.call(this, options);

  if (options.handle) {
    this._handle = options.handle; // private
  } else if (options.fd !== undefined) {
    this._handle = createHandle(options.fd);
    this._handle.open(options.fd);
    if ((options.fd == 1 || options.fd == 2) &&
        (this._handle instanceof Pipe) &&
        process.platform === 'win32') {
      // Make stdout and stderr blocking on Windows
      var err = this._handle.setBlocking(true);
      if (err)
        throw errnoException(err, 'setBlocking');
    }
    this.readable = options.readable !== false;
    this.writable = options.writable !== false;
  } else {
    // these will be set once there is a connection
    this.readable = this.writable = false;
  }

  // shut down the socket when we're finished with it.
  this.on('finish', onSocketFinish);
  this.on('_socketEnd', onSocketEnd);

  initSocketHandle(this);

  this._pendingData = null;
  this._pendingEncoding = '';

  // default to *not* allowing half open sockets
  this.allowHalfOpen = options && options.allowHalfOpen || false;

  // if we have a handle, then start the flow of data into the
  // buffer.  if not, then this will happen when we connect
  if (this._handle && options.readable !== false) {
    if (options.pauseOnCreate) {
      // stop the handle from reading and pause the stream
      this._handle.reading = false;
      this._handle.readStop();
      this._readableState.flowing = false;
    } else {
      this.read(0);
    }
  }

  // Reserve properties
  this.server = null;
  this._server = null;

  // Used after `.destroy()`
  this[BYTES_READ] = 0;
}
util.inherits(Socket, stream.Duplex);

Socket.prototype._unrefTimer = function unrefTimer() {
  for (var s = this; s !== null; s = s._parent)
    timers._unrefActive(s);
};

// the user has called .end(), and all the bytes have been
// sent out to the other side.
// If allowHalfOpen is false, or if the readable side has
// ended already, then destroy.
// If allowHalfOpen is true, then we need to do a shutdown,
// so that only the writable side will be cleaned up.
function onSocketFinish() {
  // If still connecting - defer handling 'finish' until 'connect' will happen
  if (this.connecting) {
    return this.once('connect', onSocketFinish);
  }

  if (!this.readable || this._readableState.ended) {
    return this.destroy();
  }

  // otherwise, just shutdown, or destroy() if not possible
  if (!this._handle || !this._handle.shutdown)
    return this.destroy();

  var req = new ShutdownWrap();
  req.oncomplete = afterShutdown;
  req.handle = this._handle;
  var err = this._handle.shutdown(req);

  if (err)
    return this._destroy(errnoException(err, 'shutdown'));
}


function afterShutdown(error, handle, req) {
  var self = handle.owner;

  // callback may come after call to destroy.
  if (self.destroyed)
    return;

  if (self._readableState.ended) {
    self.destroy();
  } else {
    self.once('_socketEnd', self.destroy);
  }
}

// the EOF has been received, and no more bytes are coming.
// if the writable side has ended already, then clean everything
// up.
function onSocketEnd() {
  // XXX Should not have to do as much crap in this function.
  // ended should already be true, since this is called *after*
  // the EOF errno and onread has eof'ed
  this._readableState.ended = true;
  if (this._readableState.endEmitted) {
    this.readable = false;
    maybeDestroy(this);
  } else {
    this.once('end', function() {
      this.readable = false;
      maybeDestroy(this);
    });
    this.read(0);
  }

  if (!this.allowHalfOpen) {
    this.write = writeAfterFIN;
    this.destroySoon();
  }
}

// Provide a better error message when we call end() as a result
// of the other side sending a FIN.  The standard 'write after end'
// is overly vague, and makes it seem like the user's code is to blame.
function writeAfterFIN(chunk, encoding, cb) {
  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  var er = new Error('This socket has been ended by the other party');
  er.code = 'EPIPE';
  // TODO: defer error events consistently everywhere, not just the cb
  this.emit('error', er);
  if (typeof cb === 'function') {
    process.nextTick(cb, er);
  }
}

exports.Socket = Socket;
exports.Stream = Socket; // Legacy naming.

Socket.prototype.read = function(n) {
  if (n === 0)
    return stream.Readable.prototype.read.call(this, n);

  this.read = stream.Readable.prototype.read;
  this._consuming = true;
  return this.read(n);
};


Socket.prototype.listen = function() {
  this.on('connection', arguments[0]);
  listen(this, null, null, null);
};


Socket.prototype.setTimeout = function(msecs, callback) {
  if (msecs === 0) {
    timers.unenroll(this);
    if (callback) {
      this.removeListener('timeout', callback);
    }
  } else {
    timers.enroll(this, msecs);
    timers._unrefActive(this);
    if (callback) {
      this.once('timeout', callback);
    }
  }
  return this;
};


Socket.prototype._onTimeout = function() {
  this.emit('timeout');
};


Socket.prototype.setNoDelay = function(enable) {
  if (!this._handle) {
    this.once('connect',
              enable ? this.setNoDelay : () => this.setNoDelay(enable));
    return this;
  }

  // backwards compatibility: assume true when `enable` is omitted
  if (this._handle.setNoDelay)
    this._handle.setNoDelay(enable === undefined ? true : !!enable);

  return this;
};


Socket.prototype.setKeepAlive = function(setting, msecs) {
  if (!this._handle) {
    this.once('connect', () => this.setKeepAlive(setting, msecs));
    return this;
  }

  if (this._handle.setKeepAlive)
    this._handle.setKeepAlive(setting, ~~(msecs / 1000));

  return this;
};


Socket.prototype.address = function() {
  return this._getsockname();
};


Object.defineProperty(Socket.prototype, '_connecting', {
  get: function() {
    return this.connecting;
  }
});


Object.defineProperty(Socket.prototype, 'readyState', {
  get: function() {
    if (this.connecting) {
      return 'opening';
    } else if (this.readable && this.writable) {
      return 'open';
    } else if (this.readable && !this.writable) {
      return 'readOnly';
    } else if (!this.readable && this.writable) {
      return 'writeOnly';
    } else {
      return 'closed';
    }
  }
});


Object.defineProperty(Socket.prototype, 'bufferSize', {
  get: function() {
    if (this._handle) {
      return this._handle.writeQueueSize + this._writableState.length;
    }
  }
});


// Just call handle.readStart until we have enough in the buffer
Socket.prototype._read = function(n) {
  if (this.connecting || !this._handle) {
    this.once('connect', () => this._read(n));
  } else if (!this._handle.reading) {
    // not already reading, start the flow
    this._handle.reading = true;
    var err = this._handle.readStart();
    if (err)
      this._destroy(errnoException(err, 'read'));
  }
};


Socket.prototype.end = function(data, encoding) {
  stream.Duplex.prototype.end.call(this, data, encoding);
  this.writable = false;

  // just in case we're waiting for an EOF.
  if (this.readable && !this._readableState.endEmitted)
    this.read(0);
  else
    maybeDestroy(this);
};


// Call whenever we set writable=false or readable=false
function maybeDestroy(socket) {
  if (!socket.readable &&
      !socket.writable &&
      !socket.destroyed &&
      !socket.connecting &&
      !socket._writableState.length) {
    socket.destroy();
  }
}


Socket.prototype.destroySoon = function() {
  if (this.writable)
    this.end();

  if (this._writableState.finished)
    this.destroy();
  else
    this.once('finish', this.destroy);
};


Socket.prototype._destroy = function(exception, cb) {
  function fireErrorCallbacks(self) {
    if (cb) cb(exception);
    if (exception && !self._writableState.errorEmitted) {
      process.nextTick(emitErrorNT, self, exception);
      self._writableState.errorEmitted = true;
    }
  }

  if (this.destroyed) {
    fireErrorCallbacks(this);
    return;
  }

  this.connecting = false;

  this.readable = this.writable = false;

  for (var s = this; s !== null; s = s._parent)
    timers.unenroll(s);

  if (this._handle) {
    var isException = exception ? true : false;
    // `bytesRead` should be accessible after `.destroy()`
    this[BYTES_READ] = this._handle.bytesRead;

    this._handle.close(() => {
      this.emit('close', isException);
    });
    this._handle.onread = noop;
    this._handle = null;
    this._sockname = null;
  }

  // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case Socket.prototype.destroy()
  // is called within callbacks
  this.destroyed = true;
  fireErrorCallbacks(this);

  if (this._server) {
    this._server._connections--;
    if (this._server._emitCloseIfDrained) {
      this._server._emitCloseIfDrained();
    }
  }
};


Socket.prototype.destroy = function(exception) {
  this._destroy(exception);
};


// This function is called whenever the handle gets a
// buffer, or when there's an error reading.
function onread(error, nread, buffer) {
  var handle = this;
  var self = handle.owner;
  assert(handle === self._handle, 'handle != self._handle');

  self._unrefTimer();

  if (nread > 0) {
    // read success.
    // In theory (and in practice) calling readStop right now
    // will prevent this from being called again until _read() gets
    // called again.

    // Optimization: emit the original buffer with end points
    var ret = self.push(buffer);

    if (handle.reading && !ret) {
      handle.reading = false;
      var err = handle.readStop();
      if (err)
        self._destroy(errnoException(err, 'read'));
    }
    return;
  }

  if (error !== null) {
    return self._destroy(errnoException(error, 'read'));
  }

  if (self._readableState.length === 0) {
    self.readable = false;
    maybeDestroy(self);
  }

  // push a null to signal the end of data.
  self.push(null);

  // internal end event so that we know that the actual socket
  // is no longer readable, and we can start the shutdown
  // procedure. No need to wait for all the data to be consumed.
  self.emit('_socketEnd');
}


Socket.prototype._getpeername = function() {
  if (!this._peername) {
    if (!this._handle || !this._handle.getpeername) {
      return {};
    }
    var out = {};
    var err = this._handle.getpeername(out);
    if (err) return {};  // FIXME(bnoordhuis) Throw?
    this._peername = out;
  }
  return this._peername;
};

function protoGetter(name, callback) {
  Object.defineProperty(Socket.prototype, name, {
    configurable: false,
    enumerable: true,
    get: callback
  });
}

protoGetter('bytesRead', function bytesRead() {
  return this._handle ? this._handle.bytesRead : this[BYTES_READ];
});

protoGetter('remoteAddress', function remoteAddress() {
  return this._getpeername().address;
});

protoGetter('remoteFamily', function remoteFamily() {
  return this._getpeername().family;
});

protoGetter('remotePort', function remotePort() {
  return this._getpeername().port;
});


Socket.prototype._getsockname = function() {
  if (!this._handle || !this._handle.getsockname) {
    return {};
  }
  if (!this._sockname) {
    var out = {};
    var err = this._handle.getsockname(out);
    if (err) return {};  // FIXME(bnoordhuis) Throw?
    this._sockname = out;
  }
  return this._sockname;
};


protoGetter('localAddress', function localAddress() {
  return this._getsockname().address;
});


protoGetter('localPort', function localPort() {
  return this._getsockname().port;
});


Socket.prototype.write = function(chunk, encoding, cb) {
  if (typeof chunk !== 'string' && !(chunk instanceof Buffer)) {
    throw new TypeError(
      'Invalid data, chunk must be a string or buffer, not ' + typeof chunk);
  }
  return stream.Duplex.prototype.write.apply(this, arguments);
};


Socket.prototype._writeGeneric = function(writev, data, encoding, cb) {
  // If we are still connecting, then buffer this for later.
  // The Writable logic will buffer up any more writes while
  // waiting for this one to be done.
  if (this.connecting) {
    this._pendingData = data;
    this._pendingEncoding = encoding;
    this.once('connect', function() {
      this._writeGeneric(writev, data, encoding, cb);
    });
    return;
  }
  this._pendingData = null;
  this._pendingEncoding = '';

  this._unrefTimer();

  if (!this._handle) {
    this._destroy(new Error('This socket is closed'), cb);
    return false;
  }

  var req = new WriteWrap();
  req.handle = this._handle;
  req.oncomplete = afterWrite;
  req.cb = cb;
  var err;

  if (writev) {
    var chunks = new Array(data.length << 1);
    for (var i = 0; i < data.length; i++) {
      var entry = data[i];
      chunks[i * 2] = entry.chunk;
      chunks[i * 2 + 1] = entry.encoding;
    }
    err = this._handle.writev(req, chunks);

    // Retain chunks
    if (!err) req._chunks = chunks;
  } else {
    var enc;
    if (data instanceof Buffer) {
      enc = 'buffer';
    } else {
      enc = encoding;
    }
    err = createWriteReq(req, this._handle, data, enc);
  }

  if (err)
    return this._destroy(errnoException(err, 'write', req.error), cb);

  this._bytesDispatched += req.bytes;
};


Socket.prototype._writev = function(chunks, cb) {
  this._writeGeneric(true, chunks, '', cb);
};


Socket.prototype._write = function(data, encoding, cb) {
  this._writeGeneric(false, data, encoding, cb);
};

function createWriteReq(req, handle, data, encoding) {
  switch (encoding) {
    case 'latin1':
    case 'binary':
      return handle.writeLatin1String(req, data);

    case 'buffer':
      return handle.writeBuffer(req, data);

    case 'utf8':
    case 'utf-8':
      return handle.writeUtf8String(req, data);

    case 'ascii':
      return handle.writeAsciiString(req, data);

    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return handle.writeUcs2String(req, data);

    default:
      return handle.writeBuffer(req, Buffer.from(data, encoding));
  }
}


protoGetter('bytesWritten', function bytesWritten() {
  var bytes = this._bytesDispatched;
  const state = this._writableState;
  const data = this._pendingData;
  const encoding = this._pendingEncoding;

  if (!state)
    return undefined;

  state.getBuffer().forEach(function(el) {
    if (el.chunk instanceof Buffer)
      bytes += el.chunk.length;
    else
      bytes += Buffer.byteLength(el.chunk, el.encoding);
  });

  if (data) {
    if (data instanceof Buffer)
      bytes += data.length;
    else
      bytes += Buffer.byteLength(data, encoding);
  }

  return bytes;
});


function afterWrite(error, handle, req) {
  var self = handle.owner;

  // callback may come after call to destroy.
  if (self.destroyed) {
    return;
  }

  if (error !== null) {
    var ex = errnoException(error, 'write', req.error);
    self._destroy(ex, req.cb);
    return;
  }

  self._unrefTimer();

  if (req.cb)
    req.cb.call(self);
}


function connect(self, address, port, addressType, localAddress, localPort) {
  // TODO return promise from Socket.prototype.connect which
  // wraps _connectReq.

  assert.ok(self.connecting);

  var err;

  if (localAddress || localPort) {
    throw new Error('Local address/port is not yet supported');
  }

  if (addressType === 6 || addressType === 4) {
    const req = new TCPConnectWrap();
    req.oncomplete = afterConnect;
    req.address = address;
    req.port = port;
    req.localAddress = localAddress;
    req.localPort = localPort;

    err = self._handle.connect(req, address, port);
  } else {
    const req = new PipeConnectWrap();
    req.address = address;
    req.oncomplete = afterConnect;
    err = self._handle.connect(req, address, afterConnect);
  }

  if (err) {
    var sockname = self._getsockname();
    var details;

    if (sockname) {
      details = sockname.address + ':' + sockname.port;
    }

    const ex = exceptionWithHostPort(err, 'connect', address, port, details);
    self._destroy(ex);
  }
}


Socket.prototype.connect = function(options, cb) {
  if (this.write !== Socket.prototype.write)
    this.write = Socket.prototype.write;

  if (options === null || typeof options !== 'object') {
    // Old API:
    // connect(port, [host], [cb])
    // connect(path, [cb]);
    var args = new Array(arguments.length);
    for (var i = 0; i < arguments.length; i++)
      args[i] = arguments[i];
    args = normalizeArgs(args);
    return Socket.prototype.connect.apply(this, args);
  }

  if (this.destroyed) {
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
    this.destroyed = false;
    this._handle = null;
    this._peername = null;
    this._sockname = null;
  }

  var pipe = !!options.path;

  if (!this._handle) {
    this._handle = pipe ? new Pipe() : new TCP();
    initSocketHandle(this);
  }

  if (typeof cb === 'function') {
    this.once('connect', cb);
  }

  this._unrefTimer();

  this.connecting = true;
  this.writable = true;

  if (pipe) {
    connect(this, options.path);
  } else {
    lookupAndConnect(this, options);
  }
  return this;
};


function lookupAndConnect(self, options) {
  const dns = require('dns');
  var host = options.host || 'localhost';
  var port = options.port;
  var localAddress = options.localAddress;
  var localPort = options.localPort;

  if (localAddress && !exports.isIP(localAddress))
    throw new TypeError('"localAddress" option must be a valid IP: ' +
                        localAddress);

  if (localPort && typeof localPort !== 'number')
    throw new TypeError('"localPort" option should be a number: ' + localPort);

  if (typeof port !== 'undefined') {
    if (typeof port !== 'number' && typeof port !== 'string')
      throw new TypeError('"port" option should be a number or string: ' +
                          port);
    if (!isLegalPort(port))
      throw new RangeError('"port" option should be >= 0 and < 65536: ' + port);
  }
  port |= 0;

  if (options.lookup)
    throw new TypeError('"lookup" option is not yet supported');

  var addressType = exports.isIP(host);
  if (addressType === 0)
    addressType = 4;

  process.nextTick(function() {
    if (self.connecting)
      connect(self, host, port, addressType, localAddress, localPort);
  });
}


Socket.prototype.ref = function() {
  if (!this._handle) {
    this.once('connect', this.ref);
    return this;
  }

  this._handle.ref();

  return this;
};


Socket.prototype.unref = function() {
  if (!this._handle) {
    this.once('connect', this.unref);
    return this;
  }

  this._handle.unref();

  return this;
};


function afterConnect(error, handle, req, readable, writable) {
  var self = handle.owner;

  // callback may come after call to destroy
  if (self.destroyed) {
    return;
  }

  // Update handle if it was wrapped
  // TODO(indutny): assert that the handle is actually an ancestor of old one
  handle = self._handle;

  assert.ok(self.connecting);
  self.connecting = false;
  self._sockname = null;

  if (error === null) {
    self.readable = readable;
    self.writable = writable;
    self._unrefTimer();

    self.emit('connect');

    // start the first read, or get an immediate EOF.
    // this doesn't actually consume any bytes, because len=0.
    if (readable && !self.isPaused())
      self.read(0);

  } else {
    self.connecting = false;
    var details;
    if (req.localAddress && req.localPort) {
      details = req.localAddress + ':' + req.localPort;
    }
    var ex = exceptionWithHostPort(error,
                                   'connect',
                                   req.address,
                                   req.port,
                                   details);
    if (details) {
      ex.localAddress = req.localAddress;
      ex.localPort = req.localPort;
    }
    self._destroy(ex);
  }
}


function Server(options, connectionListener) {
  if (!(this instanceof Server))
    return new Server(options, connectionListener);

  EventEmitter.call(this);

  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
    this.on('connection', connectionListener);
  } else if (options == null || typeof options === 'object') {
    options = options || {};

    if (typeof connectionListener === 'function') {
      this.on('connection', connectionListener);
    }
  } else {
    throw new TypeError('options must be an object');
  }

  this._connections = 0;

  Object.defineProperty(this, 'connections', {
    get: () => {

      if (this._usingSlaves) {
        return null;
      }
      return this._connections;
    },
    set: (val) => {
      return (this._connections = val);
    },
    configurable: true, enumerable: false
  });

  this._handle = null;
  this._usingSlaves = false;
  this._slaves = [];
  this._unref = false;

  this.allowHalfOpen = options.allowHalfOpen || false;
  this.pauseOnConnect = !!options.pauseOnConnect;
}
util.inherits(Server, EventEmitter);
exports.Server = Server;


function toNumber(x) { return (x = Number(x)) >= 0 ? x : false; }

Server.prototype._listen2 = function(address, port, addressType, backlog, fd) {
  // If there is not yet a handle, we need to create one and bind.
  // In the case of a server sent via IPC, we don't need to do this.
  if (!this._handle) {
    let handle;
    if (typeof fd === 'number' && fd >= 0) {
      try {
        handle = createHandle(fd);
      } catch (e) {
        // Not a fd we can listen on.  This will trigger an error.
        const error = exceptionWithHostPort(e, 'listen', address, port);
        process.nextTick(emitErrorNT, this, error);
        return;
      }
      handle.open(fd);
      handle.readable = true;
      handle.writable = true;
      assert(!address && !port);
    } else if (port === -1 && addressType === -1) {
      handle = new Pipe();
    } else {
      handle = new TCP();
    }
    this._handle = handle;
  }

  this._handle.onconnection = onconnection;
  this._handle.owner = this;

  // Use a backlog of 512 entries. We pass 511 to the listen() call because
  // the kernel does: backlogsize = roundup_pow_of_two(backlogsize + 1);
  // which will thus give us a backlog of 512 entries.
  this._handle.listen(address, port, backlog || 511, err => {
    if (err) {
      var ex = exceptionWithHostPort(err, 'listen', address, port);
      this._handle.close();
      this._handle = null;
      process.nextTick(emitErrorNT, this, ex);
      return;
    }

    // generate connection key, this should be unique to the connection
    this._connectionKey = addressType + ':' + address + ':' + port;

    // unref the handle if the server was unref'ed prior to listening
    if (this._unref)
      this.unref();

    process.nextTick(emitListeningNT, this);
  });
};


function emitErrorNT(self, err) {
  self.emit('error', err);
}


function emitListeningNT(self) {
  // ensure handle hasn't closed
  if (self._handle)
    self.emit('listening');
}


function listen(self, address, port, addressType, backlog, fd, exclusive) {
  self._listen2(address, port, addressType, backlog, fd);
}


Server.prototype.listen = function() {
  var args = new Array(arguments.length);
  for (var i = 0; i < arguments.length; i++)
    args[i] = arguments[i];
  var [options, cb] = normalizeArgs(args);

  if (typeof cb === 'function') {
    this.once('listening', cb);
  }

  if (args.length === 0 || typeof args[0] === 'function') {
    // Bind to a random port.
    options.port = 0;
  }

  // The third optional argument is the backlog size.
  // When the ip is omitted it can be the second argument.
  var backlog = toNumber(args.length > 1 && args[1]) ||
                toNumber(args.length > 2 && args[2]);

  options = options._handle || options.handle || options;

  if (options instanceof TCP) {
    this._handle = options;
    listen(this, null, -1, -1, backlog);
  } else if (typeof options.fd === 'number' && options.fd >= 0) {
    listen(this, null, null, null, backlog, options.fd);
  } else {
    backlog = options.backlog || backlog;

    if (typeof options.port === 'number' || typeof options.port === 'string' ||
        (typeof options.port === 'undefined' && 'port' in options)) {
      // Undefined is interpreted as zero (random port) for consistency
      // with net.connect().
      assertPort(options.port);
      if (options.host) {
        lookupAndListen(this, options.port | 0, options.host, backlog,
                        options.exclusive);
      } else {
        listen(this, null, options.port | 0, 4, backlog, undefined,
               options.exclusive);
      }
    } else if (options.path && isPipeName(options.path)) {
      // UNIX socket or Windows pipe.
      const pipeName = this._pipeName = options.path;
      listen(this, pipeName, -1, -1, backlog, undefined, options.exclusive);
    } else {
      throw new Error('Invalid listen argument: ' + options);
    }
  }

  return this;
};

function lookupAndListen(self, port, address, backlog, exclusive) {
  require('dns').lookup(address, function(err, ip, addressType) {
    if (err) {
      self.emit('error', err);
    } else {
      addressType = ip ? addressType : 4;
      listen(self, ip, port, addressType, backlog, undefined, exclusive);
    }
  });
}

Object.defineProperty(Server.prototype, 'listening', {
  get: function() {
    return !!(this._handle && this._connectionKey);
  },
  configurable: true,
  enumerable: true
});

Server.prototype.address = function() {
  if (this._handle && this._handle.getsockname) {
    var out = {};
    this._handle.getsockname(out);
    // TODO(bnoordhuis) Check err and throw?
    return out;
  } else if (this._pipeName) {
    return this._pipeName;
  } else {
    return null;
  }
};

function onconnection(err, clientHandle) {
  var handle = this;
  var self = handle.owner;

  if (err) {
    self.emit('error', errnoException(err, 'accept'));
    return;
  }

  if (self.maxConnections && self._connections >= self.maxConnections) {
    clientHandle.close();
    return;
  }

  var socket = new Socket({
    handle: clientHandle,
    allowHalfOpen: self.allowHalfOpen,
    pauseOnCreate: self.pauseOnConnect
  });
  socket.readable = socket.writable = true;


  self._connections++;
  socket.server = self;
  socket._server = self;

  self.emit('connection', socket);
}


Server.prototype.getConnections = function(cb) {
  function end(err, connections) {
    process.nextTick(cb, err, connections);
  }

  if (!this._usingSlaves) {
    return end(null, this._connections);
  }

  // Poll slaves
  var left = this._slaves.length;
  var total = this._connections;

  function oncount(err, count) {
    if (err) {
      left = -1;
      return end(err);
    }

    total += count;
    if (--left === 0) return end(null, total);
  }

  this._slaves.forEach(function(slave) {
    slave.getConnections(oncount);
  });
};


Server.prototype.close = function(cb) {
  function onSlaveClose() {
    if (--left !== 0) return;

    self._connections = 0;
    self._emitCloseIfDrained();
  }

  if (typeof cb === 'function') {
    if (!this._handle) {
      this.once('close', function() {
        cb(new Error('Not running'));
      });
    } else {
      this.once('close', cb);
    }
  }

  if (this._handle) {
    this._handle.close();
    this._handle = null;
  }

  if (this._usingSlaves) {
    var self = this;
    var left = this._slaves.length;

    // Increment connections to be sure that, even if all sockets will be closed
    // during polling of slaves, `close` event will be emitted only once.
    this._connections++;

    // Poll slaves
    this._slaves.forEach(function(slave) {
      slave.close(onSlaveClose);
    });
  } else {
    this._emitCloseIfDrained();
  }

  return this;
};

Server.prototype._emitCloseIfDrained = function() {
  if (this._handle || this._connections) {
    return;
  }

  process.nextTick(emitCloseNT, this);
};


function emitCloseNT(self) {
  self.emit('close');
}


Server.prototype.listenFD = function(fd, type) {
  return this.listen({ fd: fd });
};

Server.prototype._setupSlave = function(socketList) {
  this._usingSlaves = true;
  this._slaves.push(socketList);
};

Server.prototype.ref = function() {
  this._unref = false;

  if (this._handle)
    this._handle.ref();

  return this;
};

Server.prototype.unref = function() {
  this._unref = true;

  if (this._handle)
    this._handle.unref();

  return this;
};


exports.isIP = function(input) {
  try {
    const address = ipaddr.parse(input);
    return (address.kind === 'ipv6') ? 6 : 4;
  } catch (e) {
    return 0;
  }
};


exports.isIPv4 = function(input) {
  return exports.isIP() === 4;
}


exports.isIPv6 = function(input) {
  return exports.isIP() === 6;
}


exports._setSimultaneousAccepts = function(handle) {};


// Check that the port number is not NaN when coerced to a number,
// is an integer and that it falls within the legal range of port numbers.
function isLegalPort(port) {
  if ((typeof port !== 'number' && typeof port !== 'string') ||
      (typeof port === 'string' && port.trim().length === 0))
    return false;
  return +port === (+port >>> 0) && port <= 0xFFFF;
}


function assertPort(port) {
  if (typeof port !== 'undefined' && !isLegalPort(port))
    throw new RangeError('"port" argument must be >= 0 and < 65536');
}


function errnoException(err, syscall, original) {
  var errname = err.message;
  var message = syscall + ' ' + errname;
  if (original)
    message += ' ' + original;
  var e = new Error(message);
  e.code = errname;
  e.errno = errname;
  e.syscall = syscall;
  return e;
}


function exceptionWithHostPort(err,
                               syscall,
                               address,
                               port,
                               additional) {
  var details;
  if (port && port > 0) {
    details = address + ':' + port;
  } else {
    details = address;
  }

  if (additional) {
    details += ' - Local (' + additional + ')';
  }
  var ex = errnoException(err, syscall, details);
  ex.address = address;
  if (port) {
    ex.port = port;
  }
  return ex;
}

}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./lib/adapter":29,"_process":30,"assert":2,"buffer":16,"dns":9,"events":14,"ipaddr.js":42,"stream":56,"timers":72,"util":78}],29:[function(require,module,exports){
(function (process,Buffer){(function (){
class StreamHandle {
  constructor() {
    this.owner = null;
    this.onconnection = null;
    this.onread = null;
    this.closed = false;
    this.reading = false;

    this._listener = null;
    this._connection = null;
    this._reading = false;
    this._queuedRead = null;
  }

  close(callback) {
    if (this.closed) {
      onSuccess();
      return;
    }
    this.closed = true;

    const resource = this._listener || this._connection;
    if (resource === null) {
      onSuccess();
      return;
    }

    resource.close().then(onSuccess, onSuccess);

    function onSuccess() {
      if (callback)
        process.nextTick(callback);
    }
  }

  listen(address, port, backlog, callback) {
    let options;
    if (port === -1) {
      options = {
        path: address,
        backlog: backlog
      };
    } else {
      options = {
        host: address,
        port: port,
        backlog: backlog
      };
    }

    Socket.listen(options)
    .then(listener => {
      if (this.closed) {
        listener.close().then(noop, noop);
        callback(new Error('Handle is closed'));
        return;
      }

      this._listener = listener;
      this._acceptNext();

      callback(null);
    })
    .catch(error => {
      callback(error);
    });
  }

  _acceptNext() {
    this._listener.accept()
    .then(connection => {
      this.onconnection(null, this._create(connection));

      process.nextTick(() => {
        if (!this.closed) {
          this._acceptNext();
        }
      });
    })
    .catch(error => {
      if (this.closed) {
        return;
      }

      this.onconnection(error, null);
    });
  }

  getsockname(result) {
    if (this._listener !== null) {
      result.port = this._listener.port;
      // TODO
      result.family = 'IPv4';
      result.address = '0.0.0.0';
    }

    if (this._connection !== null) {
      // TODO
      result.port = 1234;
      result.family = 'IPv4';
      result.address = '127.0.0.1';
    }
  }

  connect(req, address, port) {
    Socket.connect({
      host: address,
      port: port,
    })
    .then(connection => {
      if (this.closed) {
        connection.close().then(noop, noop);
        req.oncomplete(new Error('Handle is closed'), this, req, false, false);
        return;
      }

      this._connection = connection;

      req.oncomplete(null, this, req, true, true);
    })
    .catch(error => {
      req.oncomplete(error, this, req, false, false);
    });
  }

  readStart() {
    const read = this._queuedRead;
    if (read !== null) {
      const [error, data] = read;
      if (error !== null) {
        return error;
      }

      this._queuedRead = null;
      process.nextTick(() => {
        this.onread(null, data.length, data);
      });
    }

    this._reading = true;
    this._readNext();
  }

  _readNext() {
    this._connection.input.read(512)
    .then(rawData => {
      const data = Buffer.from(rawData);
      if (this._reading) {
        this.onread(null, data.length, data);

        const isEof = data.length === 0;
        if (!isEof) {
          process.nextTick(() => {
            if (this._reading) {
              this._readNext();
            }
          });
        }
      } else {
        this._queuedRead = [null, data];
      }
    })
    .catch(error => {
      if (this._reading) {
        this.onread(error, -1, null);
      } else {
        this._queuedRead = [error, null];
      }
    });
  }

  readStop() {
    this._reading = false;
  }

  writeBuffer(req, data) {
    req.bytes = data.length;

    this._connection.output.writeAll(data.buffer)
    .then(connection => {
      req.oncomplete(null, this, req);
    })
    .catch(error => {
      req.oncomplete(error, this, req);
    });
  }
}

class TCP extends StreamHandle {
  _create(connection) {
    const handle = new TCP();
    handle._connection = connection;
    return handle;
  }
}

class Pipe extends StreamHandle {
  constructor() {
    super();

    throw new Error('Pipe not yet implemented');
  }

  _create(connection) {
    const handle = new Pipe();
    handle._connection = connection;
    return handle;
  }
}

class TCPConnectWrap {
  constructor() {
    this.address = '';
    this.port = 0;
    this.localAddress = null;
    this.localPort = null;
    this.oncomplete = null;
  }
}

class PipeConnectWrap {
  constructor() {
    this.address = '';
    this.oncomplete = null;
  }
}

class ShutdownWrap {
  constructor() {
    this.handle = null;
    this.oncomplete = null;
  }
}

class WriteWrap {
  constructor() {
    this.handle = null;
    this.oncomplete = null;
    this.bytes = 0;
    this.error = null;
  }
}

function noop() {}

module.exports = {
  TCP: TCP,
  Pipe: Pipe,
  TCPConnectWrap: TCPConnectWrap,
  PipeConnectWrap: PipeConnectWrap,
  ShutdownWrap: ShutdownWrap,
  WriteWrap: WriteWrap,
};

}).call(this)}).call(this,require('_process'),require("buffer").Buffer)

},{"_process":30,"buffer":16}],30:[function(require,module,exports){
// Based on https://github.com/shtylman/node-process

const EventEmitter = require('events');

const process = module.exports = {};

process.nextTick = Script.nextTick;

process.title = 'Frida';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

process.EventEmitter = EventEmitter;
process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
  throw new Error('process.binding is not supported');
};

process.cwd = function () {
  return '/'
};
process.chdir = function (dir) {
  throw new Error('process.chdir is not supported');
};
process.umask = function () {
  return 0;
};

function noop () {}

},{"events":14}],31:[function(require,module,exports){
const ios = require('./lib/ios');

const IOS = Symbol('ios');
const UNKNOWN = Symbol('unknown');

module.exports = function (view) {
  if (getOS() === IOS) {
    return ios(view);
  } else {
    return new Promise(function (resolve, reject) {
      reject(new Error('Not yet implemented for this OS'));
    });
  }
};

let cachedOS = null;
function getOS() {
  if (cachedOS === null) {
    cachedOS = detectOS();
  }
  return cachedOS;
}

function detectOS() {
  if (ObjC.available && 'UIView' in ObjC.classes) {
    return IOS;
  } else {
    return UNKNOWN;
  }
}

},{"./lib/ios":32}],32:[function(require,module,exports){
const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
const CGSize = [CGFloat, CGFloat];

module.exports = function (view) {
  return performOnMainThread(function () {
    const api = getApi();

    if (!view) {
      view = api.UIWindow.keyWindow();
    }

    const bounds = view.bounds();
    const size = bounds[1];
    api.UIGraphicsBeginImageContextWithOptions(size, 0, 0);

    view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);

    const image = api.UIGraphicsGetImageFromCurrentImageContext();
    api.UIGraphicsEndImageContext();

    const png = new ObjC.Object(api.UIImagePNGRepresentation(image));
    return png.bytes().readByteArray(png.length());
  });
};

function performOnMainThread(action) {
  return new Promise(function (resolve, reject) {
    if (getApi().NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }

    function performAction() {
      try {
        const result = action();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    }
  });
}

let cachedApi = null;
function getApi() {
  if (cachedApi === null) {
    cachedApi = {
      UIWindow: ObjC.classes.UIWindow,
      NSThread: ObjC.classes.NSThread,
      UIGraphicsBeginImageContextWithOptions: new NativeFunction(
          Module.findExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions'),
          'void', [CGSize, 'bool', CGFloat]),
      UIGraphicsEndImageContext: new NativeFunction(
          Module.findExportByName('UIKit', 'UIGraphicsEndImageContext'),
          'void', []),
      UIGraphicsGetImageFromCurrentImageContext: new NativeFunction(
          Module.findExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext'),
          'pointer', []),
      UIImagePNGRepresentation: new NativeFunction(
          Module.findExportByName('UIKit', 'UIImagePNGRepresentation'),
          'pointer', ['pointer'])
    };
  }
  return cachedApi;
}

},{}],33:[function(require,module,exports){
'use strict';

/* eslint no-invalid-this: 1 */

var ERROR_MESSAGE = 'Function.prototype.bind called on incompatible ';
var slice = Array.prototype.slice;
var toStr = Object.prototype.toString;
var funcType = '[object Function]';

module.exports = function bind(that) {
    var target = this;
    if (typeof target !== 'function' || toStr.call(target) !== funcType) {
        throw new TypeError(ERROR_MESSAGE + target);
    }
    var args = slice.call(arguments, 1);

    var bound;
    var binder = function () {
        if (this instanceof bound) {
            var result = target.apply(
                this,
                args.concat(slice.call(arguments))
            );
            if (Object(result) === result) {
                return result;
            }
            return this;
        } else {
            return target.apply(
                that,
                args.concat(slice.call(arguments))
            );
        }
    };

    var boundLength = Math.max(0, target.length - args.length);
    var boundArgs = [];
    for (var i = 0; i < boundLength; i++) {
        boundArgs.push('$' + i);
    }

    bound = Function('binder', 'return function (' + boundArgs.join(',') + '){ return binder.apply(this,arguments); }')(binder);

    if (target.prototype) {
        var Empty = function Empty() {};
        Empty.prototype = target.prototype;
        bound.prototype = new Empty();
        Empty.prototype = null;
    }

    return bound;
};

},{}],34:[function(require,module,exports){
'use strict';

var implementation = require('./implementation');

module.exports = Function.prototype.bind || implementation;

},{"./implementation":33}],35:[function(require,module,exports){
'use strict';

var undefined;

var $SyntaxError = SyntaxError;
var $Function = Function;
var $TypeError = TypeError;

// eslint-disable-next-line consistent-return
var getEvalledConstructor = function (expressionSyntax) {
	try {
		return $Function('"use strict"; return (' + expressionSyntax + ').constructor;')();
	} catch (e) {}
};

var $gOPD = Object.getOwnPropertyDescriptor;
if ($gOPD) {
	try {
		$gOPD({}, '');
	} catch (e) {
		$gOPD = null; // this is IE 8, which has a broken gOPD
	}
}

var throwTypeError = function () {
	throw new $TypeError();
};
var ThrowTypeError = $gOPD
	? (function () {
		try {
			// eslint-disable-next-line no-unused-expressions, no-caller, no-restricted-properties
			arguments.callee; // IE 8 does not throw here
			return throwTypeError;
		} catch (calleeThrows) {
			try {
				// IE 8 throws on Object.getOwnPropertyDescriptor(arguments, '')
				return $gOPD(arguments, 'callee').get;
			} catch (gOPDthrows) {
				return throwTypeError;
			}
		}
	}())
	: throwTypeError;

var hasSymbols = require('has-symbols')();

var getProto = Object.getPrototypeOf || function (x) { return x.__proto__; }; // eslint-disable-line no-proto

var needsEval = {};

var TypedArray = typeof Uint8Array === 'undefined' ? undefined : getProto(Uint8Array);

var INTRINSICS = {
	'%AggregateError%': typeof AggregateError === 'undefined' ? undefined : AggregateError,
	'%Array%': Array,
	'%ArrayBuffer%': typeof ArrayBuffer === 'undefined' ? undefined : ArrayBuffer,
	'%ArrayIteratorPrototype%': hasSymbols ? getProto([][Symbol.iterator]()) : undefined,
	'%AsyncFromSyncIteratorPrototype%': undefined,
	'%AsyncFunction%': needsEval,
	'%AsyncGenerator%': needsEval,
	'%AsyncGeneratorFunction%': needsEval,
	'%AsyncIteratorPrototype%': needsEval,
	'%Atomics%': typeof Atomics === 'undefined' ? undefined : Atomics,
	'%BigInt%': typeof BigInt === 'undefined' ? undefined : BigInt,
	'%Boolean%': Boolean,
	'%DataView%': typeof DataView === 'undefined' ? undefined : DataView,
	'%Date%': Date,
	'%decodeURI%': decodeURI,
	'%decodeURIComponent%': decodeURIComponent,
	'%encodeURI%': encodeURI,
	'%encodeURIComponent%': encodeURIComponent,
	'%Error%': Error,
	'%eval%': eval, // eslint-disable-line no-eval
	'%EvalError%': EvalError,
	'%Float32Array%': typeof Float32Array === 'undefined' ? undefined : Float32Array,
	'%Float64Array%': typeof Float64Array === 'undefined' ? undefined : Float64Array,
	'%FinalizationRegistry%': typeof FinalizationRegistry === 'undefined' ? undefined : FinalizationRegistry,
	'%Function%': $Function,
	'%GeneratorFunction%': needsEval,
	'%Int8Array%': typeof Int8Array === 'undefined' ? undefined : Int8Array,
	'%Int16Array%': typeof Int16Array === 'undefined' ? undefined : Int16Array,
	'%Int32Array%': typeof Int32Array === 'undefined' ? undefined : Int32Array,
	'%isFinite%': isFinite,
	'%isNaN%': isNaN,
	'%IteratorPrototype%': hasSymbols ? getProto(getProto([][Symbol.iterator]())) : undefined,
	'%JSON%': typeof JSON === 'object' ? JSON : undefined,
	'%Map%': typeof Map === 'undefined' ? undefined : Map,
	'%MapIteratorPrototype%': typeof Map === 'undefined' || !hasSymbols ? undefined : getProto(new Map()[Symbol.iterator]()),
	'%Math%': Math,
	'%Number%': Number,
	'%Object%': Object,
	'%parseFloat%': parseFloat,
	'%parseInt%': parseInt,
	'%Promise%': typeof Promise === 'undefined' ? undefined : Promise,
	'%Proxy%': typeof Proxy === 'undefined' ? undefined : Proxy,
	'%RangeError%': RangeError,
	'%ReferenceError%': ReferenceError,
	'%Reflect%': typeof Reflect === 'undefined' ? undefined : Reflect,
	'%RegExp%': RegExp,
	'%Set%': typeof Set === 'undefined' ? undefined : Set,
	'%SetIteratorPrototype%': typeof Set === 'undefined' || !hasSymbols ? undefined : getProto(new Set()[Symbol.iterator]()),
	'%SharedArrayBuffer%': typeof SharedArrayBuffer === 'undefined' ? undefined : SharedArrayBuffer,
	'%String%': String,
	'%StringIteratorPrototype%': hasSymbols ? getProto(''[Symbol.iterator]()) : undefined,
	'%Symbol%': hasSymbols ? Symbol : undefined,
	'%SyntaxError%': $SyntaxError,
	'%ThrowTypeError%': ThrowTypeError,
	'%TypedArray%': TypedArray,
	'%TypeError%': $TypeError,
	'%Uint8Array%': typeof Uint8Array === 'undefined' ? undefined : Uint8Array,
	'%Uint8ClampedArray%': typeof Uint8ClampedArray === 'undefined' ? undefined : Uint8ClampedArray,
	'%Uint16Array%': typeof Uint16Array === 'undefined' ? undefined : Uint16Array,
	'%Uint32Array%': typeof Uint32Array === 'undefined' ? undefined : Uint32Array,
	'%URIError%': URIError,
	'%WeakMap%': typeof WeakMap === 'undefined' ? undefined : WeakMap,
	'%WeakRef%': typeof WeakRef === 'undefined' ? undefined : WeakRef,
	'%WeakSet%': typeof WeakSet === 'undefined' ? undefined : WeakSet
};

var doEval = function doEval(name) {
	var value;
	if (name === '%AsyncFunction%') {
		value = getEvalledConstructor('async function () {}');
	} else if (name === '%GeneratorFunction%') {
		value = getEvalledConstructor('function* () {}');
	} else if (name === '%AsyncGeneratorFunction%') {
		value = getEvalledConstructor('async function* () {}');
	} else if (name === '%AsyncGenerator%') {
		var fn = doEval('%AsyncGeneratorFunction%');
		if (fn) {
			value = fn.prototype;
		}
	} else if (name === '%AsyncIteratorPrototype%') {
		var gen = doEval('%AsyncGenerator%');
		if (gen) {
			value = getProto(gen.prototype);
		}
	}

	INTRINSICS[name] = value;

	return value;
};

var LEGACY_ALIASES = {
	'%ArrayBufferPrototype%': ['ArrayBuffer', 'prototype'],
	'%ArrayPrototype%': ['Array', 'prototype'],
	'%ArrayProto_entries%': ['Array', 'prototype', 'entries'],
	'%ArrayProto_forEach%': ['Array', 'prototype', 'forEach'],
	'%ArrayProto_keys%': ['Array', 'prototype', 'keys'],
	'%ArrayProto_values%': ['Array', 'prototype', 'values'],
	'%AsyncFunctionPrototype%': ['AsyncFunction', 'prototype'],
	'%AsyncGenerator%': ['AsyncGeneratorFunction', 'prototype'],
	'%AsyncGeneratorPrototype%': ['AsyncGeneratorFunction', 'prototype', 'prototype'],
	'%BooleanPrototype%': ['Boolean', 'prototype'],
	'%DataViewPrototype%': ['DataView', 'prototype'],
	'%DatePrototype%': ['Date', 'prototype'],
	'%ErrorPrototype%': ['Error', 'prototype'],
	'%EvalErrorPrototype%': ['EvalError', 'prototype'],
	'%Float32ArrayPrototype%': ['Float32Array', 'prototype'],
	'%Float64ArrayPrototype%': ['Float64Array', 'prototype'],
	'%FunctionPrototype%': ['Function', 'prototype'],
	'%Generator%': ['GeneratorFunction', 'prototype'],
	'%GeneratorPrototype%': ['GeneratorFunction', 'prototype', 'prototype'],
	'%Int8ArrayPrototype%': ['Int8Array', 'prototype'],
	'%Int16ArrayPrototype%': ['Int16Array', 'prototype'],
	'%Int32ArrayPrototype%': ['Int32Array', 'prototype'],
	'%JSONParse%': ['JSON', 'parse'],
	'%JSONStringify%': ['JSON', 'stringify'],
	'%MapPrototype%': ['Map', 'prototype'],
	'%NumberPrototype%': ['Number', 'prototype'],
	'%ObjectPrototype%': ['Object', 'prototype'],
	'%ObjProto_toString%': ['Object', 'prototype', 'toString'],
	'%ObjProto_valueOf%': ['Object', 'prototype', 'valueOf'],
	'%PromisePrototype%': ['Promise', 'prototype'],
	'%PromiseProto_then%': ['Promise', 'prototype', 'then'],
	'%Promise_all%': ['Promise', 'all'],
	'%Promise_reject%': ['Promise', 'reject'],
	'%Promise_resolve%': ['Promise', 'resolve'],
	'%RangeErrorPrototype%': ['RangeError', 'prototype'],
	'%ReferenceErrorPrototype%': ['ReferenceError', 'prototype'],
	'%RegExpPrototype%': ['RegExp', 'prototype'],
	'%SetPrototype%': ['Set', 'prototype'],
	'%SharedArrayBufferPrototype%': ['SharedArrayBuffer', 'prototype'],
	'%StringPrototype%': ['String', 'prototype'],
	'%SymbolPrototype%': ['Symbol', 'prototype'],
	'%SyntaxErrorPrototype%': ['SyntaxError', 'prototype'],
	'%TypedArrayPrototype%': ['TypedArray', 'prototype'],
	'%TypeErrorPrototype%': ['TypeError', 'prototype'],
	'%Uint8ArrayPrototype%': ['Uint8Array', 'prototype'],
	'%Uint8ClampedArrayPrototype%': ['Uint8ClampedArray', 'prototype'],
	'%Uint16ArrayPrototype%': ['Uint16Array', 'prototype'],
	'%Uint32ArrayPrototype%': ['Uint32Array', 'prototype'],
	'%URIErrorPrototype%': ['URIError', 'prototype'],
	'%WeakMapPrototype%': ['WeakMap', 'prototype'],
	'%WeakSetPrototype%': ['WeakSet', 'prototype']
};

var bind = require('function-bind');
var hasOwn = require('has');
var $concat = bind.call(Function.call, Array.prototype.concat);
var $spliceApply = bind.call(Function.apply, Array.prototype.splice);
var $replace = bind.call(Function.call, String.prototype.replace);
var $strSlice = bind.call(Function.call, String.prototype.slice);

/* adapted from https://github.com/lodash/lodash/blob/4.17.15/dist/lodash.js#L6735-L6744 */
var rePropName = /[^%.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|%$))/g;
var reEscapeChar = /\\(\\)?/g; /** Used to match backslashes in property paths. */
var stringToPath = function stringToPath(string) {
	var first = $strSlice(string, 0, 1);
	var last = $strSlice(string, -1);
	if (first === '%' && last !== '%') {
		throw new $SyntaxError('invalid intrinsic syntax, expected closing `%`');
	} else if (last === '%' && first !== '%') {
		throw new $SyntaxError('invalid intrinsic syntax, expected opening `%`');
	}
	var result = [];
	$replace(string, rePropName, function (match, number, quote, subString) {
		result[result.length] = quote ? $replace(subString, reEscapeChar, '$1') : number || match;
	});
	return result;
};
/* end adaptation */

var getBaseIntrinsic = function getBaseIntrinsic(name, allowMissing) {
	var intrinsicName = name;
	var alias;
	if (hasOwn(LEGACY_ALIASES, intrinsicName)) {
		alias = LEGACY_ALIASES[intrinsicName];
		intrinsicName = '%' + alias[0] + '%';
	}

	if (hasOwn(INTRINSICS, intrinsicName)) {
		var value = INTRINSICS[intrinsicName];
		if (value === needsEval) {
			value = doEval(intrinsicName);
		}
		if (typeof value === 'undefined' && !allowMissing) {
			throw new $TypeError('intrinsic ' + name + ' exists, but is not available. Please file an issue!');
		}

		return {
			alias: alias,
			name: intrinsicName,
			value: value
		};
	}

	throw new $SyntaxError('intrinsic ' + name + ' does not exist!');
};

module.exports = function GetIntrinsic(name, allowMissing) {
	if (typeof name !== 'string' || name.length === 0) {
		throw new $TypeError('intrinsic name must be a non-empty string');
	}
	if (arguments.length > 1 && typeof allowMissing !== 'boolean') {
		throw new $TypeError('"allowMissing" argument must be a boolean');
	}

	var parts = stringToPath(name);
	var intrinsicBaseName = parts.length > 0 ? parts[0] : '';

	var intrinsic = getBaseIntrinsic('%' + intrinsicBaseName + '%', allowMissing);
	var intrinsicRealName = intrinsic.name;
	var value = intrinsic.value;
	var skipFurtherCaching = false;

	var alias = intrinsic.alias;
	if (alias) {
		intrinsicBaseName = alias[0];
		$spliceApply(parts, $concat([0, 1], alias));
	}

	for (var i = 1, isOwn = true; i < parts.length; i += 1) {
		var part = parts[i];
		var first = $strSlice(part, 0, 1);
		var last = $strSlice(part, -1);
		if (
			(
				(first === '"' || first === "'" || first === '`')
				|| (last === '"' || last === "'" || last === '`')
			)
			&& first !== last
		) {
			throw new $SyntaxError('property names with quotes must have matching quotes');
		}
		if (part === 'constructor' || !isOwn) {
			skipFurtherCaching = true;
		}

		intrinsicBaseName += '.' + part;
		intrinsicRealName = '%' + intrinsicBaseName + '%';

		if (hasOwn(INTRINSICS, intrinsicRealName)) {
			value = INTRINSICS[intrinsicRealName];
		} else if (value != null) {
			if (!(part in value)) {
				if (!allowMissing) {
					throw new $TypeError('base intrinsic for ' + name + ' exists, but the property is not available.');
				}
				return void undefined;
			}
			if ($gOPD && (i + 1) >= parts.length) {
				var desc = $gOPD(value, part);
				isOwn = !!desc;

				// By convention, when a data property is converted to an accessor
				// property to emulate a data property that does not suffer from
				// the override mistake, that accessor's getter is marked with
				// an `originalValue` property. Here, when we detect this, we
				// uphold the illusion by pretending to see that original data
				// property, i.e., returning the value rather than the getter
				// itself.
				if (isOwn && 'get' in desc && !('originalValue' in desc.get)) {
					value = desc.get;
				} else {
					value = value[part];
				}
			} else {
				isOwn = hasOwn(value, part);
				value = value[part];
			}

			if (isOwn && !skipFurtherCaching) {
				INTRINSICS[intrinsicRealName] = value;
			}
		}
	}
	return value;
};

},{"function-bind":34,"has":38,"has-symbols":36}],36:[function(require,module,exports){
(function (global){(function (){
'use strict';

var origSymbol = global.Symbol;
var hasSymbolSham = require('./shams');

module.exports = function hasNativeSymbols() {
	if (typeof origSymbol !== 'function') { return false; }
	if (typeof Symbol !== 'function') { return false; }
	if (typeof origSymbol('foo') !== 'symbol') { return false; }
	if (typeof Symbol('bar') !== 'symbol') { return false; }

	return hasSymbolSham();
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./shams":37}],37:[function(require,module,exports){
'use strict';

/* eslint complexity: [2, 18], max-statements: [2, 33] */
module.exports = function hasSymbols() {
	if (typeof Symbol !== 'function' || typeof Object.getOwnPropertySymbols !== 'function') { return false; }
	if (typeof Symbol.iterator === 'symbol') { return true; }

	var obj = {};
	var sym = Symbol('test');
	var symObj = Object(sym);
	if (typeof sym === 'string') { return false; }

	if (Object.prototype.toString.call(sym) !== '[object Symbol]') { return false; }
	if (Object.prototype.toString.call(symObj) !== '[object Symbol]') { return false; }

	// temp disabled per https://github.com/ljharb/object.assign/issues/17
	// if (sym instanceof Symbol) { return false; }
	// temp disabled per https://github.com/WebReflection/get-own-property-symbols/issues/4
	// if (!(symObj instanceof Symbol)) { return false; }

	// if (typeof Symbol.prototype.toString !== 'function') { return false; }
	// if (String(sym) !== Symbol.prototype.toString.call(sym)) { return false; }

	var symVal = 42;
	obj[sym] = symVal;
	for (sym in obj) { return false; } // eslint-disable-line no-restricted-syntax
	if (typeof Object.keys === 'function' && Object.keys(obj).length !== 0) { return false; }

	if (typeof Object.getOwnPropertyNames === 'function' && Object.getOwnPropertyNames(obj).length !== 0) { return false; }

	var syms = Object.getOwnPropertySymbols(obj);
	if (syms.length !== 1 || syms[0] !== sym) { return false; }

	if (!Object.prototype.propertyIsEnumerable.call(obj, sym)) { return false; }

	if (typeof Object.getOwnPropertyDescriptor === 'function') {
		var descriptor = Object.getOwnPropertyDescriptor(obj, sym);
		if (descriptor.value !== symVal || descriptor.enumerable !== true) { return false; }
	}

	return true;
};

},{}],38:[function(require,module,exports){
'use strict';

var bind = require('function-bind');

module.exports = bind.call(Function.call, Object.prototype.hasOwnProperty);

},{"function-bind":34}],39:[function(require,module,exports){
/*jshint node:true */

var assert = require('assert');

exports.HTTPParser = HTTPParser;
function HTTPParser(type) {
  assert.ok(type === HTTPParser.REQUEST || type === HTTPParser.RESPONSE || type === undefined);
  if (type === undefined) {
    // Node v12+
  } else {
    this.initialize(type);
  }
}
HTTPParser.prototype.initialize = function (type, async_resource) {
  assert.ok(type === HTTPParser.REQUEST || type === HTTPParser.RESPONSE);
  this.type = type;
  this.state = type + '_LINE';
  this.info = {
    headers: [],
    upgrade: false
  };
  this.trailers = [];
  this.line = '';
  this.isChunked = false;
  this.connection = '';
  this.headerSize = 0; // for preventing too big headers
  this.body_bytes = null;
  this.isUserCall = false;
  this.hadError = false;
};

HTTPParser.encoding = 'ascii';
HTTPParser.maxHeaderSize = 80 * 1024; // maxHeaderSize (in bytes) is configurable, but 80kb by default;
HTTPParser.REQUEST = 'REQUEST';
HTTPParser.RESPONSE = 'RESPONSE';

// Note: *not* starting with kOnHeaders=0 line the Node parser, because any
//   newly added constants (kOnTimeout in Node v12.19.0) will overwrite 0!
var kOnHeaders = HTTPParser.kOnHeaders = 1;
var kOnHeadersComplete = HTTPParser.kOnHeadersComplete = 2;
var kOnBody = HTTPParser.kOnBody = 3;
var kOnMessageComplete = HTTPParser.kOnMessageComplete = 4;

// Some handler stubs, needed for compatibility
HTTPParser.prototype[kOnHeaders] =
HTTPParser.prototype[kOnHeadersComplete] =
HTTPParser.prototype[kOnBody] =
HTTPParser.prototype[kOnMessageComplete] = function () {};

var compatMode0_12 = true;
Object.defineProperty(HTTPParser, 'kOnExecute', {
    get: function () {
      // hack for backward compatibility
      compatMode0_12 = false;
      return 99;
    }
  });

var methods = exports.methods = HTTPParser.methods = [
  'DELETE',
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'CONNECT',
  'OPTIONS',
  'TRACE',
  'COPY',
  'LOCK',
  'MKCOL',
  'MOVE',
  'PROPFIND',
  'PROPPATCH',
  'SEARCH',
  'UNLOCK',
  'BIND',
  'REBIND',
  'UNBIND',
  'ACL',
  'REPORT',
  'MKACTIVITY',
  'CHECKOUT',
  'MERGE',
  'M-SEARCH',
  'NOTIFY',
  'SUBSCRIBE',
  'UNSUBSCRIBE',
  'PATCH',
  'PURGE',
  'MKCALENDAR',
  'LINK',
  'UNLINK'
];
var method_connect = methods.indexOf('CONNECT');
HTTPParser.prototype.reinitialize = HTTPParser;
HTTPParser.prototype.close =
HTTPParser.prototype.pause =
HTTPParser.prototype.resume =
HTTPParser.prototype.free = function () {};
HTTPParser.prototype._compatMode0_11 = false;
HTTPParser.prototype.getAsyncId = function() { return 0; };

var headerState = {
  REQUEST_LINE: true,
  RESPONSE_LINE: true,
  HEADER: true
};
HTTPParser.prototype.execute = function (chunk, start, length) {
  if (!(this instanceof HTTPParser)) {
    throw new TypeError('not a HTTPParser');
  }

  // backward compat to node < 0.11.4
  // Note: the start and length params were removed in newer version
  start = start || 0;
  length = typeof length === 'number' ? length : chunk.length;

  this.chunk = chunk;
  this.offset = start;
  var end = this.end = start + length;
  try {
    while (this.offset < end) {
      if (this[this.state]()) {
        break;
      }
    }
  } catch (err) {
    if (this.isUserCall) {
      throw err;
    }
    this.hadError = true;
    return err;
  }
  this.chunk = null;
  length = this.offset - start;
  if (headerState[this.state]) {
    this.headerSize += length;
    if (this.headerSize > HTTPParser.maxHeaderSize) {
      return new Error('max header size exceeded');
    }
  }
  return length;
};

var stateFinishAllowed = {
  REQUEST_LINE: true,
  RESPONSE_LINE: true,
  BODY_RAW: true
};
HTTPParser.prototype.finish = function () {
  if (this.hadError) {
    return;
  }
  if (!stateFinishAllowed[this.state]) {
    return new Error('invalid state for EOF');
  }
  if (this.state === 'BODY_RAW') {
    this.userCall()(this[kOnMessageComplete]());
  }
};

// These three methods are used for an internal speed optimization, and it also
// works if theses are noops. Basically consume() asks us to read the bytes
// ourselves, but if we don't do it we get them through execute().
HTTPParser.prototype.consume =
HTTPParser.prototype.unconsume =
HTTPParser.prototype.getCurrentBuffer = function () {};

//For correct error handling - see HTTPParser#execute
//Usage: this.userCall()(userFunction('arg'));
HTTPParser.prototype.userCall = function () {
  this.isUserCall = true;
  var self = this;
  return function (ret) {
    self.isUserCall = false;
    return ret;
  };
};

HTTPParser.prototype.nextRequest = function () {
  this.userCall()(this[kOnMessageComplete]());
  this.reinitialize(this.type);
};

HTTPParser.prototype.consumeLine = function () {
  var end = this.end,
      chunk = this.chunk;
  for (var i = this.offset; i < end; i++) {
    if (chunk[i] === 0x0a) { // \n
      var line = this.line + chunk.toString(HTTPParser.encoding, this.offset, i);
      if (line.charAt(line.length - 1) === '\r') {
        line = line.substr(0, line.length - 1);
      }
      this.line = '';
      this.offset = i + 1;
      return line;
    }
  }
  //line split over multiple chunks
  this.line += chunk.toString(HTTPParser.encoding, this.offset, this.end);
  this.offset = this.end;
};

var headerExp = /^([^: \t]+):[ \t]*((?:.*[^ \t])|)/;
var headerContinueExp = /^[ \t]+(.*[^ \t])/;
HTTPParser.prototype.parseHeader = function (line, headers) {
  if (line.indexOf('\r') !== -1) {
    throw parseErrorCode('HPE_LF_EXPECTED');
  }

  var match = headerExp.exec(line);
  var k = match && match[1];
  if (k) { // skip empty string (malformed header)
    headers.push(k);
    headers.push(match[2]);
  } else {
    var matchContinue = headerContinueExp.exec(line);
    if (matchContinue && headers.length) {
      if (headers[headers.length - 1]) {
        headers[headers.length - 1] += ' ';
      }
      headers[headers.length - 1] += matchContinue[1];
    }
  }
};

var requestExp = /^([A-Z-]+) ([^ ]+) HTTP\/(\d)\.(\d)$/;
HTTPParser.prototype.REQUEST_LINE = function () {
  var line = this.consumeLine();
  if (!line) {
    return;
  }
  var match = requestExp.exec(line);
  if (match === null) {
    throw parseErrorCode('HPE_INVALID_CONSTANT');
  }
  this.info.method = this._compatMode0_11 ? match[1] : methods.indexOf(match[1]);
  if (this.info.method === -1) {
    throw new Error('invalid request method');
  }
  this.info.url = match[2];
  this.info.versionMajor = +match[3];
  this.info.versionMinor = +match[4];
  this.body_bytes = 0;
  this.state = 'HEADER';
};

var responseExp = /^HTTP\/(\d)\.(\d) (\d{3}) ?(.*)$/;
HTTPParser.prototype.RESPONSE_LINE = function () {
  var line = this.consumeLine();
  if (!line) {
    return;
  }
  var match = responseExp.exec(line);
  if (match === null) {
    throw parseErrorCode('HPE_INVALID_CONSTANT');
  }
  this.info.versionMajor = +match[1];
  this.info.versionMinor = +match[2];
  var statusCode = this.info.statusCode = +match[3];
  this.info.statusMessage = match[4];
  // Implied zero length.
  if ((statusCode / 100 | 0) === 1 || statusCode === 204 || statusCode === 304) {
    this.body_bytes = 0;
  }
  this.state = 'HEADER';
};

HTTPParser.prototype.shouldKeepAlive = function () {
  if (this.info.versionMajor > 0 && this.info.versionMinor > 0) {
    if (this.connection.indexOf('close') !== -1) {
      return false;
    }
  } else if (this.connection.indexOf('keep-alive') === -1) {
    return false;
  }
  if (this.body_bytes !== null || this.isChunked) { // || skipBody
    return true;
  }
  return false;
};

HTTPParser.prototype.HEADER = function () {
  var line = this.consumeLine();
  if (line === undefined) {
    return;
  }
  var info = this.info;
  if (line) {
    this.parseHeader(line, info.headers);
  } else {
    var headers = info.headers;
    var hasContentLength = false;
    var currentContentLengthValue;
    var hasUpgradeHeader = false;
    for (var i = 0; i < headers.length; i += 2) {
      switch (headers[i].toLowerCase()) {
        case 'transfer-encoding':
          this.isChunked = headers[i + 1].toLowerCase() === 'chunked';
          break;
        case 'content-length':
          currentContentLengthValue = +headers[i + 1];
          if (hasContentLength) {
            // Fix duplicate Content-Length header with same values.
            // Throw error only if values are different.
            // Known issues:
            // https://github.com/request/request/issues/2091#issuecomment-328715113
            // https://github.com/nodejs/node/issues/6517#issuecomment-216263771
            if (currentContentLengthValue !== this.body_bytes) {
              throw parseErrorCode('HPE_UNEXPECTED_CONTENT_LENGTH');
            }
          } else {
            hasContentLength = true;
            this.body_bytes = currentContentLengthValue;
          }
          break;
        case 'connection':
          this.connection += headers[i + 1].toLowerCase();
          break;
        case 'upgrade':
          hasUpgradeHeader = true;
          break;
      }
    }

    // if both isChunked and hasContentLength, isChunked wins
    // This is required so the body is parsed using the chunked method, and matches
    // Chrome's behavior.  We could, maybe, ignore them both (would get chunked
    // encoding into the body), and/or disable shouldKeepAlive to be more
    // resilient.
    if (this.isChunked && hasContentLength) {
      hasContentLength = false;
      this.body_bytes = null;
    }

    // Logic from https://github.com/nodejs/http-parser/blob/921d5585515a153fa00e411cf144280c59b41f90/http_parser.c#L1727-L1737
    // "For responses, "Upgrade: foo" and "Connection: upgrade" are
    //   mandatory only when it is a 101 Switching Protocols response,
    //   otherwise it is purely informational, to announce support.
    if (hasUpgradeHeader && this.connection.indexOf('upgrade') != -1) {
      info.upgrade = this.type === HTTPParser.REQUEST || info.statusCode === 101;
    } else {
      info.upgrade = info.method === method_connect;
    }

    if (this.isChunked && info.upgrade) {
      this.isChunked = false;
    }

    info.shouldKeepAlive = this.shouldKeepAlive();
    //problem which also exists in original node: we should know skipBody before calling onHeadersComplete
    var skipBody;
    if (compatMode0_12) {
      skipBody = this.userCall()(this[kOnHeadersComplete](info));
    } else {
      skipBody = this.userCall()(this[kOnHeadersComplete](info.versionMajor,
          info.versionMinor, info.headers, info.method, info.url, info.statusCode,
          info.statusMessage, info.upgrade, info.shouldKeepAlive));
    }
    if (skipBody === 2) {
      this.nextRequest();
      return true;
    } else if (this.isChunked && !skipBody) {
      this.state = 'BODY_CHUNKHEAD';
    } else if (skipBody || this.body_bytes === 0) {
      this.nextRequest();
      // For older versions of node (v6.x and older?), that return skipBody=1 or skipBody=true,
      //   need this "return true;" if it's an upgrade request.
      return info.upgrade;
    } else if (this.body_bytes === null) {
      this.state = 'BODY_RAW';
    } else {
      this.state = 'BODY_SIZED';
    }
  }
};

HTTPParser.prototype.BODY_CHUNKHEAD = function () {
  var line = this.consumeLine();
  if (line === undefined) {
    return;
  }
  this.body_bytes = parseInt(line, 16);
  if (!this.body_bytes) {
    this.state = 'BODY_CHUNKTRAILERS';
  } else {
    this.state = 'BODY_CHUNK';
  }
};

HTTPParser.prototype.BODY_CHUNK = function () {
  var length = Math.min(this.end - this.offset, this.body_bytes);
  this.userCall()(this[kOnBody](this.chunk, this.offset, length));
  this.offset += length;
  this.body_bytes -= length;
  if (!this.body_bytes) {
    this.state = 'BODY_CHUNKEMPTYLINE';
  }
};

HTTPParser.prototype.BODY_CHUNKEMPTYLINE = function () {
  var line = this.consumeLine();
  if (line === undefined) {
    return;
  }
  assert.equal(line, '');
  this.state = 'BODY_CHUNKHEAD';
};

HTTPParser.prototype.BODY_CHUNKTRAILERS = function () {
  var line = this.consumeLine();
  if (line === undefined) {
    return;
  }
  if (line) {
    this.parseHeader(line, this.trailers);
  } else {
    if (this.trailers.length) {
      this.userCall()(this[kOnHeaders](this.trailers, ''));
    }
    this.nextRequest();
  }
};

HTTPParser.prototype.BODY_RAW = function () {
  var length = this.end - this.offset;
  this.userCall()(this[kOnBody](this.chunk, this.offset, length));
  this.offset = this.end;
};

HTTPParser.prototype.BODY_SIZED = function () {
  var length = Math.min(this.end - this.offset, this.body_bytes);
  this.userCall()(this[kOnBody](this.chunk, this.offset, length));
  this.offset += length;
  this.body_bytes -= length;
  if (!this.body_bytes) {
    this.nextRequest();
  }
};

// backward compat to node < 0.11.6
['Headers', 'HeadersComplete', 'Body', 'MessageComplete'].forEach(function (name) {
  var k = HTTPParser['kOn' + name];
  Object.defineProperty(HTTPParser.prototype, 'on' + name, {
    get: function () {
      return this[k];
    },
    set: function (to) {
      // hack for backward compatibility
      this._compatMode0_11 = true;
      method_connect = 'CONNECT';
      return (this[k] = to);
    }
  });
});

function parseErrorCode(code) {
  var err = new Error('Parse Error');
  err.code = code;
  return err;
}

},{"assert":2}],40:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],41:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      ctor.prototype = Object.create(superCtor.prototype, {
        constructor: {
          value: ctor,
          enumerable: false,
          writable: true,
          configurable: true
        }
      })
    }
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      var TempCtor = function () {}
      TempCtor.prototype = superCtor.prototype
      ctor.prototype = new TempCtor()
      ctor.prototype.constructor = ctor
    }
  }
}

},{}],42:[function(require,module,exports){
(function() {
  var expandIPv6, ipaddr, ipv4Part, ipv4Regexes, ipv6Part, ipv6Regexes, matchCIDR, root, zoneIndex;

  ipaddr = {};

  root = this;

  if ((typeof module !== "undefined" && module !== null) && module.exports) {
    module.exports = ipaddr;
  } else {
    root['ipaddr'] = ipaddr;
  }

  matchCIDR = function(first, second, partSize, cidrBits) {
    var part, shift;
    if (first.length !== second.length) {
      throw new Error("ipaddr: cannot match CIDR for objects with different lengths");
    }
    part = 0;
    while (cidrBits > 0) {
      shift = partSize - cidrBits;
      if (shift < 0) {
        shift = 0;
      }
      if (first[part] >> shift !== second[part] >> shift) {
        return false;
      }
      cidrBits -= partSize;
      part += 1;
    }
    return true;
  };

  ipaddr.subnetMatch = function(address, rangeList, defaultName) {
    var k, len, rangeName, rangeSubnets, subnet;
    if (defaultName == null) {
      defaultName = 'unicast';
    }
    for (rangeName in rangeList) {
      rangeSubnets = rangeList[rangeName];
      if (rangeSubnets[0] && !(rangeSubnets[0] instanceof Array)) {
        rangeSubnets = [rangeSubnets];
      }
      for (k = 0, len = rangeSubnets.length; k < len; k++) {
        subnet = rangeSubnets[k];
        if (address.kind() === subnet[0].kind()) {
          if (address.match.apply(address, subnet)) {
            return rangeName;
          }
        }
      }
    }
    return defaultName;
  };

  ipaddr.IPv4 = (function() {
    function IPv4(octets) {
      var k, len, octet;
      if (octets.length !== 4) {
        throw new Error("ipaddr: ipv4 octet count should be 4");
      }
      for (k = 0, len = octets.length; k < len; k++) {
        octet = octets[k];
        if (!((0 <= octet && octet <= 255))) {
          throw new Error("ipaddr: ipv4 octet should fit in 8 bits");
        }
      }
      this.octets = octets;
    }

    IPv4.prototype.kind = function() {
      return 'ipv4';
    };

    IPv4.prototype.toString = function() {
      return this.octets.join(".");
    };

    IPv4.prototype.toNormalizedString = function() {
      return this.toString();
    };

    IPv4.prototype.toByteArray = function() {
      return this.octets.slice(0);
    };

    IPv4.prototype.match = function(other, cidrRange) {
      var ref;
      if (cidrRange === void 0) {
        ref = other, other = ref[0], cidrRange = ref[1];
      }
      if (other.kind() !== 'ipv4') {
        throw new Error("ipaddr: cannot match ipv4 address with non-ipv4 one");
      }
      return matchCIDR(this.octets, other.octets, 8, cidrRange);
    };

    IPv4.prototype.SpecialRanges = {
      unspecified: [[new IPv4([0, 0, 0, 0]), 8]],
      broadcast: [[new IPv4([255, 255, 255, 255]), 32]],
      multicast: [[new IPv4([224, 0, 0, 0]), 4]],
      linkLocal: [[new IPv4([169, 254, 0, 0]), 16]],
      loopback: [[new IPv4([127, 0, 0, 0]), 8]],
      carrierGradeNat: [[new IPv4([100, 64, 0, 0]), 10]],
      "private": [[new IPv4([10, 0, 0, 0]), 8], [new IPv4([172, 16, 0, 0]), 12], [new IPv4([192, 168, 0, 0]), 16]],
      reserved: [[new IPv4([192, 0, 0, 0]), 24], [new IPv4([192, 0, 2, 0]), 24], [new IPv4([192, 88, 99, 0]), 24], [new IPv4([198, 51, 100, 0]), 24], [new IPv4([203, 0, 113, 0]), 24], [new IPv4([240, 0, 0, 0]), 4]]
    };

    IPv4.prototype.range = function() {
      return ipaddr.subnetMatch(this, this.SpecialRanges);
    };

    IPv4.prototype.toIPv4MappedAddress = function() {
      return ipaddr.IPv6.parse("::ffff:" + (this.toString()));
    };

    IPv4.prototype.prefixLengthFromSubnetMask = function() {
      var cidr, i, k, octet, stop, zeros, zerotable;
      zerotable = {
        0: 8,
        128: 7,
        192: 6,
        224: 5,
        240: 4,
        248: 3,
        252: 2,
        254: 1,
        255: 0
      };
      cidr = 0;
      stop = false;
      for (i = k = 3; k >= 0; i = k += -1) {
        octet = this.octets[i];
        if (octet in zerotable) {
          zeros = zerotable[octet];
          if (stop && zeros !== 0) {
            return null;
          }
          if (zeros !== 8) {
            stop = true;
          }
          cidr += zeros;
        } else {
          return null;
        }
      }
      return 32 - cidr;
    };

    return IPv4;

  })();

  ipv4Part = "(0?\\d+|0x[a-f0-9]+)";

  ipv4Regexes = {
    fourOctet: new RegExp("^" + ipv4Part + "\\." + ipv4Part + "\\." + ipv4Part + "\\." + ipv4Part + "$", 'i'),
    longValue: new RegExp("^" + ipv4Part + "$", 'i')
  };

  ipaddr.IPv4.parser = function(string) {
    var match, parseIntAuto, part, shift, value;
    parseIntAuto = function(string) {
      if (string[0] === "0" && string[1] !== "x") {
        return parseInt(string, 8);
      } else {
        return parseInt(string);
      }
    };
    if (match = string.match(ipv4Regexes.fourOctet)) {
      return (function() {
        var k, len, ref, results;
        ref = match.slice(1, 6);
        results = [];
        for (k = 0, len = ref.length; k < len; k++) {
          part = ref[k];
          results.push(parseIntAuto(part));
        }
        return results;
      })();
    } else if (match = string.match(ipv4Regexes.longValue)) {
      value = parseIntAuto(match[1]);
      if (value > 0xffffffff || value < 0) {
        throw new Error("ipaddr: address outside defined range");
      }
      return ((function() {
        var k, results;
        results = [];
        for (shift = k = 0; k <= 24; shift = k += 8) {
          results.push((value >> shift) & 0xff);
        }
        return results;
      })()).reverse();
    } else {
      return null;
    }
  };

  ipaddr.IPv6 = (function() {
    function IPv6(parts, zoneId) {
      var i, k, l, len, part, ref;
      if (parts.length === 16) {
        this.parts = [];
        for (i = k = 0; k <= 14; i = k += 2) {
          this.parts.push((parts[i] << 8) | parts[i + 1]);
        }
      } else if (parts.length === 8) {
        this.parts = parts;
      } else {
        throw new Error("ipaddr: ipv6 part count should be 8 or 16");
      }
      ref = this.parts;
      for (l = 0, len = ref.length; l < len; l++) {
        part = ref[l];
        if (!((0 <= part && part <= 0xffff))) {
          throw new Error("ipaddr: ipv6 part should fit in 16 bits");
        }
      }
      if (zoneId) {
        this.zoneId = zoneId;
      }
    }

    IPv6.prototype.kind = function() {
      return 'ipv6';
    };

    IPv6.prototype.toString = function() {
      return this.toNormalizedString().replace(/((^|:)(0(:|$))+)/, '::');
    };

    IPv6.prototype.toRFC5952String = function() {
      var bestMatchIndex, bestMatchLength, match, regex, string;
      regex = /((^|:)(0(:|$)){2,})/g;
      string = this.toNormalizedString();
      bestMatchIndex = 0;
      bestMatchLength = -1;
      while ((match = regex.exec(string))) {
        if (match[0].length > bestMatchLength) {
          bestMatchIndex = match.index;
          bestMatchLength = match[0].length;
        }
      }
      if (bestMatchLength < 0) {
        return string;
      }
      return string.substring(0, bestMatchIndex) + '::' + string.substring(bestMatchIndex + bestMatchLength);
    };

    IPv6.prototype.toByteArray = function() {
      var bytes, k, len, part, ref;
      bytes = [];
      ref = this.parts;
      for (k = 0, len = ref.length; k < len; k++) {
        part = ref[k];
        bytes.push(part >> 8);
        bytes.push(part & 0xff);
      }
      return bytes;
    };

    IPv6.prototype.toNormalizedString = function() {
      var addr, part, suffix;
      addr = ((function() {
        var k, len, ref, results;
        ref = this.parts;
        results = [];
        for (k = 0, len = ref.length; k < len; k++) {
          part = ref[k];
          results.push(part.toString(16));
        }
        return results;
      }).call(this)).join(":");
      suffix = '';
      if (this.zoneId) {
        suffix = '%' + this.zoneId;
      }
      return addr + suffix;
    };

    IPv6.prototype.toFixedLengthString = function() {
      var addr, part, suffix;
      addr = ((function() {
        var k, len, ref, results;
        ref = this.parts;
        results = [];
        for (k = 0, len = ref.length; k < len; k++) {
          part = ref[k];
          results.push(part.toString(16).padStart(4, '0'));
        }
        return results;
      }).call(this)).join(":");
      suffix = '';
      if (this.zoneId) {
        suffix = '%' + this.zoneId;
      }
      return addr + suffix;
    };

    IPv6.prototype.match = function(other, cidrRange) {
      var ref;
      if (cidrRange === void 0) {
        ref = other, other = ref[0], cidrRange = ref[1];
      }
      if (other.kind() !== 'ipv6') {
        throw new Error("ipaddr: cannot match ipv6 address with non-ipv6 one");
      }
      return matchCIDR(this.parts, other.parts, 16, cidrRange);
    };

    IPv6.prototype.SpecialRanges = {
      unspecified: [new IPv6([0, 0, 0, 0, 0, 0, 0, 0]), 128],
      linkLocal: [new IPv6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10],
      multicast: [new IPv6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8],
      loopback: [new IPv6([0, 0, 0, 0, 0, 0, 0, 1]), 128],
      uniqueLocal: [new IPv6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7],
      ipv4Mapped: [new IPv6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96],
      rfc6145: [new IPv6([0, 0, 0, 0, 0xffff, 0, 0, 0]), 96],
      rfc6052: [new IPv6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96],
      '6to4': [new IPv6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16],
      teredo: [new IPv6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32],
      reserved: [[new IPv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32]]
    };

    IPv6.prototype.range = function() {
      return ipaddr.subnetMatch(this, this.SpecialRanges);
    };

    IPv6.prototype.isIPv4MappedAddress = function() {
      return this.range() === 'ipv4Mapped';
    };

    IPv6.prototype.toIPv4Address = function() {
      var high, low, ref;
      if (!this.isIPv4MappedAddress()) {
        throw new Error("ipaddr: trying to convert a generic ipv6 address to ipv4");
      }
      ref = this.parts.slice(-2), high = ref[0], low = ref[1];
      return new ipaddr.IPv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
    };

    IPv6.prototype.prefixLengthFromSubnetMask = function() {
      var cidr, i, k, part, stop, zeros, zerotable;
      zerotable = {
        0: 16,
        32768: 15,
        49152: 14,
        57344: 13,
        61440: 12,
        63488: 11,
        64512: 10,
        65024: 9,
        65280: 8,
        65408: 7,
        65472: 6,
        65504: 5,
        65520: 4,
        65528: 3,
        65532: 2,
        65534: 1,
        65535: 0
      };
      cidr = 0;
      stop = false;
      for (i = k = 7; k >= 0; i = k += -1) {
        part = this.parts[i];
        if (part in zerotable) {
          zeros = zerotable[part];
          if (stop && zeros !== 0) {
            return null;
          }
          if (zeros !== 16) {
            stop = true;
          }
          cidr += zeros;
        } else {
          return null;
        }
      }
      return 128 - cidr;
    };

    return IPv6;

  })();

  ipv6Part = "(?:[0-9a-f]+::?)+";

  zoneIndex = "%[0-9a-z]{1,}";

  ipv6Regexes = {
    zoneIndex: new RegExp(zoneIndex, 'i'),
    "native": new RegExp("^(::)?(" + ipv6Part + ")?([0-9a-f]+)?(::)?(" + zoneIndex + ")?$", 'i'),
    transitional: new RegExp(("^((?:" + ipv6Part + ")|(?:::)(?:" + ipv6Part + ")?)") + (ipv4Part + "\\." + ipv4Part + "\\." + ipv4Part + "\\." + ipv4Part) + ("(" + zoneIndex + ")?$"), 'i')
  };

  expandIPv6 = function(string, parts) {
    var colonCount, lastColon, part, replacement, replacementCount, zoneId;
    if (string.indexOf('::') !== string.lastIndexOf('::')) {
      return null;
    }
    zoneId = (string.match(ipv6Regexes['zoneIndex']) || [])[0];
    if (zoneId) {
      zoneId = zoneId.substring(1);
      string = string.replace(/%.+$/, '');
    }
    colonCount = 0;
    lastColon = -1;
    while ((lastColon = string.indexOf(':', lastColon + 1)) >= 0) {
      colonCount++;
    }
    if (string.substr(0, 2) === '::') {
      colonCount--;
    }
    if (string.substr(-2, 2) === '::') {
      colonCount--;
    }
    if (colonCount > parts) {
      return null;
    }
    replacementCount = parts - colonCount;
    replacement = ':';
    while (replacementCount--) {
      replacement += '0:';
    }
    string = string.replace('::', replacement);
    if (string[0] === ':') {
      string = string.slice(1);
    }
    if (string[string.length - 1] === ':') {
      string = string.slice(0, -1);
    }
    parts = (function() {
      var k, len, ref, results;
      ref = string.split(":");
      results = [];
      for (k = 0, len = ref.length; k < len; k++) {
        part = ref[k];
        results.push(parseInt(part, 16));
      }
      return results;
    })();
    return {
      parts: parts,
      zoneId: zoneId
    };
  };

  ipaddr.IPv6.parser = function(string) {
    var addr, k, len, match, octet, octets, zoneId;
    if (ipv6Regexes['native'].test(string)) {
      return expandIPv6(string, 8);
    } else if (match = string.match(ipv6Regexes['transitional'])) {
      zoneId = match[6] || '';
      addr = expandIPv6(match[1].slice(0, -1) + zoneId, 6);
      if (addr.parts) {
        octets = [parseInt(match[2]), parseInt(match[3]), parseInt(match[4]), parseInt(match[5])];
        for (k = 0, len = octets.length; k < len; k++) {
          octet = octets[k];
          if (!((0 <= octet && octet <= 255))) {
            return null;
          }
        }
        addr.parts.push(octets[0] << 8 | octets[1]);
        addr.parts.push(octets[2] << 8 | octets[3]);
        return {
          parts: addr.parts,
          zoneId: addr.zoneId
        };
      }
    }
    return null;
  };

  ipaddr.IPv4.isIPv4 = ipaddr.IPv6.isIPv6 = function(string) {
    return this.parser(string) !== null;
  };

  ipaddr.IPv4.isValid = function(string) {
    var e;
    try {
      new this(this.parser(string));
      return true;
    } catch (error1) {
      e = error1;
      return false;
    }
  };

  ipaddr.IPv4.isValidFourPartDecimal = function(string) {
    if (ipaddr.IPv4.isValid(string) && string.match(/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){3}$/)) {
      return true;
    } else {
      return false;
    }
  };

  ipaddr.IPv6.isValid = function(string) {
    var addr, e;
    if (typeof string === "string" && string.indexOf(":") === -1) {
      return false;
    }
    try {
      addr = this.parser(string);
      new this(addr.parts, addr.zoneId);
      return true;
    } catch (error1) {
      e = error1;
      return false;
    }
  };

  ipaddr.IPv4.parse = function(string) {
    var parts;
    parts = this.parser(string);
    if (parts === null) {
      throw new Error("ipaddr: string is not formatted like ip address");
    }
    return new this(parts);
  };

  ipaddr.IPv6.parse = function(string) {
    var addr;
    addr = this.parser(string);
    if (addr.parts === null) {
      throw new Error("ipaddr: string is not formatted like ip address");
    }
    return new this(addr.parts, addr.zoneId);
  };

  ipaddr.IPv4.parseCIDR = function(string) {
    var maskLength, match, parsed;
    if (match = string.match(/^(.+)\/(\d+)$/)) {
      maskLength = parseInt(match[2]);
      if (maskLength >= 0 && maskLength <= 32) {
        parsed = [this.parse(match[1]), maskLength];
        Object.defineProperty(parsed, 'toString', {
          value: function() {
            return this.join('/');
          }
        });
        return parsed;
      }
    }
    throw new Error("ipaddr: string is not formatted like an IPv4 CIDR range");
  };

  ipaddr.IPv4.subnetMaskFromPrefixLength = function(prefix) {
    var filledOctetCount, j, octets;
    prefix = parseInt(prefix);
    if (prefix < 0 || prefix > 32) {
      throw new Error('ipaddr: invalid IPv4 prefix length');
    }
    octets = [0, 0, 0, 0];
    j = 0;
    filledOctetCount = Math.floor(prefix / 8);
    while (j < filledOctetCount) {
      octets[j] = 255;
      j++;
    }
    if (filledOctetCount < 4) {
      octets[filledOctetCount] = Math.pow(2, prefix % 8) - 1 << 8 - (prefix % 8);
    }
    return new this(octets);
  };

  ipaddr.IPv4.broadcastAddressFromCIDR = function(string) {
    var cidr, error, i, ipInterfaceOctets, octets, subnetMaskOctets;
    try {
      cidr = this.parseCIDR(string);
      ipInterfaceOctets = cidr[0].toByteArray();
      subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
      octets = [];
      i = 0;
      while (i < 4) {
        octets.push(parseInt(ipInterfaceOctets[i], 10) | parseInt(subnetMaskOctets[i], 10) ^ 255);
        i++;
      }
      return new this(octets);
    } catch (error1) {
      error = error1;
      throw new Error('ipaddr: the address does not have IPv4 CIDR format');
    }
  };

  ipaddr.IPv4.networkAddressFromCIDR = function(string) {
    var cidr, error, i, ipInterfaceOctets, octets, subnetMaskOctets;
    try {
      cidr = this.parseCIDR(string);
      ipInterfaceOctets = cidr[0].toByteArray();
      subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
      octets = [];
      i = 0;
      while (i < 4) {
        octets.push(parseInt(ipInterfaceOctets[i], 10) & parseInt(subnetMaskOctets[i], 10));
        i++;
      }
      return new this(octets);
    } catch (error1) {
      error = error1;
      throw new Error('ipaddr: the address does not have IPv4 CIDR format');
    }
  };

  ipaddr.IPv6.parseCIDR = function(string) {
    var maskLength, match, parsed;
    if (match = string.match(/^(.+)\/(\d+)$/)) {
      maskLength = parseInt(match[2]);
      if (maskLength >= 0 && maskLength <= 128) {
        parsed = [this.parse(match[1]), maskLength];
        Object.defineProperty(parsed, 'toString', {
          value: function() {
            return this.join('/');
          }
        });
        return parsed;
      }
    }
    throw new Error("ipaddr: string is not formatted like an IPv6 CIDR range");
  };

  ipaddr.isValid = function(string) {
    return ipaddr.IPv6.isValid(string) || ipaddr.IPv4.isValid(string);
  };

  ipaddr.parse = function(string) {
    if (ipaddr.IPv6.isValid(string)) {
      return ipaddr.IPv6.parse(string);
    } else if (ipaddr.IPv4.isValid(string)) {
      return ipaddr.IPv4.parse(string);
    } else {
      throw new Error("ipaddr: the address has neither IPv6 nor IPv4 format");
    }
  };

  ipaddr.parseCIDR = function(string) {
    var e;
    try {
      return ipaddr.IPv6.parseCIDR(string);
    } catch (error1) {
      e = error1;
      try {
        return ipaddr.IPv4.parseCIDR(string);
      } catch (error1) {
        e = error1;
        throw new Error("ipaddr: the address has neither IPv6 nor IPv4 CIDR format");
      }
    }
  };

  ipaddr.fromByteArray = function(bytes) {
    var length;
    length = bytes.length;
    if (length === 4) {
      return new ipaddr.IPv4(bytes);
    } else if (length === 16) {
      return new ipaddr.IPv6(bytes);
    } else {
      throw new Error("ipaddr: the binary input is neither an IPv6 nor IPv4 address");
    }
  };

  ipaddr.process = function(string) {
    var addr;
    addr = this.parse(string);
    if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
      return addr.toIPv4Address();
    } else {
      return addr;
    }
  };

}).call(this);

},{}],43:[function(require,module,exports){
'use strict';

var hasToStringTag = typeof Symbol === 'function' && typeof Symbol.toStringTag === 'symbol';
var callBound = require('call-bind/callBound');

var $toString = callBound('Object.prototype.toString');

var isStandardArguments = function isArguments(value) {
	if (hasToStringTag && value && typeof value === 'object' && Symbol.toStringTag in value) {
		return false;
	}
	return $toString(value) === '[object Arguments]';
};

var isLegacyArguments = function isArguments(value) {
	if (isStandardArguments(value)) {
		return true;
	}
	return value !== null &&
		typeof value === 'object' &&
		typeof value.length === 'number' &&
		value.length >= 0 &&
		$toString(value) !== '[object Array]' &&
		$toString(value.callee) === '[object Function]';
};

var supportsStandardArguments = (function () {
	return isStandardArguments(arguments);
}());

isStandardArguments.isLegacyArguments = isLegacyArguments; // for tests

module.exports = supportsStandardArguments ? isStandardArguments : isLegacyArguments;

},{"call-bind/callBound":10}],44:[function(require,module,exports){
'use strict';

var toStr = Object.prototype.toString;
var fnToStr = Function.prototype.toString;
var isFnRegex = /^\s*(?:function)?\*/;
var hasToStringTag = typeof Symbol === 'function' && typeof Symbol.toStringTag === 'symbol';
var getProto = Object.getPrototypeOf;
var getGeneratorFunc = function () { // eslint-disable-line consistent-return
	if (!hasToStringTag) {
		return false;
	}
	try {
		return Function('return function*() {}')();
	} catch (e) {
	}
};
var generatorFunc = getGeneratorFunc();
var GeneratorFunction = getProto && generatorFunc ? getProto(generatorFunc) : false;

module.exports = function isGeneratorFunction(fn) {
	if (typeof fn !== 'function') {
		return false;
	}
	if (isFnRegex.test(fnToStr.call(fn))) {
		return true;
	}
	if (!hasToStringTag) {
		var str = toStr.call(fn);
		return str === '[object GeneratorFunction]';
	}
	return getProto && getProto(fn) === GeneratorFunction;
};

},{}],45:[function(require,module,exports){
(function (global){(function (){
'use strict';

var forEach = require('foreach');
var availableTypedArrays = require('available-typed-arrays');
var callBound = require('call-bind/callBound');

var $toString = callBound('Object.prototype.toString');
var hasSymbols = require('has-symbols')();
var hasToStringTag = hasSymbols && typeof Symbol.toStringTag === 'symbol';

var typedArrays = availableTypedArrays();

var $indexOf = callBound('Array.prototype.indexOf', true) || function indexOf(array, value) {
	for (var i = 0; i < array.length; i += 1) {
		if (array[i] === value) {
			return i;
		}
	}
	return -1;
};
var $slice = callBound('String.prototype.slice');
var toStrTags = {};
var gOPD = require('es-abstract/helpers/getOwnPropertyDescriptor');
var getPrototypeOf = Object.getPrototypeOf; // require('getprototypeof');
if (hasToStringTag && gOPD && getPrototypeOf) {
	forEach(typedArrays, function (typedArray) {
		var arr = new global[typedArray]();
		if (!(Symbol.toStringTag in arr)) {
			throw new EvalError('this engine has support for Symbol.toStringTag, but ' + typedArray + ' does not have the property! Please report this.');
		}
		var proto = getPrototypeOf(arr);
		var descriptor = gOPD(proto, Symbol.toStringTag);
		if (!descriptor) {
			var superProto = getPrototypeOf(proto);
			descriptor = gOPD(superProto, Symbol.toStringTag);
		}
		toStrTags[typedArray] = descriptor.get;
	});
}

var tryTypedArrays = function tryAllTypedArrays(value) {
	var anyTrue = false;
	forEach(toStrTags, function (getter, typedArray) {
		if (!anyTrue) {
			try {
				anyTrue = getter.call(value) === typedArray;
			} catch (e) { /**/ }
		}
	});
	return anyTrue;
};

module.exports = function isTypedArray(value) {
	if (!value || typeof value !== 'object') { return false; }
	if (!hasToStringTag) {
		var tag = $slice($toString(value), 8, -1);
		return $indexOf(typedArrays, tag) > -1;
	}
	if (!gOPD) { return false; }
	return tryTypedArrays(value);
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"available-typed-arrays":6,"call-bind/callBound":10,"es-abstract/helpers/getOwnPropertyDescriptor":13,"foreach":15,"has-symbols":36}],46:[function(require,module,exports){
var macho = exports;

macho.constants = require('./macho/constants');
macho.Parser = require('./macho/parser');

macho.parse = function parse(buf) {
  return new macho.Parser().execute(buf);
};

},{"./macho/constants":47,"./macho/parser":48}],47:[function(require,module,exports){
var constants = exports;

constants.cpuArch = {
  mask: 0xff000000,
  abi64: 0x01000000,
  abi32: 0x02000000
};

constants.cpuType = {
  0x01: 'vax',
  0x06: 'mc680x0',
  0x07: 'i386',
  0x01000007: 'x86_64',
  0x0a: 'mc98000',
  0x0b: 'hppa',
  0x0c: 'arm',
  0x0100000c: 'arm64',
  0x0200000c: 'arm64_32',
  0x0d: 'mc88000',
  0x0e: 'sparc',
  0x0f: 'i860',
  0x10: 'alpha',
  0x12: 'powerpc',
  0x01000012: 'powerpc64'
};

constants.endian = {
  0xffffffff: 'multiple',
  0: 'le',
  1: 'be'
};

constants.cpuSubType = {
  mask: 0x00ffffff,
  vax: {
    0: 'all',
    1: '780',
    2: '785',
    3: '750',
    4: '730',
    5: 'I',
    6: 'II',
    7: '8200',
    8: '8500',
    9: '8600',
    10: '8650',
    11: '8800',
    12: 'III'
  },
  mc680x0: {
    1: 'all',
    2: '40',
    3: '30_only'
  },
  i386: {},
  x86_64: {
    3: 'all',
    4: 'arch1'
  },
  mips: {
    0: 'all',
    1: 'r2300',
    2: 'r2600',
    3: 'r2800',
    4: 'r2000a',
    5: 'r2000',
    6: 'r3000a',
    7: 'r3000'
  },
  mc98000: {
    0: 'all',
    1: 'mc98601'
  },
  hppa: {
    0: 'all',
    1: '7100lc'
  },
  mc88000: {
    0: 'all',
    1: 'mc88100',
    2: 'mc88110'
  },
  sparc: {
    0: 'all'
  },
  i860: {
    0: 'all',
    1: '860'
  },
  powerpc: {
    0: 'all',
    1: '601',
    2: '602',
    3: '603',
    4: '603e',
    5: '603ev',
    6: '604',
    7: '604e',
    8: '620',
    9: '750',
    10: '7400',
    11: '7450',
    100: '970'
  },
  arm: {
    0: 'all',
    5: 'v4t',
    6: 'v6',
    7: 'v5tej',
    8: 'xscale',
    9: 'v7',
    10: 'v7f',
    11: 'v7s',
    12: 'v7k',
    14: 'v6m',
    15: 'v7m',
    16: 'v7em'
  },
  arm64: {
    0: 'all',
    1: 'v8',
    2: 'e'
  },
  arm64_32: {
    1: 'all'
  }
};

function cpuSubtypeIntel(a, b, name) {
  constants.cpuSubType.i386[a + (b << 4)] = name;
}

[
  [3, 0, 'all'],
  [4, 0, '486'],
  [4, 8, '486sx'],
  [5, 0, '586'],
  [6, 1, 'pentpro'],
  [6, 3, 'pentII_m3'],
  [6, 5, 'pentII_m5'],
  [7, 6, 'celeron'],
  [7, 7, 'celeron_mobile'],
  [8, 0, 'pentium_3'],
  [8, 1, 'pentium_3_m'],
  [8, 2, 'pentium_3_xeon'],
  [9, 0, 'pentium_m'],
  [10, 0, 'pentium_4'],
  [10, 1, 'pentium_4_m'],
  [11, 0, 'itanium'],
  [11, 1, 'itanium_2'],
  [12, 0, 'xeon'],
  [12, 1, 'xeon_mp']
].forEach(function(item) {
  cpuSubtypeIntel(item[0], item[1], item[2]);
});

constants.fileType = {
  1: 'object',
  2: 'execute',
  3: 'fvmlib',
  4: 'core',
  5: 'preload',
  6: 'dylib',
  7: 'dylinker',
  8: 'bundle',
  9: 'dylib_stub',
  10: 'dsym',
  11: 'kext'
};

constants.flags = {
  0x1: 'noundefs',
  0x2: 'incrlink',
  0x4: 'dyldlink',
  0x8: 'bindatload',
  0x10: 'prebound',
  0x20: 'split_segs',
  0x40: 'lazy_init',
  0x80: 'twolevel',
  0x100: 'force_flat',
  0x200: 'nomultidefs',
  0x400: 'nofixprebinding',
  0x800: 'prebindable',
  0x1000: 'allmodsbound',
  0x2000: 'subsections_via_symbols',
  0x4000: 'canonical',
  0x8000: 'weak_defines',
  0x10000: 'binds_to_weak',
  0x20000: 'allow_stack_execution',
  0x40000: 'root_safe',
  0x80000: 'setuid_safe',
  0x100000: 'reexported_dylibs',
  0x200000: 'pie',
  0x400000: 'dead_strippable_dylib',
  0x800000: 'has_tlv_descriptors',
  0x1000000: 'no_heap_execution'
};

constants.cmdType = {
  0x80000000: 'req_dyld',
  0x1: 'segment',
  0x2: 'symtab',
  0x3: 'symseg',
  0x4: 'thread',
  0x5: 'unixthread',
  0x6: 'loadfvmlib',
  0x7: 'idfvmlib',
  0x8: 'ident',
  0x9: 'fmvfile',
  0xa: 'prepage',
  0xb: 'dysymtab',
  0xc: 'load_dylib',
  0xd: 'id_dylib',
  0xe: 'load_dylinker',
  0xf: 'id_dylinker',
  0x10: 'prebound_dylib',
  0x11: 'routines',
  0x12: 'sub_framework',
  0x13: 'sub_umbrella',
  0x14: 'sub_client',
  0x15: 'sub_library',
  0x16: 'twolevel_hints',
  0x17: 'prebind_cksum',

  0x80000018: 'load_weak_dylib',
  0x19: 'segment_64',
  0x1a: 'routines_64',
  0x1b: 'uuid',
  0x8000001c: 'rpath',
  0x1d: 'code_signature',
  0x1e: 'segment_split_info',
  0x8000001f: 'reexport_dylib',
  0x20: 'lazy_load_dylib',
  0x21: 'encryption_info',
  0x80000022: 'dyld_info',
  0x80000023: 'dyld_info_only',
  0x24: 'version_min_macosx',
  0x25: 'version_min_iphoneos',
  0x26: 'function_starts',
  0x27: 'dyld_environment',
  0x80000028: 'main',
  0x29: 'data_in_code',
  0x2a: 'source_version',
  0x2b: 'dylib_code_sign_drs',
  0x2c: 'encryption_info_64',
  0x2d: 'linker_option'
};

constants.prot = {
  none: 0,
  read: 1,
  write: 2,
  execute: 4
};

constants.segFlag = {
  1: 'highvm',
  2: 'fvmlib',
  4: 'noreloc',
  8: 'protected_version_1'
};

constants.segTypeMask = 0xff;
constants.segType = {
  0: 'regular',
  1: 'zerofill',
  2: 'cstring_literals',
  3: '4byte_literals',
  4: '8byte_literals',
  5: 'literal_pointers',
  6: 'non_lazy_symbol_pointers',
  7: 'lazy_symbol_pointers',
  8: 'symbol_stubs',
  9: 'mod_init_func_pointers',
  0xa: 'mod_term_func_pointers',
  0xb: 'coalesced',
  0xc: 'gb_zerofill',
  0xd: 'interposing',
  0xe: '16byte_literals',
  0xf: 'dtrace_dof',
  0x10: 'lazy_dylib_symbol_pointers',
  0x11: 'thread_local_regular',
  0x12: 'thread_local_zerofill',
  0x13: 'thread_local_variables',
  0x14: 'thread_local_variable_pointers',
  0x15: 'thread_local_init_function_pointers'
};

constants.segAttrUsrMask = 0xff000000;
constants.segAttrUsr = {
  '-2147483648': 'pure_instructions',
  0x40000000: 'no_toc',
  0x20000000: 'strip_static_syms',
  0x10000000: 'no_dead_strip',
  0x08000000: 'live_support',
  0x04000000: 'self_modifying_code',
  0x02000000: 'debug'
};

constants.segAttrSysMask = 0x00ffff00;
constants.segAttrSys = {
  0x400: 'some_instructions',
  0x200: 'ext_reloc',
  0x100: 'loc_reloc'
};

},{}],48:[function(require,module,exports){
var util = require('util');
var Reader = require('endian-reader');

var macho = require('../macho');
var constants = macho.constants;

function Parser() {
  Reader.call(this);
};
util.inherits(Parser, Reader);
module.exports = Parser;

Parser.prototype.execute = function execute(buf) {
  var hdr = this.parseHead(buf);
  if (!hdr)
    throw new Error('File not in a mach-o format');

  hdr.cmds = this.parseCommands(hdr, hdr.body, buf);
  delete hdr.body;

  return hdr;
};

Parser.prototype.mapFlags = function mapFlags(value, map) {
  var res = {};

  for (var bit = 1; (value < 0 || bit <= value) && bit !== 0; bit <<= 1)
    if (value & bit)
      res[map[bit]] = true;

  return res;
};

Parser.prototype.parseHead = function parseHead(buf) {
  if (buf.length < 7 * 4)
    return false;

  var magic = buf.readUInt32LE(0);
  var bits;
  if (magic === 0xfeedface || magic === 0xcefaedfe)
    bits = 32;
  else if (magic === 0xfeedfacf || magic == 0xcffaedfe)
    bits = 64;
  else
    return false;

  if (magic & 0xff == 0xfe)
    this.setEndian('be');
  else
    this.setEndian('le');

  if (bits === 64 && buf.length < 8 * 4)
    return false;

  var cputype = constants.cpuType[this.readInt32(buf, 4)];
  var cpusubtype = this.readInt32(buf, 8);
  var filetype = this.readUInt32(buf, 12);
  var ncmds = this.readUInt32(buf, 16);
  var sizeofcmds = this.readUInt32(buf, 20);
  var flags = this.readUInt32(buf, 24);

  // Get endian
  var endian;
  if ((cpusubtype & constants.endian.multiple) === constants.endian.multiple)
    endian = 'multiple';
  else if (cpusubtype & constants.endian.be)
    endian = 'be';
  else
    endian = 'le';

  cpusubtype &= constants.cpuSubType.mask;

  // Get subtype
  var subtype;
  if (endian === 'multiple')
    subtype = 'all';
  else if (cpusubtype === 0)
    subtype = 'none';
  else
    subtype = constants.cpuSubType[cputype][cpusubtype];

  // Stringify flags
  var flagMap = this.mapFlags(flags, constants.flags);

  return {
    bits: bits,
    magic: magic,
    cpu: {
      type: cputype,
      subtype: subtype,
      endian: endian
    },
    filetype: constants.fileType[filetype],
    ncmds: ncmds,
    sizeofcmds: sizeofcmds,
    flags: flagMap,

    cmds: null,
    hsize: bits === 32 ? 28 : 32,
    body: bits === 32 ? buf.slice(28) : buf.slice(32)
  };
};

Parser.prototype.parseCommands = function parseCommands(hdr, buf, file) {
  var cmds = [];

  var align;
  if (hdr.bits === 32)
    align = 4;
  else
    align = 8;

  for (var offset = 0, i = 0; offset + 8 < buf.length, i < hdr.ncmds; i++) {
    var type = constants.cmdType[this.readUInt32(buf, offset)];
    var size = this.readUInt32(buf, offset + 4) - 8;

    var fileoff = offset + hdr.hsize;
    offset += 8;
    if (offset + size > buf.length)
      throw new Error('Command body OOB');

    var body = buf.slice(offset, offset + size);
    offset += size;
    if (offset & align)
      offset += align - (offset & align);

    var cmd = this.parseCommand(type, body, file);
    cmd.fileoff = fileoff;
    cmds.push(cmd);
  }

  return cmds;
};

Parser.prototype.parseCStr = function parseCStr(buf) {
  for (var i = 0; i < buf.length; i++)
    if (buf[i] === 0)
      break;
  return buf.slice(0, i).toString();
};

Parser.prototype.parseLCStr = function parseLCStr(buf, off) {
  if (off + 4 > buf.length)
    throw new Error('lc_str OOB');

  var offset = this.readUInt32(buf, off) - 8;
  if (offset > buf.length)
    throw new Error('lc_str offset OOB');

  return this.parseCStr(buf.slice(offset));
};

Parser.prototype.parseCommand = function parseCommand(type, buf, file) {
  if (type === 'segment')
    return this.parseSegmentCmd(type, buf, file);
  else if (type === 'segment_64')
    return this.parseSegmentCmd(type, buf, file);
  else if (type === 'symtab')
    return this.parseSymtab(type, buf);
  else if (type === 'symseg')
    return this.parseSymseg(type, buf);
  else if (type === 'encryption_info')
    return this.parseEncryptionInfo(type, buf);
  else if (type === 'encryption_info_64')
    return this.parseEncryptionInfo64(type, buf);
  else if (type === 'rpath')
    return this.parseRpath(type, buf);
  else if (type === 'dysymtab')
    return this.parseDysymtab(type, buf);
  else if (type === 'load_dylib' || type === 'id_dylib')
    return this.parseLoadDylib(type, buf);
  else if (type === 'load_weak_dylib')
    return this.parseLoadDylib(type, buf);
  else if (type === 'load_dylinker' || type === 'id_dylinker')
    return this.parseLoadDylinker(type, buf);
  else if (type === 'version_min_macosx' || type === 'version_min_iphoneos')
    return this.parseVersionMin(type, buf);
  else if (type === 'code_signature' || type === 'segment_split_info')
    return this.parseLinkEdit(type, buf);
  else if (type === 'function_starts')
    return this.parseFunctionStarts(type, buf, file);
  else if (type === 'data_in_code')
    return this.parseLinkEdit(type, buf);
  else if (type === 'dylib_code_sign_drs')
    return this.parseLinkEdit(type, buf);
  else if (type === 'main')
    return this.parseMain(type, buf);
  else
    return { type: type, data: buf };
};

Parser.prototype.parseSegmentCmd = function parseSegmentCmd(type, buf, file) {
  var total = type === 'segment' ? 48 : 64;
  if (buf.length < total)
    throw new Error('Segment command OOB');

  var name = this.parseCStr(buf.slice(0, 16));

  if (type === 'segment') {
    var vmaddr = this.readUInt32(buf, 16);
    var vmsize = this.readUInt32(buf, 20);
    var fileoff = this.readUInt32(buf, 24);
    var filesize = this.readUInt32(buf, 28);
    var maxprot = this.readUInt32(buf, 32);
    var initprot = this.readUInt32(buf, 36);
    var nsects = this.readUInt32(buf, 40);
    var flags = this.readUInt32(buf, 44);
  } else {
    var vmaddr = this.readUInt64(buf, 16);
    var vmsize = this.readUInt64(buf, 24);
    var fileoff = this.readUInt64(buf, 32);
    var filesize = this.readUInt64(buf, 40);
    var maxprot = this.readUInt32(buf, 48);
    var initprot = this.readUInt32(buf, 52);
    var nsects = this.readUInt32(buf, 56);
    var flags = this.readUInt32(buf, 60);
  }

  function prot(p) {
    var res = { read: false, write: false, exec: false };
    if (p !== constants.prot.none) {
      res.read = (p & constants.prot.read) !== 0;
      res.write = (p & constants.prot.write) !== 0;
      res.exec = (p & constants.prot.execute) !== 0;
    }
    return res;
  }

  var sectSize = type === 'segment' ? 32 + 9 * 4 : 32 + 8 * 4 + 2 * 8;
  var sections = [];
  for (var i = 0, off = total; i < nsects; i++, off += sectSize) {
    if (off + sectSize > buf.length)
      throw new Error('Segment OOB');

    var sectname = this.parseCStr(buf.slice(off, off + 16));
    var segname = this.parseCStr(buf.slice(off + 16, off + 32));

    if (type === 'segment') {
      var addr = this.readUInt32(buf, off + 32);
      var size = this.readUInt32(buf, off + 36);
      var offset = this.readUInt32(buf, off + 40);
      var align = this.readUInt32(buf, off + 44);
      var reloff = this.readUInt32(buf, off + 48);
      var nreloc = this.readUInt32(buf, off + 52);
      var flags = this.readUInt32(buf, off + 56);
    } else {
      var addr = this.readUInt64(buf, off + 32);
      var size = this.readUInt64(buf, off + 40);
      var offset = this.readUInt32(buf, off + 48);
      var align = this.readUInt32(buf, off + 52);
      var reloff = this.readUInt32(buf, off + 56);
      var nreloc = this.readUInt32(buf, off + 60);
      var flags = this.readUInt32(buf, off + 64);
    }

    sections.push({
      sectname: sectname,
      segname: segname,
      addr: addr,
      size: size,
      offset: offset,
      align: align,
      reloff: reloff,
      nreloc: nreloc,
      type: constants.segType[flags & constants.segTypeMask],
      attributes: {
        usr: this.mapFlags(flags & constants.segAttrUsrMask,
                           constants.segAttrUsr),
        sys: this.mapFlags(flags & constants.segAttrSysMask,
                           constants.segAttrSys)
      },
      data: file.slice(offset, offset + size)
    });
  }

  return {
    type: type,
    name: name,
    vmaddr: vmaddr,
    vmsize: vmsize,
    fileoff: fileoff,
    filesize: filesize,
    maxprot: prot(maxprot),
    initprot: prot(initprot),
    nsects: nsects,
    flags: this.mapFlags(flags, constants.segFlag),
    sections: sections
  };
};

Parser.prototype.parseSymtab = function parseSymtab(type, buf) {
  if (buf.length !== 16)
    throw new Error('symtab OOB');

  return {
    type: type,
    symoff: this.readUInt32(buf, 0),
    nsyms: this.readUInt32(buf, 4),
    stroff: this.readUInt32(buf, 8),
    strsize: this.readUInt32(buf, 12)
  };
};

Parser.prototype.parseSymseg = function parseSymseg(type, buf) {
  if (buf.length !== 8)
    throw new Error('symseg OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4)
  };
};

Parser.prototype.parseEncryptionInfo = function parseEncryptionInfo(type, buf) {
  if (buf.length !== 12)
    throw new Error('encryptinfo OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4),
    id: this.readUInt32(buf, 8),
  };
};

Parser.prototype.parseEncryptionInfo64 = function parseEncryptionInfo64(type, buf) {
  if (buf.length !== 16)
    throw new Error('encryptinfo64 OOB');

  return this.parseEncryptionInfo(type, buf.slice(0, 12));
};

Parser.prototype.parseDysymtab = function parseDysymtab(type, buf) {
  if (buf.length !== 72)
    throw new Error('dysymtab OOB');

  return {
    type: type,
    ilocalsym: this.readUInt32(buf, 0),
    nlocalsym: this.readUInt32(buf, 4),
    iextdefsym: this.readUInt32(buf, 8),
    nextdefsym: this.readUInt32(buf, 12),
    iundefsym: this.readUInt32(buf, 16),
    nundefsym: this.readUInt32(buf, 20),
    tocoff: this.readUInt32(buf, 24),
    ntoc: this.readUInt32(buf, 28),
    modtaboff: this.readUInt32(buf, 32),
    nmodtab: this.readUInt32(buf, 36),
    extrefsymoff: this.readUInt32(buf, 40),
    nextrefsyms: this.readUInt32(buf, 44),
    indirectsymoff: this.readUInt32(buf, 48),
    nindirectsyms: this.readUInt32(buf, 52),
    extreloff: this.readUInt32(buf, 56),
    nextrel: this.readUInt32(buf, 60),
    locreloff: this.readUInt32(buf, 64),
    nlocrel: this.readUInt32(buf, 68)
  };
};

Parser.prototype.parseLoadDylinker = function parseLoadDylinker(type, buf) {
  return {
    type: type,
    cmd: this.parseLCStr(buf, 0)
  };
};

Parser.prototype.parseRpath = function parseRpath (type, buf) {
  if (buf.length < 8)
    throw new Error('lc_rpath OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
  };
};

Parser.prototype.parseLoadDylib = function parseLoadDylib(type, buf) {
  if (buf.length < 16)
    throw new Error('load_dylib OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
    timestamp: this.readUInt32(buf, 4),
    current_version: this.readUInt32(buf, 8),
    compatibility_version: this.readUInt32(buf, 12)
  };
};

Parser.prototype.parseVersionMin = function parseVersionMin(type, buf) {
  if (buf.length !== 8)
    throw new Error('min version OOB');

  return {
    type: type,
    version: this.readUInt16(buf, 2) + '.' + buf[1] + '.' + buf[0],
    sdk: this.readUInt16(buf, 6) + '.' + buf[5] + '.' + buf[4]
  };
};

Parser.prototype.parseLinkEdit = function parseLinkEdit(type, buf) {
  if (buf.length !== 8)
    throw new Error('link_edit OOB');

  return {
    type: type,
    dataoff: this.readUInt32(buf, 0),
    datasize: this.readUInt32(buf, 4)
  };
};

// NOTE: returned addresses are relative to the "base address", i.e.
//       the vmaddress of the first "non-null" segment [e.g. initproto!=0]
//       (i.e. __TEXT ?)
Parser.prototype.parseFunctionStarts = function parseFunctionStarts(type,
                                                                    buf,
                                                                    file) {
  if (buf.length !== 8)
    throw new Error('function_starts OOB');

  var dataoff = this.readUInt32(buf, 0);
  var datasize = this.readUInt32(buf, 4);
  var data = file.slice(dataoff, dataoff + datasize);

  var addresses = [];
  var address = 0; // TODO? use start address / "base address"

  // read array of uleb128-encoded deltas
  var delta = 0, shift = 0;
  for (var i = 0; i < data.length; i++) {
    delta |= (data[i] & 0x7f) << shift;
    if ((data[i] & 0x80) !== 0) { // delta value not finished yet
      shift += 7;
      if (shift > 24)
        throw new Error('function_starts delta too large');
      else if (i + 1 === data.length)
        throw new Error('function_starts delta truncated');
    } else if (delta === 0) { // end of table
      break;
    } else {
      address += delta;
      addresses.push(address);
      delta = 0;
      shift = 0;
    }
  }

  return {
    type: type,
    dataoff: dataoff,
    datasize: datasize,
    addresses: addresses
  };
};

Parser.prototype.parseMain = function parseMain(type, buf) {
  if (buf.length < 16)
    throw new Error('main OOB');

  return {
    type: type,
    entryoff: this.readUInt64(buf, 0),
    stacksize: this.readUInt64(buf, 8)
  };
};

},{"../macho":46,"endian-reader":12,"util":78}],49:[function(require,module,exports){
/*
object-assign
(c) Sindre Sorhus
@license MIT
*/

'use strict';
/* eslint-disable no-unused-vars */
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var propIsEnumerable = Object.prototype.propertyIsEnumerable;

function toObject(val) {
	if (val === null || val === undefined) {
		throw new TypeError('Object.assign cannot be called with null or undefined');
	}

	return Object(val);
}

function shouldUseNative() {
	try {
		if (!Object.assign) {
			return false;
		}

		// Detect buggy property enumeration order in older V8 versions.

		// https://bugs.chromium.org/p/v8/issues/detail?id=4118
		var test1 = new String('abc');  // eslint-disable-line no-new-wrappers
		test1[5] = 'de';
		if (Object.getOwnPropertyNames(test1)[0] === '5') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test2 = {};
		for (var i = 0; i < 10; i++) {
			test2['_' + String.fromCharCode(i)] = i;
		}
		var order2 = Object.getOwnPropertyNames(test2).map(function (n) {
			return test2[n];
		});
		if (order2.join('') !== '0123456789') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test3 = {};
		'abcdefghijklmnopqrst'.split('').forEach(function (letter) {
			test3[letter] = letter;
		});
		if (Object.keys(Object.assign({}, test3)).join('') !==
				'abcdefghijklmnopqrst') {
			return false;
		}

		return true;
	} catch (err) {
		// We don't expect any of the above to throw, but better to be safe.
		return false;
	}
}

module.exports = shouldUseNative() ? Object.assign : function (target, source) {
	var from;
	var to = toObject(target);
	var symbols;

	for (var s = 1; s < arguments.length; s++) {
		from = Object(arguments[s]);

		for (var key in from) {
			if (hasOwnProperty.call(from, key)) {
				to[key] = from[key];
			}
		}

		if (getOwnPropertySymbols) {
			symbols = getOwnPropertySymbols(from);
			for (var i = 0; i < symbols.length; i++) {
				if (propIsEnumerable.call(from, symbols[i])) {
					to[symbols[i]] = from[symbols[i]];
				}
			}
		}
	}

	return to;
};

},{}],50:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],51:[function(require,module,exports){
(function (global){(function (){
/*! https://mths.be/punycode v1.4.1 by @mathias */
;(function(root) {

	/** Detect free variables */
	var freeExports = typeof exports == 'object' && exports &&
		!exports.nodeType && exports;
	var freeModule = typeof module == 'object' && module &&
		!module.nodeType && module;
	var freeGlobal = typeof global == 'object' && global;
	if (
		freeGlobal.global === freeGlobal ||
		freeGlobal.window === freeGlobal ||
		freeGlobal.self === freeGlobal
	) {
		root = freeGlobal;
	}

	/**
	 * The `punycode` object.
	 * @name punycode
	 * @type Object
	 */
	var punycode,

	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	tMin = 1,
	tMax = 26,
	skew = 38,
	damp = 700,
	initialBias = 72,
	initialN = 128, // 0x80
	delimiter = '-', // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	regexNonASCII = /[^\x20-\x7E]/, // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g, // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},

	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	floor = Math.floor,
	stringFromCharCode = String.fromCharCode,

	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
	 * A generic error utility function.
	 * @private
	 * @param {String} type The error type.
	 * @returns {Error} Throws a `RangeError` with the applicable error message.
	 */
	function error(type) {
		throw new RangeError(errors[type]);
	}

	/**
	 * A generic `Array#map` utility function.
	 * @private
	 * @param {Array} array The array to iterate over.
	 * @param {Function} callback The function that gets called for every array
	 * item.
	 * @returns {Array} A new array of values returned by the callback function.
	 */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
	 * A simple `Array#map`-like wrapper to work with domain name strings or email
	 * addresses.
	 * @private
	 * @param {String} domain The domain name or email address.
	 * @param {Function} callback The function that gets called for every
	 * character.
	 * @returns {Array} A new string of characters returned by the callback
	 * function.
	 */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
	 * Creates an array containing the numeric code points of each Unicode
	 * character in the string. While JavaScript uses UCS-2 internally,
	 * this function will convert a pair of surrogate halves (each of which
	 * UCS-2 exposes as separate characters) into a single code point,
	 * matching UTF-16.
	 * @see `punycode.ucs2.encode`
	 * @see <https://mathiasbynens.be/notes/javascript-encoding>
	 * @memberOf punycode.ucs2
	 * @name decode
	 * @param {String} string The Unicode input string (UCS-2).
	 * @returns {Array} The new array of code points.
	 */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
	 * Creates a string based on an array of numeric code points.
	 * @see `punycode.ucs2.decode`
	 * @memberOf punycode.ucs2
	 * @name encode
	 * @param {Array} codePoints The array of numeric code points.
	 * @returns {String} The new Unicode string (UCS-2).
	 */
	function ucs2encode(array) {
		return map(array, function(value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
	 * Converts a basic code point into a digit/integer.
	 * @see `digitToBasic()`
	 * @private
	 * @param {Number} codePoint The basic numeric code point value.
	 * @returns {Number} The numeric value of a basic code point (for use in
	 * representing integers) in the range `0` to `base - 1`, or `base` if
	 * the code point does not represent a value.
	 */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
	 * Converts a digit/integer into a basic code point.
	 * @see `basicToDigit()`
	 * @private
	 * @param {Number} digit The numeric value of a basic code point.
	 * @returns {Number} The basic code point whose value (when used for
	 * representing integers) is `digit`, which needs to be in the range
	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
	 * used; else, the lowercase form is used. The behavior is undefined
	 * if `flag` is non-zero and `digit` has no uppercase form.
	 */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
	 * Bias adaptation function as per section 3.4 of RFC 3492.
	 * https://tools.ietf.org/html/rfc3492#section-3.4
	 * @private
	 */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The Punycode string of ASCII-only symbols.
	 * @returns {String} The resulting string of Unicode symbols.
	 */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,
		    /** Cached calculation results */
		    baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;

			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);

		}

		return ucs2encode(output);
	}

	/**
	 * Converts a string of Unicode symbols (e.g. a domain name label) to a
	 * Punycode string of ASCII-only symbols.
	 * @memberOf punycode
	 * @param {String} input The string of Unicode symbols.
	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
	 */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],
		    /** `inputLength` will hold the number of code points in `input`. */
		    inputLength,
		    /** Cached calculation results */
		    handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base; /* no condition */; k += base) {
						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(
							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
						);
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;

		}
		return output.join('');
	}

	/**
	 * Converts a Punycode string representing a domain name or an email address
	 * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
	 * it doesn't matter if you call it on a string that has already been
	 * converted to Unicode.
	 * @memberOf punycode
	 * @param {String} input The Punycoded domain name or email address to
	 * convert to Unicode.
	 * @returns {String} The Unicode representation of the given Punycode
	 * string.
	 */
	function toUnicode(input) {
		return mapDomain(input, function(string) {
			return regexPunycode.test(string)
				? decode(string.slice(4).toLowerCase())
				: string;
		});
	}

	/**
	 * Converts a Unicode string representing a domain name or an email address to
	 * Punycode. Only the non-ASCII parts of the domain name will be converted,
	 * i.e. it doesn't matter if you call it with a domain that's already in
	 * ASCII.
	 * @memberOf punycode
	 * @param {String} input The domain name or email address to convert, as a
	 * Unicode string.
	 * @returns {String} The Punycode representation of the given domain name or
	 * email address.
	 */
	function toASCII(input) {
		return mapDomain(input, function(string) {
			return regexNonASCII.test(string)
				? 'xn--' + encode(string)
				: string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
		 * A string representing the current Punycode.js version number.
		 * @memberOf punycode
		 * @type String
		 */
		'version': '1.4.1',
		/**
		 * An object of methods to convert from JavaScript's internal character
		 * representation (UCS-2) to Unicode code points, and back.
		 * @see <https://mathiasbynens.be/notes/javascript-encoding>
		 * @memberOf punycode
		 * @type Object
		 */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define('punycode', function() {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) {
			// in Node.js, io.js, or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.punycode = punycode;
	}

}(this));

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],52:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function(qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr, vstr, k, v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],53:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var stringifyPrimitive = function(v) {
  switch (typeof v) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function(obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if (typeof obj === 'object') {
    return map(objectKeys(obj), function(k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function(v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);

  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq +
         encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map (xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],54:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":52,"./encode":53}],55:[function(require,module,exports){
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.prototype = Object.create(Buffer.prototype)

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":16}],56:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

module.exports = Stream;

var EE = require('events').EventEmitter;
var inherits = require('inherits');

inherits(Stream, EE);
Stream.Readable = require('readable-stream/lib/_stream_readable.js');
Stream.Writable = require('readable-stream/lib/_stream_writable.js');
Stream.Duplex = require('readable-stream/lib/_stream_duplex.js');
Stream.Transform = require('readable-stream/lib/_stream_transform.js');
Stream.PassThrough = require('readable-stream/lib/_stream_passthrough.js');
Stream.finished = require('readable-stream/lib/internal/streams/end-of-stream.js')
Stream.pipeline = require('readable-stream/lib/internal/streams/pipeline.js')

// Backwards-compat with node 0.4.x
Stream.Stream = Stream;



// old-style streams.  Note that the pipe method (the only relevant
// part of this class) is overridden in the Readable class.

function Stream() {
  EE.call(this);
}

Stream.prototype.pipe = function(dest, options) {
  var source = this;

  function ondata(chunk) {
    if (dest.writable) {
      if (false === dest.write(chunk) && source.pause) {
        source.pause();
      }
    }
  }

  source.on('data', ondata);

  function ondrain() {
    if (source.readable && source.resume) {
      source.resume();
    }
  }

  dest.on('drain', ondrain);

  // If the 'end' option is not supplied, dest.end() will be called when
  // source gets the 'end' or 'close' events.  Only dest.end() once.
  if (!dest._isStdio && (!options || options.end !== false)) {
    source.on('end', onend);
    source.on('close', onclose);
  }

  var didOnEnd = false;
  function onend() {
    if (didOnEnd) return;
    didOnEnd = true;

    dest.end();
  }


  function onclose() {
    if (didOnEnd) return;
    didOnEnd = true;

    if (typeof dest.destroy === 'function') dest.destroy();
  }

  // don't leave dangling pipes when there are errors.
  function onerror(er) {
    cleanup();
    if (EE.listenerCount(this, 'error') === 0) {
      throw er; // Unhandled stream error in pipe.
    }
  }

  source.on('error', onerror);
  dest.on('error', onerror);

  // remove all the event listeners that were added.
  function cleanup() {
    source.removeListener('data', ondata);
    dest.removeListener('drain', ondrain);

    source.removeListener('end', onend);
    source.removeListener('close', onclose);

    source.removeListener('error', onerror);
    dest.removeListener('error', onerror);

    source.removeListener('end', cleanup);
    source.removeListener('close', cleanup);

    dest.removeListener('close', cleanup);
  }

  source.on('end', cleanup);
  source.on('close', cleanup);

  dest.on('close', cleanup);

  dest.emit('pipe', source);

  // Allow for unix-like usage: A.pipe(B).pipe(C)
  return dest;
};

},{"events":14,"inherits":41,"readable-stream/lib/_stream_duplex.js":58,"readable-stream/lib/_stream_passthrough.js":59,"readable-stream/lib/_stream_readable.js":60,"readable-stream/lib/_stream_transform.js":61,"readable-stream/lib/_stream_writable.js":62,"readable-stream/lib/internal/streams/end-of-stream.js":66,"readable-stream/lib/internal/streams/pipeline.js":68}],57:[function(require,module,exports){
'use strict';

function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

var codes = {};

function createErrorType(code, message, Base) {
  if (!Base) {
    Base = Error;
  }

  function getMessage(arg1, arg2, arg3) {
    if (typeof message === 'string') {
      return message;
    } else {
      return message(arg1, arg2, arg3);
    }
  }

  var NodeError =
  /*#__PURE__*/
  function (_Base) {
    _inheritsLoose(NodeError, _Base);

    function NodeError(arg1, arg2, arg3) {
      return _Base.call(this, getMessage(arg1, arg2, arg3)) || this;
    }

    return NodeError;
  }(Base);

  NodeError.prototype.name = Base.name;
  NodeError.prototype.code = code;
  codes[code] = NodeError;
} // https://github.com/nodejs/node/blob/v10.8.0/lib/internal/errors.js


function oneOf(expected, thing) {
  if (Array.isArray(expected)) {
    var len = expected.length;
    expected = expected.map(function (i) {
      return String(i);
    });

    if (len > 2) {
      return "one of ".concat(thing, " ").concat(expected.slice(0, len - 1).join(', '), ", or ") + expected[len - 1];
    } else if (len === 2) {
      return "one of ".concat(thing, " ").concat(expected[0], " or ").concat(expected[1]);
    } else {
      return "of ".concat(thing, " ").concat(expected[0]);
    }
  } else {
    return "of ".concat(thing, " ").concat(String(expected));
  }
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/startsWith


function startsWith(str, search, pos) {
  return str.substr(!pos || pos < 0 ? 0 : +pos, search.length) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith


function endsWith(str, search, this_len) {
  if (this_len === undefined || this_len > str.length) {
    this_len = str.length;
  }

  return str.substring(this_len - search.length, this_len) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes


function includes(str, search, start) {
  if (typeof start !== 'number') {
    start = 0;
  }

  if (start + search.length > str.length) {
    return false;
  } else {
    return str.indexOf(search, start) !== -1;
  }
}

createErrorType('ERR_INVALID_OPT_VALUE', function (name, value) {
  return 'The value "' + value + '" is invalid for option "' + name + '"';
}, TypeError);
createErrorType('ERR_INVALID_ARG_TYPE', function (name, expected, actual) {
  // determiner: 'must be' or 'must not be'
  var determiner;

  if (typeof expected === 'string' && startsWith(expected, 'not ')) {
    determiner = 'must not be';
    expected = expected.replace(/^not /, '');
  } else {
    determiner = 'must be';
  }

  var msg;

  if (endsWith(name, ' argument')) {
    // For cases like 'first argument'
    msg = "The ".concat(name, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  } else {
    var type = includes(name, '.') ? 'property' : 'argument';
    msg = "The \"".concat(name, "\" ").concat(type, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  }

  msg += ". Received type ".concat(typeof actual);
  return msg;
}, TypeError);
createErrorType('ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF');
createErrorType('ERR_METHOD_NOT_IMPLEMENTED', function (name) {
  return 'The ' + name + ' method is not implemented';
});
createErrorType('ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
createErrorType('ERR_STREAM_DESTROYED', function (name) {
  return 'Cannot call ' + name + ' after a stream was destroyed';
});
createErrorType('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times');
createErrorType('ERR_STREAM_CANNOT_PIPE', 'Cannot pipe, not readable');
createErrorType('ERR_STREAM_WRITE_AFTER_END', 'write after end');
createErrorType('ERR_STREAM_NULL_VALUES', 'May not write null values to stream', TypeError);
createErrorType('ERR_UNKNOWN_ENCODING', function (arg) {
  return 'Unknown encoding: ' + arg;
}, TypeError);
createErrorType('ERR_STREAM_UNSHIFT_AFTER_END_EVENT', 'stream.unshift() after end event');
module.exports.codes = codes;

},{}],58:[function(require,module,exports){
(function (process){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.
'use strict';
/*<replacement>*/

var objectKeys = Object.keys || function (obj) {
  var keys = [];

  for (var key in obj) {
    keys.push(key);
  }

  return keys;
};
/*</replacement>*/


module.exports = Duplex;

var Readable = require('./_stream_readable');

var Writable = require('./_stream_writable');

require('inherits')(Duplex, Readable);

{
  // Allow the keys array to be GC'ed.
  var keys = objectKeys(Writable.prototype);

  for (var v = 0; v < keys.length; v++) {
    var method = keys[v];
    if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
  }
}

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);
  Readable.call(this, options);
  Writable.call(this, options);
  this.allowHalfOpen = true;

  if (options) {
    if (options.readable === false) this.readable = false;
    if (options.writable === false) this.writable = false;

    if (options.allowHalfOpen === false) {
      this.allowHalfOpen = false;
      this.once('end', onend);
    }
  }
}

Object.defineProperty(Duplex.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
});
Object.defineProperty(Duplex.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});
Object.defineProperty(Duplex.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
}); // the no-half-open enforcer

function onend() {
  // If the writable side ended, then we're ok.
  if (this._writableState.ended) return; // no more data can be written.
  // But allow more writes to happen in this tick.

  process.nextTick(onEndNT, this);
}

function onEndNT(self) {
  self.end();
}

Object.defineProperty(Duplex.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined || this._writableState === undefined) {
      return false;
    }

    return this._readableState.destroyed && this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (this._readableState === undefined || this._writableState === undefined) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
    this._writableState.destroyed = value;
  }
});
}).call(this)}).call(this,require('_process'))

},{"./_stream_readable":60,"./_stream_writable":62,"_process":30,"inherits":41}],59:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.
'use strict';

module.exports = PassThrough;

var Transform = require('./_stream_transform');

require('inherits')(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);
  Transform.call(this, options);
}

PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":61,"inherits":41}],60:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
'use strict';

module.exports = Readable;
/*<replacement>*/

var Duplex;
/*</replacement>*/

Readable.ReadableState = ReadableState;
/*<replacement>*/

var EE = require('events').EventEmitter;

var EElistenerCount = function EElistenerCount(emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/


var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
/*<replacement>*/


var debugUtil = require('util');

var debug;

if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function debug() {};
}
/*</replacement>*/


var BufferList = require('./internal/streams/buffer_list');

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_STREAM_PUSH_AFTER_EOF = _require$codes.ERR_STREAM_PUSH_AFTER_EOF,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_STREAM_UNSHIFT_AFTER_END_EVENT = _require$codes.ERR_STREAM_UNSHIFT_AFTER_END_EVENT; // Lazy loaded to improve the startup performance.


var StringDecoder;
var createReadableStreamAsyncIterator;
var from;

require('inherits')(Readable, Stream);

var errorOrDestroy = destroyImpl.errorOrDestroy;
var kProxyEvents = ['error', 'close', 'destroy', 'pause', 'resume'];

function prependListener(emitter, event, fn) {
  // Sadly this is not cacheable as some libraries bundle their own
  // event emitter implementation with them.
  if (typeof emitter.prependListener === 'function') return emitter.prependListener(event, fn); // This is a hack to make sure that our error handler is attached before any
  // userland ones.  NEVER DO THIS. This is here only because this code needs
  // to continue to work with older versions of Node.js that do not include
  // the prependListener() method. The goal is to eventually remove this hack.

  if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);else if (Array.isArray(emitter._events[event])) emitter._events[event].unshift(fn);else emitter._events[event] = [fn, emitter._events[event]];
}

function ReadableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream.
  // These options can be provided separately as readableXXX and writableXXX.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.readableObjectMode; // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"

  this.highWaterMark = getHighWaterMark(this, options, 'readableHighWaterMark', isDuplex); // A linked list is used to store data chunks instead of an array because the
  // linked list can remove elements from the beginning faster than
  // array.shift()

  this.buffer = new BufferList();
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false; // a flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.

  this.sync = true; // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.

  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;
  this.paused = true; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'end' (and potentially 'finish')

  this.autoDestroy = !!options.autoDestroy; // has it been destroyed

  this.destroyed = false; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // the number of writers that are awaiting a drain event in .pipe()s

  this.awaitDrain = 0; // if true, a maybeReadMore has been scheduled

  this.readingMore = false;
  this.decoder = null;
  this.encoding = null;

  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');
  if (!(this instanceof Readable)) return new Readable(options); // Checking for a Stream.Duplex instance is faster here instead of inside
  // the ReadableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  this._readableState = new ReadableState(options, this, isDuplex); // legacy

  this.readable = true;

  if (options) {
    if (typeof options.read === 'function') this._read = options.read;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
  }

  Stream.call(this);
}

Object.defineProperty(Readable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined) {
      return false;
    }

    return this._readableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._readableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
  }
});
Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;

Readable.prototype._destroy = function (err, cb) {
  cb(err);
}; // Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.


Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;
  var skipChunkCheck;

  if (!state.objectMode) {
    if (typeof chunk === 'string') {
      encoding = encoding || state.defaultEncoding;

      if (encoding !== state.encoding) {
        chunk = Buffer.from(chunk, encoding);
        encoding = '';
      }

      skipChunkCheck = true;
    }
  } else {
    skipChunkCheck = true;
  }

  return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
}; // Unshift should *always* be something directly out of read()


Readable.prototype.unshift = function (chunk) {
  return readableAddChunk(this, chunk, null, true, false);
};

function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
  debug('readableAddChunk', chunk);
  var state = stream._readableState;

  if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else {
    var er;
    if (!skipChunkCheck) er = chunkInvalid(state, chunk);

    if (er) {
      errorOrDestroy(stream, er);
    } else if (state.objectMode || chunk && chunk.length > 0) {
      if (typeof chunk !== 'string' && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
        chunk = _uint8ArrayToBuffer(chunk);
      }

      if (addToFront) {
        if (state.endEmitted) errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());else addChunk(stream, state, chunk, true);
      } else if (state.ended) {
        errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
      } else if (state.destroyed) {
        return false;
      } else {
        state.reading = false;

        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false);else maybeReadMore(stream, state);
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      maybeReadMore(stream, state);
    }
  } // We can push more data if we are below the highWaterMark.
  // Also, if we have no data yet, we can stand some more bytes.
  // This is to work around cases where hwm=0, such as the repl.


  return !state.ended && (state.length < state.highWaterMark || state.length === 0);
}

function addChunk(stream, state, chunk, addToFront) {
  if (state.flowing && state.length === 0 && !state.sync) {
    state.awaitDrain = 0;
    stream.emit('data', chunk);
  } else {
    // update the buffer info.
    state.length += state.objectMode ? 1 : chunk.length;
    if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);
    if (state.needReadable) emitReadable(stream);
  }

  maybeReadMore(stream, state);
}

function chunkInvalid(state, chunk) {
  var er;

  if (!_isUint8Array(chunk) && typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer', 'Uint8Array'], chunk);
  }

  return er;
}

Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
}; // backwards compatibility.


Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  var decoder = new StringDecoder(enc);
  this._readableState.decoder = decoder; // If setEncoding(null), decoder.encoding equals utf8

  this._readableState.encoding = this._readableState.decoder.encoding; // Iterate over current buffer to convert already stored Buffers:

  var p = this._readableState.buffer.head;
  var content = '';

  while (p !== null) {
    content += decoder.write(p.data);
    p = p.next;
  }

  this._readableState.buffer.clear();

  if (content !== '') this._readableState.buffer.push(content);
  this._readableState.length = content.length;
  return this;
}; // Don't raise the hwm > 1GB


var MAX_HWM = 0x40000000;

function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    // TODO(ronag): Throw ERR_VALUE_OUT_OF_RANGE.
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }

  return n;
} // This function is designed to be inlinable, so please take care when making
// changes to the function body.


function howMuchToRead(n, state) {
  if (n <= 0 || state.length === 0 && state.ended) return 0;
  if (state.objectMode) return 1;

  if (n !== n) {
    // Only flow one buffer at a time
    if (state.flowing && state.length) return state.buffer.head.data.length;else return state.length;
  } // If we're asking for more than the current hwm, then raise the hwm.


  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
  if (n <= state.length) return n; // Don't have enough

  if (!state.ended) {
    state.needReadable = true;
    return 0;
  }

  return state.length;
} // you can override either this method, or the async _read(n) below.


Readable.prototype.read = function (n) {
  debug('read', n);
  n = parseInt(n, 10);
  var state = this._readableState;
  var nOrig = n;
  if (n !== 0) state.emittedReadable = false; // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.

  if (n === 0 && state.needReadable && ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state); // if we've ended, and we're now clear, then finish it up.

  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  } // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.
  // if we need a readable event, then we need to do some reading.


  var doRead = state.needReadable;
  debug('need readable', doRead); // if we currently have less than the highWaterMark, then also read some

  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  } // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.


  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  } else if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true; // if the length is currently zero, then we *need* a readable event.

    if (state.length === 0) state.needReadable = true; // call internal read method

    this._read(state.highWaterMark);

    state.sync = false; // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.

    if (!state.reading) n = howMuchToRead(nOrig, state);
  }

  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;

  if (ret === null) {
    state.needReadable = state.length <= state.highWaterMark;
    n = 0;
  } else {
    state.length -= n;
    state.awaitDrain = 0;
  }

  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if (!state.ended) state.needReadable = true; // If we tried to read() past the EOF, then emit end on the next tick.

    if (nOrig !== n && state.ended) endReadable(this);
  }

  if (ret !== null) this.emit('data', ret);
  return ret;
};

function onEofChunk(stream, state) {
  debug('onEofChunk');
  if (state.ended) return;

  if (state.decoder) {
    var chunk = state.decoder.end();

    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }

  state.ended = true;

  if (state.sync) {
    // if we are sync, wait until next tick to emit the data.
    // Otherwise we risk emitting data in the flow()
    // the readable code triggers during a read() call
    emitReadable(stream);
  } else {
    // emit 'readable' now to make sure it gets picked up.
    state.needReadable = false;

    if (!state.emittedReadable) {
      state.emittedReadable = true;
      emitReadable_(stream);
    }
  }
} // Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.


function emitReadable(stream) {
  var state = stream._readableState;
  debug('emitReadable', state.needReadable, state.emittedReadable);
  state.needReadable = false;

  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    process.nextTick(emitReadable_, stream);
  }
}

function emitReadable_(stream) {
  var state = stream._readableState;
  debug('emitReadable_', state.destroyed, state.length, state.ended);

  if (!state.destroyed && (state.length || state.ended)) {
    stream.emit('readable');
    state.emittedReadable = false;
  } // The stream needs another readable event if
  // 1. It is not flowing, as the flow mechanism will take
  //    care of it.
  // 2. It is not ended.
  // 3. It is below the highWaterMark, so we can schedule
  //    another readable later.


  state.needReadable = !state.flowing && !state.ended && state.length <= state.highWaterMark;
  flow(stream);
} // at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.


function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    process.nextTick(maybeReadMore_, stream, state);
  }
}

function maybeReadMore_(stream, state) {
  // Attempt to read more data if we should.
  //
  // The conditions for reading more data are (one of):
  // - Not enough data buffered (state.length < state.highWaterMark). The loop
  //   is responsible for filling the buffer with enough data if such data
  //   is available. If highWaterMark is 0 and we are not in the flowing mode
  //   we should _not_ attempt to buffer any extra data. We'll get more data
  //   when the stream consumer calls read() instead.
  // - No data in the buffer, and the stream is in flowing mode. In this mode
  //   the loop below is responsible for ensuring read() is called. Failing to
  //   call read here would abort the flow and there's no other mechanism for
  //   continuing the flow if the stream consumer has just subscribed to the
  //   'data' event.
  //
  // In addition to the above conditions to keep reading data, the following
  // conditions prevent the data from being read:
  // - The stream has ended (state.ended).
  // - There is already a pending 'read' operation (state.reading). This is a
  //   case where the the stream has called the implementation defined _read()
  //   method, but they are processing the call asynchronously and have _not_
  //   called push() with new data. In this case we skip performing more
  //   read()s. The execution ends in this method again after the _read() ends
  //   up calling push() with more data.
  while (!state.reading && !state.ended && (state.length < state.highWaterMark || state.flowing && state.length === 0)) {
    var len = state.length;
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length) // didn't get any data, stop spinning.
      break;
  }

  state.readingMore = false;
} // abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.


Readable.prototype._read = function (n) {
  errorOrDestroy(this, new ERR_METHOD_NOT_IMPLEMENTED('_read()'));
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;

    case 1:
      state.pipes = [state.pipes, dest];
      break;

    default:
      state.pipes.push(dest);
      break;
  }

  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);
  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;
  var endFn = doEnd ? onend : unpipe;
  if (state.endEmitted) process.nextTick(endFn);else src.once('end', endFn);
  dest.on('unpipe', onunpipe);

  function onunpipe(readable, unpipeInfo) {
    debug('onunpipe');

    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }

  function onend() {
    debug('onend');
    dest.end();
  } // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.


  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);
  var cleanedUp = false;

  function cleanup() {
    debug('cleanup'); // cleanup event handlers once the pipe is broken

    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', unpipe);
    src.removeListener('data', ondata);
    cleanedUp = true; // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.

    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }

  src.on('data', ondata);

  function ondata(chunk) {
    debug('ondata');
    var ret = dest.write(chunk);
    debug('dest.write', ret);

    if (ret === false) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      // => Check whether `dest` is still a piping destination.
      if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
        debug('false write response, pause', state.awaitDrain);
        state.awaitDrain++;
      }

      src.pause();
    }
  } // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.


  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) errorOrDestroy(dest, er);
  } // Make sure our error handler is attached before userland ones.


  prependListener(dest, 'error', onerror); // Both close and finish should trigger unpipe, but only once.

  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }

  dest.once('close', onclose);

  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }

  dest.once('finish', onfinish);

  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  } // tell the dest that it's being piped to


  dest.emit('pipe', src); // start the flow if it hasn't been started already.

  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }

  return dest;
};

function pipeOnDrain(src) {
  return function pipeOnDrainFunctionResult() {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;

    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;
  var unpipeInfo = {
    hasUnpiped: false
  }; // if we're not piping anywhere, then do nothing.

  if (state.pipesCount === 0) return this; // just one destination.  most common case.

  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;
    if (!dest) dest = state.pipes; // got a match.

    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this, unpipeInfo);
    return this;
  } // slow case. multiple pipe destinations.


  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;

    for (var i = 0; i < len; i++) {
      dests[i].emit('unpipe', this, {
        hasUnpiped: false
      });
    }

    return this;
  } // try to find the right one.


  var index = indexOf(state.pipes, dest);
  if (index === -1) return this;
  state.pipes.splice(index, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];
  dest.emit('unpipe', this, unpipeInfo);
  return this;
}; // set up data events if they are asked for
// Ensure readable listeners eventually get something


Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);
  var state = this._readableState;

  if (ev === 'data') {
    // update readableListening so that resume() may be a no-op
    // a few lines down. This is needed to support once('readable').
    state.readableListening = this.listenerCount('readable') > 0; // Try start flowing on next tick if stream isn't explicitly paused

    if (state.flowing !== false) this.resume();
  } else if (ev === 'readable') {
    if (!state.endEmitted && !state.readableListening) {
      state.readableListening = state.needReadable = true;
      state.flowing = false;
      state.emittedReadable = false;
      debug('on readable', state.length, state.reading);

      if (state.length) {
        emitReadable(this);
      } else if (!state.reading) {
        process.nextTick(nReadingNextTick, this);
      }
    }
  }

  return res;
};

Readable.prototype.addListener = Readable.prototype.on;

Readable.prototype.removeListener = function (ev, fn) {
  var res = Stream.prototype.removeListener.call(this, ev, fn);

  if (ev === 'readable') {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

Readable.prototype.removeAllListeners = function (ev) {
  var res = Stream.prototype.removeAllListeners.apply(this, arguments);

  if (ev === 'readable' || ev === undefined) {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

function updateReadableListening(self) {
  var state = self._readableState;
  state.readableListening = self.listenerCount('readable') > 0;

  if (state.resumeScheduled && !state.paused) {
    // flowing needs to be set to true now, otherwise
    // the upcoming resume will not flow.
    state.flowing = true; // crude way to check if we should resume
  } else if (self.listenerCount('data') > 0) {
    self.resume();
  }
}

function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
} // pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.


Readable.prototype.resume = function () {
  var state = this._readableState;

  if (!state.flowing) {
    debug('resume'); // we flow only if there is no one listening
    // for readable, but we still have to call
    // resume()

    state.flowing = !state.readableListening;
    resume(this, state);
  }

  state.paused = false;
  return this;
};

function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    process.nextTick(resume_, stream, state);
  }
}

function resume_(stream, state) {
  debug('resume', state.reading);

  if (!state.reading) {
    stream.read(0);
  }

  state.resumeScheduled = false;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}

Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);

  if (this._readableState.flowing !== false) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }

  this._readableState.paused = true;
  return this;
};

function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);

  while (state.flowing && stream.read() !== null) {
    ;
  }
} // wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.


Readable.prototype.wrap = function (stream) {
  var _this = this;

  var state = this._readableState;
  var paused = false;
  stream.on('end', function () {
    debug('wrapped end');

    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) _this.push(chunk);
    }

    _this.push(null);
  });
  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk); // don't skip over falsy values in objectMode

    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;

    var ret = _this.push(chunk);

    if (!ret) {
      paused = true;
      stream.pause();
    }
  }); // proxy all the other methods.
  // important when wrapping filters and duplexes.

  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function methodWrap(method) {
        return function methodWrapReturnFunction() {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  } // proxy certain important events.


  for (var n = 0; n < kProxyEvents.length; n++) {
    stream.on(kProxyEvents[n], this.emit.bind(this, kProxyEvents[n]));
  } // when we try to consume some more bytes, simply unpause the
  // underlying stream.


  this._read = function (n) {
    debug('wrapped _read', n);

    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return this;
};

if (typeof Symbol === 'function') {
  Readable.prototype[Symbol.asyncIterator] = function () {
    if (createReadableStreamAsyncIterator === undefined) {
      createReadableStreamAsyncIterator = require('./internal/streams/async_iterator');
    }

    return createReadableStreamAsyncIterator(this);
  };
}

Object.defineProperty(Readable.prototype, 'readableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.highWaterMark;
  }
});
Object.defineProperty(Readable.prototype, 'readableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState && this._readableState.buffer;
  }
});
Object.defineProperty(Readable.prototype, 'readableFlowing', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.flowing;
  },
  set: function set(state) {
    if (this._readableState) {
      this._readableState.flowing = state;
    }
  }
}); // exposed for testing purposes only.

Readable._fromList = fromList;
Object.defineProperty(Readable.prototype, 'readableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.length;
  }
}); // Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.

function fromList(n, state) {
  // nothing buffered
  if (state.length === 0) return null;
  var ret;
  if (state.objectMode) ret = state.buffer.shift();else if (!n || n >= state.length) {
    // read it all, truncate the list
    if (state.decoder) ret = state.buffer.join('');else if (state.buffer.length === 1) ret = state.buffer.first();else ret = state.buffer.concat(state.length);
    state.buffer.clear();
  } else {
    // read part of list
    ret = state.buffer.consume(n, state.decoder);
  }
  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;
  debug('endReadable', state.endEmitted);

  if (!state.endEmitted) {
    state.ended = true;
    process.nextTick(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  debug('endReadableNT', state.endEmitted, state.length); // Check that we didn't get one last unshift.

  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');

    if (state.autoDestroy) {
      // In case of duplex streams we need a way to detect
      // if the writable side is ready for autoDestroy as well
      var wState = stream._writableState;

      if (!wState || wState.autoDestroy && wState.finished) {
        stream.destroy();
      }
    }
  }
}

if (typeof Symbol === 'function') {
  Readable.from = function (iterable, opts) {
    if (from === undefined) {
      from = require('./internal/streams/from');
    }

    return from(Readable, iterable, opts);
  };
}

function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }

  return -1;
}
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../errors":57,"./_stream_duplex":58,"./internal/streams/async_iterator":63,"./internal/streams/buffer_list":64,"./internal/streams/destroy":65,"./internal/streams/from":67,"./internal/streams/state":69,"./internal/streams/stream":70,"_process":30,"buffer":16,"events":14,"inherits":41,"string_decoder/":71,"util":8}],61:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.
'use strict';

module.exports = Transform;

var _require$codes = require('../errors').codes,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_TRANSFORM_ALREADY_TRANSFORMING = _require$codes.ERR_TRANSFORM_ALREADY_TRANSFORMING,
    ERR_TRANSFORM_WITH_LENGTH_0 = _require$codes.ERR_TRANSFORM_WITH_LENGTH_0;

var Duplex = require('./_stream_duplex');

require('inherits')(Transform, Duplex);

function afterTransform(er, data) {
  var ts = this._transformState;
  ts.transforming = false;
  var cb = ts.writecb;

  if (cb === null) {
    return this.emit('error', new ERR_MULTIPLE_CALLBACK());
  }

  ts.writechunk = null;
  ts.writecb = null;
  if (data != null) // single equals check for both `null` and `undefined`
    this.push(data);
  cb(er);
  var rs = this._readableState;
  rs.reading = false;

  if (rs.needReadable || rs.length < rs.highWaterMark) {
    this._read(rs.highWaterMark);
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  this._transformState = {
    afterTransform: afterTransform.bind(this),
    needTransform: false,
    transforming: false,
    writecb: null,
    writechunk: null,
    writeencoding: null
  }; // start out asking for a readable event once data is transformed.

  this._readableState.needReadable = true; // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.

  this._readableState.sync = false;

  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;
    if (typeof options.flush === 'function') this._flush = options.flush;
  } // When the writable side finishes, then flush out anything remaining.


  this.on('prefinish', prefinish);
}

function prefinish() {
  var _this = this;

  if (typeof this._flush === 'function' && !this._readableState.destroyed) {
    this._flush(function (er, data) {
      done(_this, er, data);
    });
  } else {
    done(this, null, null);
  }
}

Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
}; // This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.


Transform.prototype._transform = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_transform()'));
};

Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;

  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
}; // Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.


Transform.prototype._read = function (n) {
  var ts = this._transformState;

  if (ts.writechunk !== null && !ts.transforming) {
    ts.transforming = true;

    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};

Transform.prototype._destroy = function (err, cb) {
  Duplex.prototype._destroy.call(this, err, function (err2) {
    cb(err2);
  });
};

function done(stream, er, data) {
  if (er) return stream.emit('error', er);
  if (data != null) // single equals check for both `null` and `undefined`
    stream.push(data); // TODO(BridgeAR): Write a test for these two error cases
  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided

  if (stream._writableState.length) throw new ERR_TRANSFORM_WITH_LENGTH_0();
  if (stream._transformState.transforming) throw new ERR_TRANSFORM_ALREADY_TRANSFORMING();
  return stream.push(null);
}
},{"../errors":57,"./_stream_duplex":58,"inherits":41}],62:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.
'use strict';

module.exports = Writable;
/* <replacement> */

function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
} // It seems a linked list but it is not
// there will be only 2 of these for each stream


function CorkedRequest(state) {
  var _this = this;

  this.next = null;
  this.entry = null;

  this.finish = function () {
    onCorkedFinish(_this, state);
  };
}
/* </replacement> */

/*<replacement>*/


var Duplex;
/*</replacement>*/

Writable.WritableState = WritableState;
/*<replacement>*/

var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/

var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_STREAM_CANNOT_PIPE = _require$codes.ERR_STREAM_CANNOT_PIPE,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED,
    ERR_STREAM_NULL_VALUES = _require$codes.ERR_STREAM_NULL_VALUES,
    ERR_STREAM_WRITE_AFTER_END = _require$codes.ERR_STREAM_WRITE_AFTER_END,
    ERR_UNKNOWN_ENCODING = _require$codes.ERR_UNKNOWN_ENCODING;

var errorOrDestroy = destroyImpl.errorOrDestroy;

require('inherits')(Writable, Stream);

function nop() {}

function WritableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream,
  // e.g. options.readableObjectMode vs. options.writableObjectMode, etc.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag to indicate whether or not this stream
  // contains buffers or objects.

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.writableObjectMode; // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()

  this.highWaterMark = getHighWaterMark(this, options, 'writableHighWaterMark', isDuplex); // if _final has been called

  this.finalCalled = false; // drain event flag.

  this.needDrain = false; // at the start of calling end()

  this.ending = false; // when end() has been called, and returned

  this.ended = false; // when 'finish' is emitted

  this.finished = false; // has it been destroyed

  this.destroyed = false; // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.

  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.

  this.length = 0; // a flag to see when we're in the middle of a write.

  this.writing = false; // when true all writes will be buffered until .uncork() call

  this.corked = 0; // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.

  this.sync = true; // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.

  this.bufferProcessing = false; // the callback that's passed to _write(chunk,cb)

  this.onwrite = function (er) {
    onwrite(stream, er);
  }; // the callback that the user supplies to write(chunk,encoding,cb)


  this.writecb = null; // the amount that is being written when _write is called.

  this.writelen = 0;
  this.bufferedRequest = null;
  this.lastBufferedRequest = null; // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted

  this.pendingcb = 0; // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams

  this.prefinished = false; // True if the error was already emitted and should not be thrown again

  this.errorEmitted = false; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'finish' (and potentially 'end')

  this.autoDestroy = !!options.autoDestroy; // count buffered requests

  this.bufferedRequestCount = 0; // allocate the first CorkedRequest, there is always
  // one allocated and free to use, and we maintain at most two

  this.corkedRequestsFree = new CorkedRequest(this);
}

WritableState.prototype.getBuffer = function getBuffer() {
  var current = this.bufferedRequest;
  var out = [];

  while (current) {
    out.push(current);
    current = current.next;
  }

  return out;
};

(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function writableStateBufferGetter() {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.', 'DEP0003')
    });
  } catch (_) {}
})(); // Test _writableState for inheritance to account for Duplex streams,
// whose prototype chain only points to Readable.


var realHasInstance;

if (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {
  realHasInstance = Function.prototype[Symbol.hasInstance];
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function value(object) {
      if (realHasInstance.call(this, object)) return true;
      if (this !== Writable) return false;
      return object && object._writableState instanceof WritableState;
    }
  });
} else {
  realHasInstance = function realHasInstance(object) {
    return object instanceof this;
  };
}

function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex'); // Writable ctor is applied to Duplexes, too.
  // `realHasInstance` is necessary because using plain `instanceof`
  // would return false, as no `_writableState` property is attached.
  // Trying to use the custom `instanceof` for Writable here will also break the
  // Node.js LazyTransform implementation, which has a non-trivial getter for
  // `_writableState` that would lead to infinite recursion.
  // Checking for a Stream.Duplex instance is faster here instead of inside
  // the WritableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  if (!isDuplex && !realHasInstance.call(Writable, this)) return new Writable(options);
  this._writableState = new WritableState(options, this, isDuplex); // legacy.

  this.writable = true;

  if (options) {
    if (typeof options.write === 'function') this._write = options.write;
    if (typeof options.writev === 'function') this._writev = options.writev;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
    if (typeof options.final === 'function') this._final = options.final;
  }

  Stream.call(this);
} // Otherwise people can pipe Writable streams, which is just wrong.


Writable.prototype.pipe = function () {
  errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
};

function writeAfterEnd(stream, cb) {
  var er = new ERR_STREAM_WRITE_AFTER_END(); // TODO: defer error events consistently everywhere, not just the cb

  errorOrDestroy(stream, er);
  process.nextTick(cb, er);
} // Checks that a user-supplied chunk is valid, especially for the particular
// mode the stream is in. Currently this means that `null` is never accepted
// and undefined/non-string values are only allowed in object mode.


function validChunk(stream, state, chunk, cb) {
  var er;

  if (chunk === null) {
    er = new ERR_STREAM_NULL_VALUES();
  } else if (typeof chunk !== 'string' && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer'], chunk);
  }

  if (er) {
    errorOrDestroy(stream, er);
    process.nextTick(cb, er);
    return false;
  }

  return true;
}

Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;

  var isBuf = !state.objectMode && _isUint8Array(chunk);

  if (isBuf && !Buffer.isBuffer(chunk)) {
    chunk = _uint8ArrayToBuffer(chunk);
  }

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (isBuf) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;
  if (typeof cb !== 'function') cb = nop;
  if (state.ending) writeAfterEnd(this, cb);else if (isBuf || validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
  }
  return ret;
};

Writable.prototype.cork = function () {
  this._writableState.corked++;
};

Writable.prototype.uncork = function () {
  var state = this._writableState;

  if (state.corked) {
    state.corked--;
    if (!state.writing && !state.corked && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new ERR_UNKNOWN_ENCODING(encoding);
  this._writableState.defaultEncoding = encoding;
  return this;
};

Object.defineProperty(Writable.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = Buffer.from(chunk, encoding);
  }

  return chunk;
}

Object.defineProperty(Writable.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
}); // if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.

function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
  if (!isBuf) {
    var newChunk = decodeChunk(state, chunk, encoding);

    if (chunk !== newChunk) {
      isBuf = true;
      encoding = 'buffer';
      chunk = newChunk;
    }
  }

  var len = state.objectMode ? 1 : chunk.length;
  state.length += len;
  var ret = state.length < state.highWaterMark; // we must ensure that previous needDrain will not be reset to false.

  if (!ret) state.needDrain = true;

  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = {
      chunk: chunk,
      encoding: encoding,
      isBuf: isBuf,
      callback: cb,
      next: null
    };

    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }

    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }

  return ret;
}

function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (state.destroyed) state.onwrite(new ERR_STREAM_DESTROYED('write'));else if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;

  if (sync) {
    // defer the callback if we are being called synchronously
    // to avoid piling up things on the stack
    process.nextTick(cb, er); // this can emit finish, and it will always happen
    // after error

    process.nextTick(finishMaybe, stream, state);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er);
  } else {
    // the caller expect this to happen before if
    // it is async
    cb(er);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er); // this can emit finish, but finish must
    // always follow error

    finishMaybe(stream, state);
  }
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;
  if (typeof cb !== 'function') throw new ERR_MULTIPLE_CALLBACK();
  onwriteStateUpdate(state);
  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state) || stream.destroyed;

    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }

    if (sync) {
      process.nextTick(afterWrite, stream, state, finished, cb);
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
} // Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.


function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
} // if there's something in the buffer waiting, then process it


function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;

  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;
    var count = 0;
    var allBuffers = true;

    while (entry) {
      buffer[count] = entry;
      if (!entry.isBuf) allBuffers = false;
      entry = entry.next;
      count += 1;
    }

    buffer.allBuffers = allBuffers;
    doWrite(stream, state, true, state.length, buffer, '', holder.finish); // doWrite is almost always async, defer these to save a bit of time
    // as the hot path ends with doWrite

    state.pendingcb++;
    state.lastBufferedRequest = null;

    if (holder.next) {
      state.corkedRequestsFree = holder.next;
      holder.next = null;
    } else {
      state.corkedRequestsFree = new CorkedRequest(state);
    }

    state.bufferedRequestCount = 0;
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;
      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      state.bufferedRequestCount--; // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.

      if (state.writing) {
        break;
      }
    }

    if (entry === null) state.lastBufferedRequest = null;
  }

  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_write()'));
};

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding); // .end() fully uncorks

  if (state.corked) {
    state.corked = 1;
    this.uncork();
  } // ignore unnecessary end() calls.


  if (!state.ending) endWritable(this, state, cb);
  return this;
};

Object.defineProperty(Writable.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
});

function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}

function callFinal(stream, state) {
  stream._final(function (err) {
    state.pendingcb--;

    if (err) {
      errorOrDestroy(stream, err);
    }

    state.prefinished = true;
    stream.emit('prefinish');
    finishMaybe(stream, state);
  });
}

function prefinish(stream, state) {
  if (!state.prefinished && !state.finalCalled) {
    if (typeof stream._final === 'function' && !state.destroyed) {
      state.pendingcb++;
      state.finalCalled = true;
      process.nextTick(callFinal, stream, state);
    } else {
      state.prefinished = true;
      stream.emit('prefinish');
    }
  }
}

function finishMaybe(stream, state) {
  var need = needFinish(state);

  if (need) {
    prefinish(stream, state);

    if (state.pendingcb === 0) {
      state.finished = true;
      stream.emit('finish');

      if (state.autoDestroy) {
        // In case of duplex streams we need a way to detect
        // if the readable side is ready for autoDestroy as well
        var rState = stream._readableState;

        if (!rState || rState.autoDestroy && rState.endEmitted) {
          stream.destroy();
        }
      }
    }
  }

  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);

  if (cb) {
    if (state.finished) process.nextTick(cb);else stream.once('finish', cb);
  }

  state.ended = true;
  stream.writable = false;
}

function onCorkedFinish(corkReq, state, err) {
  var entry = corkReq.entry;
  corkReq.entry = null;

  while (entry) {
    var cb = entry.callback;
    state.pendingcb--;
    cb(err);
    entry = entry.next;
  } // reuse the free corkReq.


  state.corkedRequestsFree.next = corkReq;
}

Object.defineProperty(Writable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._writableState === undefined) {
      return false;
    }

    return this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._writableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._writableState.destroyed = value;
  }
});
Writable.prototype.destroy = destroyImpl.destroy;
Writable.prototype._undestroy = destroyImpl.undestroy;

Writable.prototype._destroy = function (err, cb) {
  cb(err);
};
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../errors":57,"./_stream_duplex":58,"./internal/streams/destroy":65,"./internal/streams/state":69,"./internal/streams/stream":70,"_process":30,"buffer":16,"inherits":41,"util-deprecate":75}],63:[function(require,module,exports){
(function (process){(function (){
'use strict';

var _Object$setPrototypeO;

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var finished = require('./end-of-stream');

var kLastResolve = Symbol('lastResolve');
var kLastReject = Symbol('lastReject');
var kError = Symbol('error');
var kEnded = Symbol('ended');
var kLastPromise = Symbol('lastPromise');
var kHandlePromise = Symbol('handlePromise');
var kStream = Symbol('stream');

function createIterResult(value, done) {
  return {
    value: value,
    done: done
  };
}

function readAndResolve(iter) {
  var resolve = iter[kLastResolve];

  if (resolve !== null) {
    var data = iter[kStream].read(); // we defer if data is null
    // we can be expecting either 'end' or
    // 'error'

    if (data !== null) {
      iter[kLastPromise] = null;
      iter[kLastResolve] = null;
      iter[kLastReject] = null;
      resolve(createIterResult(data, false));
    }
  }
}

function onReadable(iter) {
  // we wait for the next tick, because it might
  // emit an error with process.nextTick
  process.nextTick(readAndResolve, iter);
}

function wrapForNext(lastPromise, iter) {
  return function (resolve, reject) {
    lastPromise.then(function () {
      if (iter[kEnded]) {
        resolve(createIterResult(undefined, true));
        return;
      }

      iter[kHandlePromise](resolve, reject);
    }, reject);
  };
}

var AsyncIteratorPrototype = Object.getPrototypeOf(function () {});
var ReadableStreamAsyncIteratorPrototype = Object.setPrototypeOf((_Object$setPrototypeO = {
  get stream() {
    return this[kStream];
  },

  next: function next() {
    var _this = this;

    // if we have detected an error in the meanwhile
    // reject straight away
    var error = this[kError];

    if (error !== null) {
      return Promise.reject(error);
    }

    if (this[kEnded]) {
      return Promise.resolve(createIterResult(undefined, true));
    }

    if (this[kStream].destroyed) {
      // We need to defer via nextTick because if .destroy(err) is
      // called, the error will be emitted via nextTick, and
      // we cannot guarantee that there is no error lingering around
      // waiting to be emitted.
      return new Promise(function (resolve, reject) {
        process.nextTick(function () {
          if (_this[kError]) {
            reject(_this[kError]);
          } else {
            resolve(createIterResult(undefined, true));
          }
        });
      });
    } // if we have multiple next() calls
    // we will wait for the previous Promise to finish
    // this logic is optimized to support for await loops,
    // where next() is only called once at a time


    var lastPromise = this[kLastPromise];
    var promise;

    if (lastPromise) {
      promise = new Promise(wrapForNext(lastPromise, this));
    } else {
      // fast path needed to support multiple this.push()
      // without triggering the next() queue
      var data = this[kStream].read();

      if (data !== null) {
        return Promise.resolve(createIterResult(data, false));
      }

      promise = new Promise(this[kHandlePromise]);
    }

    this[kLastPromise] = promise;
    return promise;
  }
}, _defineProperty(_Object$setPrototypeO, Symbol.asyncIterator, function () {
  return this;
}), _defineProperty(_Object$setPrototypeO, "return", function _return() {
  var _this2 = this;

  // destroy(err, cb) is a private API
  // we can guarantee we have that here, because we control the
  // Readable class this is attached to
  return new Promise(function (resolve, reject) {
    _this2[kStream].destroy(null, function (err) {
      if (err) {
        reject(err);
        return;
      }

      resolve(createIterResult(undefined, true));
    });
  });
}), _Object$setPrototypeO), AsyncIteratorPrototype);

var createReadableStreamAsyncIterator = function createReadableStreamAsyncIterator(stream) {
  var _Object$create;

  var iterator = Object.create(ReadableStreamAsyncIteratorPrototype, (_Object$create = {}, _defineProperty(_Object$create, kStream, {
    value: stream,
    writable: true
  }), _defineProperty(_Object$create, kLastResolve, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kLastReject, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kError, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kEnded, {
    value: stream._readableState.endEmitted,
    writable: true
  }), _defineProperty(_Object$create, kHandlePromise, {
    value: function value(resolve, reject) {
      var data = iterator[kStream].read();

      if (data) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        resolve(createIterResult(data, false));
      } else {
        iterator[kLastResolve] = resolve;
        iterator[kLastReject] = reject;
      }
    },
    writable: true
  }), _Object$create));
  iterator[kLastPromise] = null;
  finished(stream, function (err) {
    if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
      var reject = iterator[kLastReject]; // reject if we are waiting for data in the Promise
      // returned by next() and store the error

      if (reject !== null) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        reject(err);
      }

      iterator[kError] = err;
      return;
    }

    var resolve = iterator[kLastResolve];

    if (resolve !== null) {
      iterator[kLastPromise] = null;
      iterator[kLastResolve] = null;
      iterator[kLastReject] = null;
      resolve(createIterResult(undefined, true));
    }

    iterator[kEnded] = true;
  });
  stream.on('readable', onReadable.bind(null, iterator));
  return iterator;
};

module.exports = createReadableStreamAsyncIterator;
}).call(this)}).call(this,require('_process'))

},{"./end-of-stream":66,"_process":30}],64:[function(require,module,exports){
'use strict';

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var _require = require('buffer'),
    Buffer = _require.Buffer;

var _require2 = require('util'),
    inspect = _require2.inspect;

var custom = inspect && inspect.custom || 'inspect';

function copyBuffer(src, target, offset) {
  Buffer.prototype.copy.call(src, target, offset);
}

module.exports =
/*#__PURE__*/
function () {
  function BufferList() {
    _classCallCheck(this, BufferList);

    this.head = null;
    this.tail = null;
    this.length = 0;
  }

  _createClass(BufferList, [{
    key: "push",
    value: function push(v) {
      var entry = {
        data: v,
        next: null
      };
      if (this.length > 0) this.tail.next = entry;else this.head = entry;
      this.tail = entry;
      ++this.length;
    }
  }, {
    key: "unshift",
    value: function unshift(v) {
      var entry = {
        data: v,
        next: this.head
      };
      if (this.length === 0) this.tail = entry;
      this.head = entry;
      ++this.length;
    }
  }, {
    key: "shift",
    value: function shift() {
      if (this.length === 0) return;
      var ret = this.head.data;
      if (this.length === 1) this.head = this.tail = null;else this.head = this.head.next;
      --this.length;
      return ret;
    }
  }, {
    key: "clear",
    value: function clear() {
      this.head = this.tail = null;
      this.length = 0;
    }
  }, {
    key: "join",
    value: function join(s) {
      if (this.length === 0) return '';
      var p = this.head;
      var ret = '' + p.data;

      while (p = p.next) {
        ret += s + p.data;
      }

      return ret;
    }
  }, {
    key: "concat",
    value: function concat(n) {
      if (this.length === 0) return Buffer.alloc(0);
      var ret = Buffer.allocUnsafe(n >>> 0);
      var p = this.head;
      var i = 0;

      while (p) {
        copyBuffer(p.data, ret, i);
        i += p.data.length;
        p = p.next;
      }

      return ret;
    } // Consumes a specified amount of bytes or characters from the buffered data.

  }, {
    key: "consume",
    value: function consume(n, hasStrings) {
      var ret;

      if (n < this.head.data.length) {
        // `slice` is the same for buffers and strings.
        ret = this.head.data.slice(0, n);
        this.head.data = this.head.data.slice(n);
      } else if (n === this.head.data.length) {
        // First chunk is a perfect match.
        ret = this.shift();
      } else {
        // Result spans more than one buffer.
        ret = hasStrings ? this._getString(n) : this._getBuffer(n);
      }

      return ret;
    }
  }, {
    key: "first",
    value: function first() {
      return this.head.data;
    } // Consumes a specified amount of characters from the buffered data.

  }, {
    key: "_getString",
    value: function _getString(n) {
      var p = this.head;
      var c = 1;
      var ret = p.data;
      n -= ret.length;

      while (p = p.next) {
        var str = p.data;
        var nb = n > str.length ? str.length : n;
        if (nb === str.length) ret += str;else ret += str.slice(0, n);
        n -= nb;

        if (n === 0) {
          if (nb === str.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = str.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Consumes a specified amount of bytes from the buffered data.

  }, {
    key: "_getBuffer",
    value: function _getBuffer(n) {
      var ret = Buffer.allocUnsafe(n);
      var p = this.head;
      var c = 1;
      p.data.copy(ret);
      n -= p.data.length;

      while (p = p.next) {
        var buf = p.data;
        var nb = n > buf.length ? buf.length : n;
        buf.copy(ret, ret.length - n, 0, nb);
        n -= nb;

        if (n === 0) {
          if (nb === buf.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = buf.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Make sure the linked list only shows the minimal necessary information.

  }, {
    key: custom,
    value: function value(_, options) {
      return inspect(this, _objectSpread({}, options, {
        // Only inspect one level.
        depth: 0,
        // It should not recurse.
        customInspect: false
      }));
    }
  }]);

  return BufferList;
}();
},{"buffer":16,"util":8}],65:[function(require,module,exports){
(function (process){(function (){
'use strict'; // undocumented cb() API, needed for core, not for public API

function destroy(err, cb) {
  var _this = this;

  var readableDestroyed = this._readableState && this._readableState.destroyed;
  var writableDestroyed = this._writableState && this._writableState.destroyed;

  if (readableDestroyed || writableDestroyed) {
    if (cb) {
      cb(err);
    } else if (err) {
      if (!this._writableState) {
        process.nextTick(emitErrorNT, this, err);
      } else if (!this._writableState.errorEmitted) {
        this._writableState.errorEmitted = true;
        process.nextTick(emitErrorNT, this, err);
      }
    }

    return this;
  } // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks


  if (this._readableState) {
    this._readableState.destroyed = true;
  } // if this is a duplex stream mark the writable part as destroyed as well


  if (this._writableState) {
    this._writableState.destroyed = true;
  }

  this._destroy(err || null, function (err) {
    if (!cb && err) {
      if (!_this._writableState) {
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else if (!_this._writableState.errorEmitted) {
        _this._writableState.errorEmitted = true;
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else {
        process.nextTick(emitCloseNT, _this);
      }
    } else if (cb) {
      process.nextTick(emitCloseNT, _this);
      cb(err);
    } else {
      process.nextTick(emitCloseNT, _this);
    }
  });

  return this;
}

function emitErrorAndCloseNT(self, err) {
  emitErrorNT(self, err);
  emitCloseNT(self);
}

function emitCloseNT(self) {
  if (self._writableState && !self._writableState.emitClose) return;
  if (self._readableState && !self._readableState.emitClose) return;
  self.emit('close');
}

function undestroy() {
  if (this._readableState) {
    this._readableState.destroyed = false;
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
  }

  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finalCalled = false;
    this._writableState.prefinished = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
  }
}

function emitErrorNT(self, err) {
  self.emit('error', err);
}

function errorOrDestroy(stream, err) {
  // We have tests that rely on errors being emitted
  // in the same tick, so changing this is semver major.
  // For now when you opt-in to autoDestroy we allow
  // the error to be emitted nextTick. In a future
  // semver major update we should change the default to this.
  var rState = stream._readableState;
  var wState = stream._writableState;
  if (rState && rState.autoDestroy || wState && wState.autoDestroy) stream.destroy(err);else stream.emit('error', err);
}

module.exports = {
  destroy: destroy,
  undestroy: undestroy,
  errorOrDestroy: errorOrDestroy
};
}).call(this)}).call(this,require('_process'))

},{"_process":30}],66:[function(require,module,exports){
// Ported from https://github.com/mafintosh/end-of-stream with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var ERR_STREAM_PREMATURE_CLOSE = require('../../../errors').codes.ERR_STREAM_PREMATURE_CLOSE;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    callback.apply(this, args);
  };
}

function noop() {}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function eos(stream, opts, callback) {
  if (typeof opts === 'function') return eos(stream, null, opts);
  if (!opts) opts = {};
  callback = once(callback || noop);
  var readable = opts.readable || opts.readable !== false && stream.readable;
  var writable = opts.writable || opts.writable !== false && stream.writable;

  var onlegacyfinish = function onlegacyfinish() {
    if (!stream.writable) onfinish();
  };

  var writableEnded = stream._writableState && stream._writableState.finished;

  var onfinish = function onfinish() {
    writable = false;
    writableEnded = true;
    if (!readable) callback.call(stream);
  };

  var readableEnded = stream._readableState && stream._readableState.endEmitted;

  var onend = function onend() {
    readable = false;
    readableEnded = true;
    if (!writable) callback.call(stream);
  };

  var onerror = function onerror(err) {
    callback.call(stream, err);
  };

  var onclose = function onclose() {
    var err;

    if (readable && !readableEnded) {
      if (!stream._readableState || !stream._readableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }

    if (writable && !writableEnded) {
      if (!stream._writableState || !stream._writableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }
  };

  var onrequest = function onrequest() {
    stream.req.on('finish', onfinish);
  };

  if (isRequest(stream)) {
    stream.on('complete', onfinish);
    stream.on('abort', onclose);
    if (stream.req) onrequest();else stream.on('request', onrequest);
  } else if (writable && !stream._writableState) {
    // legacy streams
    stream.on('end', onlegacyfinish);
    stream.on('close', onlegacyfinish);
  }

  stream.on('end', onend);
  stream.on('finish', onfinish);
  if (opts.error !== false) stream.on('error', onerror);
  stream.on('close', onclose);
  return function () {
    stream.removeListener('complete', onfinish);
    stream.removeListener('abort', onclose);
    stream.removeListener('request', onrequest);
    if (stream.req) stream.req.removeListener('finish', onfinish);
    stream.removeListener('end', onlegacyfinish);
    stream.removeListener('close', onlegacyfinish);
    stream.removeListener('finish', onfinish);
    stream.removeListener('end', onend);
    stream.removeListener('error', onerror);
    stream.removeListener('close', onclose);
  };
}

module.exports = eos;
},{"../../../errors":57}],67:[function(require,module,exports){
module.exports = function () {
  throw new Error('Readable.from is not available in the browser')
};

},{}],68:[function(require,module,exports){
// Ported from https://github.com/mafintosh/pump with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var eos;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    callback.apply(void 0, arguments);
  };
}

var _require$codes = require('../../../errors').codes,
    ERR_MISSING_ARGS = _require$codes.ERR_MISSING_ARGS,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED;

function noop(err) {
  // Rethrow the error if it exists to avoid swallowing it
  if (err) throw err;
}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function destroyer(stream, reading, writing, callback) {
  callback = once(callback);
  var closed = false;
  stream.on('close', function () {
    closed = true;
  });
  if (eos === undefined) eos = require('./end-of-stream');
  eos(stream, {
    readable: reading,
    writable: writing
  }, function (err) {
    if (err) return callback(err);
    closed = true;
    callback();
  });
  var destroyed = false;
  return function (err) {
    if (closed) return;
    if (destroyed) return;
    destroyed = true; // request.destroy just do .end - .abort is what we want

    if (isRequest(stream)) return stream.abort();
    if (typeof stream.destroy === 'function') return stream.destroy();
    callback(err || new ERR_STREAM_DESTROYED('pipe'));
  };
}

function call(fn) {
  fn();
}

function pipe(from, to) {
  return from.pipe(to);
}

function popCallback(streams) {
  if (!streams.length) return noop;
  if (typeof streams[streams.length - 1] !== 'function') return noop;
  return streams.pop();
}

function pipeline() {
  for (var _len = arguments.length, streams = new Array(_len), _key = 0; _key < _len; _key++) {
    streams[_key] = arguments[_key];
  }

  var callback = popCallback(streams);
  if (Array.isArray(streams[0])) streams = streams[0];

  if (streams.length < 2) {
    throw new ERR_MISSING_ARGS('streams');
  }

  var error;
  var destroys = streams.map(function (stream, i) {
    var reading = i < streams.length - 1;
    var writing = i > 0;
    return destroyer(stream, reading, writing, function (err) {
      if (!error) error = err;
      if (err) destroys.forEach(call);
      if (reading) return;
      destroys.forEach(call);
      callback(error);
    });
  });
  return streams.reduce(pipe);
}

module.exports = pipeline;
},{"../../../errors":57,"./end-of-stream":66}],69:[function(require,module,exports){
'use strict';

var ERR_INVALID_OPT_VALUE = require('../../../errors').codes.ERR_INVALID_OPT_VALUE;

function highWaterMarkFrom(options, isDuplex, duplexKey) {
  return options.highWaterMark != null ? options.highWaterMark : isDuplex ? options[duplexKey] : null;
}

function getHighWaterMark(state, options, duplexKey, isDuplex) {
  var hwm = highWaterMarkFrom(options, isDuplex, duplexKey);

  if (hwm != null) {
    if (!(isFinite(hwm) && Math.floor(hwm) === hwm) || hwm < 0) {
      var name = isDuplex ? duplexKey : 'highWaterMark';
      throw new ERR_INVALID_OPT_VALUE(name, hwm);
    }

    return Math.floor(hwm);
  } // Default value


  return state.objectMode ? 16 : 16 * 1024;
}

module.exports = {
  getHighWaterMark: getHighWaterMark
};
},{"../../../errors":57}],70:[function(require,module,exports){
module.exports = require('events').EventEmitter;

},{"events":14}],71:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

/*<replacement>*/

var Buffer = require('safe-buffer').Buffer;
/*</replacement>*/

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte. If an invalid byte is detected, -2 is returned.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return byte >> 6 === 0x02 ? -1 : -2;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// a single UTF-8 replacement character ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd';
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd';
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character is added when ending on a partial
// character.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd';
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}
},{"safe-buffer":55}],72:[function(require,module,exports){
(function (setImmediate,clearImmediate){(function (){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
}).call(this)}).call(this,require("timers").setImmediate,require("timers").clearImmediate)

},{"process/browser.js":50,"timers":72}],73:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var punycode = require('punycode');
var util = require('./util');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,

    // Special case for a simple path URL
    simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
    delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],

    // RFC 2396: characters not allowed for various reasons.
    unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
    autoEscape = ['\''].concat(unwise),
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
    nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,
    // protocols that can allow "unsafe" and "unwise" chars.
    unsafeProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that never have a hostname.
    hostlessProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that always contain a // bit.
    slashedProtocol = {
      'http': true,
      'https': true,
      'ftp': true,
      'gopher': true,
      'file': true,
      'http:': true,
      'https:': true,
      'ftp:': true,
      'gopher:': true,
      'file:': true
    },
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && util.isObject(url) && url instanceof Url) return url;

  var u = new Url;
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
  if (!util.isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
  }

  // Copy chrome, IE, opera backslash-handling behavior.
  // Back slashes before the query string get converted to forward slashes
  // See: https://code.google.com/p/chromium/issues/detail?id=25916
  var queryIndex = url.indexOf('?'),
      splitter =
          (queryIndex !== -1 && queryIndex < url.indexOf('#')) ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, '/');
  url = uSplit.join(splitter);

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  if (!slashesDenoteHost && url.split('#').length === 1) {
    // Try fast path regexp
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      this.path = rest;
      this.href = rest;
      this.pathname = simplePath[1];
      if (simplePath[2]) {
        this.search = simplePath[2];
        if (parseQueryString) {
          this.query = querystring.parse(this.search.substr(1));
        } else {
          this.query = this.search.substr(1);
        }
      } else if (parseQueryString) {
        this.search = '';
        this.query = {};
      }
      return this;
    }
  }

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1)
      hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' &&
        this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a punycoded representation of "domain".
      // It only converts parts of the domain name that
      // have non-ASCII characters, i.e. it doesn't matter if
      // you call it with a domain that already is ASCII-only.
      this.hostname = punycode.toASCII(this.hostname);
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      if (rest.indexOf(ae) === -1)
        continue;
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }


  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] &&
      this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (util.isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function() {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ?
        this.hostname :
        '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query &&
      util.isObject(this.query) &&
      Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || (query && ('?' + query)) || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes ||
      (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function(match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function(relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function(relative) {
  if (util.isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  var tkeys = Object.keys(this);
  for (var tk = 0; tk < tkeys.length; tk++) {
    var tkey = tkeys[tk];
    result[tkey] = this[tkey];
  }

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    var rkeys = Object.keys(relative);
    for (var rk = 0; rk < rkeys.length; rk++) {
      var rkey = rkeys[rk];
      if (rkey !== 'protocol')
        result[rkey] = relative[rkey];
    }

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] &&
        result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      var keys = Object.keys(relative);
      for (var v = 0; v < keys.length; v++) {
        var k = keys[v];
        result[k] = relative[k];
      }
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift()));
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
      isRelAbs = (
          relative.host ||
          relative.pathname && relative.pathname.charAt(0) === '/'
      ),
      mustEndAbs = (isRelAbs || isSourceAbs ||
                    (result.host && relative.pathname)),
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;
      else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;
        else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = (relative.host || relative.host === '') ?
                  relative.host : result.host;
    result.hostname = (relative.hostname || relative.hostname === '') ?
                      relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!util.isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especially happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ?
                       result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') +
                    (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (
      (result.host || relative.host || srcPath.length > 1) &&
      (last === '.' || last === '..') || last === '');

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last === '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' &&
      (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' ||
      (srcPath[0] && srcPath[0].charAt(0) === '/');

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' :
                                    srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especially happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ?
                     result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || (result.host && srcPath.length);

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') +
                  (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function() {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

},{"./util":74,"punycode":51,"querystring":54}],74:[function(require,module,exports){
'use strict';

module.exports = {
  isString: function(arg) {
    return typeof(arg) === 'string';
  },
  isObject: function(arg) {
    return typeof(arg) === 'object' && arg !== null;
  },
  isNull: function(arg) {
    return arg === null;
  },
  isNullOrUndefined: function(arg) {
    return arg == null;
  }
};

},{}],75:[function(require,module,exports){
(function (global){(function (){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],76:[function(require,module,exports){
arguments[4][4][0].apply(exports,arguments)
},{"dup":4}],77:[function(require,module,exports){
// Currently in sync with Node.js lib/internal/util/types.js
// https://github.com/nodejs/node/commit/112cc7c27551254aa2b17098fb774867f05ed0d9

'use strict';

var isArgumentsObject = require('is-arguments');
var isGeneratorFunction = require('is-generator-function');
var whichTypedArray = require('which-typed-array');
var isTypedArray = require('is-typed-array');

function uncurryThis(f) {
  return f.call.bind(f);
}

var BigIntSupported = typeof BigInt !== 'undefined';
var SymbolSupported = typeof Symbol !== 'undefined';

var ObjectToString = uncurryThis(Object.prototype.toString);

var numberValue = uncurryThis(Number.prototype.valueOf);
var stringValue = uncurryThis(String.prototype.valueOf);
var booleanValue = uncurryThis(Boolean.prototype.valueOf);

if (BigIntSupported) {
  var bigIntValue = uncurryThis(BigInt.prototype.valueOf);
}

if (SymbolSupported) {
  var symbolValue = uncurryThis(Symbol.prototype.valueOf);
}

function checkBoxedPrimitive(value, prototypeValueOf) {
  if (typeof value !== 'object') {
    return false;
  }
  try {
    prototypeValueOf(value);
    return true;
  } catch(e) {
    return false;
  }
}

exports.isArgumentsObject = isArgumentsObject;
exports.isGeneratorFunction = isGeneratorFunction;
exports.isTypedArray = isTypedArray;

// Taken from here and modified for better browser support
// https://github.com/sindresorhus/p-is-promise/blob/cda35a513bda03f977ad5cde3a079d237e82d7ef/index.js
function isPromise(input) {
	return (
		(
			typeof Promise !== 'undefined' &&
			input instanceof Promise
		) ||
		(
			input !== null &&
			typeof input === 'object' &&
			typeof input.then === 'function' &&
			typeof input.catch === 'function'
		)
	);
}
exports.isPromise = isPromise;

function isArrayBufferView(value) {
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView) {
    return ArrayBuffer.isView(value);
  }

  return (
    isTypedArray(value) ||
    isDataView(value)
  );
}
exports.isArrayBufferView = isArrayBufferView;


function isUint8Array(value) {
  return whichTypedArray(value) === 'Uint8Array';
}
exports.isUint8Array = isUint8Array;

function isUint8ClampedArray(value) {
  return whichTypedArray(value) === 'Uint8ClampedArray';
}
exports.isUint8ClampedArray = isUint8ClampedArray;

function isUint16Array(value) {
  return whichTypedArray(value) === 'Uint16Array';
}
exports.isUint16Array = isUint16Array;

function isUint32Array(value) {
  return whichTypedArray(value) === 'Uint32Array';
}
exports.isUint32Array = isUint32Array;

function isInt8Array(value) {
  return whichTypedArray(value) === 'Int8Array';
}
exports.isInt8Array = isInt8Array;

function isInt16Array(value) {
  return whichTypedArray(value) === 'Int16Array';
}
exports.isInt16Array = isInt16Array;

function isInt32Array(value) {
  return whichTypedArray(value) === 'Int32Array';
}
exports.isInt32Array = isInt32Array;

function isFloat32Array(value) {
  return whichTypedArray(value) === 'Float32Array';
}
exports.isFloat32Array = isFloat32Array;

function isFloat64Array(value) {
  return whichTypedArray(value) === 'Float64Array';
}
exports.isFloat64Array = isFloat64Array;

function isBigInt64Array(value) {
  return whichTypedArray(value) === 'BigInt64Array';
}
exports.isBigInt64Array = isBigInt64Array;

function isBigUint64Array(value) {
  return whichTypedArray(value) === 'BigUint64Array';
}
exports.isBigUint64Array = isBigUint64Array;

function isMapToString(value) {
  return ObjectToString(value) === '[object Map]';
}
isMapToString.working = (
  typeof Map !== 'undefined' &&
  isMapToString(new Map())
);

function isMap(value) {
  if (typeof Map === 'undefined') {
    return false;
  }

  return isMapToString.working
    ? isMapToString(value)
    : value instanceof Map;
}
exports.isMap = isMap;

function isSetToString(value) {
  return ObjectToString(value) === '[object Set]';
}
isSetToString.working = (
  typeof Set !== 'undefined' &&
  isSetToString(new Set())
);
function isSet(value) {
  if (typeof Set === 'undefined') {
    return false;
  }

  return isSetToString.working
    ? isSetToString(value)
    : value instanceof Set;
}
exports.isSet = isSet;

function isWeakMapToString(value) {
  return ObjectToString(value) === '[object WeakMap]';
}
isWeakMapToString.working = (
  typeof WeakMap !== 'undefined' &&
  isWeakMapToString(new WeakMap())
);
function isWeakMap(value) {
  if (typeof WeakMap === 'undefined') {
    return false;
  }

  return isWeakMapToString.working
    ? isWeakMapToString(value)
    : value instanceof WeakMap;
}
exports.isWeakMap = isWeakMap;

function isWeakSetToString(value) {
  return ObjectToString(value) === '[object WeakSet]';
}
isWeakSetToString.working = (
  typeof WeakSet !== 'undefined' &&
  isWeakSetToString(new WeakSet())
);
function isWeakSet(value) {
  return isWeakSetToString(value);
}
exports.isWeakSet = isWeakSet;

function isArrayBufferToString(value) {
  return ObjectToString(value) === '[object ArrayBuffer]';
}
isArrayBufferToString.working = (
  typeof ArrayBuffer !== 'undefined' &&
  isArrayBufferToString(new ArrayBuffer())
);
function isArrayBuffer(value) {
  if (typeof ArrayBuffer === 'undefined') {
    return false;
  }

  return isArrayBufferToString.working
    ? isArrayBufferToString(value)
    : value instanceof ArrayBuffer;
}
exports.isArrayBuffer = isArrayBuffer;

function isDataViewToString(value) {
  return ObjectToString(value) === '[object DataView]';
}
isDataViewToString.working = (
  typeof ArrayBuffer !== 'undefined' &&
  typeof DataView !== 'undefined' &&
  isDataViewToString(new DataView(new ArrayBuffer(1), 0, 1))
);
function isDataView(value) {
  if (typeof DataView === 'undefined') {
    return false;
  }

  return isDataViewToString.working
    ? isDataViewToString(value)
    : value instanceof DataView;
}
exports.isDataView = isDataView;

function isSharedArrayBufferToString(value) {
  return ObjectToString(value) === '[object SharedArrayBuffer]';
}
isSharedArrayBufferToString.working = (
  typeof SharedArrayBuffer !== 'undefined' &&
  isSharedArrayBufferToString(new SharedArrayBuffer())
);
function isSharedArrayBuffer(value) {
  if (typeof SharedArrayBuffer === 'undefined') {
    return false;
  }

  return isSharedArrayBufferToString.working
    ? isSharedArrayBufferToString(value)
    : value instanceof SharedArrayBuffer;
}
exports.isSharedArrayBuffer = isSharedArrayBuffer;

function isAsyncFunction(value) {
  return ObjectToString(value) === '[object AsyncFunction]';
}
exports.isAsyncFunction = isAsyncFunction;

function isMapIterator(value) {
  return ObjectToString(value) === '[object Map Iterator]';
}
exports.isMapIterator = isMapIterator;

function isSetIterator(value) {
  return ObjectToString(value) === '[object Set Iterator]';
}
exports.isSetIterator = isSetIterator;

function isGeneratorObject(value) {
  return ObjectToString(value) === '[object Generator]';
}
exports.isGeneratorObject = isGeneratorObject;

function isWebAssemblyCompiledModule(value) {
  return ObjectToString(value) === '[object WebAssembly.Module]';
}
exports.isWebAssemblyCompiledModule = isWebAssemblyCompiledModule;

function isNumberObject(value) {
  return checkBoxedPrimitive(value, numberValue);
}
exports.isNumberObject = isNumberObject;

function isStringObject(value) {
  return checkBoxedPrimitive(value, stringValue);
}
exports.isStringObject = isStringObject;

function isBooleanObject(value) {
  return checkBoxedPrimitive(value, booleanValue);
}
exports.isBooleanObject = isBooleanObject;

function isBigIntObject(value) {
  return BigIntSupported && checkBoxedPrimitive(value, bigIntValue);
}
exports.isBigIntObject = isBigIntObject;

function isSymbolObject(value) {
  return SymbolSupported && checkBoxedPrimitive(value, symbolValue);
}
exports.isSymbolObject = isSymbolObject;

function isBoxedPrimitive(value) {
  return (
    isNumberObject(value) ||
    isStringObject(value) ||
    isBooleanObject(value) ||
    isBigIntObject(value) ||
    isSymbolObject(value)
  );
}
exports.isBoxedPrimitive = isBoxedPrimitive;

function isAnyArrayBuffer(value) {
  return typeof Uint8Array !== 'undefined' && (
    isArrayBuffer(value) ||
    isSharedArrayBuffer(value)
  );
}
exports.isAnyArrayBuffer = isAnyArrayBuffer;

['isProxy', 'isExternal', 'isModuleNamespaceObject'].forEach(function(method) {
  Object.defineProperty(exports, method, {
    enumerable: false,
    value: function() {
      throw new Error(method + ' is not supported in userland');
    }
  });
});

},{"is-arguments":43,"is-generator-function":44,"is-typed-array":45,"which-typed-array":79}],78:[function(require,module,exports){
(function (process){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors ||
  function getOwnPropertyDescriptors(obj) {
    var keys = Object.keys(obj);
    var descriptors = {};
    for (var i = 0; i < keys.length; i++) {
      descriptors[keys[i]] = Object.getOwnPropertyDescriptor(obj, keys[i]);
    }
    return descriptors;
  };

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  if (typeof process !== 'undefined' && process.noDeprecation === true) {
    return fn;
  }

  // Allow for deprecating things in the process of starting up.
  if (typeof process === 'undefined') {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnvRegex = /^$/;

if (process.env.NODE_DEBUG) {
  var debugEnv = process.env.NODE_DEBUG;
  debugEnv = debugEnv.replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/,/g, '$|^')
    .toUpperCase();
  debugEnvRegex = new RegExp('^' + debugEnv + '$', 'i');
}
exports.debuglog = function(set) {
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (debugEnvRegex.test(set)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
exports.types = require('./support/types');

function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;
exports.types.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;
exports.types.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;
exports.types.isNativeError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

var kCustomPromisifiedSymbol = typeof Symbol !== 'undefined' ? Symbol('util.promisify.custom') : undefined;

exports.promisify = function promisify(original) {
  if (typeof original !== 'function')
    throw new TypeError('The "original" argument must be of type Function');

  if (kCustomPromisifiedSymbol && original[kCustomPromisifiedSymbol]) {
    var fn = original[kCustomPromisifiedSymbol];
    if (typeof fn !== 'function') {
      throw new TypeError('The "util.promisify.custom" argument must be of type Function');
    }
    Object.defineProperty(fn, kCustomPromisifiedSymbol, {
      value: fn, enumerable: false, writable: false, configurable: true
    });
    return fn;
  }

  function fn() {
    var promiseResolve, promiseReject;
    var promise = new Promise(function (resolve, reject) {
      promiseResolve = resolve;
      promiseReject = reject;
    });

    var args = [];
    for (var i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }
    args.push(function (err, value) {
      if (err) {
        promiseReject(err);
      } else {
        promiseResolve(value);
      }
    });

    try {
      original.apply(this, args);
    } catch (err) {
      promiseReject(err);
    }

    return promise;
  }

  Object.setPrototypeOf(fn, Object.getPrototypeOf(original));

  if (kCustomPromisifiedSymbol) Object.defineProperty(fn, kCustomPromisifiedSymbol, {
    value: fn, enumerable: false, writable: false, configurable: true
  });
  return Object.defineProperties(
    fn,
    getOwnPropertyDescriptors(original)
  );
}

exports.promisify.custom = kCustomPromisifiedSymbol

function callbackifyOnRejected(reason, cb) {
  // `!reason` guard inspired by bluebird (Ref: https://goo.gl/t5IS6M).
  // Because `null` is a special error value in callbacks which means "no error
  // occurred", we error-wrap so the callback consumer can distinguish between
  // "the promise rejected with null" or "the promise fulfilled with undefined".
  if (!reason) {
    var newReason = new Error('Promise was rejected with a falsy value');
    newReason.reason = reason;
    reason = newReason;
  }
  return cb(reason);
}

function callbackify(original) {
  if (typeof original !== 'function') {
    throw new TypeError('The "original" argument must be of type Function');
  }

  // We DO NOT return the promise as it gives the user a false sense that
  // the promise is actually somehow related to the callback's execution
  // and that the callback throwing will reject the promise.
  function callbackified() {
    var args = [];
    for (var i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }

    var maybeCb = args.pop();
    if (typeof maybeCb !== 'function') {
      throw new TypeError('The last argument must be of type Function');
    }
    var self = this;
    var cb = function() {
      return maybeCb.apply(self, arguments);
    };
    // In true node style we process the callback on `nextTick` with all the
    // implications (stack, `uncaughtException`, `async_hooks`)
    original.apply(this, args)
      .then(function(ret) { process.nextTick(cb.bind(null, null, ret)) },
            function(rej) { process.nextTick(callbackifyOnRejected.bind(null, rej, cb)) });
  }

  Object.setPrototypeOf(callbackified, Object.getPrototypeOf(original));
  Object.defineProperties(callbackified,
                          getOwnPropertyDescriptors(original));
  return callbackified;
}
exports.callbackify = callbackify;

}).call(this)}).call(this,require('_process'))

},{"./support/isBuffer":76,"./support/types":77,"_process":30,"inherits":41}],79:[function(require,module,exports){
(function (global){(function (){
'use strict';

var forEach = require('foreach');
var availableTypedArrays = require('available-typed-arrays');
var callBound = require('call-bind/callBound');

var $toString = callBound('Object.prototype.toString');
var hasSymbols = require('has-symbols')();
var hasToStringTag = hasSymbols && typeof Symbol.toStringTag === 'symbol';

var typedArrays = availableTypedArrays();

var $slice = callBound('String.prototype.slice');
var toStrTags = {};
var gOPD = require('es-abstract/helpers/getOwnPropertyDescriptor');
var getPrototypeOf = Object.getPrototypeOf; // require('getprototypeof');
if (hasToStringTag && gOPD && getPrototypeOf) {
	forEach(typedArrays, function (typedArray) {
		if (typeof global[typedArray] === 'function') {
			var arr = new global[typedArray]();
			if (!(Symbol.toStringTag in arr)) {
				throw new EvalError('this engine has support for Symbol.toStringTag, but ' + typedArray + ' does not have the property! Please report this.');
			}
			var proto = getPrototypeOf(arr);
			var descriptor = gOPD(proto, Symbol.toStringTag);
			if (!descriptor) {
				var superProto = getPrototypeOf(proto);
				descriptor = gOPD(superProto, Symbol.toStringTag);
			}
			toStrTags[typedArray] = descriptor.get;
		}
	});
}

var tryTypedArrays = function tryAllTypedArrays(value) {
	var foundName = false;
	forEach(toStrTags, function (getter, typedArray) {
		if (!foundName) {
			try {
				var name = getter.call(value);
				if (name === typedArray) {
					foundName = name;
				}
			} catch (e) {}
		}
	});
	return foundName;
};

var isTypedArray = require('is-typed-array');

module.exports = function whichTypedArray(value) {
	if (!isTypedArray(value)) { return false; }
	if (!hasToStringTag) { return $slice($toString(value), 8, -1); }
	return tryTypedArrays(value);
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"available-typed-arrays":6,"call-bind/callBound":10,"es-abstract/helpers/getOwnPropertyDescriptor":13,"foreach":15,"has-symbols":36,"is-typed-array":45}],80:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.clipboard = void 0;
const color_1 = require("../lib/color");
const libjava_1 = require("./lib/libjava");
var clipboard;
(function (clipboard) {
    clipboard.monitor = () => {
        // -- Sample Java
        //
        // ClipboardManager f = (ClipboardManager)getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
        // ClipData.Item i = f.getPrimaryClip().getItemAt(0);
        // Log.e("t", "?:" + i.getText());
        send(`${color_1.colors.yellowBright("Warning!")} This module is still broken. A pull request fixing it would be awesome!`);
        // https://developer.android.com/reference/android/content/Context.html#CLIPBOARD_SERVICE
        const CLIPBOARD_SERVICE = "clipboard";
        // a variable for clipboard text
        let data;
        return libjava_1.wrapJavaPerform(() => {
            const clipboardManager = Java.use("android.content.ClipboardManager");
            const context = libjava_1.getApplicationContext();
            const clipboardHandle = context.getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
            const cp = Java.cast(clipboardHandle, clipboardManager);
            setInterval(() => {
                const primaryClip = cp.getPrimaryClip();
                // Check if there is at least some data
                if (primaryClip == null || primaryClip.getItemCount() <= 0) {
                    return;
                }
                // If we have managed to get the primary clipboard and there are
                // items stored in it, process an update.
                const currentString = primaryClip.getItemAt(0).coerceToText(context).toString();
                // If the data is the same, just stop.
                if (data === currentString) {
                    return;
                }
                // Update the data with the new string and report back.
                data = currentString;
                send(`${color_1.colors.blackBright(`[pasteboard-monitor]`)} Data: ${color_1.colors.greenBright(data.toString())}`);
            }, 1000 * 5);
        });
    };
})(clipboard = exports.clipboard || (exports.clipboard = {}));

},{"../lib/color":117,"./lib/libjava":87}],81:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.androidfilesystem = void 0;
const fs = __importStar(require("fs"));
const helpers_1 = require("../lib/helpers");
const libjava_1 = require("./lib/libjava");
var androidfilesystem;
(function (androidfilesystem) {
    androidfilesystem.exists = (path) => {
        // -- Sample Java
        //
        // File path = new File(".");
        // Boolean e = path.exists();
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const currentFile = file.$new(path);
            return currentFile.exists();
        });
    };
    androidfilesystem.readable = (path) => {
        // -- Sample Java Code
        //
        // File d = new File(".");
        // d.canRead();
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const currentFile = file.$new(path);
            return currentFile.canRead();
        });
    };
    androidfilesystem.writable = (path) => {
        // -- Sample Java Code
        //
        // File d = new File(".");
        // d.canWrite();
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const currentFile = file.$new(path);
            return currentFile.canWrite();
        });
    };
    androidfilesystem.pathIsFile = (path) => {
        // -- Sample Java Code
        //
        // File d = new File(".");
        // d.isFile();
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const currentFile = file.$new(path);
            return currentFile.isFile();
        });
    };
    androidfilesystem.pwd = () => {
        // -- Sample Java
        //
        // getApplicationContext().getFilesDir().getAbsolutePath()
        return libjava_1.wrapJavaPerform(() => {
            const context = libjava_1.getApplicationContext();
            return context.getFilesDir().getAbsolutePath().toString();
        });
    };
    // heavy lifting is done in frida-fs here.
    androidfilesystem.readFile = (path) => {
        return fs.readFileSync(path);
    };
    // heavy lifting is done in frida-fs here.
    androidfilesystem.writeFile = (path, data) => {
        const writeStream = fs.createWriteStream(path);
        writeStream.on("error", (error) => {
            throw error;
        });
        writeStream.write(helpers_1.hexStringToBytes(data));
        writeStream.end();
    };
    androidfilesystem.deleteFile = (path) => {
        // -- Sample Java Code
        //
        // File d = new File(".");
        // d.delete();
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const currentFile = file.$new(path);
            return currentFile.delete();
        });
    };
    androidfilesystem.ls = (p) => {
        // -- Sample Java Code
        //
        // File d = new File(".");
        // File[] files = d.listFiles();
        // Log.e(getClass().getName(), "Files: " + files.length);
        // for (int i = 0; i < files.length; i++) {
        //     Log.e(getClass().getName(),
        //             files[i].getName() + ": " + files[i].canRead()
        //             + " " + files[i].lastModified()
        //             + " " + files[i].length()
        //     );
        // }
        return libjava_1.wrapJavaPerform(() => {
            const file = Java.use("java.io.File");
            const directory = file.$new(p);
            const response = {
                files: {},
                path: p,
                readable: directory.canRead(),
                writable: directory.canWrite(),
            };
            if (!response.readable) {
                return response;
            }
            // get a listing of the files in the directory
            const files = directory.listFiles();
            for (const f of files) {
                response.files[f.getName()] = {
                    attributes: {
                        isDirectory: f.isDirectory(),
                        isFile: f.isFile(),
                        isHidden: f.isHidden(),
                        lastModified: f.lastModified(),
                        size: f.length(),
                    },
                    fileName: f.getName(),
                    readable: f.canRead(),
                    writable: f.canWrite(),
                };
            }
            return response;
        });
    };
})(androidfilesystem = exports.androidfilesystem || (exports.androidfilesystem = {}));

},{"../lib/helpers":119,"./lib/libjava":87,"fs":18}],82:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.general = void 0;
const libjava_1 = require("./lib/libjava");
var general;
(function (general) {
    general.deoptimize = () => {
        return libjava_1.wrapJavaPerform(() => {
            Java.deoptimizeEverything();
        });
    };
})(general = exports.general || (exports.general = {}));

},{"./lib/libjava":87}],83:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.heap = void 0;
const color_1 = require("../lib/color");
const libjava_1 = require("./lib/libjava");
var heap;
(function (heap) {
    heap.handles = {};
    const getInstance = (hashcode) => {
        const matches = [];
        // Search for this handle, and push the results to matches
        Object.keys(heap.handles).forEach((clazz) => {
            heap.handles[clazz].filter((heapObject) => {
                if (heapObject.hashcode === hashcode) {
                    matches.push(heapObject);
                }
            });
        });
        if (matches.length > 1) {
            color_1.colors.log(`Found ${color_1.colors.redBright(matches.length.toString())} handles, this is probably a bug, please report it!`);
        }
        if (matches.length > 0) {
            libjava_1.wrapJavaPerform(() => {
                color_1.colors.log(`${color_1.colors.blackBright(`Handle ` + hashcode + ` is to class `)}
        ${color_1.colors.greenBright(matches[0].instance.$className)}`);
            });
            return matches[0].instance;
        }
        color_1.colors.log(`${color_1.colors.yellowBright(`Warning:`)} Could not find a known handle for ${hashcode}. ` +
            `Try searching class instances first.`);
        return null;
    };
    heap.getInstances = (clazz) => {
        return libjava_1.wrapJavaPerform(() => {
            heap.handles[clazz] = [];
            // tslint:disable:only-arrow-functions
            // tslint:disable:object-literal-shorthand
            // tslint:disable:no-empty
            Java.choose(clazz, {
                onComplete: function () {
                    color_1.colors.log(`Class instance enumeration complete for ${color_1.colors.green(clazz)}`);
                },
                onMatch: function (instance) {
                    heap.handles[clazz].push({
                        instance: instance,
                        hashcode: instance.hashCode(),
                    });
                },
            });
            // tslint:enable
            return heap.handles[clazz].map((h) => {
                return {
                    hashcode: h.hashcode,
                    classname: clazz,
                    tostring: h.instance.toString(),
                };
            });
        });
    };
    heap.methods = (handle) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazz = getInstance(handle);
            if (clazz == null) {
                return [];
            }
            return clazz.class.getDeclaredMethods().map((method) => {
                return method.toGenericString();
            });
        });
    };
    heap.execute = (handle, method, returnString = false) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazz = getInstance(handle);
            if (clazz == null) {
                return;
            }
            color_1.colors.log(`${color_1.colors.blackBright(`Executing method:`)} ${color_1.colors.greenBright(`${method}()`)}`);
            const returnValue = clazz[method]();
            if (returnString && returnValue) {
                return returnValue.toString();
            }
            return returnValue;
        });
    };
    heap.fields = (handle) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazz = getInstance(handle);
            if (clazz == null) {
                return;
            }
            return clazz.class.getDeclaredFields().map((field) => {
                const fieldName = field.getName();
                const fieldInstance = clazz.class.getDeclaredField(fieldName);
                fieldInstance.setAccessible(true);
                let fieldValue = fieldInstance.get(clazz);
                // Cast a string if possible
                if (fieldValue) {
                    fieldValue = fieldValue.toString();
                }
                return {
                    name: fieldName,
                    value: fieldValue,
                };
            });
        });
    };
    heap.evaluate = (handle, js) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazz = getInstance(handle);
            if (clazz == null) {
                return;
            }
            // tslint:disable-next-line:no-eval
            eval(js);
        });
    };
})(heap = exports.heap || (exports.heap = {}));

},{"../lib/color":117,"./lib/libjava":87}],84:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hooking = void 0;
const color_1 = require("../lib/color");
const jobs_1 = require("../lib/jobs");
const libjava_1 = require("./lib/libjava");
var hooking;
(function (hooking) {
    const splitClassMethod = (fqClazz) => {
        // split a fully qualified class name, assuming the last period denotes the method
        const methodSeperatorIndex = fqClazz.lastIndexOf(".");
        const clazz = fqClazz.substring(0, methodSeperatorIndex);
        const method = fqClazz.substring(methodSeperatorIndex + 1); // Increment by 1 to exclude the leading period
        return [clazz, method];
    };
    hooking.getClasses = () => {
        return libjava_1.wrapJavaPerform(() => {
            return Java.enumerateLoadedClassesSync();
        });
    };
    hooking.getClassLoaders = () => {
        return libjava_1.wrapJavaPerform(() => {
            let loaders = [];
            Java.enumerateClassLoaders({
                onMatch: function (l) {
                    if (l == null) {
                        return;
                    }
                    loaders.push(l.toString());
                },
                onComplete: function () { }
            });
            return loaders;
        });
    };
    hooking.getClassMethods = (className) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazz = Java.use(className);
            return clazz.class.getDeclaredMethods().map((method) => {
                return method.toGenericString();
            });
        });
    };
    hooking.watchClass = (clazz) => {
        return libjava_1.wrapJavaPerform(() => {
            const clazzInstance = Java.use(clazz);
            const uniqueMethods = clazzInstance.class.getDeclaredMethods().map((method) => {
                // perform a cleanup of the method. An example after toGenericString() would be:
                // public void android.widget.ScrollView.draw(android.graphics.Canvas) throws Exception
                // public final rx.c.b<java.lang.Throwable> com.apple.android.music.icloud.a.a(rx.c.b<java.lang.Throwable>)
                let m = method.toGenericString();
                // Remove generics from the method
                while (m.includes("<")) {
                    m = m.replace(/<.*?>/g, "");
                }
                // remove any "Throws" the method may have
                if (m.indexOf(" throws ") !== -1) {
                    m = m.substring(0, m.indexOf(" throws "));
                }
                // remove scope and return type declarations (aka: first two words)
                // remove the class name
                // remove the signature and return
                m = m.slice(m.lastIndexOf(" "));
                m = m.replace(` ${clazz}.`, "");
                return m.split("(")[0];
            }).filter((value, index, self) => {
                return self.indexOf(value) === index;
            });
            // start a new job container
            const job = {
                identifier: jobs_1.jobs.identifier(),
                implementations: [],
                type: `watch-class for: ${clazz}`,
            };
            uniqueMethods.forEach((method) => {
                clazzInstance[method].overloads.forEach((m) => {
                    // get the argument types for this overload
                    const calleeArgTypes = m.argumentTypes.map((arg) => arg.className);
                    send(`Hooking ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(method)}(${color_1.colors.red(calleeArgTypes.join(", "))})`);
                    // replace the implementation of this method
                    // tslint:disable-next-line:only-arrow-functions
                    m.implementation = function () {
                        send(color_1.colors.blackBright(`[${job.identifier}] `) +
                            `Called ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(m.methodName)}(${color_1.colors.red(calleeArgTypes.join(", "))})`);
                        // actually run the intended method
                        return m.apply(this, arguments);
                    };
                    // record this implementation override for the job
                    job.implementations.push(m);
                });
            });
            // record the job
            jobs_1.jobs.add(job);
        });
    };
    hooking.watchMethod = (fqClazz, filterOverload, dargs, dbt, dret) => {
        const [clazz, method] = splitClassMethod(fqClazz);
        send(`Attempting to watch class ${color_1.colors.green(clazz)} and method ${color_1.colors.green(method)}.`);
        if (filterOverload != null) {
            send(color_1.colors.blackBright(`Will filter for method overload with arguments:`) +
                ` ${color_1.colors.green(filterOverload)}`);
        }
        return libjava_1.wrapJavaPerform(() => {
            const throwable = Java.use("java.lang.Throwable");
            const targetClass = Java.use(clazz);
            // Ensure that the method exists on the class
            if (targetClass[method] === undefined) {
                send(`${color_1.colors.red("Error:")} Unable to find method ${color_1.colors.redBright(method)} in class ${color_1.colors.green(clazz)}`);
                return;
            }
            // start a new job container
            const job = {
                identifier: jobs_1.jobs.identifier(),
                implementations: [],
                type: `watch-method for: ${fqClazz}`,
            };
            targetClass[method].overloads.forEach((m) => {
                // get the argument types for this overload
                const calleeArgTypes = m.argumentTypes.map((arg) => arg.className);
                // check if we need to filter on a specific overload
                if (filterOverload != null && calleeArgTypes.join(",") !== filterOverload) {
                    return;
                }
                send(`Hooking ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(method)}(${color_1.colors.red(calleeArgTypes.join(", "))})`);
                // replace the implementation of this method
                // tslint:disable-next-line:only-arrow-functions
                m.implementation = function () {
                    send(color_1.colors.blackBright(`[${job.identifier}] `) +
                        `Called ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(m.methodName)}(${color_1.colors.red(calleeArgTypes.join(", "))})`);
                    // dump a backtrace
                    if (dbt) {
                        send(color_1.colors.blackBright(`[${job.identifier}] `) + "Backtrace:\n\t" +
                            throwable.$new().getStackTrace().map((traceElement) => traceElement.toString() + "\n\t").join(""));
                    }
                    // dump arguments
                    if (dargs && calleeArgTypes.length > 0) {
                        const argValues = [];
                        for (const h of arguments) {
                            argValues.push((h || "(none)").toString());
                        }
                        send(color_1.colors.blackBright(`[${job.identifier}] `) +
                            `Arguments ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(m.methodName)}(${color_1.colors.red(argValues.join(", "))})`);
                    }
                    // actually run the intended method
                    const retVal = m.apply(this, arguments);
                    // dump the return value
                    if (dret) {
                        const retValStr = (retVal || "(none)").toString();
                        send(color_1.colors.blackBright(`[${job.identifier}] `) + `Return Value: ${color_1.colors.red(retValStr)}`);
                    }
                    // also return the captured return value
                    return retVal;
                };
                // record this implementation override for the job
                job.implementations.push(m);
            });
            // register the job
            jobs_1.jobs.add(job);
        });
    };
    hooking.getCurrentActivity = () => {
        return libjava_1.wrapJavaPerform(() => {
            const activityThread = Java.use("android.app.ActivityThread");
            const activity = Java.use("android.app.Activity");
            const activityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
            const currentActivityThread = activityThread.currentActivityThread();
            const activityRecords = currentActivityThread.mActivities.value.values().toArray();
            let currentActivity;
            for (const i of activityRecords) {
                const activityRecord = Java.cast(i, activityClientRecord);
                if (!activityRecord.paused.value) {
                    currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activity);
                    break;
                }
            }
            if (currentActivity) {
                // Discover an active fragment
                const fm = currentActivity.getFragmentManager();
                const fragment = fm.findFragmentById(libjava_1.R("content_frame", "id"));
                return {
                    activity: currentActivity.$className,
                    fragment: fragment.$className,
                };
            }
            return {
                activity: null,
                fragment: null,
            };
        });
    };
    hooking.getActivities = () => {
        return libjava_1.wrapJavaPerform(() => {
            const packageManager = Java.use("android.content.pm.PackageManager");
            const GET_ACTIVITIES = packageManager.GET_ACTIVITIES.value;
            const context = libjava_1.getApplicationContext();
            return Array.prototype.concat(context.getPackageManager()
                .getPackageInfo(context.getPackageName(), GET_ACTIVITIES).activities.value.map((activityInfo) => {
                return activityInfo.name.value;
            }));
        });
    };
    hooking.getServices = () => {
        return libjava_1.wrapJavaPerform(() => {
            const activityThread = Java.use("android.app.ActivityThread");
            const arrayMap = Java.use("android.util.ArrayMap");
            const packageManager = Java.use("android.content.pm.PackageManager");
            const GET_SERVICES = packageManager.GET_SERVICES.value;
            const currentApplication = activityThread.currentApplication();
            // not using the helper as we need other variables too
            const context = currentApplication.getApplicationContext();
            let services = [];
            currentApplication.mLoadedApk.value.mServices.value.values().toArray().map((potentialServices) => {
                Java.cast(potentialServices, arrayMap).keySet().toArray().map((service) => {
                    services.push(service.$className);
                });
            });
            services = services.concat(context.getPackageManager()
                .getPackageInfo(context.getPackageName(), GET_SERVICES).services.value.map((activityInfo) => {
                return activityInfo.name.value;
            }));
            return services;
        });
    };
    hooking.getBroadcastReceivers = () => {
        return libjava_1.wrapJavaPerform(() => {
            const activityThread = Java.use("android.app.ActivityThread");
            const arrayMap = Java.use("android.util.ArrayMap");
            const packageManager = Java.use("android.content.pm.PackageManager");
            const GET_RECEIVERS = packageManager.GET_RECEIVERS.value;
            const currentApplication = activityThread.currentApplication();
            // not using the helper as we need other variables too
            const context = currentApplication.getApplicationContext();
            let receivers = [];
            currentApplication.mLoadedApk.value.mReceivers.value.values().toArray().map((potentialReceivers) => {
                Java.cast(potentialReceivers, arrayMap).keySet().toArray().map((receiver) => {
                    receivers.push(receiver.$className);
                });
            });
            receivers = receivers.concat(context.getPackageManager()
                .getPackageInfo(context.getPackageName(), GET_RECEIVERS).receivers.value.map((activityInfo) => {
                return activityInfo.name.value;
            }));
            return receivers;
        });
    };
    hooking.setReturnValue = (fqClazz, filterOverload, newRet) => {
        const [clazz, method] = splitClassMethod(fqClazz);
        send(`Attempting to modify return value for class ${color_1.colors.green(clazz)} and method ${color_1.colors.green(method)}.`);
        if (filterOverload != null) {
            send(color_1.colors.blackBright(`Will filter for method overload with arguments:`) +
                ` ${color_1.colors.green(filterOverload)}`);
        }
        return libjava_1.wrapJavaPerform(() => {
            const job = {
                identifier: jobs_1.jobs.identifier(),
                implementations: [],
                type: `set-return for: ${fqClazz}`,
            };
            const targetClazz = Java.use(clazz);
            targetClazz[method].overloads.forEach((m) => {
                // get the argument types for this method
                const calleeArgTypes = m.argumentTypes.map((arg) => arg.className);
                // check if we need to filter on a specific overload
                if (filterOverload != null && calleeArgTypes.join(",") !== filterOverload) {
                    return;
                }
                send(`Hooking ${color_1.colors.green(clazz)}.${color_1.colors.greenBright(method)}(${color_1.colors.red(calleeArgTypes.join(", "))})`);
                // tslint:disable-next-line:only-arrow-functions
                m.implementation = function () {
                    let retVal = m.apply(this, arguments);
                    // Override retval if needed
                    if (retVal !== newRet) {
                        send(color_1.colors.blackBright(`[${job.identifier}] `) + `Return value was not ${color_1.colors.red(newRet.toString())}, ` +
                            `setting to ${color_1.colors.green(newRet.toString())}.`);
                        // update the return value
                        retVal = newRet;
                    }
                    return retVal;
                };
                // record override
                job.implementations.push(m);
            });
            jobs_1.jobs.add(job);
        });
    };
})(hooking = exports.hooking || (exports.hooking = {}));

},{"../lib/color":117,"../lib/jobs":120,"./lib/libjava":87}],85:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.intent = void 0;
const color_1 = require("../lib/color");
const libjava_1 = require("./lib/libjava");
var intent;
(function (intent) {
    // https://developer.android.com/reference/android/content/Intent.html#FLAG_ACTIVITY_NEW_TASK
    const FLAG_ACTIVITY_NEW_TASK = 0x10000000;
    // starts an Android activity
    // This method does not yet allow for 'extra' data to be send along
    // with the intent.
    intent.startActivity = (activityClass) => {
        // -- Sample Java
        //
        // Intent intent = new Intent(this, DisplayMessageActivity.class);
        // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        //
        // startActivity(intent);
        return libjava_1.wrapJavaPerform(() => {
            const context = libjava_1.getApplicationContext();
            // Setup a new Intent
            const androidIntent = Java.use("android.content.Intent");
            // Get the Activity class's .class
            const newActivity = Java.use(activityClass).class;
            send(`Starting activity ${color_1.colors.green(activityClass)}...`);
            // Init and launch the intent
            const newIntent = androidIntent.$new(context, newActivity);
            newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(newIntent);
            send(color_1.colors.blackBright(`Activity successfully asked to start.`));
        });
    };
    // starts an Android service
    intent.startService = (serviceClass) => {
        // -- Sample Java
        //
        // Intent intent = new Intent(this, Service.class);
        // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        //
        // startService(intent);
        return libjava_1.wrapJavaPerform(() => {
            const context = libjava_1.getApplicationContext();
            // Setup a new Intent
            const androidIntent = Java.use("android.content.Intent");
            // Get the Activity class's .class
            const newService = Java.use(serviceClass).$className;
            send(`Starting service ${color_1.colors.green(serviceClass)}...`);
            // Init and launch the intent
            const newIntent = androidIntent.$new(context, newService);
            newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);
            context.startService(newIntent);
            send(color_1.colors.blackBright(`Service successfully asked to start.`));
        });
    };
})(intent = exports.intent || (exports.intent = {}));

},{"../lib/color":117,"./lib/libjava":87}],86:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.keystore = void 0;
const color_1 = require("../lib/color");
const libjava_1 = require("./lib/libjava");
const jobs_1 = require("../lib/jobs");
var keystore;
(function (keystore) {
    // Dump entries in the Android Keystore, together with a flag
    // indicating if its a key or a certificate.
    //
    // Ref: https://developer.android.com/reference/java/security/KeyStore.html
    keystore.list = () => {
        // - Sample Java
        //
        // KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        // ks.load(null);
        // Enumeration<String> aliases = ks.aliases();
        //
        // while(aliases.hasMoreElements()) {
        //     Log.e("E", "Aliases = " + aliases.nextElement());
        // }
        return libjava_1.wrapJavaPerform(() => {
            const keyStore = Java.use("java.security.KeyStore");
            const entries = [];
            // Prepare the AndroidKeyStore keystore provider and load it.
            // Maybe at a later stage we should support adding other stores
            // like from file or JKS.
            const ks = keyStore.getInstance("AndroidKeyStore");
            ks.load(null, null);
            // Get the aliases and loop through them. The aliases() method
            // return an Enumeration<String> type.
            const aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                const alias = aliases.nextElement();
                entries.push({
                    alias: alias.toString(),
                    is_certificate: ks.isCertificateEntry(alias),
                    is_key: ks.isKeyEntry(alias),
                });
            }
            return entries;
        });
    };
    // Delete all entries in the Android Keystore
    //
    // Ref: https://developer.android.com/reference/java/security/KeyStore.html#deleteEntry(java.lang.String)
    keystore.clear = () => {
        // - Sample Java
        //
        // KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        // ks.load(null);
        // Enumeration<String> aliases = ks.aliases();
        //
        // while(aliases.hasMoreElements()) {
        //     ks.deleteEntry(aliases.nextElement());
        // }
        return libjava_1.wrapJavaPerform(() => {
            const keyStore = Java.use("java.security.KeyStore");
            // Prepare the AndroidKeyStore keystore provider and load it.
            // Maybe at a later stage we should support adding other stores
            // like from file or JKS.
            const ks = keyStore.getInstance("AndroidKeyStore");
            ks.load(null, null);
            // Get the aliases and loop through them. The aliases() method
            // return an Enumeration<String> type.
            const aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                ks.deleteEntry(aliases.nextElement());
            }
            send(color_1.colors.blackBright(`Keystore entries cleared`));
        });
    };
    // keystore watch methods
    // Watch for KeyStore.load();
    // TODO: Store the keystores themselves maybe?
    const keystoreLoad = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            const ks = Java.use("java.security.KeyStore");
            const ksLoad = ks.load.overload("java.io.InputStream", "[C");
            send(color_1.colors.blackBright(`[${ident}] Watching Keystore.load("java.io.InputStream", "[C")`));
            ksLoad.implementation = function (stream, password) {
                send(color_1.colors.blackBright(`[${ident}] `) +
                    `Keystore.load(${color_1.colors.greenBright(stream)}, ${color_1.colors.redBright(password || `null`)}) ` +
                    `called, loading a ${color_1.colors.cyanBright(this.getType())} keystore.`);
                return this.load(stream, password);
            };
        });
    };
    // Watch for Keystore.getKey().
    // TODO: Extract more information, like the key itself maybe?
    const keystoreGetKey = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            const ks = Java.use("java.security.KeyStore");
            const ksGetKey = ks.getKey.overload("java.lang.String", "[C");
            send(color_1.colors.blackBright(`[${ident}] Watching Keystore.getKey("java.lang.String", "[C")`));
            ksGetKey.implementation = function (alias, password) {
                const key = this.getKey(alias, password);
                send(color_1.colors.blackBright(`[${ident}] `) +
                    `Keystore.getKey(${color_1.colors.greenBright(alias)}, ${color_1.colors.redBright(password || `null`)}) ` +
                    `called, returning a ${color_1.colors.greenBright(key.$className)} instance.`);
                return key;
            };
            return ksGetKey;
        });
    };
    // Android KeyStore watcher.
    // Many, many more methods can be added here..
    keystore.watchKeystore = () => {
        const job = {
            identifier: jobs_1.jobs.identifier(),
            implementations: [],
            type: "android-keystore-watch",
        };
        job.implementations.push(keystoreLoad(job.identifier));
        job.implementations.push(keystoreGetKey(job.identifier));
        jobs_1.jobs.add(job);
    };
})(keystore = exports.keystore || (exports.keystore = {}));

},{"../lib/color":117,"../lib/jobs":120,"./lib/libjava":87}],87:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.R = exports.getApplicationContext = exports.wrapJavaPerform = void 0;
// all Java calls need to be wrapped in a Java.perform().
// this helper just wraps that into a Promise that the
// rpc export will sniff and resolve before returning
// the result when its ready.
const wrapJavaPerform = (fn) => {
    return new Promise((resolve, reject) => {
        Java.perform(() => {
            try {
                resolve(fn());
            }
            catch (e) {
                reject(e);
            }
        });
    });
};
exports.wrapJavaPerform = wrapJavaPerform;
const getApplicationContext = () => {
    const ActivityThread = Java.use("android.app.ActivityThread");
    const currentApplication = ActivityThread.currentApplication();
    return currentApplication.getApplicationContext();
};
exports.getApplicationContext = getApplicationContext;
// A helper method to access the R class for the app.
// Typical usage within an app would be something like:
//  R.id.content_frame.
//
// Using this method, the above example would be:
//  R("content_frame", "id")
const R = (name, type) => {
    const context = exports.getApplicationContext();
    // https://github.com/bitpay/android-sdk/issues/14#issue-202495610
    return context.getResources().getIdentifier(name, type, context.getPackageName());
};
exports.R = R;

},{}],88:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sslpinning = void 0;
const color_1 = require("../lib/color");
const helpers_1 = require("../lib/helpers");
const jobs_1 = require("../lib/jobs");
const libjava_1 = require("./lib/libjava");
var sslpinning;
(function (sslpinning) {
    // a simple flag to control if we should be quiet or not
    let quiet = false;
    const sslContextEmptyTrustManager = (ident) => {
        // -- Sample Java
        //
        // "Generic" TrustManager Example
        //
        // TrustManager[] trustAllCerts = new TrustManager[] {
        //     new X509TrustManager() {
        //         public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        //             return null;
        //         }
        //         public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
        //         public void checkServerTrusted(X509Certificate[] certs, String authType) {  }
        //     }
        // };
        // SSLContext sslcontect = SSLContext.getInstance("TLS");
        // sslcontect.init(null, trustAllCerts, null);
        return libjava_1.wrapJavaPerform(() => {
            const x509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const sSLContext = Java.use("javax.net.ssl.SSLContext");
            // Some 'anti-frida' detections will scan /proc/<pid>/maps.
            // Rename the tempFileNaming prefix as this could end up in maps.
            // https://github.com/frida/frida-java-bridge/blob/8b3790f7489ff5be7b19ddaccf5149d4e7738460/lib/class-factory.js#L94
            if (Java.classFactory.tempFileNaming.prefix == 'frida') {
                Java.classFactory.tempFileNaming.prefix = 'onetwothree';
            }
            // Implement a new TrustManager
            // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
            const TrustManager = Java.registerClass({
                implements: [x509TrustManager],
                methods: {
                    // tslint:disable-next-line:no-empty
                    checkClientTrusted(chain, authType) { },
                    // tslint:disable-next-line:no-empty
                    checkServerTrusted(chain, authType) { },
                    getAcceptedIssuers() {
                        return [];
                    },
                },
                name: "com.sensepost.test.TrustManager",
            });
            // Prepare the TrustManagers array to pass to SSLContext.init()
            const TrustManagers = [TrustManager.$new()];
            send(color_1.colors.blackBright("Custom TrustManager ready, overriding SSLContext.init()"));
            // Get a handle on the init() on the SSLContext class
            const SSLContextInit = sSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
            // Override the init method, specifying our new TrustManager
            SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                    color_1.colors.green(`SSLContext.init()`) +
                    `, overriding TrustManager with empty one.`);
                SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
            };
            return SSLContextInit;
        });
    };
    const okHttp3CertificatePinnerCheck = (ident) => {
        // -- Sample Java
        //
        // Example used to test this bypass.
        //
        // String hostname = "swapi.co";
        // CertificatePinner certificatePinner = new CertificatePinner.Builder()
        //         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        //         .build();
        // OkHttpClient client = new OkHttpClient.Builder()
        //         .certificatePinner(certificatePinner)
        //         .build();
        // Request request = new Request.Builder()
        //         .url("https://swapi.co/api/people/1")
        //         .build();
        // Response response = client.newCall(request).execute();
        return libjava_1.wrapJavaPerform(() => {
            try {
                const certificatePinner = Java.use("okhttp3.CertificatePinner");
                send(color_1.colors.blackBright(`Found okhttp3.CertificatePinner, overriding CertificatePinner.check()`));
                const CertificatePinnerCheck = certificatePinner.check.overload("java.lang.String", "java.util.List");
                // tslint:disable-next-line:only-arrow-functions
                CertificatePinnerCheck.implementation = function () {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                        color_1.colors.green(`OkHTTP 3.x CertificatePinner.check()`) +
                        `, not throwing an exception.`);
                };
                return CertificatePinnerCheck;
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    const okHttp3CertificatePinnerCheckOkHttp = (ident) => {
        // -- Sample Java
        //
        // Example used to test this bypass.
        //
        // String hostname = "swapi.co";
        // CertificatePinner certificatePinner = new CertificatePinner.Builder()
        //         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        //         .build();
        // OkHttpClient client = new OkHttpClient.Builder()
        //         .certificatePinner(certificatePinner)
        //         .build();
        // Request request = new Request.Builder()
        //         .url("https://swapi.co/api/people/1")
        //         .build();
        // Response response = client.newCall(request).execute();
        return libjava_1.wrapJavaPerform(() => {
            try {
                const certificatePinner = Java.use("okhttp3.CertificatePinner");
                send(color_1.colors.blackBright(`Found okhttp3.CertificatePinner, overriding CertificatePinner.check$okhttp()`));
                const CertificatePinnerCheckOkHttp = certificatePinner.check$okhttp.overload("java.lang.String", "u15");
                // tslint:disable-next-line:only-arrow-functions
                CertificatePinnerCheckOkHttp.implementation = function () {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called check$okhttp ` +
                        color_1.colors.green(`OkHTTP 3.x CertificatePinner.check$okhttp()`) +
                        `, not throwing an exception.`);
                };
                return CertificatePinnerCheckOkHttp;
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    const appceleratorTitaniumPinningTrustManager = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            try {
                const pinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
                send(color_1.colors.blackBright(`Found appcelerator.https.PinningTrustManager, ` +
                    `overriding PinningTrustManager.checkServerTrusted()`));
                const PinningTrustManagerCheckServerTrusted = pinningTrustManager.checkServerTrusted;
                // tslint:disable-next-line:only-arrow-functions
                PinningTrustManagerCheckServerTrusted.implementation = function () {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                        color_1.colors.green(`PinningTrustManager.checkServerTrusted()`) +
                        `, not throwing an exception.`);
                };
                return PinningTrustManagerCheckServerTrusted;
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    // Android 7+ TrustManagerImpl.verifyChain()
    // The work in the following NCC blog post was a great help for this hook!
    // hattip @AdriVillaB :)
    // https://www.nccgroup.trust/uk/about-us/newsroom-and-events/
    //  blogs/2017/november/bypassing-androids-network-security-configuration/
    //
    // More information: https://sensepost.com/blog/2018/tip-toeing-past-android-7s-network-security-configuration/
    const trustManagerImplVerifyChainCheck = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            try {
                const trustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                send(color_1.colors.blackBright(`Found com.android.org.conscrypt.TrustManagerImpl, ` +
                    `overriding TrustManagerImpl.verifyChain()`));
                // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/
                //  platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                const TrustManagerImplverifyChain = trustManagerImpl.verifyChain;
                // tslint:disable-next-line:only-arrow-functions
                TrustManagerImplverifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called (Android 7+) ` +
                        color_1.colors.green(`TrustManagerImpl.verifyChain()`) + `, not throwing an exception.`);
                    // Skip all the logic and just return the chain again :P
                    return untrustedChain;
                };
                return TrustManagerImplverifyChain;
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    // Android 7+ TrustManagerImpl.checkTrustedRecursive()
    // The work in the following method is based on:
    // https://techblog.mediaservice.net/2018/11/universal-android-ssl-pinning-bypass-2/
    const trustManagerImplCheckTrustedRecursiveCheck = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            try {
                const arrayList = Java.use("java.util.ArrayList");
                const trustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                send(color_1.colors.blackBright(`Found com.android.org.conscrypt.TrustManagerImpl, ` +
                    `overriding TrustManagerImpl.checkTrustedRecursive()`));
                // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/
                //  platform/java/org/conscrypt/TrustManagerImpl.java#391
                const TrustManagerImplcheckTrustedRecursive = trustManagerImpl.checkTrustedRecursive;
                // tslint:disable-next-line:only-arrow-functions
                TrustManagerImplcheckTrustedRecursive.implementation = function (certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called (Android 7+) ` +
                        color_1.colors.green(`TrustManagerImpl.checkTrustedRecursive()`) + `, not throwing an exception.`);
                    // Return an empty list
                    return arrayList.$new();
                };
                return TrustManagerImplcheckTrustedRecursive;
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    const phoneGapSSLCertificateChecker = (ident) => {
        return libjava_1.wrapJavaPerform(() => {
            try {
                const sslCertificateChecker = Java.use("nl.xservices.plugins.SSLCertificateChecker");
                send(color_1.colors.blackBright(`Found nl.xservices.plugins.SSLCertificateChecker, ` +
                    `overriding SSLCertificateChecker.execute()`));
                const SSLCertificateCheckerExecute = sslCertificateChecker.execute;
                SSLCertificateCheckerExecute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation =
                    // tslint:disable-next-line:only-arrow-functions
                    function (str, jsonArray, callBackContext) {
                        helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                            color_1.colors.green(`SSLCertificateChecker.execute()`) +
                            `, not throwing an exception.`);
                        callBackContext.success("CONNECTION_SECURE");
                        return true;
                    };
            }
            catch (err) {
                if (err.message.indexOf("ClassNotFoundException") === 0) {
                    throw new Error(err);
                }
            }
        });
    };
    // the main exported function to run all of the pinning bypass methods known
    sslpinning.disable = (q) => {
        if (q) {
            send(color_1.colors.yellow(`Quiet mode enabled. Not reporting invocations.`));
            quiet = true;
        }
        const job = {
            identifier: jobs_1.jobs.identifier(),
            implementations: [],
            type: "android-sslpinning-disable",
        };
        job.implementations.push(sslContextEmptyTrustManager(job.identifier));
        job.implementations.push(okHttp3CertificatePinnerCheck(job.identifier));
        job.implementations.push(okHttp3CertificatePinnerCheckOkHttp(job.identifier));
        job.implementations.push(appceleratorTitaniumPinningTrustManager(job.identifier));
        job.implementations.push(trustManagerImplVerifyChainCheck(job.identifier));
        job.implementations.push(trustManagerImplCheckTrustedRecursiveCheck(job.identifier));
        job.implementations.push(phoneGapSSLCertificateChecker(job.identifier));
        jobs_1.jobs.add(job);
    };
})(sslpinning = exports.sslpinning || (exports.sslpinning = {}));

},{"../lib/color":117,"../lib/helpers":119,"../lib/jobs":120,"./lib/libjava":87}],89:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.proxy = void 0;
const libjava_1 = require("./lib/libjava");
const color_1 = require("../lib/color");
var proxy;
(function (proxy) {
    proxy.set = (host, port) => {
        return libjava_1.wrapJavaPerform(() => {
            var proxyHost = host;
            var proxyPort = port;
            var System = Java.use("java.lang.System");
            if (System != undefined) {
                send(color_1.colors.green(`Setting properties for a proxy`));
                System.setProperty("http.proxyHost", proxyHost);
                System.setProperty("http.proxyPort", proxyPort);
                System.setProperty("https.proxyHost", proxyHost);
                System.setProperty("https.proxyPort", proxyPort);
                send(`${color_1.colors.green(`Proxy configured to ` + proxyHost + ` ` + proxyPort)}`);
            }
        });
    };
})(proxy = exports.proxy || (exports.proxy = {}));

},{"../lib/color":117,"./lib/libjava":87}],90:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.root = void 0;
const color_1 = require("../lib/color");
const jobs_1 = require("../lib/jobs");
const libjava_1 = require("./lib/libjava");
var root;
(function (root) {
    const commonPaths = [
        "/data/local/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/bin/failsafe/su",
        "/system/bin/su",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/sd/xbin/su",
        "/system/xbin/busybox",
        "/system/xbin/daemonsu",
        "/system/xbin/su",
    ];
    const testKeysCheck = (success, ident) => {
        return libjava_1.wrapJavaPerform(() => {
            const JavaString = Java.use("java.lang.String");
            JavaString.contains.implementation = function (name) {
                if (name !== "test-keys") {
                    return this.contains.call(this, name);
                }
                if (success) {
                    send(color_1.colors.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + color_1.colors.green(`successful`) + `.`);
                    return true;
                }
                else {
                    send(color_1.colors.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + color_1.colors.green(`failed`) + `.`);
                    return false;
                }
            };
            return JavaString;
        });
    };
    const execSuCheck = (success, ident) => {
        return libjava_1.wrapJavaPerform(() => {
            const JavaRuntime = Java.use("java.lang.Runtime");
            const iOException = Java.use("java.io.IOException");
            JavaRuntime.exec.overload("java.lang.String").implementation = function (command) {
                if (command.endsWith("su")) {
                    if (success) {
                        send(color_1.colors.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, allowing.`);
                        return this.apply(this, arguments);
                    }
                    else {
                        send(color_1.colors.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, throwing IOException.`);
                        throw iOException.$new("objection anti-root");
                    }
                }
                // call the original method
                return this.exec.overload("java.lang.String").call(this, command);
            };
            return JavaRuntime;
        });
    };
    const fileExistsCheck = (success, ident) => {
        return libjava_1.wrapJavaPerform(() => {
            const JavaFile = Java.use("java.io.File");
            JavaFile.exists.implementation = function () {
                const filename = this.getAbsolutePath();
                if (commonPaths.indexOf(filename) >= 0) {
                    if (success) {
                        send(color_1.colors.blackBright(`[${ident}] `) +
                            `File existence check for ${filename} detected, marking as ${color_1.colors.green("true")}.`);
                        return true;
                    }
                    else {
                        send(color_1.colors.blackBright(`[${ident}] `) +
                            `File existence check for ${filename} detected, marking as ${color_1.colors.green("false")}.`);
                        return false;
                    }
                }
                // call the original method
                return this.exists.call(this);
            };
            return JavaFile;
        });
    };
    root.disable = () => {
        const job = {
            identifier: jobs_1.jobs.identifier(),
            implementations: [],
            type: "root-detection-disable",
        };
        job.implementations.push(testKeysCheck(false, job.identifier));
        job.implementations.push(execSuCheck(false, job.identifier));
        job.implementations.push(fileExistsCheck(false, job.identifier));
        jobs_1.jobs.add(job);
    };
    root.enable = () => {
        const job = {
            identifier: jobs_1.jobs.identifier(),
            implementations: [],
            type: "root-detection-enable",
        };
        job.implementations.push(testKeysCheck(true, job.identifier));
        job.implementations.push(execSuCheck(true, job.identifier));
        job.implementations.push(fileExistsCheck(true, job.identifier));
        jobs_1.jobs.add(job);
    };
})(root = exports.root || (exports.root = {}));

},{"../lib/color":117,"../lib/jobs":120,"./lib/libjava":87}],91:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.androidshell = void 0;
const libjava_1 = require("./lib/libjava");
var androidshell;
(function (androidshell) {
    // Executes shell commands on an Android device using Runtime.getRuntime().exec()
    androidshell.execute = (cmd) => {
        // -- Sample Java
        //
        // Process command = Runtime.getRuntime().exec("ls -l /");
        // InputStreamReader isr = new InputStreamReader(command.getInputStream());
        // BufferedReader br = new BufferedReader(isr);
        //
        // StringBuilder sb = new StringBuilder();
        // String line = "";
        //
        // while ((line = br.readLine()) != null) {
        //     sb.append(line + "\n");
        // }
        //
        // String output = sb.toString();
        return libjava_1.wrapJavaPerform(() => {
            const runtime = Java.use("java.lang.Runtime");
            const inputStreamReader = Java.use("java.io.InputStreamReader");
            const bufferedReader = Java.use("java.io.BufferedReader");
            const stringBuilder = Java.use("java.lang.StringBuilder");
            // Run the command
            const command = runtime.getRuntime().exec(cmd);
            // Read 'stderr'
            const stdErrInputStreamReader = inputStreamReader.$new(command.getErrorStream());
            let bufferedReaderInstance = bufferedReader.$new(stdErrInputStreamReader);
            const stdErrStringBuilder = stringBuilder.$new();
            let lineBuffer;
            // tslint:disable-next-line:no-conditional-assignment
            while ((lineBuffer = bufferedReaderInstance.readLine()) != null) {
                stdErrStringBuilder.append(lineBuffer + "\n");
            }
            // Read 'stdout'
            const stdOutInputStreamReader = inputStreamReader.$new(command.getInputStream());
            bufferedReaderInstance = bufferedReader.$new(stdOutInputStreamReader);
            const stdOutStringBuilder = stringBuilder.$new();
            lineBuffer = "";
            // tslint:disable-next-line:no-conditional-assignment
            while ((lineBuffer = bufferedReaderInstance.readLine()) != null) {
                stdOutStringBuilder.append(lineBuffer + "\n");
            }
            return {
                command: cmd,
                stdErr: stdErrStringBuilder.toString(),
                stdOut: stdOutStringBuilder.toString(),
            };
        });
    };
})(androidshell = exports.androidshell || (exports.androidshell = {}));

},{"./lib/libjava":87}],92:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.userinterface = void 0;
const color_1 = require("../lib/color");
const libjava_1 = require("./lib/libjava");
var userinterface;
(function (userinterface) {
    // https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
    const FLAG_SECURE = 0x00002000;
    userinterface.screenshot = () => {
        return libjava_1.wrapJavaPerform(() => {
            // Take a screenshot by making use of a View's drawing cache:
            //  ref: https://developer.android.com/reference/android/view/View.html#getDrawingCache(boolean)
            const activityThread = Java.use("android.app.ActivityThread");
            const activity = Java.use("android.app.Activity");
            const activityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
            const bitmap = Java.use("android.graphics.Bitmap");
            const byteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            const compressFormat = Java.use("android.graphics.Bitmap$CompressFormat");
            let bytes;
            const currentActivityThread = activityThread.currentActivityThread();
            const activityRecords = currentActivityThread.mActivities.value.values().toArray();
            let currentActivity;
            for (const i of activityRecords) {
                const activityRecord = Java.cast(i, activityClientRecord);
                if (!activityRecord.paused.value) {
                    currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activity);
                    break;
                }
            }
            if (currentActivity) {
                const view = currentActivity.getWindow().getDecorView().getRootView();
                view.setDrawingCacheEnabled(true);
                const bitmapInstance = bitmap.createBitmap(view.getDrawingCache());
                view.setDrawingCacheEnabled(false);
                const outputStream = byteArrayOutputStream.$new();
                bitmapInstance.compress(compressFormat.PNG.value, 100, outputStream);
                bytes = outputStream.buf.value;
            }
            return bytes;
        });
    };
    userinterface.setFlagSecure = (v) => {
        return libjava_1.wrapJavaPerform(() => {
            const activityThread = Java.use("android.app.ActivityThread");
            const activity = Java.use("android.app.Activity");
            const activityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
            const currentActivityThread = activityThread.currentActivityThread();
            const activityRecords = currentActivityThread.mActivities.value.values().toArray();
            let currentActivity;
            for (const i of activityRecords) {
                const activityRecord = Java.cast(i, activityClientRecord);
                if (!activityRecord.paused.value) {
                    currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activity);
                    break;
                }
            }
            if (currentActivity) {
                // Somehow the next line prevents Frida from throwing an abort error
                currentActivity.getWindow();
                // Set flag and trigger update (Throws abort without first calling getWindow())
                Java.scheduleOnMainThread(() => {
                    currentActivity.getWindow().setFlags(v ? FLAG_SECURE : 0, FLAG_SECURE);
                    send(`FLAG_SECURE set to ${color_1.colors.green(v.toString())}`);
                });
            }
        });
    };
})(userinterface = exports.userinterface || (exports.userinterface = {}));

},{"../lib/color":117,"./lib/libjava":87}],93:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.custom = void 0;
var custom;
(function (custom) {
    custom.evaluate = (js) => {
        // tslint:disable-next-line:no-eval
        eval(js);
    };
})(custom = exports.custom || (exports.custom = {}));

},{}],94:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.environment = void 0;
const libjava_1 = require("../android/lib/libjava");
const constants_1 = require("../ios/lib/constants");
const helpers_1 = require("../ios/lib/helpers");
const constants_2 = require("../lib/constants");
var environment;
(function (environment) {
    // small helper function to lookup ios bundle paths
    const getPathForNSLocation = (NSPath) => {
        const p = helpers_1.getNSFileManager().URLsForDirectory_inDomains_(NSPath, constants_1.NSUserDomainMask).lastObject();
        if (p) {
            return p.path().toString();
        }
        return "";
    };
    environment.runtime = () => {
        if (ObjC.available) {
            return constants_2.DeviceType.IOS;
        }
        if (Java.available) {
            return constants_2.DeviceType.ANDROID;
        }
        return constants_2.DeviceType.UNKNOWN;
    };
    environment.frida = () => {
        return {
            arch: Process.arch,
            debugger: Process.isDebuggerAttached(),
            filename: Script.fileName,
            heap: Frida.heapSize,
            platform: Process.platform,
            runtime: Script.runtime,
            version: Frida.version,
        };
    };
    environment.iosPackage = () => {
        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // NSString *pictures = [[fm URLsForDirectory:NSPicturesDirectory inDomains:NSUserDomainMask] lastObject].path;
        // NSBundle *bundle = [NSBundle mainBundle];
        // NSString *bundlePath = [bundle bundlePath];
        // NSString *receipt = [bundle appStoreReceiptURL].path;
        // NSString *resourcePath = [bundle resourcePath];
        const { UIDevice } = ObjC.classes;
        const mb = helpers_1.getNSMainBundle();
        return {
            applicationName: mb.objectForInfoDictionaryKey_("CFBundleIdentifier").toString(),
            deviceName: UIDevice.currentDevice().name().toString(),
            identifierForVendor: UIDevice.currentDevice().identifierForVendor().toString(),
            model: UIDevice.currentDevice().model().toString(),
            systemName: UIDevice.currentDevice().systemName().toString(),
            systemVersion: UIDevice.currentDevice().systemVersion().toString(),
        };
    };
    environment.iosPaths = () => {
        const mb = helpers_1.getNSMainBundle();
        return {
            BundlePath: mb.bundlePath().toString(),
            CachesDirectory: getPathForNSLocation(constants_1.NSSearchPaths.NSCachesDirectory),
            DocumentDirectory: getPathForNSLocation(constants_1.NSSearchPaths.NSDocumentDirectory),
            LibraryDirectory: getPathForNSLocation(constants_1.NSSearchPaths.NSLibraryDirectory),
        };
    };
    environment.androidPackage = () => {
        return libjava_1.wrapJavaPerform(() => {
            // https://developer.android.com/reference/android/os/Build.html
            const Build = Java.use("android.os.Build");
            return {
                application_name: libjava_1.getApplicationContext().getPackageName(),
                board: Build.BOARD.value.toString(),
                brand: Build.BRAND.value.toString(),
                device: Build.DEVICE.value.toString(),
                host: Build.HOST.value.toString(),
                id: Build.ID.value.toString(),
                model: Build.MODEL.value.toString(),
                product: Build.PRODUCT.value.toString(),
                user: Build.USER.value.toString(),
                version: Java.androidVersion,
            };
        });
    };
    environment.androidPaths = () => {
        // -- Sample Java
        //
        // getApplicationContext().getFilesDir().getAbsolutePath()
        return libjava_1.wrapJavaPerform(() => {
            const context = libjava_1.getApplicationContext();
            return {
                cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
                codeCacheDirectory: "getCodeCacheDir" in context ? context.getCodeCacheDir()
                    .getAbsolutePath().toString() : "n/a",
                externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
                filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
                obbDir: context.getObbDir().getAbsolutePath().toString(),
                packageCodePath: context.getPackageCodePath().toString(),
            };
        });
    };
})(environment = exports.environment || (exports.environment = {}));

},{"../android/lib/libjava":87,"../ios/lib/constants":109,"../ios/lib/helpers":110,"../lib/constants":118}],95:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.http = void 0;
const fs = __importStar(require("fs"));
const httpLib = __importStar(require("http"));
const url = __importStar(require("url"));
const color_1 = require("../lib/color");
var http;
(function (http) {
    let httpServer;
    let listenPort;
    let servePath;
    const log = (m) => {
        color_1.colors.log(`[http server] ${m}`);
    };
    const dirListingHTML = (p) => {
        let h = `
    <html>
      <body>
        <h2>Index Of /</h2>
        {file_listing}
      </body>
    </html>
    `;
        h = h.replace(`{file_listing}`, () => {
            return fs.readdirSync(p).map((f) => {
                return `<a href="${f}">${f}</a>`;
            }).join("<br>");
        });
        return h;
    };
    http.start = (pwd, port = 9000) => {
        if (httpServer) {
            log(color_1.colors.redBright(`Server appears to already be running`));
            return;
        }
        if (!pwd.endsWith("/")) {
            pwd = pwd + "/";
        }
        log(`${color_1.colors.blackBright(`Starting HTTP server in: ${pwd}`)}`);
        servePath = pwd;
        httpServer = httpLib.createServer((req, res) => {
            log(`${color_1.colors.greenBright(req.method)} ${req.url}`);
            const parsedUrl = url.parse(req.url);
            if (parsedUrl.path === "/") {
                res.end(dirListingHTML(pwd));
                return;
            }
            res.setHeader("Content-type", "application/octet-stream");
            res.end(fs.readFileSync(pwd + parsedUrl.path));
        });
        httpServer.listen(port);
        listenPort = port;
    };
    http.stop = () => {
        if (!httpServer) {
            log(color_1.colors.yellowBright(`Server does not appear to be running.`));
            return;
        }
        log(color_1.colors.blackBright(`Waiting for client connections to close then stopping...`));
        httpServer.close()
            .once("close", () => {
            log(color_1.colors.blackBright(`Server closed.`));
            httpServer = undefined;
        });
    };
    http.status = () => {
        if (httpServer) {
            log(`Server is running on port ` +
                `${color_1.colors.greenBright(listenPort.toString())} serving ${color_1.colors.greenBright(servePath)}`);
            return;
        }
        log(color_1.colors.yellowBright(`Server does not appear to be running.`));
    };
})(http = exports.http || (exports.http = {}));

},{"../lib/color":117,"fs":18,"http":19,"url":73}],96:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.memory = void 0;
const color_1 = require("../lib/color");
var memory;
(function (memory) {
    memory.listModules = () => {
        return Process.enumerateModules();
    };
    memory.listExports = (name) => {
        const mod = Process.enumerateModules().filter((m) => m.name === name);
        if (mod.length <= 0) {
            return null;
        }
        return mod[0].enumerateExports();
    };
    memory.listRanges = (protection = "rw-") => {
        return Process.enumerateRanges(protection);
    };
    memory.dump = (address, size) => {
        // Originally part of Frida <=11 but got removed in 12.
        // https://github.com/frida/frida-python/commit/72899a4315998289fb171149d62477ba7d1fcb91
        return new NativePointer(address).readByteArray(size);
    };
    memory.search = (pattern, onlyOffsets = false) => {
        const addresses = memory.listRanges("rw-")
            .map((range) => {
            return Memory.scanSync(range.base, range.size, pattern)
                .map((match) => {
                if (!onlyOffsets) {
                    color_1.colors.log(hexdump(match.address, {
                        ansi: true,
                        header: false,
                        length: 48,
                    }));
                }
                return match.address.toString();
            });
        }).filter((m) => m.length !== 0);
        return addresses.reduce((a, b) => a.concat(b));
    };
    memory.write = (address, value) => {
        new NativePointer(address).writeByteArray(value);
    };
})(memory = exports.memory || (exports.memory = {}));

},{"../lib/color":117}],97:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ping = void 0;
const ping = () => true;
exports.ping = ping;

},{}],98:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ping_1 = require("./generic/ping");
const android_1 = require("./rpc/android");
const environment_1 = require("./rpc/environment");
const ios_1 = require("./rpc/ios");
const jobs_1 = require("./rpc/jobs");
const memory_1 = require("./rpc/memory");
const other_1 = require("./rpc/other");
rpc.exports = {
    ...android_1.android,
    ...ios_1.ios,
    ...environment_1.env,
    ...jobs_1.jobs,
    ...memory_1.memory,
    ...other_1.other,
    ping: () => ping_1.ping(),
};

},{"./generic/ping":97,"./rpc/android":121,"./rpc/environment":122,"./rpc/ios":123,"./rpc/jobs":124,"./rpc/memory":125,"./rpc/other":126}],99:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.binary = void 0;
// tslint:disable-next-line:no-var-requires
const macho = require("macho");
const filesystem_1 = require("./filesystem");
var binary;
(function (binary) {
    const isEncrypted = (cmds) => {
        for (const cmd of cmds) {
            // https://opensource.apple.com/source/cctools/cctools-921/include/mach-o/loader.h.auto.html
            // struct encryption_info_command {
            //    [ ... ]
            //   uint32_t	cryptid;	/* which enryption system, 0 means not-encrypted yet */
            // };
            if (cmd.type === "encryption_info" || cmd.type === "encryption_info_64") {
                if (cmd.id !== 0) {
                    return true;
                }
            }
        }
        return false;
    };
    binary.info = () => {
        const modules = Process.enumerateModules();
        const parsedModules = {};
        modules.forEach((a) => {
            if (!a.path.includes(".app")) {
                return;
            }
            const imports = new Set(a.enumerateImports().map((i) => i.name));
            const fb = filesystem_1.iosfilesystem.readFile(a.path);
            try {
                const exe = macho.parse(fb);
                parsedModules[a.name] = {
                    arc: imports.has("objc_release"),
                    canary: imports.has("__stack_chk_fail"),
                    encrypted: isEncrypted(exe.cmds),
                    pie: exe.flags.pie ? true : false,
                    rootSafe: exe.flags.root_safe ? true : false,
                    stackExec: exe.flags.allow_stack_execution ? true : false,
                    type: exe.filetype,
                };
            }
            catch (e) {
                // ignore any errors. especially ones where
                // the target path is not a mach-o
            }
        });
        return parsedModules;
    };
})(binary = exports.binary || (exports.binary = {}));

},{"./filesystem":104,"macho":46}],100:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.binarycookies = void 0;
var binarycookies;
(function (binarycookies) {
    binarycookies.get = () => {
        // -- Sample Objective-C
        //
        // NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        // NSArray *cookies = [cs cookies];
        const cookies = [];
        const HTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
        const cookieStore = HTTPCookieStorage.sharedHTTPCookieStorage();
        const cookieJar = cookieStore.cookies();
        if (cookieJar.count() <= 0) {
            return cookies;
        }
        for (let i = 0; i < cookieJar.count(); i++) {
            // get the actual cookie from the jar
            const cookie = cookieJar.objectAtIndex_(i);
            // <NSHTTPCookie version:0 name:"__cfduid" value:"d2546c60b09a710a151d974e662f40c081498064665"
            // expiresDate:2018-06-21 17:04:25 +0000 created:2017-06-21 17:04:26 +0000 sessionOnly:FALSE
            // domain:".swapi.co" partition:"none" path:"/" isSecure:FALSE>
            const cookieData = {
                domain: cookie.domain().toString(),
                expiresDate: cookie.expiresDate() ? cookie.expiresDate().toString() : "null",
                isHTTPOnly: cookie.isHTTPOnly().toString(),
                isSecure: cookie.isSecure().toString(),
                name: cookie.name().toString(),
                path: cookie.path().toString(),
                value: cookie.value().toString(),
                version: cookie.version().toString(),
            };
            cookies.push(cookieData);
        }
        return cookies;
    };
})(binarycookies = exports.binarycookies || (exports.binarycookies = {}));

},{}],101:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bundles = void 0;
const constants_1 = require("./lib/constants");
var bundles;
(function (bundles) {
    // https://developer.apple.com/documentation/foundation/nsbundle/1408056-allframeworks?language=objc
    // https://developer.apple.com/documentation/foundation/nsbundle/1413705-allbundles?language=objc
    bundles.getBundles = (type) => {
        // -- Sample ObjC
        //
        // for (id ob in [NSBundle allBundles]) {
        //   NSDictionary *i = [ob infoDictionary];
        //   NSString *p = [ob bundlePath];
        //   NSLog(@"%@:%@ @ %@", [i objectForKey:@"CFBundleIdentifier"],
        //         [i objectForKey:@"CFBundleShortVersionString"], p);
        // }
        // Figure out which bundle type to enumerate
        let frameworks;
        if (type === constants_1.BundleType.NSBundleFramework) {
            frameworks = ObjC.classes.NSBundle.allFrameworks();
        }
        else if (type === constants_1.BundleType.NSBundleAllBundles) {
            frameworks = ObjC.classes.NSBundle.allBundles();
        }
        const appBundles = [];
        const frameworksLength = frameworks.count().valueOf();
        for (let i = 0; i !== frameworksLength; i++) {
            // get information about the bundle itself
            const bundle = frameworks.objectAtIndex_(i);
            const bundleInfo = bundle.infoDictionary();
            // get values for the keys we are interested in
            const bundlePath = bundle.bundlePath();
            const CFBundleIdentifier = bundleInfo.objectForKey_("CFBundleIdentifier");
            const CFBundleShortVersionString = bundleInfo.objectForKey_("CFBundleShortVersionString");
            const CFBundleExecutable = bundleInfo.objectForKey_("CFBundleExecutable");
            appBundles.push({
                bundle: CFBundleIdentifier ? CFBundleIdentifier.toString() : null,
                executable: CFBundleExecutable ? CFBundleExecutable.toString() : null,
                path: bundlePath.toString(),
                version: CFBundleShortVersionString ? CFBundleShortVersionString.toString() : null,
            });
        }
        return appBundles;
    };
})(bundles = exports.bundles || (exports.bundles = {}));

},{"./lib/constants":109}],102:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.credentialstorage = void 0;
var credentialstorage;
(function (credentialstorage) {
    credentialstorage.dump = () => {
        // -- Sample ObjC to create and dump a credential
        // NSURLProtectionSpace *ps = [[NSURLProtectionSpace alloc]
        //  initWithHost:@"foo.com" port:80 protocol:@"https" realm:NULL
        //  authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
        // NSURLCredential *creds = [[NSURLCredential alloc]
        //  initWithUser:@"user" password:@"password" persistence:NSURLCredentialPersistencePermanent];
        // NSURLCredentialStorage *cs = [NSURLCredentialStorage sharedCredentialStorage];
        // [cs setCredential:creds forProtectionSpace:ps];
        // NSDictionary *allcreds = [cs allCredentials];
        // NSLog(@"%@", allcreds);
        const credentialStorage = ObjC.classes.NSURLCredentialStorage;
        const data = [];
        const credentialsDict = credentialStorage.sharedCredentialStorage().allCredentials();
        if (credentialsDict.count() <= 0) {
            return data;
        }
        const protectionSpaceEnumerator = credentialsDict.keyEnumerator();
        let urlProtectionSpace;
        // tslint:disable-next-line:no-conditional-assignment
        while ((urlProtectionSpace = protectionSpaceEnumerator.nextObject()) !== null) {
            const userNameEnumerator = credentialsDict.objectForKey_(urlProtectionSpace).keyEnumerator();
            let userName;
            // tslint:disable-next-line:no-conditional-assignment
            while ((userName = userNameEnumerator.nextObject()) !== null) {
                const creds = credentialsDict.objectForKey_(urlProtectionSpace).objectForKey_(userName);
                // Add the creds for this protection space.
                const credentialData = {
                    authMethod: urlProtectionSpace.authenticationMethod().toString(),
                    host: urlProtectionSpace.host().toString(),
                    password: creds.password().toString(),
                    port: urlProtectionSpace.port(),
                    protocol: urlProtectionSpace.protocol().toString(),
                    user: creds.user().toString(),
                };
                data.push(credentialData);
            }
        }
        return data;
    };
})(credentialstorage = exports.credentialstorage || (exports.credentialstorage = {}));

},{}],103:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ioscrypto = void 0;
const color_1 = require("../lib/color");
const helpers_1 = require("../lib/helpers");
const jobs_1 = require("../lib/jobs");
const helpers_2 = require("./lib/helpers");
// Encryption algorithms implemented by this module.
const CCAlgorithm = {
    0: { name: "kCCAlgorithmAES128", blocksize: 16 },
    1: { name: "kCCAlgorithmDES", blocksize: 8 },
    2: { name: "kCCAlgorithm3DES", blocksize: 8 },
    3: { name: "kCCAlgorithmCAST", blocksize: 8 },
    4: { name: "kCCAlgorithmRC4", blocksize: 8 },
    5: { name: "kCCAlgorithmRC2", blocksize: 8 }
};
// Encryption algorithms implemented by this module.
const CCOperation = {
    0: "kCCEncrypt",
    1: "kCCDecrypt"
};
// Options flags, passed to CCCryptorCreate().
const CCOption = {
    1: "kCCOptionPKCS7Padding",
    2: "kCCOptionECBMode"
};
// alg for pbkdf. Right now only pbkdf2 is supported by CommonCrypto
const CCPBKDFAlgorithm = {
    2: "kCCPBKDF2"
};
// alg for prt for pbkdf
const CCPseudoRandomAlgorithm = {
    1: "kCCPRFHmacAlgSHA1",
    2: "kCCPRFHmacAlgSHA224",
    3: "kCCPRFHmacAlgSHA256",
    4: "kCCPRFHmacAlgSHA384",
    5: "kCCPRFHmacAlgSHA512"
};
var ioscrypto;
(function (ioscrypto) {
    // ident for crypto hooks job
    let cryptoidentifier = null;
    // operation being performed 0=encrypt 1=decrypt
    let op = 0;
    // needed to keep track of CCAlgorithm so we can know
    // blocksize from CCCryptorCreate to CCCryptorUpdate
    let alg = 0;
    // keep track of all the output bytes.
    // this is necessary because CCCryptorUpdate needs to be
    // append the final block from CCCryptorFinal
    let dataOutBytes = null;
    const secrandomcopybytes = (ident) => {
        const hook = "SecRandomCopyBytes";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.secrandomcopybytes = {};
                this.secrandomcopybytes.rnd = args[0].toInt32();
                this.secrandomcopybytes.count = args[1].toInt32();
                this.bytes = args[2];
            },
            onLeave(retval) {
                this.secrandomcopybytes.bytes = helpers_2.arrayBufferToHex(this.bytes.readByteArray(this.secrandomcopybytes.count));
                helpers_1.fsend(ident, hook, this.secrandomcopybytes);
            }
        });
    };
    const cckeyderivationpbkdf = (ident) => {
        const hook = "CCKeyDerivationPBKDF";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.cckeyderivationpbkdf = {};
                // args[0]  "kCCPBKDF2" is the only alg supported by CommonCrypto
                this.cckeyderivationpbkdf.algorithm = CCPBKDFAlgorithm[args[0].toInt32()];
                // args[1]  The text password used as input to the derivation
                //          function. The actual octets present in this string
                //          will be used with no additional processing.  It's
                //          extremely important that the same encoding and
                //          normalization be used each time this routine is
                //          called if the same key is  expected to be derived.
                // args[2]  The length of the text password in bytes.
                const passwordPtr = args[1];
                const passwordLen = args[2].toInt32();
                const passwordBytes = helpers_2.arrayBufferToHex(passwordPtr.readByteArray(passwordLen));
                try {
                    this.cckeyderivationpbkdf.password = helpers_2.hexToString(passwordBytes);
                }
                catch {
                    this.cckeyderivationpbkdf.password = passwordBytes;
                }
                // args[3]  The salt byte values used as input to the derivation function.
                // args[4]  The length of the salt in bytes.
                const saltPtr = args[3];
                const saltLen = args[4].toInt32();
                this.cckeyderivationpbkdf.saltBytes = helpers_2.arrayBufferToHex(saltPtr.readByteArray(saltLen));
                // args[5]  The Pseudo Random Algorithm to use for the derivation iterations.
                this.cckeyderivationpbkdf.prf = CCPseudoRandomAlgorithm[args[5].toInt32()];
                // args[6]  The number of rounds of the Pseudo Random Algorithm to use.
                this.cckeyderivationpbkdf.rounds = args[6].toInt32();
                // args[7]  The resulting derived key produced by the function.
                //          The space for this must be provided by the caller.
                this.derivedKeyPtr = args[7];
                // args[8]  The expected length of the derived key in bytes.
                this.derivedKeyLen = args[8].toInt32();
            },
            onLeave(retval) {
                this.cckeyderivationpbkdf.derivedKey = helpers_2.arrayBufferToHex(this.derivedKeyPtr.readByteArray(this.derivedKeyLen));
                helpers_1.fsend(ident, hook, this.cckeyderivationpbkdf);
            }
        });
    };
    const cccrypt = (ident) => {
        const hook = "CCCrypt";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.cccrpyt = {};
                // args[0]  Defines the basic operation: kCCEncrypt or kCCDecrypt.
                this.op = args[0].toInt32();
                this.cccrpyt.op = CCOperation[this.op];
                // args[1]  Defines the encryption algorithm.
                this.alg = args[1].toInt32();
                this.cccrpyt.alg = CCAlgorithm[alg].name;
                // args[2]  A word of flags defining options. See discussion for the CCOptions type.
                this.cccrpyt.options = CCOption[args[2].toInt32()];
                // args[3]  Raw key material, length keyLength bytes.
                // args[4]  Length of key material. Must be appropriate
                // 				  for the select algorithm. Some algorithms may
                //  				provide for varying key lengths.
                const key = args[3];
                this.cccrpyt.keyLength = args[4].toInt32();
                this.cccrpyt.key = helpers_2.arrayBufferToHex(key.readByteArray(this.cccrpyt.keyLength));
                // args[5]  Initialization vector, optional. Used for
                // 				  Cipher Block Chaining (CBC) mode. If present,
                // 				  must be the same length as the selected
                // 				  algorithm's block size. If CBC mode is
                // 				  selected (by the absence of any mode bits in
                // 				  the options	flags) and no IV is present, a
                // 				  NULL (all zeroes) IV will be used. This is
                // 				  ignored if ECB mode is used or if a stream
                // 		  		cipher algorithm is selected.
                const iv = args[5];
                this.cccrpyt.iv = helpers_2.arrayBufferToHex(iv.readByteArray(CCAlgorithm[alg].blocksize));
                // args[6]  Data to encrypt or decrypt, length dataInLength bytes.
                // args[7]  Length of data to encrypt or decrypt.
                const dataInPtr = args[6];
                const dataInLength = args[7].toInt32();
                const dataInHex = helpers_2.arrayBufferToHex(dataInPtr.readByteArray(dataInLength));
                this.cccrpyt.dataIn = this.op ? dataInHex : helpers_2.hexToString(dataInHex);
                // args[8]  Result is written here. Allocated by caller.
                //          Encryption and decryption can be performed
                //          "in-place", with the same buffer used for
                //          input and output.
                this.dataOut = args[8];
                // args[9]  The size of the dataOut buffer in bytes.
                this.dataOutAvailable = args[9].toInt32();
                // args[10] On successful return, the number of bytes written
                //          to dataOut. If kCCBufferTooSmall is returned as
                //          a result of insufficient buffer space being
                //          provided, the required buffer space is returned
                //          here.
                this.dataOutMoved = args[10];
            },
            onLeave(retval) {
                const dataOutHex = helpers_2.arrayBufferToHex(this.dataOut.readByteArray(this.dataOutAvailable));
                this.cccrpyt.dataOut = this.op ? helpers_2.hexToString(dataOutHex) : dataOutHex;
                helpers_1.fsend(ident, hook, this.cccrpyt);
            }
        });
    };
    const cccryptorcreate = (ident) => {
        const hook = "CCCryptorCreate";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.cccryptorcreate = {};
                // args[0]  Defines the basic operation: kCCEncrypt or kCCDecrypt.
                op = args[0].toInt32();
                this.cccryptorcreate.op = CCOperation[op];
                // args[1]  Defines the encryption algorithm.
                alg = args[1].toInt32();
                this.cccryptorcreate.alg = CCAlgorithm[alg].name;
                // args[2]  A word of flags defining options. See discussion for the CCOptions type.
                const option = args[2].toInt32();
                this.cccryptorcreate.options = CCOption[option];
                // args[3]  Raw key material, length keyLength bytes.
                // args[4]  Length of key material. Must be appropriate
                // 				  for the select algorithm. Some algorithms may
                //  				provide for varying key lengths.
                const keyPtr = args[3];
                this.cccryptorcreate.keyLength = args[4].toInt32();
                this.cccryptorcreate.key = helpers_2.arrayBufferToHex(keyPtr.readByteArray(this.cccryptorcreate.keyLength));
                // args[5]  Initialization vector, optional. Used for
                // 				  Cipher Block Chaining (CBC) mode. If present,
                // 				  must be the same length as the selected
                // 				  algorithm's block size. If CBC mode is
                // 				  selected (by the absence of any mode bits in
                // 				  the options	flags) and no IV is present, a
                // 				  NULL (all zeroes) IV will be used. This is
                // 				  ignored if ECB mode is used or if a stream
                // 		  		cipher algorithm is selected.
                const ivPtr = args[5];
                this.cccryptorcreate.iv = helpers_2.arrayBufferToHex(ivPtr.readByteArray(CCAlgorithm[alg].blocksize));
            },
            onLeave(retval) {
                helpers_1.fsend(ident, hook, this.cccryptorcreate);
            }
        });
    };
    const cccryptorupdate = (ident) => {
        const hook = "CCCryptorUpdate";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.cccryptorupdate = {};
                // reset for the next operation.
                dataOutBytes = "";
                // args[1]  Data to process, length dataInLength bytes.
                const dataInPtr = args[1];
                // args[2]  Length of data to process.
                this.dataInLength = args[2].toInt32();
                // args[3]  Result is written here. Allocated by caller.
                // 	  		  Encryption and decryption can be performed
                // 				  "in-place", with the same buffer used for
                // 				  input and output.
                this.dataOutPtr = args[3];
                // args[4]  The size of the dataOut buffer in bytes.
                this.dataOutAvailable = args[4].toInt32();
                const dataIn = helpers_2.arrayBufferToHex(dataInPtr.readByteArray(this.dataInLength));
                this.cccryptorupdate.dataIn = op ? dataIn : helpers_2.hexToString(dataIn);
            },
            onLeave(retval) {
                const blocksize = CCAlgorithm[alg].blocksize;
                // if the messsage is longer than 1 block then we need to
                // remember everything before the final block
                if (this.dataInLength > blocksize) {
                    // TODO: There is sometimes padding added to the end of this message
                    // someone please fix this in a pull request. it is super hacky.
                    dataOutBytes = helpers_2.arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable)).split("000000")[0];
                    this.cccryptorupdate.dataOut = dataOutBytes;
                }
                helpers_1.fsend(ident, hook, this.cccryptorupdate);
            }
        });
    };
    const cccryptorfinal = (ident) => {
        const hook = "CCCryptorFinal";
        return Interceptor.attach(Module.getExportByName(null, hook), {
            onEnter(args) {
                this.cccryptorfinal = {};
                // args[1]  Result is written here. Allocated by caller.
                // 	  		  Encryption and decryption can be performed
                // 				  "in-place", with the same buffer used for
                // 				  input and output.
                this.dataOutPtr = args[1];
                // args[2]  The size of the dataOut buffer in bytes.
                this.dataOutAvailable = args[2].toInt32();
            },
            onLeave(retval) {
                // var dataOutHex = arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable))
                // this.cccryptorfinal.dataOut = op ? hexToString(dataOutHex) : dataOutHex
                // append the final block the any previous blocks that might exist
                dataOutBytes += helpers_2.arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable));
                this.cccryptorfinal.dataOut = this.op ? helpers_2.hexToString(dataOutBytes) : dataOutBytes;
                // this.cccryptorfinal.dataOut = dataOutBytes
                helpers_1.fsend(ident, hook, this.cccryptorfinal);
            }
        });
    };
    ioscrypto.monitor = () => {
        // if we already have a job registered then return
        if (jobs_1.jobs.hasIdent(cryptoidentifier)) {
            send(`${color_1.colors.greenBright("Job already registered")}: ${color_1.colors.blueBright(cryptoidentifier)}`);
            return;
        }
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: "ios-crypto-monitor",
        };
        cryptoidentifier = job.identifier;
        job.invocations.push(secrandomcopybytes(job.identifier));
        job.invocations.push(cckeyderivationpbkdf(job.identifier));
        job.invocations.push(cccrypt(job.identifier));
        job.invocations.push(cccryptorcreate(job.identifier));
        job.invocations.push(cccryptorupdate(job.identifier));
        job.invocations.push(cccryptorfinal(job.identifier));
        jobs_1.jobs.add(job);
    };
})(ioscrypto = exports.ioscrypto || (exports.ioscrypto = {}));

},{"../lib/color":117,"../lib/helpers":119,"../lib/jobs":120,"./lib/helpers":110}],104:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.iosfilesystem = void 0;
const fs = __importStar(require("fs"));
const helpers_1 = require("../lib/helpers");
const helpers_2 = require("./lib/helpers");
var iosfilesystem;
(function (iosfilesystem) {
    // a resolved nsfilemanager instance
    let fileManager;
    const getFileManager = () => {
        if (fileManager === undefined) {
            fileManager = helpers_2.getNSFileManager();
            return fileManager;
        }
        return fileManager;
    };
    iosfilesystem.exists = (path) => {
        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // if ([fm fileExistsAtPath:@"/"]) {
        //     NSLog(@"Yep!");
        // }
        const fm = getFileManager();
        const p = ObjC.classes.NSString.stringWithString_(path);
        return fm.fileExistsAtPath_(p);
    };
    iosfilesystem.readable = (path) => {
        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);
        const fm = getFileManager();
        const p = ObjC.classes.NSString.stringWithString_(path);
        return fm.isReadableFileAtPath_(p);
    };
    iosfilesystem.writable = (path) => {
        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);
        const fm = getFileManager();
        const p = ObjC.classes.NSString.stringWithString_(path);
        return fm.isWritableFileAtPath_(p);
    };
    iosfilesystem.pathIsFile = (path) => {
        const fm = getFileManager();
        const isDir = Memory.alloc(Process.pointerSize);
        fm.fileExistsAtPath_isDirectory_(path, isDir);
        // deref the isDir pointer to get the bool
        // *isDir === 1 means the path is a directory
        return isDir.readInt() === 0;
    };
    // returns a 'pwd' that assumes the current bundle's path
    // is the directory we are interested in. the handling of
    // pwd is actually handled in the python world and this
    // method is only really called as a starting point.
    iosfilesystem.pwd = () => {
        // -- Sample Objective-C
        //
        // NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];
        const NSBundle = ObjC.classes.NSBundle;
        return NSBundle.mainBundle().bundlePath().toString();
    };
    // heavy lifting is done in frida-fs here.
    iosfilesystem.readFile = (path) => {
        return fs.readFileSync(path);
    };
    // heavy lifting is done in frida-fs here.
    iosfilesystem.writeFile = (path, data) => {
        const writeStream = fs.createWriteStream(path);
        writeStream.on("error", (error) => {
            throw error;
        });
        writeStream.write(helpers_1.hexStringToBytes(data));
        writeStream.end();
    };
    iosfilesystem.deleteFile = (path) => {
        const fm = getFileManager();
        const err = Memory.alloc(Process.pointerSize);
        fm.removeItemAtPath_error_(path, err);
        // deref the isDir pointer to get the bool
        // *isDir === 1 means the path is a directory
        return err.readInt() === 0;
    };
    iosfilesystem.ls = (path) => {
        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // NSString *bundleURL = [[NSBundle mainBundle] bundlePath];
        // NSArray *contents = [fm contentsOfDirectoryAtPath:bundleURL error:nil];
        // for (id item in contents) {
        //     NSString *p = [[NSString alloc] initWithFormat:@"%@/%@",bundleURL, item];
        //     NSDictionary *attribs = [fm attributesOfItemAtPath:p error:nil];
        //     NSLog(@"%@ - %@", p, attribs);
        // }
        const fm = getFileManager();
        const p = ObjC.classes.NSString.stringWithString_(path);
        const response = {
            files: {},
            path: `${path}`,
            readable: fm.isReadableFileAtPath_(p),
            writable: fm.isWritableFileAtPath_(p),
        };
        // not being able to read the path should leave us bailing early
        if (!response.readable) {
            return response;
        }
        const pathContents = fm.contentsOfDirectoryAtPath_error_(path, NULL);
        const fileCount = pathContents.count();
        // loop-de-loop files
        for (let i = 0; i < fileCount; i++) {
            // pick a file off contents
            const file = pathContents.objectAtIndex_(i);
            const pathFileData = {
                attributes: {},
                fileName: file.toString(),
                readable: undefined,
                writable: undefined,
            };
            // generate a full path to the file
            const filePath = [path, "/", file].join("");
            const currentFilePath = ObjC.classes.NSString.stringWithString_(filePath);
            // check read / write
            pathFileData.readable = fm.isReadableFileAtPath_(currentFilePath);
            pathFileData.writable = fm.isWritableFileAtPath_(currentFilePath);
            // get attributes
            const attributes = fm.attributesOfItemAtPath_error_(currentFilePath, NULL);
            // if we were able to get attributes for the item,
            // append them to those for this file. (example is listing
            // files in / have some that cant have attributes read for :|)
            if (attributes) {
                // loop the attributes and set them in the file_data
                // dictionary
                const enumerator = attributes.keyEnumerator();
                let key;
                // tslint:disable-next-line:no-conditional-assignment
                while ((key = enumerator.nextObject()) !== null) {
                    // get attribute data
                    const value = attributes.objectForKey_(key);
                    // add it to the attributes for this item
                    pathFileData.attributes[key] = value.toString();
                }
            }
            // finally, add the file to the final response
            response.files[file] = pathFileData;
        }
        return response;
    };
})(iosfilesystem = exports.iosfilesystem || (exports.iosfilesystem = {}));

},{"../lib/helpers":119,"./lib/helpers":110,"fs":18}],105:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.heap = void 0;
const color_1 = require("../lib/color");
const helpers_1 = require("./lib/helpers");
var heap;
(function (heap) {
    const enumerateInstances = (clazz) => {
        if (!ObjC.classes.hasOwnProperty(clazz)) {
            color_1.colors.log(`Unknown Objective-C class: ${color_1.colors.redBright(clazz)}`);
            return [];
        }
        const specifier = {
            class: ObjC.classes[clazz],
            subclasses: true,
        };
        return ObjC.chooseSync(specifier);
    };
    heap.getInstances = (clazz) => {
        color_1.colors.log(`${color_1.colors.blackBright(`Enumerating live instances of`)} ${color_1.colors.greenBright(clazz)}...`);
        return enumerateInstances(clazz).map((instance) => {
            try {
                return {
                    className: instance.$className,
                    handle: instance.handle.toString(),
                    ivars: instance.$ivars,
                    kind: instance.$kind,
                    methods: instance.$ownMethods,
                    superClass: instance.$superClass.$className,
                };
            }
            catch (err) {
                color_1.colors.log(`Warning: ${color_1.colors.yellowBright(err)}`);
            }
        });
    };
    const resolvePointer = (pointer) => {
        const o = new ObjC.Object(new NativePointer(pointer));
        color_1.colors.log(`${color_1.colors.blackBright(`Pointer ` + pointer + ` is to class `)}${color_1.colors.greenBright(o.$className)}`);
        return o;
    };
    heap.getIvars = (pointer, toUTF8) => {
        const { $className, $ivars } = resolvePointer(pointer);
        // if we need to get utf8 representations, start a new object with
        // which cloned properties will have utf8 values. we _could_ have
        // just gone and replaces values in $ivars, but there are some
        // access errors for that.
        if (toUTF8) {
            const $clonedIvars = {};
            color_1.colors.log(color_1.colors.blackBright(`Converting ivar values to UTF8 strings...`));
            for (const k in $ivars) {
                if ($ivars.hasOwnProperty(k)) {
                    const v = $ivars[k];
                    $clonedIvars[k] = helpers_1.bytesToUTF8(v);
                }
            }
            return [$className, $clonedIvars];
        }
        return [$className, $ivars];
    };
    heap.getMethods = (pointer) => {
        const { $className, $ownMethods } = resolvePointer(pointer);
        return [$className, $ownMethods];
    };
    heap.callInstanceMethod = (pointer, method, returnString) => {
        const i = resolvePointer(pointer);
        color_1.colors.log(`${color_1.colors.blackBright(`Executing:`)} ${color_1.colors.greenBright(`[${i.$className} ${method}]`)}`);
        const result = i[method]();
        if (returnString) {
            return result.toString();
        }
        return i[method]();
    };
    heap.evaluate = (pointer, js) => {
        const ptr = resolvePointer(pointer);
        // tslint:disable-next-line:no-eval
        eval(js);
    };
})(heap = exports.heap || (exports.heap = {}));

},{"../lib/color":117,"./lib/helpers":110}],106:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hooking = void 0;
const color_1 = require("../lib/color");
const jobs_1 = require("../lib/jobs");
var hooking;
(function (hooking) {
    hooking.getClasses = () => {
        return ObjC.classes;
    };
    hooking.getClassMethods = (className, includeParents) => {
        if (ObjC.classes[className] === undefined) {
            return [];
        }
        // Show all methods of the class
        if (includeParents) {
            return ObjC.classes[className].$methods;
        }
        return ObjC.classes[className].$ownMethods;
    };
    hooking.searchMethods = (partial) => {
        const results = []; // the response
        Object.keys(ObjC.classes).forEach((clazz) => {
            ObjC.classes[clazz].$ownMethods.forEach((method) => {
                if (method.toLowerCase().indexOf(partial) !== -1) {
                    results.push(`[` + ObjC.classes[clazz].$className + ` ` + method + `]`);
                }
            });
        });
        return results;
    };
    hooking.watchClass = (clazz, parents) => {
        const target = ObjC.classes[clazz];
        if (!target) {
            send(`${color_1.colors.red(`Error!`)} Unable to find class ${color_1.colors.redBright(clazz)}!`);
            return;
        }
        // Start a new Job
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: `watch-class-methods for: ${clazz}`,
        };
        // with parents as true, include methods from a parent class,
        // otherwise simply hook the target class' own  methods
        const watchInvocations = (parents ? target.$methods : target.$ownMethods).map((method) => {
            // filter and make sure we have a type and name. Looks like some methods can
            // have '' as name... am expecting something like "- isJailBroken"
            if (method.split(" ").length !== 2) {
                send(color_1.colors.red(`Skipping method `) + `${color_1.colors.greenBright(`'` + method + `'`)}` +
                    color_1.colors.red(`, does not match <type> <name> format`));
                return;
            }
            send(color_1.colors.blackBright(`Watching method: ${color_1.colors.greenBright(method)}`));
            return Interceptor.attach(target[method].implementation, {
                onEnter: (args) => {
                    const receiver = new ObjC.Object(args[0]);
                    send(color_1.colors.blackBright(`[${job.identifier}] `) +
                        `Called: ${color_1.colors.green(`[${receiver.$className} ${ObjC.selectorAsString(args[1])}]`)} ` +
                        `(Kind: ${color_1.colors.cyan(receiver.$kind)}) (Super: ${color_1.colors.cyan(receiver.$superClass.$className)})`);
                },
            });
        });
        // register the job
        watchInvocations.forEach((invocation) => {
            job.invocations.push(invocation);
        });
        jobs_1.jobs.add(job);
    };
    hooking.watchMethod = (selector, dargs, dbt, dret) => {
        const resolver = new ApiResolver("objc");
        let matchedMethod = {
            address: undefined,
            name: undefined,
        };
        // handle the resolvers error it may throw if the selector format is off.
        try {
            // select the first match
            const ressolved = resolver.enumerateMatches(selector);
            if (ressolved.length <= 0) {
                send(`${color_1.colors.red(`Error:`)} No matches for selector ${color_1.colors.redBright(`${selector}`)}. ` +
                    `Double check the name, or try "ios hooking list class_methods" first.`);
                return;
            }
            // not sure if this will ever be the case... but lets log it
            // anyways
            if (ressolved.length > 1) {
                send(`${color_1.colors.yellow(`Warning:`)} More than one result for selector ${color_1.colors.redBright(`${selector}`)}!`);
            }
            matchedMethod = ressolved[0];
        }
        catch (error) {
            send(`${color_1.colors.red(`Error:`)} Unable to find address for selector ${color_1.colors.redBright(`${selector}`)}! ` +
                `The error was:\n` + color_1.colors.red(error));
            return;
        }
        // Start a new Job
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: `watch-method for: ${selector}`,
        };
        // Attach to the discovered match
        // TODO: loop correctly when globbing
        send(`Found selector at ${color_1.colors.green(matchedMethod.address.toString())} as ${color_1.colors.green(matchedMethod.name)}`);
        const watchInvocation = Interceptor.attach(matchedMethod.address, {
            // tslint:disable-next-line:object-literal-shorthand
            onEnter: function (args) {
                // how many arguments do we have in this selector?
                const argumentCount = (selector.match(/:/g) || []).length;
                const receiver = new ObjC.Object(args[0]);
                send(color_1.colors.blackBright(`[${job.identifier}] `) +
                    `Called: ${color_1.colors.green(`${selector}`)} ${color_1.colors.blue(`${argumentCount}`)} arguments` +
                    `(Kind: ${color_1.colors.cyan(receiver.$kind)}) (Super: ${color_1.colors.cyan(receiver.$superClass.$className)})`);
                // if we should include a backtrace to here, do that.
                if (dbt) {
                    send(color_1.colors.blackBright(`[${job.identifier}] `) +
                        `${color_1.colors.green(`${selector}`)} Backtrace:\n\t` +
                        Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"));
                }
                if (dargs && argumentCount > 0) {
                    const methodSplit = ObjC.selectorAsString(args[1]).split(":").filter((val) => val);
                    const r = methodSplit.map((argName, position) => {
                        // As this is an ObjectiveC method, the arguments are as follows:
                        // 0. 'self'
                        // 1. The selector (object.name:)
                        // 2. The first arg
                        //
                        // For this reason do we shift it by 2 positions to get an 'instance' for
                        // the argument value.
                        const t = new ObjC.Object(args[position + 2]);
                        return `${argName}: ${color_1.colors.greenBright(`${t}`)}`;
                    });
                    send(color_1.colors.blackBright(`[${job.identifier}] `) +
                        `Argument dump: [${color_1.colors.green(receiver.$className)} ${r.join(" ")}]`);
                }
            },
            onLeave: (retval) => {
                // do nothing if we are not expected to dump return values
                if (!dret) {
                    return;
                }
                send(color_1.colors.blackBright(`[${job.identifier}] `) + `Return Value: ${color_1.colors.red(retval.toString())}`);
            },
        });
        // register the job
        job.invocations.push(watchInvocation);
        jobs_1.jobs.add(job);
    };
    hooking.setMethodReturn = (selector, returnValue) => {
        const TRUE = new NativePointer(0x1);
        const FALSE = new NativePointer(0x0);
        const resolver = new ApiResolver("objc");
        let matchedMethod = {
            address: undefined,
            name: undefined,
        };
        // handle the resolvers error it may throw if the selector format
        // is off.
        try {
            // select the first match
            matchedMethod = resolver.enumerateMatches(selector)[0];
        }
        catch (error) {
            send(`${color_1.colors.red(`Error!`)} Unable to find address for selector ${color_1.colors.redBright(`${selector}`)}! ` +
                `The error was:\n` + color_1.colors.red(error));
            return;
        }
        // no match? then just leave.
        if (!matchedMethod.address) {
            send(`${color_1.colors.red(`Error!`)} Unable to find address for selector ${color_1.colors.redBright(`${selector}`)}!`);
            return;
        }
        // Start a new Job
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: `set-method-return for: ${selector}`,
        };
        // Attach to the discovered match
        // TODO: loop correctly when globbing
        send(`Found selector at ${color_1.colors.green(matchedMethod.address.toString())} as ${color_1.colors.green(matchedMethod.name)}`);
        const watchInvocation = Interceptor.attach(matchedMethod.address, {
            onLeave: (retval) => {
                switch (returnValue) {
                    case true:
                        if (retval.equals(TRUE)) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${job.identifier}] `) +
                            `${color_1.colors.green(selector)} ` +
                            `Return value was: ${color_1.colors.red(retval.toString())}, overriding to ${color_1.colors.green(TRUE.toString())}`);
                        retval.replace(TRUE);
                        break;
                    case false:
                        if (retval.equals(FALSE)) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${job.identifier}] `) +
                            `${color_1.colors.green(selector)} ` +
                            `Return value was: ${color_1.colors.red(retval.toString())}, overriding to ${color_1.colors.green(FALSE.toString())}`);
                        retval.replace(FALSE);
                        break;
                }
            },
        });
        // register the job
        job.invocations.push(watchInvocation);
        jobs_1.jobs.add(job);
    };
})(hooking = exports.hooking || (exports.hooking = {}));

},{"../lib/color":117,"../lib/jobs":120}],107:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.iosjailbreak = void 0;
const color_1 = require("../lib/color");
const jobs_1 = require("../lib/jobs");
// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!
// Hook NSFileManager and fopen calls and check if it is to a common path.
// Hook canOpenURL for Cydia deep link.
const jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
];
var iosjailbreak;
(function (iosjailbreak) {
    // toggles replies to fileExistsAtPath: for the paths in jailbreakPaths
    const fileExistsAtPath = (success, ident) => {
        return Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter(args) {
                // Use a marker to check onExit if we need to manipulate
                // the response.
                this.is_common_path = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }
                // depending on the desired state, we flip retval
                switch (success) {
                    case (true):
                        // ignore successful lookups
                        if (!retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `fileExistsAtPath: check for ` +
                            color_1.colors.green(this.path) + ` failed with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as successful.`);
                        retval.replace(new NativePointer(0x01));
                        break;
                    case (false):
                        // ignore failed lookups
                        if (retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `fileExistsAtPath: check for ` +
                            color_1.colors.green(this.path) + ` was successful with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as failed.`);
                        retval.replace(new NativePointer(0x00));
                        break;
                }
            },
        });
    };
    // toggles replies to fopen: for the paths in jailbreakPaths
    const fopen = (success, ident) => {
        return Interceptor.attach(Module.findExportByName(null, "fopen"), {
            onEnter(args) {
                this.is_common_path = false;
                // Extract the path
                this.path = args[0].readCString();
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }
                // depending on the desired state, we flip retval
                switch (success) {
                    case (true):
                        // ignore successful lookups
                        if (!retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `fopen: check for ` +
                            color_1.colors.green(this.path) + ` failed with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as successful.`);
                        retval.replace(new NativePointer(0x01));
                        break;
                    case (false):
                        // ignore failed lookups
                        if (retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `fopen: check for ` +
                            color_1.colors.green(this.path) + ` was successful with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as failed.`);
                        retval.replace(new NativePointer(0x00));
                        break;
                }
            },
        });
    };
    // toggles replies to canOpenURL for Cydia
    const canOpenURL = (success, ident) => {
        return Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
            onEnter(args) {
                this.is_flagged = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                if (this.path.startsWith('cydia') || this.path.startsWith('Cydia')) {
                    this.is_flagged = true;
                }
            },
            onLeave(retval) {
                if (!this.is_flagged) {
                    return;
                }
                // depending on the desired state, we flip retval
                switch (success) {
                    case (true):
                        // ignore successful lookups
                        if (!retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `canOpenURL: check for ` +
                            color_1.colors.green(this.path) + ` failed with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as successful.`);
                        retval.replace(new NativePointer(0x01));
                        break;
                    case (false):
                        // ignore failed
                        if (retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `canOpenURL: check for ` +
                            color_1.colors.green(this.path) + ` was successful with: ` +
                            color_1.colors.red(retval.toString()) + `, marking it as failed.`);
                        retval.replace(new NativePointer(0x00));
                        break;
                }
            },
        });
    };
    const libSystemBFork = (success, ident) => {
        // Hook fork() in libSystem.B.dylib and return 0
        // TODO: Hook vfork
        const libSystemBdylibFork = Module.findExportByName("libSystem.B.dylib", "fork");
        // iOS simulator does not have libSystem.B.dylib
        // TODO: Remove as iOS 12 similar may have this now.
        if (!libSystemBdylibFork) {
            return new InvocationListener();
        }
        return Interceptor.attach(libSystemBdylibFork, {
            onLeave(retval) {
                switch (success) {
                    case (true):
                        // already successful forks are ok
                        if (!retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `Call to ` +
                            color_1.colors.green(`libSystem.B.dylib::fork()`) + ` failed with ` +
                            color_1.colors.red(retval.toString()) + ` marking it as successful.`);
                        retval.replace(new NativePointer(0x1));
                        break;
                    case (false):
                        // already failed forks are ok
                        if (retval.isNull()) {
                            return;
                        }
                        send(color_1.colors.blackBright(`[${ident}] `) + `Call to ` +
                            color_1.colors.green(`libSystem.B.dylib::fork()`) + ` was successful with ` +
                            color_1.colors.red(retval.toString()) + ` marking it as failed.`);
                        retval.replace(new NativePointer(0x0));
                        break;
                }
            },
        });
    };
    iosjailbreak.disable = () => {
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: "ios-jailbreak-disable",
        };
        job.invocations.push(fileExistsAtPath(false, job.identifier));
        job.invocations.push(libSystemBFork(false, job.identifier));
        job.invocations.push(fopen(false, job.identifier));
        job.invocations.push(canOpenURL(false, job.identifier));
        jobs_1.jobs.add(job);
    };
    iosjailbreak.enable = () => {
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: "ios-jailbreak-enable",
        };
        job.invocations.push(fileExistsAtPath(true, job.identifier));
        job.invocations.push(libSystemBFork(true, job.identifier));
        job.invocations.push(fopen(true, job.identifier));
        job.invocations.push(canOpenURL(true, job.identifier));
        jobs_1.jobs.add(job);
    };
})(iosjailbreak = exports.iosjailbreak || (exports.iosjailbreak = {}));

},{"../lib/color":117,"../lib/jobs":120}],108:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ioskeychain = void 0;
// dumps all of the keychain items available to the current
// application.
const color_1 = require("../lib/color");
const helpers_1 = require("../lib/helpers");
const constants_1 = require("./lib/constants");
const helpers_2 = require("./lib/helpers");
const libobjc_1 = require("./lib/libobjc");
// keychain item times to query for
const itemClasses = [
    constants_1.kSec.kSecClassKey,
    constants_1.kSec.kSecClassIdentity,
    constants_1.kSec.kSecClassCertificate,
    constants_1.kSec.kSecClassGenericPassword,
    constants_1.kSec.kSecClassInternetPassword,
];
var ioskeychain;
(function (ioskeychain) {
    // The parent method that enumerates the iOS keychain
    const enumerateKeychain = () => {
        // -- Sample Objective-C
        //
        // NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
        // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
        // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
        // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
        // [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
        // NSArray *itemClasses = [NSArray arrayWithObjects:
        //                         (__bridge id)kSecClassKey,
        //                         (__bridge id)kSecClassIdentity,
        //                         (__bridge id)kSecClassCertificate,
        //                         (__bridge id)kSecClassGenericPassword,
        //                         (__bridge id)kSecClassInternetPassword,
        //                         nil];
        // for (id itemClass in itemClasses) {
        //     NSLog(@"Querying: %@", itemClass);
        //     [query setObject:itemClass forKey:(__bridge id)kSecClass];
        //     CFTypeRef result = NULL;
        //     OSStatus findStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        //     if(findStatus != errSecSuccess) {
        //         NSLog(@"Failed to query keychain for types %@", itemClass);
        //         continue;
        //     }
        //     // loopy-loop the results
        //     for (NSDictionary *entry in (__bridge NSDictionary *)result) {
        //         NSString *stringRes = [[NSString alloc] initWithData:[entry objectForKey:@"v_Data"]
        //                                                     encoding:NSUTF8StringEncoding];
        //         NSLog(@"%@", stringRes);
        //     }
        //     if (result != NULL) {
        //         CFRelease(result);
        //     }
        // }
        // http://nshipster.com/bool/
        const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);
        // the base query dictionary to use for the keychain lookups
        const searchDictionary = ObjC.classes.NSMutableDictionary.alloc().init();
        searchDictionary.setObject_forKey_(kCFBooleanTrue, constants_1.kSec.kSecReturnAttributes);
        searchDictionary.setObject_forKey_(kCFBooleanTrue, constants_1.kSec.kSecReturnData);
        searchDictionary.setObject_forKey_(kCFBooleanTrue, constants_1.kSec.kSecReturnRef);
        searchDictionary.setObject_forKey_(constants_1.kSec.kSecMatchLimitAll, constants_1.kSec.kSecMatchLimit);
        // loop each of the keychain class types and extract data
        const itemClassResults = itemClasses.map((clazz) => {
            const data = []; // start empty.
            searchDictionary.setObject_forKey_(clazz, constants_1.kSec.kSecClass);
            // prepare a pointer for the results and call SecItemCopyMatching to get them
            const resultsPointer = Memory.alloc(Process.pointerSize);
            const copyResult = libobjc_1.libObjc.SecItemCopyMatching(searchDictionary, resultsPointer);
            // without results (aka non-zero OSStatus) we just move along.
            if (!copyResult.isNull()) {
                return data;
            }
            // read the resultant dict of the lookup from memory
            const searchResults = new ObjC.Object(resultsPointer.readPointer());
            // if the results in the dict is empty (which is not something I expect),
            // fail fast too.
            if (searchResults.length <= 0) {
                return data;
            }
            // read each key chain entry for the current item_class and populate
            // the item_class items we will return
            for (let i = 0; i < searchResults.count(); i++) {
                data.push({
                    clazz,
                    data: searchResults.objectAtIndex_(i),
                });
            }
            return data;
        });
        return [].concat(...itemClassResults).filter((n) => n !== undefined);
    };
    // print raw entries using some Frida magic
    // to do the toString() repr...
    ioskeychain.listRaw = () => {
        enumerateKeychain().forEach((e) => {
            color_1.colors.log(e.data);
        });
    };
    // dump the contents of the iOS keychain, returning the
    // results as an array representation.
    ioskeychain.list = (smartDecode = false) => {
        return enumerateKeychain().map((entry) => {
            const { data, clazz } = entry;
            return {
                access_control: (data.containsKey_(constants_1.kSec.kSecAttrAccessControl)) ? decodeAcl(data) : "",
                accessible_attribute: helpers_1.reverseEnumLookup(constants_1.kSec, helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrAccessible))),
                account: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrAccount)),
                alias: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrAlias)),
                comment: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrComment)),
                create_date: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrCreationDate)),
                creator: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrCreator)),
                custom_icon: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrHasCustomIcon)),
                data: (clazz !== "keys") ?
                    (smartDecode) ?
                        helpers_2.smartDataToString(data.objectForKey_(constants_1.kSec.kSecValueData)) :
                        helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecValueData)) :
                    "(Key data not displayed)",
                dataHex: helpers_2.bytesToHexString(data.objectForKey_(constants_1.kSec.kSecValueData)),
                description: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrDescription)),
                entitlement_group: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrAccessGroup)),
                generic: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrGeneric)),
                invisible: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrIsInvisible)),
                item_class: helpers_1.reverseEnumLookup(constants_1.kSec, clazz),
                label: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrLabel)),
                modification_date: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrModificationDate)),
                negative: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrIsNegative)),
                protected: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecProtectedDataItemAttr)),
                script_code: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrScriptCode)),
                service: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrService)),
                type: helpers_2.bytesToUTF8(data.objectForKey_(constants_1.kSec.kSecAttrType)),
            };
        });
    };
    // clean out the keychain
    ioskeychain.empty = () => {
        const searchDictionary = ObjC.classes.NSMutableDictionary.alloc().init();
        itemClasses.forEach((clazz) => {
            // set the class-type we are querying for now & delete
            searchDictionary.setObject_forKey_(clazz, constants_1.kSec.kSecClass);
            libobjc_1.libObjc.SecItemDelete(searchDictionary);
        });
    };
    // add a string entry to the keychain
    ioskeychain.add = (account, service, data) => {
        // prepare the dictionary for SecItemAdd()
        const itemDict = ObjC.classes.NSMutableDictionary.alloc().init();
        itemDict.setObject_forKey_(constants_1.kSec.kSecClassGenericPassword, constants_1.kSec.kSecClass);
        [
            { "type": "account", "value": account, "ksec": constants_1.kSec.kSecAttrAccount },
            { "type": "service", "value": service, "ksec": constants_1.kSec.kSecAttrService },
            { "type": "data", "value": data, "ksec": constants_1.kSec.kSecValueData }
        ].forEach(e => {
            if (e.value == null)
                return;
            const v = ObjC.classes.NSString.stringWithString_(e.value)
                .dataUsingEncoding_(constants_1.NSUTF8StringEncoding);
            itemDict.setObject_forKey_(v, e.ksec);
        });
        // Add the keychain entry
        const result = libobjc_1.libObjc.SecItemAdd(itemDict, NULL);
        return result.isNull();
    };
    // decode the access control attributes on a keychain
    // entry into a human readable string. Getting an idea of what the
    // constraints actually are is done using an undocumented method,
    // SecAccessControlGetConstraints.
    const decodeAcl = (entry) => {
        const acl = new ObjC.Object(libobjc_1.libObjc.SecAccessControlGetConstraints(entry.objectForKey_(constants_1.kSec.kSecAttrAccessControl)));
        // Ensure we were able to get the SecAccessControlRef
        if (acl.handle.isNull()) {
            return "None";
        }
        const flags = [];
        const aclEnum = acl.keyEnumerator();
        let aclItemkey;
        // tslint:disable-next-line:no-conditional-assignment
        while ((aclItemkey = aclEnum.nextObject()) !== null) {
            const aclItem = acl.objectForKey_(aclItemkey);
            switch (helpers_2.smartDataToString(aclItemkey)) {
                // Defaults?
                case "dacl":
                    break;
                case "osgn":
                    flags.push("kSecAttrKeyClassPrivate");
                    break;
                case "od":
                    const constraints = aclItem;
                    const constraintEnum = constraints.keyEnumerator();
                    let constraintItemKey;
                    // tslint:disable-next-line:no-conditional-assignment
                    while ((constraintItemKey = constraintEnum.nextObject()) !== null) {
                        switch (helpers_2.smartDataToString(constraintItemKey)) {
                            case "cpo":
                                flags.push("kSecAccessControlUserPresence");
                                break;
                            case "cup":
                                flags.push("kSecAccessControlDevicePasscode");
                                break;
                            case "pkofn":
                                constraints.objectForKey_("pkofn") === 1 ?
                                    flags.push("Or") :
                                    flags.push("And");
                                break;
                            case "cbio":
                                constraints.objectForKey_("cbio").count() === 1 ?
                                    flags.push("kSecAccessControlBiometryAny") :
                                    flags.push("kSecAccessControlBiometryCurrentSet");
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case "prp":
                    flags.push("kSecAccessControlApplicationPassword");
                    break;
                default:
                    break;
            }
        }
        return flags.join(" ");
    };
})(ioskeychain = exports.ioskeychain || (exports.ioskeychain = {}));

},{"../lib/color":117,"../lib/helpers":119,"./lib/constants":109,"./lib/helpers":110,"./lib/libobjc":111}],109:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BundleType = exports.NSUTF8StringEncoding = exports.NSUserDomainMask = exports.NSSearchPaths = exports.kSec = void 0;
// constants used for Security Attributes etc.
// NSLog(@"kSecAttrService: %@", kSecAttrService);
var kSec;
(function (kSec) {
    // To reference some of the constants, the had to be echoed to
    // get their values.
    // NSLog(@"Constants Dump");
    // NSLog(@"kSecAttrService: %@", kSecAttrService);
    // NSLog(@"End Constants Dump");
    kSec["kSecReturnAttributes"] = "r_Attributes";
    kSec["kSecReturnData"] = "r_Data";
    kSec["kSecReturnRef"] = "r_Ref";
    kSec["kSecMatchLimit"] = "m_Limit";
    kSec["kSecMatchLimitAll"] = "m_LimitAll";
    kSec["kSecClass"] = "class";
    kSec["kSecClassKey"] = "keys";
    kSec["kSecClassIdentity"] = "idnt";
    kSec["kSecClassCertificate"] = "cert";
    kSec["kSecClassGenericPassword"] = "genp";
    kSec["kSecClassInternetPassword"] = "inet";
    kSec["kSecAttrService"] = "svce";
    kSec["kSecAttrAccount"] = "acct";
    kSec["kSecAttrAccessGroup"] = "agrp";
    kSec["kSecAttrLabel"] = "labl";
    kSec["kSecAttrCreationDate"] = "cdat";
    kSec["kSecAttrAccessControl"] = "accc";
    kSec["kSecAttrGeneric"] = "gena";
    kSec["kSecAttrSynchronizable"] = "sync";
    kSec["kSecAttrModificationDate"] = "mdat";
    kSec["kSecAttrServer"] = "srvr";
    kSec["kSecAttrDescription"] = "desc";
    kSec["kSecAttrComment"] = "icmt";
    kSec["kSecAttrCreator"] = "crtr";
    kSec["kSecAttrType"] = "type";
    kSec["kSecAttrScriptCode"] = "scrp";
    kSec["kSecAttrAlias"] = "alis";
    kSec["kSecAttrIsInvisible"] = "invi";
    kSec["kSecAttrIsNegative"] = "nega";
    kSec["kSecAttrHasCustomIcon"] = "cusi";
    kSec["kSecProtectedDataItemAttr"] = "prot";
    kSec["kSecAttrAccessible"] = "pdmn";
    kSec["kSecAttrAccessibleWhenUnlocked"] = "ak";
    kSec["kSecAttrAccessibleAfterFirstUnlock"] = "ck";
    kSec["kSecAttrAccessibleAlways"] = "dk";
    kSec["kSecAttrAccessibleWhenUnlockedThisDeviceOnly"] = "aku";
    kSec["kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"] = "akpu";
    kSec["kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"] = "cku";
    kSec["kSecAttrAccessibleAlwaysThisDeviceOnly"] = "dku";
    kSec["kSecValueData"] = "v_Data";
})(kSec = exports.kSec || (exports.kSec = {}));
// typedef NS_ENUM(NSUInteger, NSSearchPathDirectory) {
//     NSApplicationDirectory = 1,             // supported applications (Applications)
//     NSDemoApplicationDirectory,             // unsupported applications, demonstration versions (Demos)
// tslint:disable-next-line:max-line-length
//     NSDeveloperApplicationDirectory,        // developer applications (Developer/Applications). DEPRECATED - there is no one single Developer directory.
//     NSAdminApplicationDirectory,            // system and network administration applications (Administration)
// tslint:disable-next-line:max-line-length
//     NSLibraryDirectory,                     // various documentation, support, and configuration files, resources (Library)
// tslint:disable-next-line:max-line-length
//     NSDeveloperDirectory,                   // developer resources (Developer) DEPRECATED - there is no one single Developer directory.
//     NSUserDirectory,                        // user home directories (Users)
//     NSDocumentationDirectory,               // documentation (Documentation)
//     NSDocumentDirectory,                    // documents (Documents)
//     NSCoreServiceDirectory,                 // location of CoreServices directory (System/Library/CoreServices)
// tslint:disable-next-line:max-line-length
//     NSAutosavedInformationDirectory NS_ENUM_AVAILABLE(10_6, 4_0) = 11,   // location of autosaved documents (Documents/Autosaved)
//     NSDesktopDirectory = 12,                // location of user's desktop
//     NSCachesDirectory = 13,                 // location of discardable cache files (Library/Caches)
// tslint:disable-next-line:max-line-length
//     NSApplicationSupportDirectory = 14,     // location of application support files (plug-ins, etc) (Library/Application Support)
//
//     [... snip ...]
//
// };
var NSSearchPaths;
(function (NSSearchPaths) {
    NSSearchPaths[NSSearchPaths["NSApplicationDirectory"] = 1] = "NSApplicationDirectory";
    NSSearchPaths[NSSearchPaths["NSDemoApplicationDirectory"] = 2] = "NSDemoApplicationDirectory";
    NSSearchPaths[NSSearchPaths["NSDeveloperApplicationDirectory"] = 3] = "NSDeveloperApplicationDirectory";
    NSSearchPaths[NSSearchPaths["NSAdminApplicationDirectory"] = 4] = "NSAdminApplicationDirectory";
    NSSearchPaths[NSSearchPaths["NSLibraryDirectory"] = 5] = "NSLibraryDirectory";
    NSSearchPaths[NSSearchPaths["NSDeveloperDirectory"] = 6] = "NSDeveloperDirectory";
    NSSearchPaths[NSSearchPaths["NSUserDirectory"] = 7] = "NSUserDirectory";
    NSSearchPaths[NSSearchPaths["NSDocumentationDirectory"] = 8] = "NSDocumentationDirectory";
    NSSearchPaths[NSSearchPaths["NSDocumentDirectory"] = 9] = "NSDocumentDirectory";
    NSSearchPaths[NSSearchPaths["NSCoreServiceDirectory"] = 10] = "NSCoreServiceDirectory";
    NSSearchPaths[NSSearchPaths["NSAutosavedInformationDirectory"] = 11] = "NSAutosavedInformationDirectory";
    NSSearchPaths[NSSearchPaths["NSDesktopDirectory"] = 12] = "NSDesktopDirectory";
    NSSearchPaths[NSSearchPaths["NSCachesDirectory"] = 13] = "NSCachesDirectory";
    NSSearchPaths[NSSearchPaths["NSApplicationSupportDirectory"] = 14] = "NSApplicationSupportDirectory";
})(NSSearchPaths = exports.NSSearchPaths || (exports.NSSearchPaths = {}));
exports.NSUserDomainMask = 1;
exports.NSUTF8StringEncoding = 4;
var BundleType;
(function (BundleType) {
    BundleType[BundleType["NSBundleFramework"] = 1] = "NSBundleFramework";
    BundleType[BundleType["NSBundleAllBundles"] = 2] = "NSBundleAllBundles";
})(BundleType = exports.BundleType || (exports.BundleType = {}));

},{}],110:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hexToString = exports.arrayBufferToHex = exports.getNSMainBundle = exports.getNSFileManager = exports.bytesToHexString = exports.bytesToUTF8 = exports.smartDataToString = exports.unArchiveDataAndGetString = void 0;
const constants_1 = require("./constants");
// Attempt to unarchive data. Returning a string of `` indicates that the
// unarchiving failed.
const unArchiveDataAndGetString = (data) => {
    try {
        // tslint:disable-next-line:max-line-length
        // https://developer.apple.com/documentation/foundation/nskeyedunarchiver/1574811-unarchivetoplevelobjectwithdata
        // This one is marked as DEPRECATED, but seems to still be a thing in
        // iOS 12. Ok for now.
        const NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
        const unArchivedData = NSKeyedUnarchiver.unarchiveTopLevelObjectWithData_error_(data, NULL);
        // if we have a null value, this data is probably not archived
        if (unArchivedData === null) {
            return ``;
        }
        switch (unArchivedData.$className) {
            case "__NSDictionary":
            case "__NSDictionaryI":
                const dict = new ObjC.Object(unArchivedData);
                const enumerator = dict.keyEnumerator();
                let key;
                const s = {};
                // tslint:disable-next-line:no-conditional-assignment
                while ((key = enumerator.nextObject()) !== null) {
                    s[key] = `${dict.objectForKey_(key)}`;
                }
                return JSON.stringify(s);
            default:
                return ``;
        }
    }
    catch (e) {
        return data.toString();
    }
};
exports.unArchiveDataAndGetString = unArchiveDataAndGetString;
const smartDataToString = (raw) => {
    if (raw === null) {
        return "";
    }
    try {
        const dataObject = new ObjC.Object(raw);
        switch (dataObject.$className) {
            case "__NSCFData":
                try {
                    const unarchivedData = exports.unArchiveDataAndGetString(dataObject);
                    if (unarchivedData.length > 0) {
                        return unarchivedData;
                    }
                    // tslint:disable-next-line:no-empty
                }
                catch (e) { }
                try {
                    const data = dataObject.readUtf8String(dataObject.length());
                    if (data.length > 0) {
                        return data;
                    }
                    // tslint:disable-next-line:no-empty
                }
                catch (e) { }
            case "__NSCFNumber":
                return dataObject.integerValue();
            case "NSTaggedPointerString":
            case "__NSDate":
            case "__NSCFString":
            case "__NSTaggedDate":
                return dataObject.toString();
            default:
                return `(could not get string for class: ${dataObject.$className})`;
        }
    }
    catch (e) {
        return "(failed to decode)";
    }
};
exports.smartDataToString = smartDataToString;
const bytesToUTF8 = (data) => {
    // Sample Objective-C
    //
    // char buf[] = "\x41\x42\x43\x44";
    // NSString *p = [[NSString alloc] initWithBytes:buf length:5 encoding:NSUTF8StringEncoding];
    if (data === null) {
        return "";
    }
    if (!data.hasOwnProperty("bytes")) {
        return data.toString();
    }
    const s = ObjC.classes.NSString.alloc().initWithBytes_length_encoding_(data.bytes(), data.length(), constants_1.NSUTF8StringEncoding);
    if (s) {
        return s.UTF8String();
    }
    return "";
};
exports.bytesToUTF8 = bytesToUTF8;
const bytesToHexString = (data) => {
    // https://stackoverflow.com/a/50767210
    if (data == null) {
        return "";
    }
    const buffer = data.bytes().readByteArray(data.length());
    return Array.from(new Uint8Array(buffer)).map((b) => ("0" + b.toString(16)).substr(-2)).join("");
};
exports.bytesToHexString = bytesToHexString;
const getNSFileManager = () => {
    const NSFM = ObjC.classes.NSFileManager;
    return NSFM.defaultManager();
};
exports.getNSFileManager = getNSFileManager;
const getNSMainBundle = () => {
    const bundle = ObjC.classes.NSBundle;
    return bundle.mainBundle();
};
exports.getNSMainBundle = getNSMainBundle;
const arrayBufferToHex = (arrayBuffer) => {
    if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
        throw new TypeError('Expected input to be an ArrayBuffer');
    }
    const buffer = new Uint8Array(arrayBuffer);
    let result = '';
    let value;
    for (const byte of buffer) {
        value = byte.toString(16);
        result += (value.length === 1 ? '0' + value : value);
    }
    return result;
};
exports.arrayBufferToHex = arrayBufferToHex;
const hexToString = (hexx) => {
    const hex = hexx.toString(); // force conversion
    let str = '';
    for (let i = 0; (i < hex.length && hex.substr(i, 2) !== '00'); i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
};
exports.hexToString = hexToString;

},{"./constants":109}],111:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.libObjc = void 0;
const nativeExports = {
    // iOS keychain methods
    SecAccessControlGetConstraints: {
        argTypes: ["pointer"],
        exportName: "SecAccessControlGetConstraints",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemAdd: {
        argTypes: ["pointer", "pointer"],
        exportName: "SecItemAdd",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemCopyMatching: {
        argTypes: ["pointer", "pointer"],
        exportName: "SecItemCopyMatching",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemDelete: {
        argTypes: ["pointer"],
        exportName: "SecItemDelete",
        moduleName: "Security",
        retType: "pointer",
    },
    // SSL pinning methods
    SSLCreateContext: {
        argTypes: ["pointer", "int", "int"],
        exportName: "SSLCreateContext",
        moduleName: "Security",
        retType: "pointer",
    },
    SSLHandshake: {
        argTypes: ["pointer"],
        exportName: "SSLHandshake",
        moduleName: "Security",
        retType: "int",
    },
    SSLSetSessionOption: {
        argTypes: ["pointer", "int", "bool"],
        exportName: "SSLSetSessionOption",
        moduleName: "Security",
        retType: "int",
    },
    // iOS 10+ TLS methods
    nw_tls_create_peer_trust: {
        argTypes: ["pointer", "bool", "pointer"],
        exportName: "nw_tls_create_peer_trust",
        moduleName: "libnetwork.dylib",
        retType: "int",
    },
    tls_helper_create_peer_trust: {
        argTypes: ["pointer", "bool", "pointer"],
        exportName: "tls_helper_create_peer_trust",
        moduleName: "libcoretls_cfhelpers.dylib",
        retType: "int",
    },
    // iOS 11+ libboringssl methods
    SSL_CTX_set_custom_verify: {
        argTypes: ["pointer", "int", "pointer"],
        exportName: "SSL_CTX_set_custom_verify",
        moduleName: "libboringssl.dylib",
        retType: "void",
    },
    SSL_get_psk_identity: {
        argTypes: ["pointer"],
        exportName: "SSL_get_psk_identity",
        moduleName: "libboringssl.dylib",
        retType: "pointer",
    },
    // iOS 13+ libboringssl methods
    SSL_set_custom_verify: {
        argTypes: ["pointer", "int", "pointer"],
        exportName: "SSL_set_custom_verify",
        moduleName: "libboringssl.dylib",
        retType: "void",
    },
};
const api = {
    SecAccessControlGetConstraints: null,
    SecItemAdd: null,
    SecItemCopyMatching: null,
    SecItemDelete: null,
    SSLCreateContext: null,
    SSLHandshake: null,
    SSLSetSessionOption: null,
    nw_tls_create_peer_trust: null,
    tls_helper_create_peer_trust: null,
    SSL_CTX_set_custom_verify: null,
    SSL_get_psk_identity: null,
    SSL_set_custom_verify: null,
};
// proxy method resolution
exports.libObjc = new Proxy(api, {
    get: (target, key) => {
        if (target[key] === null) {
            const f = Module.findExportByName(nativeExports[key].moduleName, nativeExports[key].exportName) || new NativePointer(0x00);
            target[key] = new NativeFunction(f, nativeExports[key].retType, nativeExports[key].argTypes);
        }
        return target[key];
    },
});

},{}],112:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nsuserdefaults = void 0;
var nsuserdefaults;
(function (nsuserdefaults) {
    nsuserdefaults.get = () => {
        // -- Sample Objective-C
        //
        // NSUserDefaults *d = [[NSUserDefaults alloc] init];
        // NSLog(@"%@", [d dictionaryRepresentation]);
        const defaults = ObjC.classes.NSUserDefaults;
        const data = defaults.alloc().init().dictionaryRepresentation();
        return data.toString();
    };
})(nsuserdefaults = exports.nsuserdefaults || (exports.nsuserdefaults = {}));

},{}],113:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pasteboard = void 0;
const color_1 = require("../lib/color");
var pasteboard;
(function (pasteboard) {
    pasteboard.monitor = () => {
        // -- Sample Objective-C
        //
        // UIPasteboard *pb = [UIPasteboard generalPasteboard];
        // NSLog(@"%@", [pb string]);
        // NSLog(@"%@", [pb image]);
        const UIPasteboard = ObjC.classes.UIPasteboard;
        const Pasteboard = UIPasteboard.generalPasteboard();
        let data = "";
        setInterval(() => {
            const currentString = Pasteboard.string().toString();
            // do nothing if the strings are the same as the last one
            // we know about
            if (currentString === data) {
                return;
            }
            // update the string_data with the new string
            data = currentString;
            // ... and send the update along
            send(`${color_1.colors.blackBright(`[pasteboard-monitor]`)} Data: ${color_1.colors.greenBright(data.toString())}`);
            // 5 second poll
        }, 1000 * 5);
    };
})(pasteboard = exports.pasteboard || (exports.pasteboard = {}));

},{"../lib/color":117}],114:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sslpinning = void 0;
const color_1 = require("../lib/color");
const helpers_1 = require("../lib/helpers");
const jobs_1 = require("../lib/jobs");
const libobjc_1 = require("./lib/libobjc");
// These hooks attempt many ways to kill SSL pinning and certificate
// validations. The first sections search for common libraries and
// class methods used in many examples online to demonstrate how
// to pin SSL certificates.
// As far as libraries and classes go, this hook searches for:
//
//  - AFNetworking.
//      AFNetworking has a very easy pinning feature that can be disabled
//      by setting the 'PinningMode' to 'None'.
//
//  - NSURLSession.
//      NSURLSession makes use of a delegate method with the signature
//      'URLSession:didReceiveChallenge:completionHandler:' that allows
//      developers to extract the server presented certificate and make
//      decisions to complete the request or cancel it. The hook for this
//      Class searches for the selector and replaces it one that will
//      continue regardless of the logic in this method, and apply the
//      original block as a callback, with a successful return.
//
//  - NSURLConnection.
//      While an old method, works similar to NSURLSession, except there is
//      no completionHandler block, so just the successful challenge is returned.
// The more 'lower level' stuff is basically a reimplementation of the commonly
// known 'SSL-Killswitch2'[1], which hooks and replaces lower level certificate validation
// methods with ones that will always pass. An important note should be made on the
// implementation changes from iOS9 to iOS10 as detailed here[2]. This hook also tries
// to implement those for iOS10.
//  [1] https://github.com/nabla-c0d3/ssl-kill-switch2/blob/master/SSLKillSwitch/SSLKillSwitch.m
//  [2] https://nabla-c0d3.github.io/blog/2017/02/05/ios10-ssl-kill-switch/
// Many apps implement the SSL pinning in interesting ways, if this hook fails, all
// is not lost yet. Sometimes, there is a method that just checks some configuration
// item somewhere, and returns a BOOL, indicating whether pinning is applicable or
// not. So, hunt that method and hook it :)
var sslpinning;
(function (sslpinning) {
    // a simple flag to control if we should be quiet or not
    let quiet = false;
    const afNetworking = (ident) => {
        const { AFHTTPSessionManager, AFSecurityPolicy } = ObjC.classes;
        // If AFNetworking is not a thing, just move on.
        if (!(AFHTTPSessionManager && AFSecurityPolicy)) {
            return [];
        }
        send(color_1.colors.blackBright(`[${ident}] `) + `Found AFNetworking library. Hooking known pinning methods.`);
        // -[AFSecurityPolicy setSSLPinningMode:]
        const setSSLPinningmode = Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
            onEnter(args) {
                // typedef NS_ENUM(NSUInteger, AFSSLPinningMode) {
                //     AFSSLPinningModeNone,
                //     AFSSLPinningModePublicKey,
                //     AFSSLPinningModeCertificate,
                // };
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] Called ` +
                    color_1.colors.green(`-[AFSecurityPolicy setSSLPinningMode:]`) + ` with mode ` +
                    color_1.colors.red(args[2].toString()));
                if (!args[2].isNull()) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`-[AFSecurityPolicy setSSLPinningMode:]`) + ` mode to ` +
                        color_1.colors.green(`0x0`));
                    // update mode to 0 (AFSSLPinningModeNone), bypassing it.
                    args[2] = new NativePointer(0x0);
                }
            },
        });
        // -[AFSecurityPolicy setAllowInvalidCertificates:]
        const setAllowInvalidCertificates = Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
            onEnter(args) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] Called ` +
                    color_1.colors.green(`-[AFSecurityPolicy setAllowInvalidCertificates:]`) + ` with allow ` +
                    color_1.colors.red(args[2].toString()));
                if (args[2].equals(new NativePointer(0x0))) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`-[AFSecurityPolicy setAllowInvalidCertificates:]`) + ` allow to ` +
                        color_1.colors.green(`0x1`));
                    // Basically, do [policy setAllowInvalidCertificates:YES];
                    args[2] = new NativePointer(0x1);
                }
            },
        });
        // +[AFSecurityPolicy policyWithPinningMode:]
        const policyWithPinningMode = Interceptor.attach(AFSecurityPolicy["+ policyWithPinningMode:"].implementation, {
            onEnter(args) {
                // typedef NS_ENUM(NSUInteger, AFSSLPinningMode) {
                //     AFSSLPinningModeNone,
                //     AFSSLPinningModePublicKey,
                //     AFSSLPinningModeCertificate,
                // };
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] Called ` +
                    color_1.colors.green(`+[AFSecurityPolicy policyWithPinningMode:]`) + ` with mode ` +
                    color_1.colors.red(args[2].toString()));
                if (!args[2].isNull()) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`+[AFSecurityPolicy policyWithPinningMode:]`) + ` mode to ` +
                        color_1.colors.green(`0x0`));
                    // effectively set to AFSSLPinningModeNone
                    args[2] = new NativePointer(0x0);
                }
            },
        });
        // +[AFSecurityPolicy policyWithPinningMode:withPinnedCertificates:]
        const policyWithPinningModewithPinnedCertificates = (AFSecurityPolicy["+ policyWithPinningMode:withPinnedCertificates:"]) ? Interceptor.attach(AFSecurityPolicy["+ policyWithPinningMode:withPinnedCertificates:"].implementation, {
            onEnter(args) {
                // typedef NS_ENUM(NSUInteger, AFSSLPinningMode) {
                //     AFSSLPinningModeNone,
                //     AFSSLPinningModePublicKey,
                //     AFSSLPinningModeCertificate,
                // };
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] Called ` +
                    color_1.colors.green(`+[AFSecurityPolicy policyWithPinningMode:withPinnedCertificates:]`) + ` with mode ` +
                    color_1.colors.red(args[2].toString()));
                if (!args[2].isNull()) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`+[AFSecurityPolicy policyWithPinningMode:withPinnedCertificates:]`) + ` mode to ` +
                        color_1.colors.green(`0x0`));
                    // effectively set to AFSSLPinningModeNone
                    args[2] = new NativePointer(0x0);
                }
            },
        }) : null;
        return [
            setSSLPinningmode,
            setAllowInvalidCertificates,
            policyWithPinningMode,
            policyWithPinningModewithPinnedCertificates,
        ];
    };
    const nsUrlSession = (ident) => {
        const NSURLCredential = ObjC.classes.NSURLCredential;
        const resolver = new ApiResolver("objc");
        // - [NSURLSession URLSession:didReceiveChallenge:completionHandler:]
        const search = resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]");
        // Move along if no NSURLSession usage is found
        if (search.length <= 0) {
            return [];
        }
        send(color_1.colors.blackBright(`Found NSURLSession based classes. Hooking known pinning methods.`));
        // hook all of the methods that matched the selector
        return search.map((i) => {
            return Interceptor.attach(i.address, {
                onEnter(args) {
                    // 0
                    // 1
                    // 2 URLSession
                    // 3 didReceiveChallenge
                    // 4 completionHandler
                    const receiver = new ObjC.Object(args[0]);
                    const selector = ObjC.selectorAsString(args[1]);
                    const challenge = new ObjC.Object(args[3]);
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[AFNetworking] Called ` +
                        color_1.colors.green(`-[${receiver} ${selector}]`) + `, ensuring pinning is passed`);
                    // get the original completion handler, and save it
                    const completionHandler = new ObjC.Block(args[4]);
                    const savedCompletionHandler = completionHandler.implementation;
                    // ignore everything the original method wanted to do,
                    // and prepare the successful arguments for the original
                    // completion handler
                    completionHandler.implementation = () => {
                        // Example handler source
                        // SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
                        // SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
                        // NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
                        // NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"swapi.co" ofType:@"der"];
                        // NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
                        // if ([remoteCertificateData isEqualToData:localCertData]) {
                        //     NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
                        //     [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
                        //     completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                        // } else {
                        //     [[challenge sender] cancelAuthenticationChallenge:challenge];
                        //     completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
                        // }
                        const credential = NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                        challenge.sender().useCredential_forAuthenticationChallenge_(credential, challenge);
                        // typedef NS_ENUM(NSInteger, NSURLSessionAuthChallengeDisposition) {
                        //     NSURLSessionAuthChallengeUseCredential = 0,
                        //     NSURLSessionAuthChallengePerformDefaultHandling = 1,
                        //     NSURLSessionAuthChallengeCancelAuthenticationChallenge = 2,
                        //     NSURLSessionAuthChallengeRejectProtectionSpace = 3,
                        // } NS_ENUM_AVAILABLE(NSURLSESSION_AVAILABLE, 7_0);
                        savedCompletionHandler(0, credential);
                    };
                },
            });
        });
    };
    // TrustKit
    const trustKit = (ident) => {
        // https://github.com/datatheorem/TrustKit/blob/
        //  71878dce8c761fc226fecc5dbb6e86fbedaee05e/TrustKit/TSKPinningValidator.m#L84
        if (!ObjC.classes.TSKPinningValidator) {
            return;
        }
        send(color_1.colors.blackBright(`[${ident}] `) + `Found TrustKit. Hooking known pinning methods.`);
        return Interceptor.attach(ObjC.classes.TSKPinningValidator["- evaluateTrust:forHostname:"].implementation, {
            onLeave(retval) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[TrustKit] Called ` +
                    color_1.colors.green(`-[TSKPinningValidator evaluateTrust:forHostname:]`) + ` with result ` +
                    color_1.colors.red(retval.toString()));
                if (!retval.isNull()) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[TrustKit] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`-[TSKPinningValidator evaluateTrust:forHostname:]`) + ` mode to ` +
                        color_1.colors.green(`0x0`));
                    retval.replace(new NativePointer(0x0));
                }
            },
        });
    };
    const cordovaCustomURLConnectionDelegate = (ident) => {
        // https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin/blob/
        //  67634bfdf4a31bb09b301db40f8f27fbd8818f61/src/ios/SSLCertificateChecker.m#L109-L116
        if (!ObjC.classes.CustomURLConnectionDelegate) {
            return;
        }
        send(color_1.colors.blackBright(`[${ident}] `) + `Found SSLCertificateChecker-PhoneGap-Plugin.` +
            ` Hooking known pinning methods.`);
        return Interceptor.attach(ObjC.classes.CustomURLConnectionDelegate["- isFingerprintTrusted:"].implementation, {
            onLeave(retval) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[SSLCertificateChecker-PhoneGap-Plugin] Called ` +
                    color_1.colors.green(`-[CustomURLConnectionDelegate isFingerprintTrusted:]`) + ` with result ` +
                    color_1.colors.red(retval.toString()));
                if (retval.isNull()) {
                    helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `[SSLCertificateChecker-PhoneGap-Plugin] ` +
                        color_1.colors.blueBright(`Altered `) +
                        color_1.colors.green(`-[CustomURLConnectionDelegate isFingerprintTrusted:]`) + ` mode to ` +
                        color_1.colors.green(`0x1`));
                    retval.replace(new NativePointer(0x1));
                }
            },
        });
    };
    const sSLSetSessionOption = (ident) => {
        const kSSLSessionOptionBreakOnServerAuth = 0;
        const noErr = 0;
        const SSLSetSessionOption = libobjc_1.libObjc.SSLSetSessionOption;
        Interceptor.replace(SSLSetSessionOption, new NativeCallback((context, option, value) => {
            // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
            //  ^ from SSL-Kill-Switch2 sources
            // https://github.com/nabla-c0d3/ssl-kill-switch2/blob/
            //  f7e73a2044340d59f2b96d972afcbc3c2f50ab27/SSLKillSwitch/SSLKillSwitch.m#L70
            if (option === kSSLSessionOptionBreakOnServerAuth) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                    color_1.colors.green(`SSLSetSessionOption()`) +
                    `, removing ability to modify kSSLSessionOptionBreakOnServerAuth.`);
                return noErr;
            }
            return SSLSetSessionOption(context, option, value);
        }, "int", ["pointer", "int", "bool"]));
        return SSLSetSessionOption;
    };
    const sSLCreateContext = (ident) => {
        const kSSLSessionOptionBreakOnServerAuth = 0;
        const SSLSetSessionOption = libobjc_1.libObjc.SSLSetSessionOption;
        const SSLCreateContext = libobjc_1.libObjc.SSLCreateContext;
        Interceptor.replace(SSLCreateContext, new NativeCallback((alloc, protocolSide, connectionType) => {
            // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
            //  ^ from SSL-Kill-Switch2 sources
            //  https://github.com/nabla-c0d3/ssl-kill-switch2/blob/
            //    f7e73a2044340d59f2b96d972afcbc3c2f50ab27/SSLKillSwitch/SSLKillSwitch.m#L89
            const sslContext = SSLCreateContext(alloc, protocolSide, connectionType);
            SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, 1);
            helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                color_1.colors.green(`SSLCreateContext()`) +
                `, setting kSSLSessionOptionBreakOnServerAuth to disable cert validation.`);
            return sslContext;
        }, "pointer", ["pointer", "int", "int"]));
        return SSLCreateContext;
    };
    const sSLHandshake = (ident) => {
        const errSSLServerAuthCompared = -9481;
        const SSLHandshake = libobjc_1.libObjc.SSLHandshake;
        Interceptor.replace(SSLHandshake, new NativeCallback((context) => {
            const result = SSLHandshake(context);
            if (result === errSSLServerAuthCompared) {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                    color_1.colors.green(`SSLHandshake()`) +
                    `, calling again to skip certificate validation.`);
                return SSLHandshake(context);
            }
            return result;
        }, "int", ["pointer"]));
        return SSLHandshake;
    };
    // tls_helper_create_peer_trust
    const tlsHelperCreatePeerTrust = (ident) => {
        const noErr = 0;
        const tlsHelper = libobjc_1.libObjc.tls_helper_create_peer_trust;
        if (tlsHelper.isNull()) {
            return null;
        }
        Interceptor.replace(tlsHelper, new NativeCallback((hdsk, server, SecTrustRef) => {
            helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                color_1.colors.green(`tls_helper_create_peer_trust()`) +
                `, returning noErr.`);
            return noErr;
        }, "int", ["pointer", "bool", "pointer"]));
        return tlsHelper;
    };
    // nw_tls_create_peer_trust
    const nwTlsCreatePeerTrust = (ident) => {
        const peerTrust = libobjc_1.libObjc.nw_tls_create_peer_trust;
        if (peerTrust.isNull()) {
            return null;
        }
        return Interceptor.attach(peerTrust, {
            onEnter: () => {
                helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                    color_1.colors.green(`nw_tls_create_peer_trust()`) +
                    `, ` +
                    color_1.colors.red(`no working bypass implemented yet.`));
            },
        });
        // TODO: nw_tls_create_peer_trust() always returns 0, but also seems to have
        // some internal logic that makes a simple replacement not work.
        //
        // const noErr = 0;
        // Interceptor.replace(peerTrust, new NativeCallback((hdsk, server, SecTrustRef) => {
        //   send(
        //     c.blackBright(`[${ident}] `) + `Called ` +
        //     c.green(`nw_tls_create_peer_trust()`) +
        //     `, returning noErr.`,
        //   );
        //   return noErr;
        // }, "int", ["pointer", "bool", "pointer"]));
        // return peerTrust;
    };
    // SSL_CTX_set_custom_verify
    const sSLCtxSetCustomVerify = (ident) => {
        const getPskIdentity = libobjc_1.libObjc.SSL_get_psk_identity;
        let setCustomVerify = libobjc_1.libObjc.SSL_set_custom_verify;
        if (setCustomVerify.isNull()) {
            send(color_1.colors.blackBright(`SSL_set_custom_verify not found, trying SSL_CTX_set_custom_verify`));
            setCustomVerify = libobjc_1.libObjc.SSL_CTX_set_custom_verify;
        }
        if (setCustomVerify.isNull() || getPskIdentity.isNull()) {
            return null;
        }
        // tslint:disable-next-line:only-arrow-functions variable-name
        const customVerifyCallback = new NativeCallback(function (ssl, out_alert) {
            helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                color_1.colors.green(`custom SSL context verify callback`) +
                `, returning SSL_VERIFY_NONE.`);
            return 0;
        }, "int", ["pointer", "pointer"]);
        // tslint:disable-next-line:only-arrow-functions
        Interceptor.replace(setCustomVerify, new NativeCallback(function (ssl, mode, callback) {
            helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                color_1.colors.green(`SSL_CTX_set_custom_verify()`) +
                `, setting custom callback.`);
            setCustomVerify(ssl, mode, customVerifyCallback);
        }, "void", ["pointer", "int", "pointer"]));
        // tslint:disable-next-line:only-arrow-functions
        Interceptor.replace(getPskIdentity, new NativeCallback(function (ssl) {
            helpers_1.qsend(quiet, color_1.colors.blackBright(`[${ident}] `) + `Called ` +
                color_1.colors.green(`SSL_get_psk_identity()`) +
                `, returning "fakePSKidentity".`);
            return "fakePSKidentity";
        }, "pointer", ["pointer"]));
    };
    // exposed method to setup all of the interceptor invocations and replacements
    sslpinning.disable = (q) => {
        if (q) {
            send(`Quiet mode enabled. Not reporting invocations.`);
            quiet = true;
        }
        const job = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            replacements: [],
            type: "ios-sslpinning-disable",
        };
        // Framework hooks.
        send(color_1.colors.blackBright(`Hooking common framework methods`));
        afNetworking(job.identifier).forEach((i) => {
            job.invocations.push(i);
        });
        nsUrlSession(job.identifier).forEach((i) => {
            job.invocations.push(i);
        });
        job.invocations.push(trustKit(job.identifier));
        job.invocations.push(cordovaCustomURLConnectionDelegate(job.identifier));
        // Low level hooks.
        // iOS 9<
        send(color_1.colors.blackBright(`Hooking lower level SSL methods`));
        job.replacements.push(sSLSetSessionOption(job.identifier));
        job.replacements.push(sSLCreateContext(job.identifier));
        job.replacements.push(sSLHandshake(job.identifier));
        // iOS 10>
        send(color_1.colors.blackBright(`Hooking lower level TLS methods`));
        job.replacements.push(tlsHelperCreatePeerTrust(job.identifier));
        job.invocations.push(nwTlsCreatePeerTrust(job.identifier));
        // iOS 11>
        send(color_1.colors.blackBright(`Hooking BoringSSL methods`));
        job.invocations.push(sSLCtxSetCustomVerify(job.identifier));
        jobs_1.jobs.add(job);
    };
})(sslpinning = exports.sslpinning || (exports.sslpinning = {}));

},{"../lib/color":117,"../lib/helpers":119,"../lib/jobs":120,"./lib/libobjc":111}],115:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.plist = void 0;
var plist;
(function (plist) {
    plist.read = (path) => {
        // -- Sample Objective-C
        //
        // NSMutableDictionary *result = [[NSMutableDictionary alloc] initWithContentsOfFile:path];
        const dictionary = ObjC.classes.NSMutableDictionary;
        return dictionary.alloc().initWithContentsOfFile_(path).toString();
    };
    plist.write = (path, data) => {
        // TODO
    };
})(plist = exports.plist || (exports.plist = {}));

},{}],116:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.userinterface = void 0;
// tslint:disable-next-line:no-var-requires
const sc = require("frida-screenshot");
const color_1 = require("../lib/color");
const jobs_1 = require("../lib/jobs");
var userinterface;
(function (userinterface) {
    userinterface.screenshot = () => {
        // heavy lifting thanks to frida-screenshot!
        // https://github.com/nowsecure/frida-screenshot
        return sc();
    };
    userinterface.dump = () => {
        return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();
    };
    userinterface.alert = (message) => {
        const { UIAlertController, UIAlertAction, UIApplication } = ObjC.classes;
        // Defining a Block that will be passed as handler parameter
        // to +[UIAlertAction actionWithTitle:style:handler:]
        const handler = new ObjC.Block({
            argTypes: ["object"],
            implementation: () => { return; },
            retType: "void",
        });
        // Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
        ObjC.schedule(ObjC.mainQueue, () => {
            // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
            const alertController = UIAlertController.alertControllerWithTitle_message_preferredStyle_("Alert", message, 1);
            // Again using integer numeral for style parameter that is enum
            const okButton = UIAlertAction.actionWithTitle_style_handler_("OK", 0, handler);
            alertController.addAction_(okButton);
            // Instead of using `ObjC.choose()` and looking for UIViewController instances
            // on the heap, we have direct access through UIApplication:
            UIApplication.sharedApplication().keyWindow()
                .rootViewController().presentViewController_animated_completion_(alertController, true, NULL);
        });
    };
    userinterface.biometricsBypass = () => {
        // -- Sample Objective-C
        //
        // LAContext *myContext = [[LAContext alloc] init];
        // NSError *authError = nil;
        // NSString *myLocalizedReasonString = @"Please authenticate.";
        // if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
        //     [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication
        //               localizedReason:myLocalizedReasonString
        //                         reply:^(BOOL success, NSError *error) {
        //                             if (success) {
        //                                 dispatch_async(dispatch_get_main_queue(), ^{
        //                                     [self performSegueWithIdentifier:@"LocalAuthSuccess" sender:nil];
        //                                 });
        //                             } else {
        //                                 dispatch_async(dispatch_get_main_queue(), ^{
        //                                     UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"Error"
        //                                                                                         message:error.description
        //                                                                                         delegate:self
        //                                                                                cancelButtonTitle:@"OK"
        //                                                                                otherButtonTitles:nil, nil];
        //                                     [alertView show];
        //                                     // Rather than show a UIAlert here, use the
        //                                     // error to determine if you should push to a keypad for PIN entry.
        //                                 });
        //                             }
        //                         }];
        const policyJob = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: "ios-biometrics-disable-evaluatePolicy",
        };
        const lacontext1 = Interceptor.attach(ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
            onEnter(args) {
                // localizedReason:
                const reason = new ObjC.Object(args[3]);
                send(color_1.colors.blackBright(`[${policyJob.identifier}] `) + `Localized Reason for auth requirement (evaluatePolicy): ` +
                    color_1.colors.green(reason.toString()));
                // get the original block that should run on success for reply:
                // and save that block as a callback, to run once we change the reply
                // from the OS to a true
                const originalBlock = new ObjC.Block(args[4]);
                const savedReplyBlock = originalBlock.implementation;
                originalBlock.implementation = (success, error) => {
                    send(color_1.colors.blackBright(`[${policyJob.identifier}] `) + `OS authentication response: ` +
                        color_1.colors.red(success));
                    if (!success === true) {
                        send(color_1.colors.blackBright(`[${policyJob.identifier}] `) +
                            color_1.colors.greenBright("Marking OS response as True instead"));
                        // Change the success response from the OS to true
                        success = true;
                        error = null;
                    }
                    // and run the original block
                    savedReplyBlock(success, error);
                    send(color_1.colors.blackBright(`[${policyJob.identifier}] `) +
                        color_1.colors.green("Biometrics bypass hook complete (evaluatePolicy)"));
                };
            },
        });
        // register the job
        policyJob.invocations.push(lacontext1);
        jobs_1.jobs.add(policyJob);
        // -- Sample Swift
        // https://gist.github.com/algrid/f3f03915f264f243b9d06e875ad198c8/raw/03998319903ad9d939f85bbcc94ce9c23042b82b/KeychainBio.swift
        const accessControlJob = {
            identifier: jobs_1.jobs.identifier(),
            invocations: [],
            type: "ios-biometrics-disable-evaluateAccessControl",
        };
        const lacontext2 = Interceptor.attach(ObjC.classes.LAContext["- evaluateAccessControl:operation:localizedReason:reply:"].implementation, {
            onEnter(args) {
                // localizedReason:
                const reason = new ObjC.Object(args[4]);
                send(color_1.colors.blackBright(`[${accessControlJob.identifier}] `) + `Localized Reason for auth requirement (evaluateAccessControl): ` +
                    color_1.colors.green(reason.toString()));
                // get the original block that should run on success for reply:
                // and save that block as a callback, to run once we change the reply
                // from the OS to a true
                const originalBlock = new ObjC.Block(args[5]);
                const savedReplyBlock = originalBlock.implementation;
                originalBlock.implementation = (success, error) => {
                    send(color_1.colors.blackBright(`[${accessControlJob.identifier}] `) + `OS authentication response: ` +
                        color_1.colors.red(success));
                    if (!success === true) {
                        send(color_1.colors.blackBright(`[${accessControlJob.identifier}] `) +
                            color_1.colors.greenBright("Marking OS response as True instead"));
                        // Change the success response from the OS to true
                        success = true;
                        error = null;
                    }
                    // and run the original block
                    savedReplyBlock(success, error);
                    send(color_1.colors.blackBright(`[${accessControlJob.identifier}] `) +
                        color_1.colors.green("Biometrics bypass hook complete (evaluateAccessControl)"));
                };
            },
        });
        // register the job
        accessControlJob.invocations.push(lacontext2);
        jobs_1.jobs.add(accessControlJob);
    };
})(userinterface = exports.userinterface || (exports.userinterface = {}));

},{"../lib/color":117,"../lib/jobs":120,"frida-screenshot":31}],117:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.colors = void 0;
var colors;
(function (colors) {
    const base = `\x1B[%dm`;
    const reset = `\x1b[39m`;
    colors.black = (message) => colors.ansify(30, message);
    colors.blue = (message) => colors.ansify(34, message);
    colors.cyan = (message) => colors.ansify(36, message);
    colors.green = (message) => colors.ansify(32, message);
    colors.magenta = (message) => colors.ansify(35, message);
    colors.red = (message) => colors.ansify(31, message);
    colors.white = (message) => colors.ansify(37, message);
    colors.yellow = (message) => colors.ansify(33, message);
    colors.blackBright = (message) => colors.ansify(90, message);
    colors.redBright = (message) => colors.ansify(91, message);
    colors.greenBright = (message) => colors.ansify(92, message);
    colors.yellowBright = (message) => colors.ansify(93, message);
    colors.blueBright = (message) => colors.ansify(94, message);
    colors.cyanBright = (message) => colors.ansify(96, message);
    colors.whiteBright = (message) => colors.ansify(97, message);
    // return an ansified string
    colors.ansify = (color, ...msg) => base.replace(`%d`, color.toString()) + msg.join(``) + reset;
    // tslint:disable-next-line:no-eval
    colors.clog = (color, ...msg) => eval("console").log(colors.ansify(color, ...msg));
    // tslint:disable-next-line:no-eval
    colors.log = (...msg) => eval("console").log(msg.join(``));
    // log based on a quiet flag
    colors.qlog = (quiet, ...msg) => {
        if (quiet === false) {
            colors.log(...msg);
        }
    };
})(colors = exports.colors || (exports.colors = {}));

},{}],118:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DeviceType = void 0;
var DeviceType;
(function (DeviceType) {
    DeviceType["IOS"] = "ios";
    DeviceType["ANDROID"] = "android";
    DeviceType["UNKNOWN"] = "unknown";
})(DeviceType = exports.DeviceType || (exports.DeviceType = {}));

},{}],119:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.debugDump = exports.fsend = exports.qsend = exports.hexStringToBytes = exports.reverseEnumLookup = void 0;
const util_1 = __importDefault(require("util"));
const color_1 = require("./color");
// sure, TS does not support this, but meh.
// https://www.reddit.com/r/typescript/comments/87i59e/beginner_advice_strongly_typed_function_for/
function reverseEnumLookup(enumType, value) {
    for (const key in enumType) {
        if (Object.hasOwnProperty.call(enumType, key) && enumType[key] === value) {
            return key;
        }
    }
    return undefined;
}
exports.reverseEnumLookup = reverseEnumLookup;
// converts a hexstring to a bytearray
const hexStringToBytes = (str) => {
    const a = [];
    for (let i = 0, len = str.length; i < len; i += 2) {
        a.push(parseInt(str.substr(i, 2), 16));
    }
    return new Uint8Array(a);
};
exports.hexStringToBytes = hexStringToBytes;
// only send if quiet is not true
const qsend = (quiet, message) => {
    if (quiet === false) {
        send(message);
    }
};
exports.qsend = qsend;
// send a preformated dict
const fsend = (ident, hook, message) => {
    send(color_1.colors.blackBright(`[${ident}] `) +
        color_1.colors.magenta(`[${hook}]`) +
        printArgs(message));
};
exports.fsend = fsend;
// a small helper method to use util to dump
const debugDump = (o, depth = 2) => {
    color_1.colors.log(color_1.colors.blackBright("\n[start debugDump]"));
    color_1.colors.log(util_1.default.inspect(o, true, depth, true));
    color_1.colors.log(color_1.colors.blackBright("[end debugDump]\n"));
};
exports.debugDump = debugDump;
// a small helper method to format JSON nicely before printing
function printArgs(args) {
    let printableString = " (\n";
    for (const arg in args) {
        printableString += `  ${color_1.colors.blue(arg)} : ${args[arg]}\n`;
    }
    printableString += ")";
    return printableString;
}

},{"./color":117,"util":78}],120:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jobs = void 0;
const color_1 = require("./color");
var jobs;
(function (jobs) {
    // a record of all of the jobs in the current process
    let currentJobs = [];
    jobs.identifier = () => Math.random().toString(36).substring(2, 8);
    jobs.all = () => currentJobs;
    jobs.add = (jobData) => {
        send(`Registering job ` + color_1.colors.blueBright(`${jobData.identifier}`) +
            `. Type: ` + color_1.colors.greenBright(`${jobData.type}`));
        currentJobs.push(jobData);
    };
    // determine of a job already exists based on an identifier
    jobs.hasIdent = (ident) => {
        const m = currentJobs.filter((job) => {
            if (job.identifier === ident) {
                return true;
            }
        });
        return m.length > 0;
    };
    // determine if a job already exists based on a type
    jobs.hasType = (type) => {
        const m = currentJobs.filter((job) => {
            if (job.type === type) {
                return true;
            }
        });
        return m.length > 0;
    };
    // kills a job by detaching any invocations and removing
    // the job by identifier
    jobs.kill = (ident) => {
        currentJobs.forEach((job) => {
            if (job.identifier === ident) {
                // detach any invocations
                if (job.invocations && job.invocations.length > 0) {
                    job.invocations.forEach((invocation) => {
                        (invocation) ? invocation.detach() :
                            color_1.colors.log(color_1.colors.blackBright(`[warn] Skipping detach on null`));
                    });
                }
                // revert any replacements
                if (job.replacements && job.replacements.length > 0) {
                    job.replacements.forEach((replacement) => {
                        Interceptor.revert(replacement);
                    });
                }
                // remove implementation replacements
                if (job.implementations && job.implementations.length > 0) {
                    job.implementations.forEach((method) => {
                        // TODO: May be racy if the method is currently used.
                        method.implementation = null;
                    });
                }
                // remove the job from the current jobs
                currentJobs = currentJobs.filter((j) => {
                    return j.identifier !== job.identifier;
                });
            }
        });
        return true;
    };
})(jobs = exports.jobs || (exports.jobs = {}));

},{"./color":117}],121:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.android = void 0;
const clipboard_1 = require("../android/clipboard");
const filesystem_1 = require("../android/filesystem");
const heap_1 = require("../android/heap");
const hooking_1 = require("../android/hooking");
const intent_1 = require("../android/intent");
const keystore_1 = require("../android/keystore");
const pinning_1 = require("../android/pinning");
const root_1 = require("../android/root");
const shell_1 = require("../android/shell");
const userinterface_1 = require("../android/userinterface");
const proxy_1 = require("../android/proxy");
const general_1 = require("../android/general");
exports.android = {
    // android clipboard
    androidMonitorClipboard: () => clipboard_1.clipboard.monitor(),
    // android general
    androidDeoptimize: () => general_1.general.deoptimize(),
    // android command execution
    androidShellExec: (cmd) => shell_1.androidshell.execute(cmd),
    // android filesystem
    androidFileCwd: () => filesystem_1.androidfilesystem.pwd(),
    androidFileDelete: (path) => filesystem_1.androidfilesystem.deleteFile(path),
    androidFileDownload: (path) => filesystem_1.androidfilesystem.readFile(path),
    androidFileExists: (path) => filesystem_1.androidfilesystem.exists(path),
    androidFileLs: (path) => filesystem_1.androidfilesystem.ls(path),
    androidFilePathIsFile: (path) => filesystem_1.androidfilesystem.pathIsFile(path),
    androidFileReadable: (path) => filesystem_1.androidfilesystem.readable(path),
    androidFileUpload: (path, data) => filesystem_1.androidfilesystem.writeFile(path, data),
    androidFileWritable: (path) => filesystem_1.androidfilesystem.writable(path),
    // android hooking
    androidHookingGetClassMethods: (className) => hooking_1.hooking.getClassMethods(className),
    androidHookingGetClasses: () => hooking_1.hooking.getClasses(),
    androidHookingGetClassLoaders: () => hooking_1.hooking.getClassLoaders(),
    androidHookingGetCurrentActivity: () => hooking_1.hooking.getCurrentActivity(),
    androidHookingListActivities: () => hooking_1.hooking.getActivities(),
    androidHookingListBroadcastReceivers: () => hooking_1.hooking.getBroadcastReceivers(),
    androidHookingListServices: () => hooking_1.hooking.getServices(),
    androidHookingSetMethodReturn: (fqClazz, filterOverload, ret) => hooking_1.hooking.setReturnValue(fqClazz, filterOverload, ret),
    androidHookingWatchClass: (clazz) => hooking_1.hooking.watchClass(clazz),
    androidHookingWatchMethod: (fqClazz, filterOverload, dargs, dbt, dret) => hooking_1.hooking.watchMethod(fqClazz, filterOverload, dargs, dbt, dret),
    // android heap methods
    androidHeapEvaluateHandleMethod: (handle, js) => heap_1.heap.evaluate(handle, js),
    androidHeapExecuteHandleMethod: (handle, method, returnString) => heap_1.heap.execute(handle, method, returnString),
    androidHeapGetLiveClassInstances: (clazz) => heap_1.heap.getInstances(clazz),
    androidHeapPrintFields: (handle) => heap_1.heap.fields(handle),
    androidHeapPrintMethods: (handle) => heap_1.heap.methods(handle),
    // android intents
    androidIntentStartActivity: (activityClass) => intent_1.intent.startActivity(activityClass),
    androidIntentStartService: (serviceClass) => intent_1.intent.startService(serviceClass),
    // android keystore
    androidKeystoreClear: () => keystore_1.keystore.clear(),
    androidKeystoreList: () => keystore_1.keystore.list(),
    androidKeystoreWatch: () => keystore_1.keystore.watchKeystore(),
    // android ssl pinning
    androidSslPinningDisable: (quiet) => pinning_1.sslpinning.disable(quiet),
    // android proxy set/unset
    androidProxySet: (host, port) => proxy_1.proxy.set(host, port),
    // android root detection
    androidRootDetectionDisable: () => root_1.root.disable(),
    androidRootDetectionEnable: () => root_1.root.enable(),
    // android user interface
    androidUiScreenshot: () => userinterface_1.userinterface.screenshot(),
    androidUiSetFlagSecure: (v) => userinterface_1.userinterface.setFlagSecure(v),
};

},{"../android/clipboard":80,"../android/filesystem":81,"../android/general":82,"../android/heap":83,"../android/hooking":84,"../android/intent":85,"../android/keystore":86,"../android/pinning":88,"../android/proxy":89,"../android/root":90,"../android/shell":91,"../android/userinterface":92}],122:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.env = void 0;
const environment_1 = require("../generic/environment");
exports.env = {
    // environment
    envAndroid: () => environment_1.environment.androidPackage(),
    envAndroidPaths: () => environment_1.environment.androidPaths(),
    envFrida: () => environment_1.environment.frida(),
    envIos: () => environment_1.environment.iosPackage(),
    envIosPaths: () => environment_1.environment.iosPaths(),
    envRuntime: () => environment_1.environment.runtime(),
};

},{"../generic/environment":94}],123:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ios = void 0;
const binary_1 = require("../ios/binary");
const binarycookies_1 = require("../ios/binarycookies");
const bundles_1 = require("../ios/bundles");
const credentialstorage_1 = require("../ios/credentialstorage");
const filesystem_1 = require("../ios/filesystem");
const heap_1 = require("../ios/heap");
const hooking_1 = require("../ios/hooking");
const crypto_1 = require("../ios/crypto");
const jailbreak_1 = require("../ios/jailbreak");
const keychain_1 = require("../ios/keychain");
const constants_1 = require("../ios/lib/constants");
const nsuserdefaults_1 = require("../ios/nsuserdefaults");
const pasteboard_1 = require("../ios/pasteboard");
const pinning_1 = require("../ios/pinning");
const plist_1 = require("../ios/plist");
const userinterface_1 = require("../ios/userinterface");
exports.ios = {
    // binary
    iosBinaryInfo: () => binary_1.binary.info(),
    // ios binary cookies
    iosCookiesGet: () => binarycookies_1.binarycookies.get(),
    // ios nsurlcredentialstorage
    iosCredentialStorage: () => credentialstorage_1.credentialstorage.dump(),
    // ios filesystem
    iosFileCwd: () => filesystem_1.iosfilesystem.pwd(),
    iosFileDelete: (path) => filesystem_1.iosfilesystem.deleteFile(path),
    iosFileDownload: (path) => filesystem_1.iosfilesystem.readFile(path),
    iosFileExists: (path) => filesystem_1.iosfilesystem.exists(path),
    iosFileLs: (path) => filesystem_1.iosfilesystem.ls(path),
    iosFilePathIsFile: (path) => filesystem_1.iosfilesystem.pathIsFile(path),
    iosFileReadable: (path) => filesystem_1.iosfilesystem.readable(path),
    iosFileUpload: (path, data) => filesystem_1.iosfilesystem.writeFile(path, data),
    iosFileWritable: (path) => filesystem_1.iosfilesystem.writable(path),
    // ios heap
    iosHeapEvaluateJs: (pointer, js) => heap_1.heap.evaluate(pointer, js),
    iosHeapExecMethod: (pointer, method, returnString) => heap_1.heap.callInstanceMethod(pointer, method, returnString),
    iosHeapPrintIvars: (pointer, toUTF8) => heap_1.heap.getIvars(pointer, toUTF8),
    iosHeapPrintLiveInstances: (clazz) => heap_1.heap.getInstances(clazz),
    iosHeapPrintMethods: (pointer) => heap_1.heap.getMethods(pointer),
    // ios hooking
    iosHookingGetClassMethods: (className, includeParents) => hooking_1.hooking.getClassMethods(className, includeParents),
    iosHookingGetClasses: () => hooking_1.hooking.getClasses(),
    iosHookingSearchMethods: (partial) => hooking_1.hooking.searchMethods(partial),
    iosHookingSetReturnValue: (selector, returnVal) => hooking_1.hooking.setMethodReturn(selector, returnVal),
    iosHookingWatchClass: (clazz, parents) => hooking_1.hooking.watchClass(clazz, parents),
    iosHookingWatchMethod: (selector, dargs, dbt, dret) => hooking_1.hooking.watchMethod(selector, dargs, dbt, dret),
    // ios crypto monitoring
    iosMonitorCryptoEnable: () => crypto_1.ioscrypto.monitor(),
    // jailbreak detection
    iosJailbreakDisable: () => jailbreak_1.iosjailbreak.disable(),
    iosJailbreakEnable: () => jailbreak_1.iosjailbreak.enable(),
    // plist files
    iosPlistRead: (path) => plist_1.plist.read(path),
    // ios user interface
    iosUiAlert: (message) => userinterface_1.userinterface.alert(message),
    iosUiBiometricsBypass: () => userinterface_1.userinterface.biometricsBypass(),
    iosUiScreenshot: () => userinterface_1.userinterface.screenshot(),
    iosUiWindowDump: () => userinterface_1.userinterface.dump(),
    // ios ssl pinning
    iosPinningDisable: (quiet) => pinning_1.sslpinning.disable(quiet),
    // ios pasteboard
    iosMonitorPasteboard: () => pasteboard_1.pasteboard.monitor(),
    // ios frameworks & bundles
    iosBundlesGetBundles: () => bundles_1.bundles.getBundles(constants_1.BundleType.NSBundleAllBundles),
    iosBundlesGetFrameworks: () => bundles_1.bundles.getBundles(constants_1.BundleType.NSBundleFramework),
    // ios keychain
    iosKeychainAdd: (account, service, data) => keychain_1.ioskeychain.add(account, service, data),
    iosKeychainEmpty: () => keychain_1.ioskeychain.empty(),
    iosKeychainList: (smartDecode) => keychain_1.ioskeychain.list(smartDecode),
    iosKeychainListRaw: () => keychain_1.ioskeychain.listRaw(),
    // ios nsuserdefaults
    iosNsuserDefaultsGet: () => nsuserdefaults_1.nsuserdefaults.get(),
};

},{"../ios/binary":99,"../ios/binarycookies":100,"../ios/bundles":101,"../ios/credentialstorage":102,"../ios/crypto":103,"../ios/filesystem":104,"../ios/heap":105,"../ios/hooking":106,"../ios/jailbreak":107,"../ios/keychain":108,"../ios/lib/constants":109,"../ios/nsuserdefaults":112,"../ios/pasteboard":113,"../ios/pinning":114,"../ios/plist":115,"../ios/userinterface":116}],124:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jobs = void 0;
const jobs_1 = require("../lib/jobs");
exports.jobs = {
    // jobs
    jobsGet: () => jobs_1.jobs.all(),
    jobsKill: (ident) => jobs_1.jobs.kill(ident),
};

},{"../lib/jobs":120}],125:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.memory = void 0;
const memory_1 = require("../generic/memory");
exports.memory = {
    memoryDump: (address, size) => memory_1.memory.dump(address, size),
    memoryListExports: (name) => memory_1.memory.listExports(name),
    memoryListModules: () => memory_1.memory.listModules(),
    memoryListRanges: (protection) => memory_1.memory.listRanges(protection),
    memorySearch: (pattern, onlyOffsets) => memory_1.memory.search(pattern, onlyOffsets),
    memoryWrite: (address, value) => memory_1.memory.write(address, value),
};

},{"../generic/memory":96}],126:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.other = void 0;
const custom_1 = require("../generic/custom");
const http_1 = require("../generic/http");
exports.other = {
    evaluate: (js) => custom_1.custom.evaluate(js),
    // http server
    httpServerStart: (p, port) => http_1.http.start(p, port),
    httpServerStatus: () => http_1.http.status(),
    httpServerStop: () => http_1.http.stop(),
};

},{"../generic/custom":93,"../generic/http":95}]},{},[98])