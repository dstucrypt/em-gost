/*
 *
 * Interface code for emscripten-compiled gost89 (dstu200) code
 *
 * */
'use strict';

var util = require('./util.js');
var c = require('./uadstu.js');

var convert_password = function (parsed, pw, raw) {
    var vm_out, vm_pw, args, argtypes, ret = null;
    vm_out = c.allocate(32, 'i8', c.ALLOC_STACK);
    vm_pw = c.allocate(c.intArrayFromString(pw), 'i8', c.ALLOC_STACK);
    if (parsed.format === 'IIT') {
        args = [vm_pw, pw.length, vm_out];
        argtypes = ['number', 'number', 'number'];

        ret = c.ccall('iit_convert_password', 'number', argtypes, args);
    }
    if (parsed.format === 'PBES2') {
        args = [vm_pw, pw.length, util.asnbuf(parsed.salt), parsed.salt.length, parsed.iters, vm_out];
        argtypes = ['number', 'number', 'number', 'number', 'number'];
        ret = c.ccall('pbes2_convert_password', 'number', argtypes, args);
    }
    if (ret === 0) {
        if (raw === true) {
            return vm_out;
        }
        return util.read_buf(vm_out, 32);
    }

    throw new Error("Failed to convert key");
};

var decode_data = function (parsed, pw) {
    var args, argtypes, bkey, rbuf, ret;

    bkey = convert_password(parsed, pw, true);
    if (parsed.format === 'IIT') {
        rbuf = c.allocate(parsed.body.length + parsed.pad.length, 'i8', c.ALLOC_STACK);
        args = [
            util.asnbuf([parsed.body, parsed.pad]), parsed.body.length,
            bkey,
            util.asnbuf(parsed.mac),
            rbuf
        ];
        argtypes = ['number', 'number', 'number', 'number'];
        ret = c.ccall('iit_decode_data', 'number', argtypes, args);
    }
    if (parsed.format === 'PBES2') {
        rbuf = c.allocate(parsed.body.length, 'i8', c.ALLOC_STACK);
        args = [
            util.asnbuf(parsed.body), parsed.body.length,
            bkey,
            util.asnbuf(parsed.iv),
            util.asnbuf(parsed.sbox),
            rbuf
        ];
        argtypes = ['number', 'number', 'number', 'number', 'number', 'number'];
        ret = c.ccall('pbes2_decode_data', 'number', argtypes, args);

    }
    if (ret === 0) {
        return util.read_buf(rbuf, parsed.body.length, 'hex');
    }
};

var compute_hash = function (contents) {
    var args, argtypes, vm_contents, rbuf, err, ret, buffer;
    if ((typeof contents) === 'string') {
        buffer = new Buffer(contents);
    } else {
        buffer = contents;
    }
    rbuf = c.allocate(32, 'i8', c.ALLOC_STACK);
    vm_contents = c.allocate(buffer, 'i8', c.ALLOC_STACK);
    args = [vm_contents, buffer.length, rbuf];
    argtypes = ['number', 'number', 'number'];
    err = c.ccall('compute_hash', 'number', argtypes, args);
    if (err === 0) {
        ret = util.read_buf(rbuf, 32);
        return ret;
    }
    throw new Error("Document hasher failed");
};

var gost_unwrap = function (kek, inp) {
    var args, argtypes, vm_kek, vm_inp, rbuf, err;

    rbuf = c.allocate(32, 'i8', c.ALLOC_STACK);
    vm_kek = c.allocate(kek, 'i8', c.ALLOC_STACK);
    vm_inp = c.allocate(inp, 'i8', c.ALLOC_STACK);
    args = [vm_inp, vm_kek, rbuf];
    argtypes = ['number', 'number', 'number'];
    err = c.ccall('gost_key_unwrap', 'number', argtypes, args);
    if (err === 0) {
        return util.read_buf(rbuf, 32);
    }
    throw new Error("Key wrapper failed");
};

var gost_keywrap = function (kek, inp, iv) {
    var args, argtypes, vm_kek, vm_inp, vm_iv, rbuf, err;

    rbuf = c.allocate(44, 'i8', c.ALLOC_STACK);
    vm_kek = c.allocate(kek, 'i8', c.ALLOC_STACK);
    vm_inp = c.allocate(inp, 'i8', c.ALLOC_STACK);
    vm_iv = c.allocate(iv, 'i8', c.ALLOC_STACK);

    args = [vm_inp, vm_kek, vm_iv, rbuf];
    argtypes = ['number', 'number', 'number', 'number'];
    err = c.ccall('gost_key_wrap', 'number', argtypes, args);
    if (err === 0) {
        return util.read_buf(rbuf, 44);
    }
    throw new Error("Key wrapper failed");
};

var gost_kdf = function (buffer) {
    return compute_hash(buffer);
};

var gost_crypt = function (mode, inp, key, iv) {
    var args, argtypes, vm_kek, vm_wcek, rbuf, err;
    rbuf = c.allocate(Math.ceil(inp.length/8) * 8, 'i8', c.ALLOC_STACK);

    args = [mode, util.asnbuf(inp), inp.length,
            util.asnbuf(key), util.asnbuf(iv),
            rbuf];
    argtypes = ['number', 'number', 'number', 'number', 'number', 'number'];
    err = c.ccall('gost_crypt', 'number', argtypes, args);
    if (err == 0) {
        return util.read_buf(rbuf, inp.length);
    }

    throw new Error("Decrypt failed, code " + err);
}

var gost_decrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(1, cypher, key, iv);
};

var gost_encrypt_cfb = function(cypher, key, iv) {
    return gost_crypt(0, cypher, key, iv);
};

module.exports.decode_data = decode_data;
module.exports.convert_password = convert_password;
module.exports.compute_hash = compute_hash;
module.exports.gost_kdf = gost_kdf;
module.exports.gost_unwrap = gost_unwrap;
module.exports.gost_keywrap = gost_keywrap;
module.exports.gost_decrypt_cfb = gost_decrypt_cfb;
module.exports.gost_encrypt_cfb = gost_encrypt_cfb;
